package assay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/toolregistry"
)

// Snapshot is an immutable, private copy of the executable Assayer
// distribution -- cli.py plus the assayer/ package -- built once per
// governed transaction, before that transaction's replay identity is
// calculated. It is the ONLY thing Evaluate ever executes against.
//
// Sol9 P0-4: the old Evaluate reloaded the trusted-tool registry, resolved
// python3 again, sealed only cli.py, and set PYTHONPATH to the live
// checkout -- so a concurrent edit to assayer/checks.py or profiles.py
// between replay-identity calculation and subprocess launch changed which
// bytes actually produced the verdict, while the ledgered identity still
// recorded the pre-edit state. Freezing one Snapshot (tree hash + held
// python handle) before replay and threading that same object through
// every Evaluate call in the transaction closes that TOCTOU window.
type Snapshot struct {
	// Dir is the private, read-only directory containing the copied cli.py
	// and assayer/ package.
	Dir string
	// CLIPath is Dir/cli.py -- the only entry point ever executed.
	CLIPath string
	// TreeHash is a sha256 over exactly the file set copied into Dir
	// (path+content), sorted by path. This is the execution identity, as
	// opposed to internal/runtime's broader (and noisier) whole-checkout
	// assayerRepoTreeHash.
	TreeHash string
	// Python is the verified, held python3 handle resolved once for this
	// snapshot. Evaluate must launch through this handle, never re-resolve
	// python for itself.
	Python *toolregistry.Handle
	// Dirty is true when Repo was a real git checkout with uncommitted
	// changes at snapshot-build time: what's on disk right now cannot
	// necessarily be reproduced by a later audit against a specific commit,
	// so strict replay must be disabled for a transaction built from one.
	Dirty       bool
	DirtyReason string
}

// Close releases the held python handle and removes the private snapshot
// directory. Safe to call on a nil Snapshot.
func (s *Snapshot) Close() {
	if s == nil {
		return
	}
	if s.Python != nil {
		s.Python.Close()
	}
	if s.Dir != "" {
		_ = filepath.Walk(s.Dir, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
		_ = os.RemoveAll(s.Dir)
	}
}

// BuildSnapshot copies cfg.Repo's executable distribution into a private
// read-only directory and resolves+holds a verified python3 handle through
// registry. The caller must build this exactly ONCE per governed
// transaction -- before that transaction's replay identity is calculated --
// and thread the returned *Snapshot through every Evaluate call in the
// transaction; never rebuild per-artifact and never let Evaluate rebuild
// its own.
func BuildSnapshot(registry *toolregistry.Registry, cfg Config) (*Snapshot, error) {
	if !cfg.Configured() {
		return nil, fmt.Errorf("assay: cannot build an execution snapshot for an unconfigured repo")
	}
	if registry == nil {
		return nil, fmt.Errorf("assay: cannot build an execution snapshot without a frozen tool registry")
	}
	python := strings.TrimSpace(cfg.Python)
	if python == "" {
		python = "python3"
	}
	pythonHandle, err := registry.ResolveHandle("python3", python, toolregistry.KindTrustedController)
	if err != nil {
		return nil, fmt.Errorf("assay: resolve trusted python3 handle: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			pythonHandle.Close()
		}
	}()

	if _, statErr := os.Stat(filepath.Join(cfg.Repo, "cli.py")); statErr != nil {
		return nil, fmt.Errorf("assay: cli.py missing from repo %s: %w", cfg.Repo, statErr)
	}

	dir, err := os.MkdirTemp("", "governator-assayer-snapshot-*")
	if err != nil {
		return nil, fmt.Errorf("assay: create snapshot dir: %w", err)
	}
	fail := func(format string, args ...any) (*Snapshot, error) {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("assay: snapshot: "+format, args...)
	}

	type copiedFile struct{ rel, sha string }
	var copied []copiedFile

	copyOne := func(srcRel string) error {
		src := filepath.Join(cfg.Repo, filepath.FromSlash(srcRel))
		data, rerr := os.ReadFile(src)
		if rerr != nil {
			return fmt.Errorf("read %s: %w", srcRel, rerr)
		}
		dst := filepath.Join(dir, filepath.FromSlash(srcRel))
		if merr := os.MkdirAll(filepath.Dir(dst), 0o700); merr != nil {
			return fmt.Errorf("mkdir for %s: %w", srcRel, merr)
		}
		if werr := os.WriteFile(dst, data, 0o600); werr != nil {
			return fmt.Errorf("write %s: %w", srcRel, werr)
		}
		sum := sha256.Sum256(data)
		copied = append(copied, copiedFile{rel: filepath.ToSlash(srcRel), sha: hex.EncodeToString(sum[:])})
		return nil
	}

	if cerr := copyOne("cli.py"); cerr != nil {
		return fail("%s", cerr)
	}

	assayerPkgDir := filepath.Join(cfg.Repo, "assayer")
	if info, statErr := os.Stat(assayerPkgDir); statErr == nil && info.IsDir() {
		walkErr := filepath.Walk(assayerPkgDir, func(path string, info os.FileInfo, werr error) error {
			if werr != nil {
				return werr
			}
			if info.IsDir() {
				if info.Name() == "__pycache__" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".py") {
				return nil
			}
			rel, relErr := filepath.Rel(cfg.Repo, path)
			if relErr != nil {
				return relErr
			}
			return copyOne(rel)
		})
		if walkErr != nil {
			return fail("copy assayer package: %s", walkErr)
		}
	}

	// Lock down: no writer, including this same process, touches these
	// bytes again before Close() explicitly tears the snapshot down.
	for _, cf := range copied {
		if cerr := os.Chmod(filepath.Join(dir, filepath.FromSlash(cf.rel)), 0o400); cerr != nil {
			return fail("chmod %s: %s", cf.rel, cerr)
		}
	}
	dirErr := filepath.Walk(dir, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			return os.Chmod(path, 0o500)
		}
		return nil
	})
	if dirErr != nil {
		return fail("lock directory tree: %s", dirErr)
	}

	sort.Slice(copied, func(i, j int) bool { return copied[i].rel < copied[j].rel })
	items := make([]map[string]string, 0, len(copied))
	for _, cf := range copied {
		items = append(items, map[string]string{"path": cf.rel, "sha256": cf.sha})
	}
	canonical, _ := json.Marshal(items)
	treeSum := sha256.Sum256(canonical)

	dirty, dirtyReason := snapshotDirty(registry, cfg.Repo)

	ok = true
	return &Snapshot{
		Dir:         dir,
		CLIPath:     filepath.Join(dir, "cli.py"),
		TreeHash:    hex.EncodeToString(treeSum[:]),
		Python:      pythonHandle,
		Dirty:       dirty,
		DirtyReason: dirtyReason,
	}, nil
}

// snapshotDirty is a best-effort, read-only probe (same shape as
// pythonStdlibReadRoots/environment.go's assayerCommit): any failure to
// resolve git or run the probe reports "not dirty" rather than blocking a
// snapshot build over a diagnostic-only signal. A repo with no .git at all
// (e.g. a pinned fixture) has no notion of "uncommitted changes" and is
// never dirty.
func snapshotDirty(registry *toolregistry.Registry, repo string) (bool, string) {
	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		return false, ""
	}
	gitHandle, err := registry.ResolveHandle("git", "git", toolregistry.KindTrustedController)
	if err != nil {
		return false, ""
	}
	defer gitHandle.Close()
	ctx, cancel := context.WithTimeout(context.Background(), environmentProbeTimeout)
	defer cancel()
	cmd, cerr := gitHandle.Command(ctx, "-C", repo, "status", "--porcelain")
	if cerr != nil {
		return false, ""
	}
	cmd.Env = controllerenv.Base()
	var out bytes.Buffer
	cmd.Stdout = &out
	if rerr := cmd.Run(); rerr != nil {
		return false, ""
	}
	if strings.TrimSpace(out.String()) != "" {
		return true, "assayer repo has uncommitted changes at snapshot-build time"
	}
	return false, ""
}
