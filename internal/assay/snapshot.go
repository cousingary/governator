package assay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/toolregistry"
)

// AssayerSnapshotMutated is the exact quarantine token Sol10 P0-4 requires
// (mirroring runtime.ConsumedArtifactMutated's Sol10 P0-1 shape): any
// Snapshot.Verify mismatch, at either verification point (immediately
// before launch, immediately after evaluation), must report exactly this
// string -- never a differently-worded message describing the same
// condition -- so operators and the redteam corpus can grep for one fixed
// token.
const AssayerSnapshotMutated = "ASSAYER_SNAPSHOT_MUTATED"

// Snapshot is a private, read-only copy of the executable Assayer
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
//
// Sol10 P0-4: mode 0400/0500 alone is not immutability against a second
// process sharing this same OS user -- exactly like
// toolregistry.SealedCopy's own doc comment concludes for a single sealed
// executable (memfd_create+F_ADD_SEALS was tried and rejected: linkat(2)
// publishing an anonymous shmem-backed inode into a real, PATH-discoverable
// directory entry fails EXDEV, and FS_IMMUTABLE_FL needs
// CAP_LINUX_IMMUTABLE, which Governator does not run with) -- that same
// process can chmod the directory or a file back open, overwrite a file in
// place, or unlink/rename a replacement over it. So, like SealedCopy, this
// is honestly a private read-only copy, never an immutable one: Dir/files
// hold no kernel-enforced write boundary against this same UID. What makes
// it safe to execute against is Verify -- every file's bytes are retained
// through an open descriptor from the moment it is copied, and the caller
// (assay.Evaluate) MUST call Verify immediately before the launch that will
// import Dir, and again immediately after that launch completes, before
// trusting the verdict it produced. Any mismatch is exactly
// AssayerSnapshotMutated; there is no retry or silent re-copy.
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

	// files is the retained-descriptor manifest Verify walks: one entry per
	// file copied into Dir, opened read-only immediately after it was
	// written and chmod'd, so later re-reads go through the same
	// descriptor rather than reopening the (possibly since-replaced) path.
	files []snapshotFile
}

// snapshotFile is one copied file's golden identity: the relative path
// inside Dir, its content hash at copy time, the retained read-only
// descriptor, and the dev/inode pair that descriptor's directory entry
// resolved to at open time -- mirrors toolregistry.SealedCopy's fields
// exactly, for the same reason (Verify below is SealedCopy.Verify's
// same-UID-tamper check, generalized from one file to a whole tree).
type snapshotFile struct {
	rel    string
	sha256 string
	file   *os.File
	dev    uint64
	ino    uint64
}

// Close releases the held python handle and every retained per-file
// descriptor, then removes the private snapshot directory. Safe to call on
// a nil Snapshot.
func (s *Snapshot) Close() {
	if s == nil {
		return
	}
	if s.Python != nil {
		s.Python.Close()
	}
	for _, sf := range s.files {
		if sf.file != nil {
			_ = sf.file.Close()
		}
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

// Verify re-checks every copied snapshot file against its retained
// descriptor and dev/inode identity, and confirms Dir's tree still
// contains exactly the files that were copied -- no more, no fewer (Sol10
// P0-4 cases 21/22). The caller MUST invoke this immediately before
// launching Python against the snapshot, and again immediately after that
// launch completes, before trusting the verdict it produced: a same-UID
// process elsewhere on the host can chmod Dir back open and, at any point
// between BuildSnapshot's tree-hash calculation and either check, unlink
// and replace a file, rename a different file over one, or chmod-and-
// overwrite one in place -- mode 0400/0500 alone denies none of that to a
// process sharing this same UID (see Snapshot's doc comment). Any mismatch
// is reported as exactly AssayerSnapshotMutated; Verify never re-copies or
// otherwise repairs what it finds, only reports it.
func (s *Snapshot) Verify() error {
	if s == nil {
		return fmt.Errorf("assay: cannot verify a nil snapshot")
	}
	seen := make(map[string]bool, len(s.files))
	for _, sf := range s.files {
		seen[sf.rel] = true
		abs := filepath.Join(s.Dir, filepath.FromSlash(sf.rel))
		info, err := os.Lstat(abs)
		if err != nil {
			return fmt.Errorf("%s: snapshot file %q unreadable: %w", AssayerSnapshotMutated, sf.rel, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: snapshot file %q replaced with a symlink", AssayerSnapshotMutated, sf.rel)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: snapshot file %q: platform exposes no inode identity", AssayerSnapshotMutated, sf.rel)
		}
		if uint64(st.Dev) != sf.dev || uint64(st.Ino) != sf.ino {
			return fmt.Errorf("%s: snapshot file %q: directory entry replaced since publish (dev/inode mismatch)", AssayerSnapshotMutated, sf.rel)
		}
		if _, err := sf.file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("%s: snapshot file %q: rewind retained descriptor: %w", AssayerSnapshotMutated, sf.rel, err)
		}
		sum := sha256.New()
		if _, err := io.Copy(sum, sf.file); err != nil {
			return fmt.Errorf("%s: snapshot file %q: read retained descriptor: %w", AssayerSnapshotMutated, sf.rel, err)
		}
		if hex.EncodeToString(sum.Sum(nil)) != sf.sha256 {
			return fmt.Errorf("%s: snapshot file %q: content changed since publish", AssayerSnapshotMutated, sf.rel)
		}
	}
	// An attacker need not overwrite an enrolled file if Python's import
	// machinery will just as happily pick up a brand-new module dropped
	// alongside it -- confirm the tree contains no file outside the
	// enrolled manifest.
	extra, err := extraSnapshotFile(s.Dir, seen)
	if err != nil {
		return fmt.Errorf("%s: walk snapshot tree: %w", AssayerSnapshotMutated, err)
	}
	if extra != "" {
		return fmt.Errorf("%s: unexpected file %q present in snapshot tree", AssayerSnapshotMutated, extra)
	}
	return nil
}

// extraSnapshotFile walks dir and returns the first regular file whose
// path (relative to dir, slash-normalized) is not a key in enrolled, or ""
// if every file on disk is enrolled.
func extraSnapshotFile(dir string, enrolled map[string]bool) (string, error) {
	var found string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() || found != "" {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if !enrolled[rel] {
			found = rel
		}
		return nil
	})
	return found, err
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

	// Retain an open read-only descriptor to every copied file, right here
	// while the tree is freshest, so Verify's later re-reads (immediately
	// before launch, and again immediately after evaluation) go through the
	// descriptor rather than reopening a path a same-UID process may since
	// have unlinked and replaced (Sol10 P0-4). filesOK guards cleanup on any
	// failure in this loop -- an error here must not leak the descriptors
	// already opened.
	files := make([]snapshotFile, 0, len(copied))
	filesOK := false
	defer func() {
		if !filesOK {
			for _, sf := range files {
				if sf.file != nil {
					_ = sf.file.Close()
				}
			}
		}
	}()
	for _, cf := range copied {
		f, oerr := os.Open(filepath.Join(dir, filepath.FromSlash(cf.rel)))
		if oerr != nil {
			return fail("open retained descriptor for %s: %s", cf.rel, oerr)
		}
		info, serr := f.Stat()
		if serr != nil {
			_ = f.Close()
			return fail("stat retained descriptor for %s: %s", cf.rel, serr)
		}
		st, stok := info.Sys().(*syscall.Stat_t)
		if !stok {
			_ = f.Close()
			return fail("retain %s: platform exposes no inode identity", cf.rel)
		}
		sum := sha256.New()
		if _, cerr := io.Copy(sum, f); cerr != nil {
			_ = f.Close()
			return fail("hash retained descriptor for %s: %s", cf.rel, cerr)
		}
		if hex.EncodeToString(sum.Sum(nil)) != cf.sha {
			_ = f.Close()
			return fail("retained descriptor for %s does not match the bytes just written", cf.rel)
		}
		files = append(files, snapshotFile{rel: cf.rel, sha256: cf.sha, file: f, dev: uint64(st.Dev), ino: uint64(st.Ino)})
	}
	filesOK = true

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
		files:       files,
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
