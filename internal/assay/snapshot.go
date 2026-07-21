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
	"time"

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

// SnapshotProtocolVersion identifies the shape of SnapshotIdentity below --
// bump only when that field set changes, mirroring
// ArtifactProtocolVersion/BridgePolicyVersion's existing versioning
// convention elsewhere in this package.
const SnapshotProtocolVersion = "gov-assay-snapshot-identity-v1"

// SnapshotIdentity is Sol10 P0-6's fix: the ONE and ONLY source of Assayer
// transaction identity. Every field here is resolved once, inside
// BuildSnapshot, from data already gathered while building this same
// Snapshot -- never re-read from cfg.Repo, never re-resolved against the
// trusted-tool registry, afterward. Before this type existed,
// internal/runtime's resolvedAssayerEnvironmentHash/resolvedAssayerParticipants
// combined a caller's frozen *Snapshot with several LIVE reads performed
// after that Snapshot was already built (a live repo tree walk, a freshly
// resolved python3, assay.DescribeEnvironment) -- so the ledgered identity
// described a hybrid of the snapshot actually executed plus whatever the
// live checkout/registry happened to be at the moment identity was
// computed, not the identity of any single executable transaction. A
// caller that wants Assayer transaction identity now reads this struct and
// nothing else.
type SnapshotIdentity struct {
	// PackageHash is TreeHash: a sha256 over exactly the file set copied
	// into Dir (path+content), sorted by path.
	PackageHash string
	// PythonIdentity is the verified python3 handle's registry identity,
	// captured once at resolve time -- never re-resolved.
	PythonIdentity toolregistry.Identity
	// RuntimeHash/DependencyHash/LockHash are
	// Runtime.RuntimeHash/DependencyHash/LockHash -- see RuntimeManifest's
	// doc comment. LockHash is the declared dependency lock's own hash
	// (requirements-lock.txt), distinct from DependencyHash (the *installed*
	// bytes): binding it here means a lockfile edit with no corresponding
	// change to what's actually installed still mints a different identity.
	RuntimeHash    string
	DependencyHash string
	LockHash       string
	// ProfileHash is assayer/profiles.py's content hash at copy time, taken
	// directly from the bytes actually copied into Dir -- never a separate
	// live read of cfg.Repo.
	ProfileHash string
	// ProtocolVersion is SnapshotProtocolVersion at build time.
	ProtocolVersion string
	// GitCommit is cfg.Repo's commit (or PINNED_COMMIT fixture marker),
	// resolved once here, at snapshot-build time -- a later live
	// git-rev-parse against the (possibly since-changed) checkout never
	// factors into an already-built transaction's identity.
	GitCommit string
	// Dirty mirrors Snapshot.Dirty.
	Dirty bool
}

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
	// (path+content), sorted by path. This is the execution identity --
	// also exposed as Identity.PackageHash, the copy every replay-identity
	// caller should read (see SnapshotIdentity's doc comment).
	TreeHash string
	// Python is the verified, held python3 handle resolved once for this
	// snapshot. Evaluate must launch through this handle, never re-resolve
	// python for itself.
	Python *toolregistry.Handle
	// Runtime is Sol10 P0-5's frozen record of the Python runtime this
	// snapshot's subprocess actually executes against -- the stdlib closure
	// Evaluate grants read access to, hashed once here (isolated startup
	// probe) rather than rediscovered live on every Evaluate call. See
	// RuntimeManifest's doc comment.
	Runtime RuntimeManifest
	// Dirty is true when Repo was a real git checkout with uncommitted
	// changes at snapshot-build time: what's on disk right now cannot
	// necessarily be reproduced by a later audit against a specific commit,
	// so strict replay must be disabled for a transaction built from one.
	Dirty       bool
	DirtyReason string

	// Identity is Sol10 P0-6's SnapshotIdentity -- the sole source of
	// Assayer transaction identity. See that type's doc comment.
	Identity SnapshotIdentity

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

	// Sol10 P0-5: resolve the frozen runtime manifest here, once, through
	// the same held handle -- never inside Evaluate, and never via the old
	// pythonStdlibReadRoots' live-per-call ambient probe. The stdlib
	// closure this returns is the exact (and only) thing Evaluate grants
	// read access to; a host whose stdlib this can't resolve/hash cannot
	// back the immutable-evaluator guarantee at all, so this is fail
	// closed like Session 1/2's boundary primitives, not best-effort like
	// DescribeEnvironment's metadata probes below.
	runtimeManifest, rerr := buildRuntimeManifest(pythonHandle, cfg.Repo)
	if rerr != nil {
		return nil, fmt.Errorf("assay: snapshot: resolve frozen python runtime manifest: %w", rerr)
	}

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

	// Sol10 P0-6: resolved once, here, from data this call already has in
	// hand -- profileHash from the bytes just copied (never a separate live
	// read), gitCommit from one probe at build time (never re-read by a
	// later identity calculation against the possibly-since-changed live
	// checkout).
	treeHash := hex.EncodeToString(treeSum[:])
	profileHash := ""
	for _, cf := range copied {
		if cf.rel == "assayer/profiles.py" {
			profileHash = cf.sha
			break
		}
	}
	identity := SnapshotIdentity{
		PackageHash:     treeHash,
		PythonIdentity:  pythonHandle.Identity,
		RuntimeHash:     runtimeManifest.RuntimeHash,
		DependencyHash:  runtimeManifest.DependencyHash,
		LockHash:        runtimeManifest.LockHash,
		ProfileHash:     profileHash,
		ProtocolVersion: SnapshotProtocolVersion,
		GitCommit:       assayerCommit(cfg.Repo),
		Dirty:           dirty,
	}

	ok = true
	return &Snapshot{
		Dir:         dir,
		CLIPath:     filepath.Join(dir, "cli.py"),
		TreeHash:    treeHash,
		Python:      pythonHandle,
		Runtime:     runtimeManifest,
		Dirty:       dirty,
		DirtyReason: dirtyReason,
		Identity:    identity,
		files:       files,
	}, nil
}

// runtimeProbeTimeout bounds the isolated sysconfig probe subprocess only
// (path discovery) -- the filesystem hashing that follows is local I/O, not
// attacker-controlled, and is not itself context-bounded, matching
// BuildSnapshot's own file-copy loop above.
const runtimeProbeTimeout = 10 * time.Second

// RuntimeManifest is Sol10 P0-5's frozen record of the Python runtime a
// Snapshot's subprocess actually executes against.
//
// The defect: the pre-P0-5 pythonStdlibReadRoots discovered and permitted
// *live* stdlib/platstdlib/purelib/platlib directories on every Evaluate
// call, via `python -c "import sysconfig ..."` run with full site
// initialization already in effect -- so ambient sitecustomize.py/.pth
// files could shape the probe itself before it ever printed a path, and the
// granted read roots (including site-packages) were whatever happened to be
// on disk at call time, never frozen into replay identity.
//
// The fix has two parts. First, Evaluate always launches with the `-S`
// interpreter flag (never here -- BuildSnapshot only *resolves* the
// manifest; Evaluate is what launches), which disables the `site` module
// entirely: no .pth file in any site-packages directory is ever processed,
// sitecustomize.py/usercustomize.py are never imported, and site-packages
// is never added to sys.path -- structurally, not by scanning for those
// files. That is safe specifically because the `evaluate` subcommand never
// imports a third-party package (`cli.py`'s own `from assayer.store import
// Store` is safe: Store.client only imports `supabase` lazily, inside a
// property -- see assay_integration_test.go's rationale comment), so
// StdlibReadRoots below never needs to include purelib/platlib at all.
// Second, the probe that resolves StdlibReadRoots itself now also runs with
// `-S` (buildRuntimeManifest), closing Sol's "startup problem" for the
// probe the same way.
//
// RuntimeHash and DependencyHash exist so a stdlib module or an installed
// dependency changing bytes -- with or without a corresponding lockfile
// change -- shows up in the frozen identity a later replay compares
// against (Sol10 P0-5 cases 27/28), even though DependencyHash's inputs are
// deliberately never granted read authority during execution.
type RuntimeManifest struct {
	// StdlibReadRoots are the exact directories Evaluate grants read access
	// to so the interpreter can import its own standard library -- resolved
	// once here, never re-probed live inside Evaluate. Never includes
	// purelib/platlib (site-packages): see the type doc comment.
	StdlibReadRoots []string
	// RuntimeHash is a sha256 over the sorted (path, content) pairs of
	// every file under StdlibReadRoots -- the frozen identity of exactly
	// what Evaluate's subprocess can import.
	RuntimeHash string
	// DependencyHash is a sha256 over the sorted (path, content) pairs of
	// every file actually installed under the resolved purelib/platlib
	// directories (site-packages), when this host's python3 has any --
	// present for identity/reproducibility only, since this content is
	// deliberately never part of ReadRoots/PYTHONPATH (evaluate never
	// imports it). Empty, with DependencyUnavailableReason set, when no
	// site-packages directory is resolvable; that is a value observation
	// about the host's Python layout, not a build failure -- unlike
	// RuntimeHash/StdlibReadRoots, this half of the manifest is
	// best-effort.
	DependencyHash string
	// LockHash is sha256(requirements-lock.txt) at cfg.Repo, when present
	// -- the declared dependency lock's own identity, recorded separately
	// from DependencyHash (the *installed* bytes) so "the lock file
	// changed" and "what's installed changed" are two distinct signals,
	// never collapsed into one.
	LockHash string
	// DependencyUnavailableReason explains why DependencyHash is empty.
	DependencyUnavailableReason string
}

// buildRuntimeManifest resolves and hashes RuntimeManifest for python,
// exactly once, at BuildSnapshot time. The stdlib half is mandatory (a
// probe or hash failure fails snapshot construction closed); the
// dependency half is best-effort, matching this file's DescribeEnvironment-
// style probes.
func buildRuntimeManifest(python *toolregistry.Handle, repo string) (RuntimeManifest, error) {
	probeCtx, cancel := context.WithTimeout(context.Background(), runtimeProbeTimeout)
	defer cancel()
	// -S: isolated startup (Sol10 P0-5's "startup problem") -- this probe
	// must not let ambient site configuration shape which paths it
	// discovers, exactly like Evaluate's own launch must not let it shape
	// evaluation.
	cmd, err := python.Command(probeCtx, "-S", "-c",
		"import sysconfig\n"+
			"for k in ('stdlib','platstdlib','purelib','platlib'):\n"+
			"    print(k + '=' + sysconfig.get_path(k))\n")
	if err != nil {
		return RuntimeManifest{}, fmt.Errorf("construct isolated sysconfig probe: %w", err)
	}
	cmd.Env = controllerenv.Base()
	out, err := cmd.Output()
	if err != nil {
		return RuntimeManifest{}, fmt.Errorf("run isolated sysconfig probe: %w", err)
	}

	stdlibSeen := map[string]bool{}
	siteSeen := map[string]bool{}
	var stdlibRoots, siteRoots []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, path, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || path == "" {
			continue
		}
		if _, statErr := os.Stat(path); statErr != nil {
			continue
		}
		switch key {
		case "stdlib", "platstdlib":
			if !stdlibSeen[path] {
				stdlibSeen[path] = true
				stdlibRoots = append(stdlibRoots, path)
			}
		case "purelib", "platlib":
			if !siteSeen[path] {
				siteSeen[path] = true
				siteRoots = append(siteRoots, path)
			}
		}
	}
	if len(stdlibRoots) == 0 {
		return RuntimeManifest{}, fmt.Errorf("isolated sysconfig probe resolved no stdlib/platstdlib directory")
	}

	runtimeHash, herr := hashPathTree(stdlibRoots)
	if herr != nil {
		return RuntimeManifest{}, fmt.Errorf("hash stdlib tree: %w", herr)
	}
	if runtimeHash == "" {
		return RuntimeManifest{}, fmt.Errorf("stdlib tree hashed to no files at %v", stdlibRoots)
	}

	manifest := RuntimeManifest{StdlibReadRoots: stdlibRoots, RuntimeHash: runtimeHash}

	depHash, depErr := hashPathTree(siteRoots)
	switch {
	case depErr != nil:
		manifest.DependencyUnavailableReason = fmt.Sprintf("hash site-packages tree: %s", depErr)
	case depHash == "":
		manifest.DependencyUnavailableReason = "no site-packages directory resolved for this python3"
	default:
		manifest.DependencyHash = depHash
	}

	if data, rerr := os.ReadFile(filepath.Join(repo, "requirements-lock.txt")); rerr == nil {
		sum := sha256.Sum256(data)
		manifest.LockHash = hex.EncodeToString(sum[:])
	}

	return manifest, nil
}

// hashPathTree returns a sha256 over the sorted (root-qualified relative
// path, content) pairs of every regular file under roots -- "" (never an
// error) when roots resolves to zero files. __pycache__ directories and
// symlinks are skipped: a symlink could resolve outside the declared root,
// silently widening what's actually being attested to, and __pycache__ is
// derived, non-source content that would make the hash flap on every
// interpreter run without the underlying .py source ever changing. A
// missing root is skipped, not an error -- callers decide whether an
// entirely empty result is fatal (buildRuntimeManifest: fatal for stdlib,
// best-effort for site-packages).
func hashPathTree(roots []string) (string, error) {
	type fileEntry struct{ key, sha string }
	var entries []fileEntry
	for _, root := range roots {
		info, statErr := os.Stat(root)
		if statErr != nil || !info.IsDir() {
			continue
		}
		walkErr := filepath.Walk(root, func(path string, fi os.FileInfo, werr error) error {
			if werr != nil {
				return werr
			}
			if fi.IsDir() {
				if fi.Name() == "__pycache__" {
					return filepath.SkipDir
				}
				return nil
			}
			if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return fmt.Errorf("read %s: %w", path, rerr)
			}
			sum := sha256.Sum256(data)
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			entries = append(entries, fileEntry{
				key: root + "::" + filepath.ToSlash(rel),
				sha: hex.EncodeToString(sum[:]),
			})
			return nil
		})
		if walkErr != nil {
			return "", walkErr
		}
	}
	if len(entries) == 0 {
		return "", nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	items := make([]map[string]string, 0, len(entries))
	for _, e := range entries {
		items = append(items, map[string]string{"path": e.key, "sha256": e.sha})
	}
	canonical, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// snapshotDirty is a best-effort, read-only probe (same shape as
// buildRuntimeManifest's DependencyHash half/environment.go's
// assayerCommit): any failure to
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
