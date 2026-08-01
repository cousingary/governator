package assay

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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
	// PackageTreeHash is the canonical hash of the executable source-tree
	// members that were packed into Package. Assayer's `identity` command
	// emits this same value, allowing the release integration gate to bind the
	// tool-reported checkout to the exact source tree Snapshot sealed.
	PackageTreeHash string
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
	// DependencyUnavailableReason is non-empty when DependencyHash could not
	// be resolved (Sol12 P1-6). Binding it into identity ensures two
	// different unknown dependency environments never compare equal: each
	// carries its own distinct reason string. When this field is non-empty,
	// strict replay is disabled and production approval is blocked -- an
	// unknown dependency identity is never silently accepted.
	DependencyUnavailableReason string
	// InterpreterIdentityHash is Sol11 P1-1's addition: a sha256 over the
	// isolated probe's own interpreter-identity JSON (sys.version,
	// sys.implementation name/cache_tag, hexversion, abiflags, byteorder,
	// platform, and the SOABI/EXT_SUFFIX/Py_ENABLE_SHARED/SIZEOF_VOID_P/
	// WITH_PYMALLOC config vars) -- see buildRuntimeManifest. RuntimeHash
	// alone hashes stdlib file content but says nothing about which exact
	// interpreter build produced that content (ABI tag, word size, build
	// config); this closes that gap so a same-stdlib-bytes-different-
	// interpreter-build swap still changes replay identity.
	InterpreterIdentityHash string
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
	// Cleanliness mirrors Snapshot.Cleanliness -- see that field's doc
	// comment and the Cleanliness type doc comment (Sol11 P1-2).
	Cleanliness Cleanliness
}

type packagedFile struct{ rel, sha string }

// packageTreeHash is deliberately independent of zip metadata. Both this Go
// package and Assayer's `cli.py identity` hash sorted
// path/NUL/content-sha256/newline records, where cli.py's archive name is
// __main__.py. Keep the encoding byte-for-byte in sync with Assayer.
func packageTreeHash(files []packagedFile) string {
	files = append([]packagedFile(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	h := sha256.New()
	for _, file := range files {
		_, _ = h.Write([]byte(file.rel))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(file.sha))
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Snapshot is the executable Assayer distribution -- cli.py plus the
// assayer/ package -- built once per governed transaction, before that
// transaction's replay identity is calculated. It is the ONLY thing
// Evaluate ever executes against.
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
// Sol10 P0-4 built a private, chmod(0400/0500) read-only directory copy,
// with every file's bytes retained through an open descriptor and
// re-verified immediately before and after each launch. Sol11 P0-6 found
// the remaining gap: a same-UID process could chmod the directory back
// open between the two Verify calls, replace a module's bytes while
// Python's import machinery (which reads by PATHNAME from PYTHONPATH, never
// through the retained descriptor) was actually reading it, then restore
// the original bytes before the post-launch Verify -- both verification
// passes succeed while different bytes actually produced the verdict, since
// neither one is checking DURING the window that matters. Mode bits are a
// permission check a same-UID chmod can always undo; they were never a
// kernel boundary (exactly SealedCopy's own doc comment, and toolregistry's
// memfd_create+F_ADD_SEALS note this file's history already carried: EXDEV
// blocks linkat(2)'ing a sealed memfd into a real, PATH-discoverable
// directory entry, which is why every PATH-based tool launch elsewhere in
// this codebase settled for "private copy + re-verify" instead).
//
// The fix removes the pathname entirely rather than trying to detect
// tampering of one. Package is a sealed, unlinked memfd (memfd_create,
// never linkat'd into any directory) holding a zip archive -- cli.py
// renamed to __main__.py, plus assayer/*.py -- sealed with F_SEAL_WRITE |
// F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL immediately after being
// written. Evaluate launches Python with Package's own held descriptor
// passed as the script argument (via toolregistry.FDAllocator, exactly like
// Sol11 P0-5's descriptor-only executable launch); Python's zipimport reads
// __main__.py and every assayer/*.py member straight out of the zip, never
// touching PYTHONPATH or any real directory. There is no directory entry
// for a same-UID process to chmod, unlink, or rename over: the kernel
// refuses every write/truncate/mmap-write syscall against the sealed fd
// outright, for every process holding any descriptor to it (verified
// empirically: even the owning process's own second, freshly-reopened
// /proc/self/fd/<n> handle to the same memfd is refused identically -- see
// TestV11Case34/35 in v11_s5_immutable_package_test.go). Verify below is
// now defense-in-depth (confirms the seals are still exactly what
// BuildSnapshot set, and that the bytes still match, in case of a Go-level
// bug elsewhere) rather than the load-bearing detection mechanism it was
// before this session -- the actual guarantee is now structural, not
// after-the-fact.
type Snapshot struct {
	// Package is the sealed, unlinked memfd holding the zip archive Evaluate
	// executes. See the type doc comment.
	Package *os.File
	// PackageHash is a sha256 over Package's exact sealed bytes. Also
	// exposed as Identity.PackageHash, the copy every replay-identity
	// caller should read (see SnapshotIdentity's doc comment).
	PackageHash string
	// WorkDir is a private, empty directory created once per Snapshot,
	// containing nothing: Evaluate's launch still needs a real,
	// stat-able Workspace path to anchor its (read-only) Landlock rule, but
	// the package itself is never read from a directory anymore, so this
	// directory holds no Assayer content at all -- unlike the old Dir, its
	// own contents carry no execution identity.
	WorkDir string
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
	// Dirty is true whenever Cleanliness is not CleanlinessClean -- i.e. Repo
	// was a real git checkout with uncommitted changes at snapshot-build
	// time, OR its cleanliness could not be determined at all (Sol11 P1-2:
	// an indeterminate checkout is never treated as clean). What's on disk
	// right now cannot necessarily be reproduced by a later audit against a
	// specific commit, so strict replay must be disabled for a transaction
	// built from either state.
	Dirty       bool
	DirtyReason string
	// Cleanliness is the tri-state result snapshotDirty actually observed
	// (Sol11 P1-2). See the Cleanliness type doc comment.
	Cleanliness Cleanliness

	// Identity is Sol10 P0-6's SnapshotIdentity -- the sole source of
	// Assayer transaction identity. See that type's doc comment.
	Identity SnapshotIdentity
}

// Close releases the held python handle and the sealed package descriptor,
// then removes WorkDir. Safe to call on a nil Snapshot.
func (s *Snapshot) Close() {
	if s == nil {
		return
	}
	if s.Python != nil {
		s.Python.Close()
	}
	if s.Package != nil {
		_ = s.Package.Close()
	}
	if s.WorkDir != "" {
		_ = os.RemoveAll(s.WorkDir)
	}
}

// Verify re-checks Package's bytes and seal state against what
// BuildSnapshot recorded. Sol11 P0-6 makes this defense-in-depth rather than
// the load-bearing detection mechanism it was before this session (see
// Snapshot's doc comment): the sealed, unlinked memfd cannot actually be
// mutated by any same-UID process in the first place, so a mismatch here
// would mean a bug in this process's own bookkeeping (wrong descriptor,
// double-close-and-reuse of the fd number) rather than an external attack.
// The caller (assay.Evaluate) still calls this immediately before and after
// every launch, matching the pre-existing double-check convention. Any
// mismatch is reported as exactly AssayerSnapshotMutated.
func (s *Snapshot) Verify() error {
	if s == nil {
		return fmt.Errorf("assay: cannot verify a nil snapshot")
	}
	if s.Package == nil {
		return fmt.Errorf("%s: snapshot has no package descriptor", AssayerSnapshotMutated)
	}
	if err := verifyPackageSeals(s.Package); err != nil {
		return fmt.Errorf("%s: %w", AssayerSnapshotMutated, err)
	}
	if _, err := s.Package.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("%s: rewind package descriptor: %w", AssayerSnapshotMutated, err)
	}
	sum := sha256.New()
	if _, err := io.Copy(sum, s.Package); err != nil {
		return fmt.Errorf("%s: read package descriptor: %w", AssayerSnapshotMutated, err)
	}
	if hex.EncodeToString(sum.Sum(nil)) != s.PackageHash {
		return fmt.Errorf("%s: package content changed since publish", AssayerSnapshotMutated)
	}
	return nil
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
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("assay: sealed-memfd package execution is unsupported on %s", runtime.GOOS)
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
	var packaged []packagedFile

	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	fail := func(format string, args ...any) (*Snapshot, error) {
		return nil, fmt.Errorf("assay: snapshot: "+format, args...)
	}

	// addOne writes srcRel's content into the zip under zipRel, recording
	// its content hash for PackageHash/ProfileHash below. cli.py is
	// deliberately renamed to __main__.py: Python's zipimport machinery
	// treats a zip archive containing __main__.py as directly executable
	// (the same shape `python archive.pyz` runs today), which is exactly
	// what lets Evaluate hand the whole package to Python as one launch
	// argument instead of a script path plus a PYTHONPATH directory entry.
	addOne := func(srcRel, zipRel string) error {
		data, rerr := os.ReadFile(filepath.Join(cfg.Repo, filepath.FromSlash(srcRel)))
		if rerr != nil {
			return fmt.Errorf("read %s: %w", srcRel, rerr)
		}
		w, werr := zw.Create(zipRel)
		if werr != nil {
			return fmt.Errorf("add %s to package: %w", zipRel, werr)
		}
		if _, werr := w.Write(data); werr != nil {
			return fmt.Errorf("write %s into package: %w", zipRel, werr)
		}
		sum := sha256.Sum256(data)
		packaged = append(packaged, packagedFile{rel: zipRel, sha: hex.EncodeToString(sum[:])})
		return nil
	}

	if cerr := addOne("cli.py", "__main__.py"); cerr != nil {
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
			return addOne(rel, filepath.ToSlash(rel))
		})
		if walkErr != nil {
			return fail("package assayer package: %s", walkErr)
		}
	}
	if cerr := zw.Close(); cerr != nil {
		return fail("close package archive: %s", cerr)
	}
	zipBytes := buf.Bytes()
	packageSum := sha256.Sum256(zipBytes)
	packageHash := hex.EncodeToString(packageSum[:])
	treeHash := packageTreeHash(packaged)

	pkg, merr := sealPackageMemfd(zipBytes)
	if merr != nil {
		return fail("%s", merr)
	}
	pkgOK := false
	defer func() {
		if !pkgOK {
			_ = pkg.Close()
		}
	}()

	workDir, werr := os.MkdirTemp("", "governator-assayer-workdir-*")
	if werr != nil {
		return fail("create workspace anchor dir: %s", werr)
	}
	if cerr := os.Chmod(workDir, 0o500); cerr != nil {
		_ = os.RemoveAll(workDir)
		return fail("chmod workspace anchor dir: %s", cerr)
	}

	cleanliness, cleanlinessReason := snapshotDirty(registry, cfg.Repo)

	// Sol10 P0-6: resolved once, here, from data this call already has in
	// hand -- profileHash from the bytes just packaged (never a separate
	// live read), gitCommit from one probe at build time (never re-read by
	// a later identity calculation against the possibly-since-changed live
	// checkout).
	profileHash := ""
	for _, pf := range packaged {
		if pf.rel == "assayer/profiles.py" {
			profileHash = pf.sha
			break
		}
	}
	identity := SnapshotIdentity{
		PackageHash:                 packageHash,
		PackageTreeHash:             treeHash,
		PythonIdentity:              pythonHandle.Identity,
		RuntimeHash:                 runtimeManifest.RuntimeHash,
		DependencyHash:              runtimeManifest.DependencyHash,
		LockHash:                    runtimeManifest.LockHash,
		DependencyUnavailableReason: runtimeManifest.DependencyUnavailableReason,
		InterpreterIdentityHash:     runtimeManifest.InterpreterIdentityHash,
		ProfileHash:                 profileHash,
		ProtocolVersion:             SnapshotProtocolVersion,
		GitCommit:                   assayerCommit(cfg.Repo),
		Dirty:                       cleanliness != CleanlinessClean,
		Cleanliness:                 cleanliness,
	}

	ok = true
	pkgOK = true
	return &Snapshot{
		Package:     pkg,
		PackageHash: packageHash,
		WorkDir:     workDir,
		Python:      pythonHandle,
		Runtime:     runtimeManifest,
		Dirty:       cleanliness != CleanlinessClean,
		DirtyReason: cleanlinessReason,
		Cleanliness: cleanliness,
		Identity:    identity,
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
	// InterpreterIdentityHash mirrors SnapshotIdentity.InterpreterIdentityHash
	// -- see that field's doc comment. Mandatory, like RuntimeHash: a probe
	// that cannot produce it fails BuildSnapshot closed.
	InterpreterIdentityHash string
}

// interpreterProbeScript is buildRuntimeManifest's single isolated ("-S")
// probe. It emits one "PATH k=v" line per sysconfig path resolved (the
// pre-existing stdlib/site-packages discovery) plus one "IDENTITY {json}"
// line describing the interpreter build itself -- Sol11 P1-1's addition.
// RuntimeHash (via hashPathTree over StdlibReadRoots) already changes when
// stdlib file *content* changes; it says nothing about which interpreter
// *build* produced that content (word size, ABI tag, build configuration),
// so a same-bytes-different-build swap could otherwise go unnoticed. The
// identity JSON is emitted with sort_keys=True so its exact printed bytes
// are a deterministic function of the interpreter's own reported values,
// safe to hash directly without re-parsing.
const interpreterProbeScript = "import sysconfig, sys, json\n" +
	"for k in ('stdlib', 'platstdlib', 'purelib', 'platlib'):\n" +
	"    print('PATH ' + k + '=' + sysconfig.get_path(k))\n" +
	"identity = {\n" +
	"    'version': sys.version,\n" +
	"    'implementation_name': sys.implementation.name,\n" +
	"    'cache_tag': getattr(sys.implementation, 'cache_tag', ''),\n" +
	"    'hexversion': sys.hexversion,\n" +
	"    'abiflags': getattr(sys, 'abiflags', ''),\n" +
	"    'maxsize': sys.maxsize,\n" +
	"    'byteorder': sys.byteorder,\n" +
	"    'platform': sys.platform,\n" +
	"    'config_vars': {k: sysconfig.get_config_var(k) for k in ('SOABI', 'EXT_SUFFIX', 'Py_ENABLE_SHARED', 'SIZEOF_VOID_P', 'WITH_PYMALLOC')},\n" +
	"}\n" +
	"print('IDENTITY ' + json.dumps(identity, sort_keys=True))\n"

// buildRuntimeManifest resolves and hashes RuntimeManifest for python,
// exactly once, at BuildSnapshot time. The stdlib half (including
// InterpreterIdentityHash) is mandatory (a probe or hash failure fails
// snapshot construction closed); the dependency half is best-effort,
// matching this file's DescribeEnvironment-style probes.
func buildRuntimeManifest(python *toolregistry.Handle, repo string) (RuntimeManifest, error) {
	probeCtx, cancel := context.WithTimeout(context.Background(), runtimeProbeTimeout)
	defer cancel()
	// -S: isolated startup (Sol10 P0-5's "startup problem") -- this probe
	// must not let ambient site configuration shape which paths it
	// discovers, exactly like Evaluate's own launch must not let it shape
	// evaluation.
	cmd, err := python.Command(probeCtx, "-S", "-c", interpreterProbeScript)
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
	var interpreterIdentityLine string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "IDENTITY "); ok {
			interpreterIdentityLine = rest
			continue
		}
		rest, ok := strings.CutPrefix(line, "PATH ")
		if !ok {
			continue
		}
		key, path, cutOK := strings.Cut(rest, "=")
		if !cutOK || path == "" {
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
	if strings.TrimSpace(interpreterIdentityLine) == "" {
		return RuntimeManifest{}, fmt.Errorf("isolated sysconfig probe produced no interpreter identity line")
	}

	runtimeHash, herr := hashPathTree(stdlibRoots)
	if herr != nil {
		return RuntimeManifest{}, fmt.Errorf("hash stdlib tree: %w", herr)
	}
	if runtimeHash == "" {
		return RuntimeManifest{}, fmt.Errorf("stdlib tree hashed to no files at %v", stdlibRoots)
	}

	idSum := sha256.Sum256([]byte(interpreterIdentityLine))
	manifest := RuntimeManifest{
		StdlibReadRoots:         stdlibRoots,
		RuntimeHash:             runtimeHash,
		InterpreterIdentityHash: hex.EncodeToString(idSum[:]),
	}

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

// hashPathTree returns a sha256 over the sorted (root-qualified logical
// path, content-or-target) tuples of every executable object under roots --
// "" (never an error) when roots resolves to zero entries. A missing root is
// skipped, not an error -- callers decide whether an entirely empty result
// is fatal (buildRuntimeManifest: fatal for stdlib, best-effort for
// site-packages).
//
// Sol11 P1-1: before this session, __pycache__ directories and symlinks were
// both skipped entirely -- but Python can execute a .pyc from __pycache__,
// a symlinked module, or a native extension reached through a symlink, so
// the recorded hash could stay unchanged while executable runtime content
// actually changed. Neither is skipped now: __pycache__ is walked like any
// other directory, and a symlink is resolved and its TARGET's content is
// hashed under the symlink's own logical path -- with the symlink's own
// resolved-target string also recorded as a distinct entry, so retargeting
// the link to different bytes at a different location is caught even when
// the two locations happen to contain byte-identical content (a change to
// either the content or the identity of what a logical path resolves to
// must change this hash). A symlinked directory is walked exactly once per
// root (visitedTargets below), bounding the walk against a symlink cycle.
func hashPathTree(roots []string) (string, error) {
	type fileEntry struct{ key, sha string }
	var entries []fileEntry
	for _, root := range roots {
		info, statErr := os.Stat(root)
		if statErr != nil || !info.IsDir() {
			continue
		}
		visitedTargets := map[string]bool{}
		var walk func(rel, dir string) error
		walk = func(rel, dir string) error {
			names, rerr := os.ReadDir(dir)
			if rerr != nil {
				return fmt.Errorf("read %s: %w", dir, rerr)
			}
			for _, name := range names {
				entryRel := name.Name()
				if rel != "" {
					entryRel = rel + "/" + entryRel
				}
				full := filepath.Join(dir, name.Name())
				fi, lerr := os.Lstat(full)
				if lerr != nil {
					return fmt.Errorf("lstat %s: %w", full, lerr)
				}
				switch {
				case fi.Mode()&os.ModeSymlink != 0:
					resolved, everr := filepath.EvalSymlinks(full)
					if everr != nil {
						return fmt.Errorf("resolve symlink %s: %w", full, everr)
					}
					rinfo, serr := os.Stat(resolved)
					if serr != nil {
						return fmt.Errorf("stat symlink target %s -> %s: %w", full, resolved, serr)
					}
					entries = append(entries, fileEntry{
						key: root + "::" + entryRel + "::SYMLINK_TARGET",
						sha: resolved,
					})
					if rinfo.IsDir() {
						if visitedTargets[resolved] {
							continue
						}
						visitedTargets[resolved] = true
						if werr := walk(entryRel, resolved); werr != nil {
							return werr
						}
						continue
					}
					data, rerr := os.ReadFile(resolved)
					if rerr != nil {
						return fmt.Errorf("read symlink target %s -> %s: %w", full, resolved, rerr)
					}
					sum := sha256.Sum256(data)
					entries = append(entries, fileEntry{key: root + "::" + entryRel, sha: hex.EncodeToString(sum[:])})
				case fi.IsDir():
					if werr := walk(entryRel, full); werr != nil {
						return werr
					}
				case fi.Mode().IsRegular():
					data, rerr := os.ReadFile(full)
					if rerr != nil {
						return fmt.Errorf("read %s: %w", full, rerr)
					}
					sum := sha256.Sum256(data)
					entries = append(entries, fileEntry{key: root + "::" + entryRel, sha: hex.EncodeToString(sum[:])})
				default:
					// device/socket/fifo/etc -- never executable Python
					// content, not part of this identity.
				}
			}
			return nil
		}
		if werr := walk("", root); werr != nil {
			return "", werr
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

// Cleanliness is Sol11 P1-2's tri-state result for whether the Assayer
// checkout could be verified free of uncommitted changes at snapshot-build
// time. Before this session snapshotDirty returned a plain bool that
// conflated "definitely clean" with "could not tell" (git unresolvable,
// command construction failed, `git status` itself failed or timed out) --
// every one of those indeterminate cases silently reported false ("not
// dirty"), so an Assayer checkout whose cleanliness Governator could not
// actually observe was represented in evidence and replay identity exactly
// as if it had been verified clean. CleanlinessUnknown makes that
// distinction real: like CleanlinessDirty, it disables strict replay
// (Snapshot.Dirty is true for both), and internal/runtime's runOnce refuses
// to let a transaction built from an CleanlinessUnknown snapshot merge or
// approve at all -- there is deliberately no override flag for this: the
// only way to "resolve" it is for a later probe against the same checkout
// to return a definitive CleanlinessClean or CleanlinessDirty.
type Cleanliness string

const (
	CleanlinessClean   Cleanliness = "clean"
	CleanlinessDirty   Cleanliness = "dirty"
	CleanlinessUnknown Cleanliness = "unknown"
)

// snapshotDirty probes repo's git cleanliness. Unlike
// buildRuntimeManifest's DependencyHash half/environment.go's assayerCommit
// (genuinely best-effort diagnostic metadata that must never block a
// snapshot build), a git probe failure here is NOT waved through as clean:
// Sol11 P1-2 requires every path that used to report "not dirty" on
// failure -- can't resolve git, can't construct the command, `git status`
// itself errors or times out via environmentProbeTimeout's context deadline
// -- to report CleanlinessUnknown with a reason instead. A repo with no
// .git entry at all (e.g. a pinned, non-git fixture/distribution) has no
// notion of "uncommitted changes" at all and is unambiguously
// CleanlinessClean, not indeterminate -- that is a real, positive
// observation about the repo's shape, not a failed probe.
func snapshotDirty(registry *toolregistry.Registry, repo string) (Cleanliness, string) {
	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		if os.IsNotExist(err) {
			return CleanlinessClean, ""
		}
		return CleanlinessUnknown, fmt.Sprintf("stat %s: %s", filepath.Join(repo, ".git"), err)
	}
	gitHandle, err := registry.ResolveHandle("git", "git", toolregistry.KindTrustedController)
	if err != nil {
		return CleanlinessUnknown, fmt.Sprintf("resolve trusted git handle: %s", err)
	}
	defer gitHandle.Close()
	ctx, cancel := context.WithTimeout(context.Background(), environmentProbeTimeout)
	defer cancel()
	cmd, cerr := gitHandle.Command(ctx, "-C", repo, "status", "--porcelain")
	if cerr != nil {
		return CleanlinessUnknown, fmt.Sprintf("construct git status probe: %s", cerr)
	}
	cmd.Env = controllerenv.Base()
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if rerr := cmd.Run(); rerr != nil {
		reason := strings.TrimSpace(errOut.String())
		if reason == "" {
			reason = rerr.Error()
		}
		return CleanlinessUnknown, fmt.Sprintf("git status probe failed: %s", reason)
	}
	if strings.TrimSpace(out.String()) != "" {
		return CleanlinessDirty, "assayer repo has uncommitted changes at snapshot-build time"
	}
	return CleanlinessClean, ""
}
