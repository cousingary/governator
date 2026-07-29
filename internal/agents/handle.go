package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/stage"
	"github.com/cousingary/governator/internal/toolregistry"
)

// BackendIdentity is the operator-declared model/provider identity behind a
// backend's CLI wrapper (Sol P1-2). A backend NAME is not identity: the same
// "claude-code" wrapper can point at a different account, org, or model
// revision over time without its binary or adapter ever changing. These
// fields come from the operator's config.Backend declaration, never
// inferred from the backend name.
type BackendIdentity struct {
	Provider      string
	AccountID     string
	OrgID         string
	ModelRevision string
	Endpoint      string
	ReasoningMode string
	ApprovalMode  string
	SandboxMode   string
	// ConfigHash is the effective backend-specific operator configuration
	// hash (mirrors attest.EffectiveBackendConfigHash, duplicated here since
	// internal/attest imports internal/agents and not the reverse).
	ConfigHash string
}

// Known reports whether the operator declared enough identity to trust a
// replay or high-risk native-sandbox reuse decision bound to it. Provider and
// ModelRevision are the two facts every backend has and every operator can
// declare; their absence means "unknown," which callers must treat as
// blocking rather than as "unchanged since last time."
func (b BackendIdentity) Known() bool {
	return b.Provider != "" && b.ModelRevision != ""
}

func identityFor(cfg config.Config, name string) BackendIdentity {
	b := cfg.Backends[name]
	return BackendIdentity{
		Provider:      b.Provider,
		AccountID:     b.AccountID,
		OrgID:         b.OrgID,
		ModelRevision: b.ModelRevision,
		Endpoint:      b.Endpoint,
		ReasoningMode: b.ReasoningMode,
		ApprovalMode:  b.ApprovalMode,
		SandboxMode:   b.SandboxMode,
		ConfigHash:    backendConfigHash(b),
	}
}

func backendConfigHash(b config.Backend) string {
	data, err := json.Marshal(b)
	if err != nil {
		return "unhashable"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// BackendExecutionHandle is the immutable, single-construction-per-run
// identity+launch record for the executable that will actually run a
// governed backend. Sol P0-6: resolving a backend twice in one run -- once
// to decide containment/attestation, again later to compute execution
// identity and launch -- leaves a window where PATH or the file on disk can
// change between the two looks, and even a single resolve-then-launch pair
// is a TOCTOU on its own (hash a path, then separately ask the OS to exec
// that same path). ResolveHandle closes both: it resolves, opens, stats, and
// hashes the executable exactly once from one open file descriptor, keeps
// that descriptor open for the handle's lifetime, and Launch (via
// LaunchCommand) execs the open descriptor directly on platforms that
// support it instead of the path a second time.
//
// Every trust-bearing consumer for a given run -- the containment decision,
// attestation lookup, execution identity/replay, the launch, and the audit
// record -- must be built from the ONE handle a caller resolved for that
// run. Callers must Close the handle exactly once when the run using it is
// finished (including the launch).
type BackendExecutionHandle struct {
	PathResolution

	VersionOutput  string
	VersionOK      bool
	AdapterID      string
	AdapterVersion string
	ModelID        string
	Identity       BackendIdentity

	// AllowedEnv is this backend's declared extra environment variable
	// names (config.Backend.AllowedEnv, Sol P1-14) — LaunchCommand's
	// caller (defaultExecutor) filters the subprocess environment down to
	// agents.BuildAllowedEnv's fixed baseline plus these names, never the
	// full inherited environment.
	AllowedEnv []string

	// OwnerUID/OwnerGID/Mode are read from the fstat of the SAME open
	// descriptor used for hashing, never a second path-based stat.
	OwnerUID       uint32
	OwnerGID       uint32
	Mode           os.FileMode
	ParentWritable bool

	file *os.File
	// closureRoot (Sol12 P0-5) is the private, content-addressed directory
	// holding a Node backend's FROZEN executable closure (entry script +
	// package.json + lockfile + resolved node_modules tree), built once at
	// resolution so the launch reads a verified tree instead of a live,
	// same-UID-mutable node_modules symlink. Empty for a non-Node backend
	// (it launches its own held descriptor directly -- the executable IS the
	// whole closure). Cleaned up on Close.
	closureRoot string
	// launchPath is the pathname actually launched when a pathname launch is
	// unavoidable: a Node backend must be launched by pathname (Node module
	// resolution walks up from the running script's own directory, so the
	// /proc/self/fd/<n> fd-launch a compiled backend uses breaks it). Empty
	// for a non-Node backend (fd-launched via file above). VerifyUnchanged
	// re-hashes this path immediately before launch to close the
	// verify-then-swap-then-exec window for the frozen entry the same way it
	// does for a compiled backend's CanonicalPath.
	launchPath string
}

// ResolveHandle resolves agent's configured backend binary exactly once into
// an immutable BackendExecutionHandle: PATH lookup (if not already
// absolute), symlink canonicalization, a single open of the canonical path,
// and every fact derived from that one open descriptor (owner, mode, content
// hash, version evidence). Fails closed -- never a sentinel -- when the
// binary cannot be found, opened, or hashed. cfg is the caller's already-
// loaded config.Config (the same value threaded everywhere else in a run,
// e.g. computeExecutionIdentity) -- ResolveHandle reads cfg.Backends
// directly rather than the config.Current() package singleton ResolvePath
// uses, so it never observes a config reload the rest of the run didn't.
func ResolveHandle(ctx context.Context, cfg config.Config, agent Agent) (h *BackendExecutionHandle, err error) {
	requested := cfg.Backends[agent.Name()].Bin
	if strings.TrimSpace(requested) == "" {
		requested = agent.Name()
	}
	resolvedPath := requested
	if !filepath.IsAbs(resolvedPath) {
		looked, lerr := exec.LookPath(resolvedPath)
		if lerr != nil {
			return nil, fmt.Errorf("resolve backend %q: look up executable %q: %w", agent.Name(), requested, lerr)
		}
		resolvedPath = looked
	}
	abs, aerr := filepath.Abs(resolvedPath)
	if aerr != nil {
		return nil, fmt.Errorf("resolve backend %q: %w", agent.Name(), aerr)
	}
	canonical := abs
	if eval, everr := filepath.EvalSymlinks(abs); everr == nil {
		canonical = eval
	}

	f, operr := os.Open(canonical)
	if operr != nil {
		return nil, fmt.Errorf("resolve backend %q: open executable %s: %w", agent.Name(), canonical, operr)
	}
	closeOnErr := true
	defer func() {
		if closeOnErr {
			_ = f.Close()
		}
	}()

	info, serr := f.Stat()
	if serr != nil {
		return nil, fmt.Errorf("resolve backend %q: stat open executable %s: %w", agent.Name(), canonical, serr)
	}
	var ownerUID, ownerGID uint32
	fileIdent := "path=" + canonical
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		ownerUID, ownerGID = st.Uid, st.Gid
		fileIdent = fmt.Sprintf("dev=%d ino=%d path=%s", st.Dev, st.Ino, canonical)
	}

	sum := sha256.New()
	if _, cerr := io.Copy(sum, f); cerr != nil {
		return nil, fmt.Errorf("resolve backend %q: hash open executable %s: %w", agent.Name(), canonical, cerr)
	}
	sha := hex.EncodeToString(sum.Sum(nil))

	h = &BackendExecutionHandle{
		PathResolution: PathResolution{
			Backend:       agent.Name(),
			Requested:     requested,
			ResolvedPath:  abs,
			CanonicalPath: canonical,
			FileIdentity:  fileIdent,
			SHA256:        sha,
		},
		AdapterID:      agent.Name(),
		AdapterVersion: agent.Name() + "-adapter-v1",
		ModelID:        agent.Name(),
		Identity:       identityFor(cfg, agent.Name()),
		AllowedEnv:     append([]string(nil), cfg.Backends[agent.Name()].AllowedEnv...),
		OwnerUID:       ownerUID,
		OwnerGID:       ownerGID,
		Mode:           info.Mode(),
		ParentWritable: parentTrustState(canonical) || ForceParentWritable,
		file:           f,
	}

	// Sol12 P0-5: freeze+hash a Node backend's dependency closure into a
	// private copy (replacing the pre-P0-5 live node_modules symlink) and
	// bind its hash into PathResolution for replay identity. Non-Node
	// backends are marked closure-proven (the executable is its own closure).
	h.freezeNodeDependencyClosure()

	closeOnErr = false
	return h, nil
}

// ProbeVersion runs a bounded "--version" probe and records the result on
// the handle. It is deliberately NOT run automatically by ResolveHandle:
// version evidence is only needed by flows generating a fresh capability
// attestation (VerifyHighRiskNative's lookup keys never include it), so
// every other consumer of a resolved handle -- the containment decision,
// execution identity, replay, and the launch itself -- would otherwise pay
// for an extra subprocess execution (real fork/exec latency, up to
// versionProbeTimeout if the binary hangs) on every single governed run for
// no benefit. Callers that do need version evidence call this explicitly.
func (h *BackendExecutionHandle) ProbeVersion(ctx context.Context) {
	h.VersionOutput, h.VersionOK = h.probeVersion(ctx)
}

// Close releases the handle's open file descriptor. Safe to call once,
// after the handle is done being used for launch.
func (h *BackendExecutionHandle) Close() error {
	if h == nil {
		return nil
	}
	var err error
	if h.file != nil {
		err = h.file.Close()
		h.file = nil
	}
	if h.closureRoot != "" {
		if rerr := os.RemoveAll(h.closureRoot); err == nil && rerr != nil {
			err = rerr
		}
		h.closureRoot = ""
	}
	return err
}

// Resolution projects the handle down to the legacy Resolution shape, for
// callers (attest.GenerateFromResolution) that were built against it before
// BackendExecutionHandle existed. Both views describe the exact same single
// resolution -- this is a read, never a second lookup.
func (h *BackendExecutionHandle) Resolution() Resolution {
	return Resolution{
		PathResolution: h.PathResolution,
		VersionOutput:  h.VersionOutput,
		VersionOK:      h.VersionOK,
		AdapterID:      h.AdapterID,
		AdapterVersion: h.AdapterVersion,
		ModelID:        h.ModelID,
	}
}

// File returns the handle's held, already-verified backend executable
// descriptor for a caller that must compose it into a launch chain with more
// than one descriptor-backed layer of its own (Sol12 P0-4's descriptor-backed
// backend launch, the direct analog of toolregistry.Handle.File for controller
// tools). The handle retains ownership: callers must not close the returned
// file directly (use Close), and must not use it after Close. Returns nil for
// a Node backend (launchPath set) -- those launch their frozen entry by
// pathname because Node module resolution requires it, so no held executable
// descriptor participates in the launch.
func (h *BackendExecutionHandle) File() *os.File {
	if h == nil {
		return nil
	}
	return h.file
}

// fdLaunchArgs returns the pseudo-path and ExtraFiles needed to exec h's
// already-open, already-hashed executable directly via its file descriptor,
// when that's available on this platform. ok is false when unavailable
// (non-Linux, or the handle holds no open file) -- callers must then fall
// back to VerifyUnchanged plus a path-based launch.
//
// This is what actually closes report attack 6: /proc/self/fd/<n> resolves
// straight to the inode this handle already opened and hashed, not a fresh
// directory-entry lookup, so a file replaced, deleted, or repointed at the
// same path after ResolveHandle returns cannot change what execs.
func (h *BackendExecutionHandle) fdLaunchArgs() (path string, extraFiles []*os.File, ok bool) {
	if h == nil || h.file == nil || runtime.GOOS != "linux" {
		return "", nil, false
	}
	return "/proc/self/fd/3", []*os.File{h.file}, true
}

// freezeNodeDependencyClosure (Sol12 P0-5) builds a private, content-addressed
// copy of a Node-based backend's COMPLETE executable closure -- entry script,
// package.json, lockfile, and the resolved node_modules dependency tree
// (including native addons) -- and binds its content hash into h.PathResolution
// so the run's replay identity describes the exact bytes the backend imports,
// not just the entry script it started from. The frozen copy REPLACES the live
// node_modules symlink the pre-P0-5 sealed-launch path used: that symlink left
// the whole dependency tree live, unverified, and same-UID-mutable after replay
// identity construction, so a swapped JS dependency executed under the
// original backend's identity (directly relevant to Node-based Codex/OpenCode).
//
// h.closureRoot/launchPath are populated for composeBackendLaunch to launch
// from; DependencyClosureHash/DependencyClosureProven flow into PathResolution
// (and thus ExecutionIdentity) for replay binding and the strict-replay gate.
// On any failure the closure is left unproven (DependencyClosureProven=false)
// and runtime.computeExecutionIdentity disables strict replay for the run.
//
// Non-Node backends are their own closure (SHA256 already binds the whole
// executable), so this just marks them proven and returns.
func (h *BackendExecutionHandle) freezeNodeDependencyClosure() {
	if h == nil {
		return
	}
	if !isNodeExecutable(h.CanonicalPath) {
		h.DependencyClosureProven = true
		return
	}
	root, hash, err := buildFrozenNodeClosure(h.CanonicalPath, h.file)
	if err != nil {
		// Honest failure: closure unprovable -> strict replay disabled by the
		// identity gate. Leave closureRoot empty so the launch falls back to
		// the held executable descriptor; DependencyClosureProven stays false.
		h.DependencyClosureHash = ""
		h.DependencyClosureProven = false
		return
	}
	h.closureRoot = root
	h.launchPath = filepath.Join(root, "entry")
	h.DependencyClosureHash = hash
	h.DependencyClosureProven = true
}

// buildFrozenNodeClosure creates a private mode-0500 directory, copies the
// entry script, package.json, lockfiles, and the resolved node_modules tree
// into it (content-hashing every byte under its relative path), and returns
// the directory + the closure hash. entryFile is the already-verified,
// already-open descriptor of the original entry script; it is rewound and
// copied rather than re-reading the live path. The tree is built writable
// (0700) and locked down to read/execute-only (0500/0400) in a final pass so
// every file can be created before the directories that contain them go
// read-only.
func buildFrozenNodeClosure(canonicalEntry string, entryFile *os.File) (root, hash string, err error) {
	dir, merr := os.MkdirTemp("", "governator-node-closure-*")
	if merr != nil {
		return "", "", fmt.Errorf("create root: %w", merr)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(dir)
		}
	}()

	hasher := sha256.New()
	entrySHA, err := copyVerifiedFD(entryFile, filepath.Join(dir, "entry"), 0500)
	if err != nil {
		return "", "", fmt.Errorf("freeze entry: %w", err)
	}
	fmt.Fprintf(hasher, "entry::%s\n", entrySHA)

	srcDir := filepath.Dir(canonicalEntry)
	for _, name := range []string{"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"} {
		if cerr := copyMetaHashed(filepath.Join(srcDir, name), filepath.Join(dir, name), name, hasher); cerr != nil {
			return "", "", fmt.Errorf("freeze %s: %w", name, cerr)
		}
	}
	if nm := nearestNodeModules(canonicalEntry); nm != "" {
		if cerr := copyTreeHashed(nm, filepath.Join(dir, "node_modules"), "node_modules", hasher); cerr != nil {
			return "", "", fmt.Errorf("freeze node_modules: %w", cerr)
		}
	}
	// Best-effort lockdown: read/execute-only for the owner so a
	// non-same-UID process cannot mutate the frozen tree. Same-UID mutation
	// is the residual boundary the closure hash + VerifyUnchanged cover
	// (cross-run) and that memfd/seals would be needed to close in-run; this
	// chmod mirrors the pre-P0-5 sealed-launch dir's hygiene without being
	// the security boundary itself.
	lockdownFrozenTree(dir)
	// S7: the copy-time digest above cannot be re-evaluated after launch.
	// Bind identity to a deterministic fingerprint of the frozen tree itself
	// so VerifyUnchanged can inspect every executable dependency both before
	// and after the backend runs.
	hash, err = hashFrozenNodeClosure(dir)
	if err != nil {
		return "", "", fmt.Errorf("hash frozen closure: %w", err)
	}
	cleanup = false
	return dir, hash, nil
}

// hashFrozenNodeClosure fingerprints every object the Node launcher can
// resolve from root. Its exact representation is deliberately independent of
// source paths, modes, and the copy operation, so it can be recomputed after
// execution to detect mutation of a JS dependency, lockfile, symlink, or
// native addon.
func hashFrozenNodeClosure(root string) (string, error) {
	sum := sha256.New()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		switch {
		case info.IsDir():
			_, _ = fmt.Fprintf(sum, "%s::DIR\n", rel)
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return err
			}
			inside, err := filepath.Rel(root, resolved)
			if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) || filepath.IsAbs(inside) {
				return fmt.Errorf("symlink %s escapes frozen dependency closure to %s", rel, resolved)
			}
			objectHash, err := hashFrozenNodeObject(resolved, map[string]bool{})
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(sum, "%s::SYMLINK::%s::TARGET::%s\n", rel, link, objectHash)
		case info.Mode().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fileHash := sha256.Sum256(data)
			_, _ = fmt.Fprintf(sum, "%s::FILE::%x\n", rel, fileHash)
		default:
			return fmt.Errorf("unsupported frozen dependency object %s (mode %s)", rel, info.Mode())
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// lockdownFrozenTree chmods every file beneath root to 0400 and every
// directory (including root) to 0500, best-effort. filepath.Walk visits a
// directory before its contents, and 0500 retains the execute bit needed to
// traverse into it, so the post-lockdown walk ordering stays consistent.
func lockdownFrozenTree(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			_ = os.Chmod(path, 0500)
		} else {
			_ = os.Chmod(path, 0400)
		}
		return nil
	})
}

// copyVerifiedFD rewinds the already-verified open descriptor src, copies its
// bytes into an O_EXCL private file at dst with the given mode, and returns the
// SHA256 of the bytes copied (which must match the descriptor's recorded hash).
func copyVerifiedFD(src *os.File, dst string, mode os.FileMode) (string, error) {
	if src == nil {
		return "", fmt.Errorf("no open entry descriptor")
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind entry: %w", err)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", err
	}
	sum := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, sum), src)
	closeErr := out.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := os.Chmod(dst, mode); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// copyMetaHashed copies a single metadata file (package.json/lockfile) from src
// to dst if it exists, writing its content hash under relKey to hasher. A
// missing file (os.IsNotExist) is a no-op -- not every Node package has every
// lockfile.
func copyMetaHashed(src, dst, relKey string, hasher hash.Hash) error {
	in, err := os.Open(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	sum := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, sum), in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Fprintf(hasher, "%s::%s\n", relKey, hex.EncodeToString(sum.Sum(nil)))
	return nil
}

// copyTreeHashed recursively copies the dependency tree rooted at src into dst.
// Symlinks are accepted only when their resolved target remains inside src and
// can be resolved without a cycle. Escaping and broken links are rejected: a
// frozen closure must never retain a pointer to mutable storage outside it.
func copyTreeHashed(src, dst, relPrefix string, hasher hash.Hash) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		switch {
		case info.IsDir():
			return os.MkdirAll(target, 0700)
		case info.Mode()&os.ModeSymlink != 0:
			link, lerr := os.Readlink(path)
			if lerr != nil {
				return lerr
			}
			resolved, rerr := filepath.EvalSymlinks(path)
			if rerr != nil {
				return fmt.Errorf("resolve symlink %s: %w", path, rerr)
			}
			inside, rerr := filepath.Rel(src, resolved)
			if rerr != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) || filepath.IsAbs(inside) {
				return fmt.Errorf("symlink %s escapes dependency closure to %s", path, resolved)
			}
			objectHash, rerr := hashFrozenNodeObject(resolved, map[string]bool{})
			if rerr != nil {
				return fmt.Errorf("hash symlink target %s: %w", path, rerr)
			}
			if cerr := copyTreeEnsureParent(target); cerr != nil {
				return cerr
			}
			// Absolute links into the source tree would still point at the
			// mutable source after freezing; rebase them into the copy.
			frozenLink := link
			if filepath.IsAbs(link) {
				frozenLink, rerr = filepath.Rel(filepath.Dir(target), filepath.Join(dst, inside))
				if rerr != nil {
					return rerr
				}
			}
			if lerr := os.Symlink(frozenLink, target); lerr != nil {
				return lerr
			}
			fmt.Fprintf(hasher, "%s/%s::SYMLINK::%s::TARGET::%s\n", relPrefix, rel, link, objectHash)
			return nil
		default:
			return copyTreeFile(path, target, relPrefix+"/"+rel, hasher)
		}
	})
}

// hashFrozenNodeObject hashes the resolved object behind an internal symlink.
// Following links here is deliberately cycle-detecting and rejects broken or
// special files, so the target identity is bound to bytes, not just a link
// spelling. The normal tree walk also hashes each object at its own path.
func hashFrozenNodeObject(path string, active map[string]bool) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if active[resolved] {
		return "", fmt.Errorf("symlink cycle at %s", path)
	}
	active[resolved] = true
	defer delete(active, resolved)
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	sum := sha256.New()
	if info.IsDir() {
		entries, err := os.ReadDir(resolved)
		if err != nil {
			return "", err
		}
		for _, entry := range entries {
			childHash, err := hashFrozenNodeObject(filepath.Join(resolved, entry.Name()), active)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(sum, "%s::%s\n", entry.Name(), childHash)
		}
		return hex.EncodeToString(sum.Sum(nil)), nil
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("unsupported symlink target type %s", info.Mode())
	}
	f, err := os.Open(resolved)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// copyTreeFile copies one regular dependency file and hashes its content.
func copyTreeFile(src, dst, relKey string, hasher hash.Hash) error {
	if cerr := copyTreeEnsureParent(dst); cerr != nil {
		return cerr
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	sum := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, sum), in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Fprintf(hasher, "%s::%s\n", relKey, hex.EncodeToString(sum.Sum(nil)))
	return nil
}

func copyTreeEnsureParent(target string) error {
	parent := filepath.Dir(target)
	if parent == "." || parent == "" {
		return nil
	}
	return os.MkdirAll(parent, 0700)
}

// nearestNodeModules walks up from executablePath's own directory looking
// for a sibling node_modules directory, mirroring Node's own module
// resolution search order. Returns "" if none is found within a bounded
// number of levels -- most backends aren't Node CLIs at all, so absence is
// the common, unremarkable case, not an error.
func nearestNodeModules(executablePath string) string {
	dir := filepath.Dir(executablePath)
	for i := 0; i < 12; i++ {
		candidate := filepath.Join(dir, "node_modules")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// composeBackendLaunch (Sol12 P0-4) is the descriptor-only launch composition
// for a governed backend -- the direct analog of stage.ComposeHandleLaunch for
// controller tools. It wires the backend's launch object into plan's own
// self-exec/unshare layers and scope's own containment primitive, all through
// one shared FDAllocator, and returns the fully-composed *exec.Cmd with
// ExtraFiles populated, so no governed backend reaches the kernel through a
// mutable pathname after final identity verification.
//
// Non-Node backend: the held, already-verified executable descriptor
// (handle.File()) is the fd-backed final exec -- /proc/self/fd/<n>, the same
// inode ResolveHandle opened and hashed, so a file replaced or repointed at
// the same path after resolution cannot change what execs.
//
// Node backend (handle.closureRoot set): Node module resolution walks up from
// the running script's own directory, so the entry cannot be fd-launched
// (/proc/self/fd has no node_modules). It launches by pathname from the frozen
// closure copy (handle.launchPath) -- the wrapper layers (scope primitive,
// plan self-exec/unshare) stay descriptor-backed through the shared alloc, and
// the frozen closure dir is the plan's read root. plan.Active must be true.
func composeBackendLaunch(ctx context.Context, scope *containment.Scope, plan enforce.Plan, handle *BackendExecutionHandle, args []string, dir string) (*exec.Cmd, error) {
	alloc := &toolregistry.FDAllocator{}
	executable := handle.CanonicalPath
	readRoot := filepath.Dir(handle.CanonicalPath)
	var execBin string
	var execFile *os.File
	if handle.closureRoot != "" {
		executable = handle.launchPath
		readRoot = handle.closureRoot
		execBin = handle.launchPath
	} else {
		execFile = handle.File()
	}
	extended, err := plan.WithExecutableAndReadRoots(executable, readRoot)
	if err != nil {
		return nil, err
	}
	wb, wa := extended.WrapWith(alloc, execBin, execFile, args)
	cmd := scope.CommandWith(ctx, alloc, wb, wa, dir)
	cmd.ExtraFiles = append(cmd.ExtraFiles, alloc.Files()...)
	return cmd, nil
}

// VerifyUnchanged re-stats and re-hashes the actually-launched object RIGHT
// NOW and fails closed if it is missing or no longer matches what ResolveHandle
// captured. For a non-Node backend that is h.CanonicalPath (the held
// descriptor is exec'd directly, but a script's shebang still makes the kernel
// re-open content, so the fresh re-hash is the only thing that catches an
// in-place truncate+overwrite swap). For a Node backend it is h.launchPath --
// the frozen entry the launch actually execs (CanonicalPath only feeds identity
// there); the frozen entry's content is a copy of the original entry, so it
// must still match h.SHA256. The dev/inode identity check applies only to the
// original canonical path (the frozen entry has a fresh inode).
func (h *BackendExecutionHandle) VerifyUnchanged() error {
	if h.closureRoot != "" {
		got, err := hashFrozenNodeClosure(h.closureRoot)
		if err != nil {
			return fmt.Errorf("backend dependency closure re-verification: %w", err)
		}
		if got != h.DependencyClosureHash {
			return fmt.Errorf("backend dependency closure re-verification: frozen closure content changed between resolution and verification")
		}
	}
	target := h.CanonicalPath
	wantSHA := h.SHA256
	if h.launchPath != "" {
		target = h.launchPath
	}
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("backend identity re-verification: %s: %w", target, err)
	}
	if h.launchPath == "" {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			wantIdent := h.FileIdentity
			gotIdent := fmt.Sprintf("dev=%d ino=%d path=%s", st.Dev, st.Ino, h.CanonicalPath)
			if wantIdent != "" && gotIdent != wantIdent {
				return fmt.Errorf("backend identity re-verification: %s changed identity between resolution and launch (was %q, now %q)", h.CanonicalPath, wantIdent, gotIdent)
			}
		}
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("backend identity re-verification: read %s: %w", target, err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != wantSHA {
		return fmt.Errorf("backend identity re-verification: %s content changed between resolution and launch", target)
	}
	return nil
}

// probeVersion runs a bounded "--version" probe against h's already-open
// descriptor (via fdLaunchArgs when available, else the canonical path
// directly -- this happens before any hostile swap window matters, since
// it's part of resolution itself, not a separate later launch). This
// executes the resolved binary -- ResolveHandle runs on EVERY resolution,
// not just fresh-attestation flows, so any backend that doesn't special-case
// --version (or a hostile one that ignores flags entirely) must not be able
// to write anywhere real: the probe always runs in a disposable scratch
// directory, never whatever cwd the calling process happens to have.
func (h *BackendExecutionHandle) probeVersion(ctx context.Context) (string, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, versionProbeTimeout)
	defer cancel()
	scratch, err := os.MkdirTemp("", "gov-resolve-probe-")
	if err != nil {
		return "", false
	}
	defer os.RemoveAll(scratch)
	var cmd *exec.Cmd
	if path, extra, ok := h.fdLaunchArgs(); ok {
		cmd = exec.CommandContext(probeCtx, path, "--version") // govratchet:exec-allow(diagnostic_only)
		cmd.Env = controllerenv.Base()
		cmd.ExtraFiles = extra
	} else {
		cmd = exec.CommandContext(probeCtx, h.CanonicalPath, "--version") // govratchet:exec-allow(diagnostic_only)
		cmd.Env = controllerenv.Base()
	}
	cmd.Dir = scratch
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if len(text) > 4096 {
		text = text[:4096]
	}
	return text, err == nil && probeCtx.Err() == nil
}

// ForceParentWritable is a test-only seam, mirroring
// enforce.ForceUnsupported/SelfExeOverride: parentTrustState has no
// meaningful way to be mocked (a real untrusted-owner, group/world-writable
// ancestor directory requires a second real uid, which an unprivileged test
// process cannot construct), so the post-v4 hardening plan's Session 3 (item
// D) redteam attack proving effectLedgerViolations' executable_launch gate
// actually reaches quarantine end-to-end sets this true for the run instead
// of faking a whole hostile multi-user filesystem. Never set outside a test.
var ForceParentWritable bool

// parentTrustState reports whether any directory in path's ancestry (up to
// the filesystem root) is writable by a party other than its owner --
// group- or world-writable, where the owner is not this process's effective
// user and not root. A high-risk run must not depend on an executable
// reachable only because something upstream of it could be modified by an
// untrusted party (report P0-6's "parent-directory trust state"; the full
// trusted-tool registry lands in Session 4). Fails closed (reports writable)
// when a directory in the chain cannot be stat'd.
func parentTrustState(path string) bool {
	euid := os.Geteuid()
	dir := filepath.Dir(path)
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return true
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			untrustedOwner := int(st.Uid) != euid && st.Uid != 0
			groupOrWorldWritable := info.Mode()&0o022 != 0
			if groupOrWorldWritable && untrustedOwner {
				return true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// handleCtxKey threads a run's single BackendExecutionHandle through ctx from
// the point it's resolved down to whichever executor ends up spawning the
// process -- the same pattern internal/containment uses for Scope, so
// defaultExecutor and runner executors can reach the handle without a change
// to the widely-implemented Executor function signature.
type handleCtxKey struct{}

// ContextWithHandle attaches h to ctx for the executors invoked during this
// launch to retrieve via HandleFromContext.
func ContextWithHandle(ctx context.Context, h *BackendExecutionHandle) context.Context {
	return context.WithValue(ctx, handleCtxKey{}, h)
}

// HandleFromContext retrieves the handle ContextWithHandle attached, if any.
func HandleFromContext(ctx context.Context) (*BackendExecutionHandle, bool) {
	h, _ := ctx.Value(handleCtxKey{}).(*BackendExecutionHandle)
	return h, h != nil
}

// LaunchCommand builds the *exec.Cmd that will actually run a governed
// backend for callers WITHOUT a descendant-owning Scope (doctor probes, direct
// adapter tests, and any governed launch whose executor left no scope in
// context). The scope-bearing governed path composes its launch directly
// inside LaunchStaged via composeBackendLaunch (Sol12 P0-4), launching through
// /proc/self/fd/<held-fd>; this function is the fd-launch-or-path fallback for
// everything else.
//
// No handle at all (Request.ResolvedBin was empty -- gov doctor probes, tests,
// or any caller outside a governed run): plain path launch. Handle present:
// VerifyUnchanged runs UNCONDITIONALLY first. This is deliberate, not
// redundant: fdLaunchArgs' /proc/self/fd exec closes the classic TOCTOU for a
// compiled binary (holding the fd survives an unlink+recreate at the same
// path), but a script backend's "#!/bin/sh" line makes the KERNEL re-open the
// path itself to find the interpreter -- so an in-place truncate+overwrite
// swap (os.WriteFile, cp, a non-atomic editor save; the common case, and what
// report attack 6's fixture does) is invisible to the held fd and only
// VerifyUnchanged's fresh re-hash catches it. After that gate passes, fd-based
// exec is still used when available as additional hardening.
func LaunchCommand(ctx context.Context, handle *BackendExecutionHandle, bin string, args []string) (*exec.Cmd, error) {
	if handle == nil {
		return exec.CommandContext(ctx, bin, args...), nil // govratchet:exec-allow(production_launch_factory) -- no handle means no governed-run verification context (test/non-governed caller)
	}
	if err := handle.VerifyUnchanged(); err != nil {
		return nil, err
	}
	// A Node backend (frozen-closure launchPath set) cannot be fd-launched:
	// Node module resolution walks up from the running script's directory.
	// For the no-Scope path, launch the frozen entry by pathname (already
	// re-verified by VerifyUnchanged above).
	if handle.closureRoot != "" {
		return exec.CommandContext(ctx, handle.launchPath, args...), nil // govratchet:exec-allow(production_launch_factory) -- post-VerifyUnchanged frozen closure entry
	}
	if path, extra, ok := handle.fdLaunchArgs(); ok {
		cmd := exec.CommandContext(ctx, path, args...) // govratchet:exec-allow(production_launch_factory) -- path is the verified fd pseudo-path, not an attacker-controlled pathname
		cmd.ExtraFiles = extra
		// argv[0] stays the configured bin name (cosmetic only -- execve
		// resolves cmd.Path, the fd, regardless of argv[0]) so a backend
		// that inspects its own argv[0] doesn't see the fd pseudo-path.
		cmd.Args[0] = bin
		return cmd, nil
	}
	return exec.CommandContext(ctx, bin, args...), nil // govratchet:exec-allow(production_launch_factory) -- post-VerifyUnchanged fallback when fd-launch is unavailable
}

// LaunchStaged runs a governed backend command through internal/stage.
// Executor when a descendant-owning Scope and enforcement Plan are both
// present (Sol redteam v7 S1 gap-closure) -- the composition
// agents.defaultExecutor and runner.LocalWorktreeRunner.executor's
// "hasScope" branch each built independently before this migration, now
// shared here so both get the SAME unique per-stage scope naming
// (RunID-StageID-nonce, closing the S1 "scope names reused" secondary
// finding for the backend specifically -- shellStage already has this for
// validators) and the SAME descendant-extinction proof StageExecutor
// already gives every other migrated stage, instead of registering into
// the run's single shared Scope the way the backend did before this
// migration.
//
// Sol12 P0-4: the launch itself is descriptor-backed composition
// (composeBackendLaunch), no longer the pre-P0-5 sealed-pathname copy. The
// held backend descriptor (or, for a Node backend, the frozen closure entry)
// is threaded through the same shared FDAllocator as the scope primitive and
// plan self-exec/unshare layers, so no governed backend reaches the kernel
// through a mutable pathname after final identity verification. This
// migration is about WHERE the scope, timeout, and extinction bookkeeping
// live, plus how the process is built/confined; the streaming-output and
// descendant-extinction behavior is unchanged.
//
// scope's OWN RunID/IsStrong are reused to derive this stage's identity and
// containment strength rather than threading a second copy of the run's
// requireStrong decision through context: stage.Executor.Run always builds
// its own NEW, independent per-stage Scope internally (it never reads one
// from ctx), so scope here is consulted only for its metadata, never
// launched into directly.
func LaunchStaged(ctx context.Context, handle *BackendExecutionHandle, bin string, args []string, workdir string, out io.Writer, scope *containment.Scope, plan enforce.Plan) (exitCode int, descendantsGone bool, err error) {
	execID := stage.ExecutableIdentity{CanonicalPath: bin}
	var allowedEnv []string
	if handle != nil {
		execID = stage.ExecutableIdentity{CanonicalPath: handle.CanonicalPath, SHA256: handle.SHA256}
		allowedEnv = handle.AllowedEnv
	}
	envValues := BuildAllowedEnv(allowedEnv)
	factory := func(c context.Context, s *containment.Scope, p enforce.Plan, b string, a []string, d string) (*exec.Cmd, error) {
		if handle != nil {
			// VerifyUnchanged runs UNCONDITIONALLY first regardless of what
			// follows (deliberate, not redundant -- a script backend's
			// shebang makes the kernel re-open content, so an in-place
			// truncate+overwrite swap is invisible to the held fd and only
			// this fresh re-hash catches it).
			if err := handle.VerifyUnchanged(); err != nil {
				return nil, err
			}
			if p.Active {
				return composeBackendLaunch(c, s, p, handle, a, d)
			}
			// Plan inactive but scope present: launch the backend through
			// the scope's own descriptor-backed primitive only (no
			// __sandbox_exec wrap), one shared alloc. Non-Node: held fd;
			// Node: frozen entry pathname.
			alloc := &toolregistry.FDAllocator{}
			var execArg string
			if handle.closureRoot != "" {
				execArg = handle.launchPath
			} else {
				execArg = alloc.Arg(handle.File())
			}
			cmd := s.CommandWith(c, alloc, execArg, a, d)
			cmd.ExtraFiles = append(cmd.ExtraFiles, alloc.Files()...)
			return cmd, nil
		}
		// No handle (doctor probes / non-governed caller reached a scope
		// path): plain scope launch with the plan wrap, unchanged.
		var wrapFiles []*os.File
		bb, aa := b, a
		if p.Active {
			bb, aa, wrapFiles = p.Wrap(b, a)
		}
		cmd := s.Command(c, bb, aa, d)
		cmd.ExtraFiles = append(cmd.ExtraFiles, wrapFiles...)
		return cmd, nil
	}
	res, runErr := stage.NewExecutor().Run(ctx, stage.StageSpec{
		RunID:            scope.RunID(),
		StageID:          "backend",
		Executable:       execID,
		Arguments:        args,
		WorkingDirectory: workdir,
		Environment:      stage.FrozenEnvironment{Values: envValues, Hash: controllerenv.Hash(envValues)},
		OutputCapture:    stage.CaptureNone,
		DescendantPolicy: stage.DescendantPolicy{RequireStrong: scope.IsStrong()},
		EnforcementPlan:  plan,
		CommandFactory:   factory,
		// The backend can stream large transcripts over a long run --
		// unlike a quick validator/Assayer call, so Output (the internal,
		// otherwise-unbounded capture buffer stage.Executor.Run always
		// keeps) is never consulted here. out gets the real, streaming
		// transcript writer directly; matches the pre-migration byte-exact
		// behavior instead of buffering the whole run in memory first.
		Stdout: out,
		Stderr: out,
	})
	return res.ExitStatus, res.DescendantsGone, runErr
}
