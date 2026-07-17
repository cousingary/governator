package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	file      *os.File
	sealedDir string
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
	if h.sealedDir != "" {
		if rerr := os.RemoveAll(h.sealedDir); err == nil && rerr != nil {
			err = rerr
		}
		h.sealedDir = ""
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

// sealedExecutablePath copies the already-open, already-hashed backend
// executable into a private, mode-0500 directory and returns that immutable
// launch path for wrapper-based execution. Scope wrappers such as unshare or
// systemd-run cannot reliably receive our backend fd all the way to the final
// exec, so the S7-safe fallback is an object copied from the verified fd into
// a directory the backend does not know or control, never the mutable original
// pathname.
func (h *BackendExecutionHandle) sealedExecutablePath() (string, error) {
	if h == nil || h.file == nil {
		return "", fmt.Errorf("backend identity: no open executable handle available for sealed launch")
	}
	if h.sealedDir != "" {
		return filepath.Join(h.sealedDir, "backend"), nil
	}
	dir, err := os.MkdirTemp("", "governator-backend-exec-*")
	if err != nil {
		return "", fmt.Errorf("backend identity: create sealed exec dir: %w", err)
	}
	outPath := filepath.Join(dir, "backend")
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("backend identity: create sealed exec copy: %w", err)
	}
	if _, err := h.file.Seek(0, io.SeekStart); err != nil {
		_ = out.Close()
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("backend identity: rewind verified executable fd: %w", err)
	}
	_, copyErr := io.Copy(out, h.file)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("backend identity: copy verified executable: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("backend identity: close sealed exec copy: %w", closeErr)
	}
	if err := os.Chmod(outPath, 0500); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("backend identity: chmod sealed exec copy: %w", err)
	}
	// Node-based backends (codex, opencode, ...) resolve sibling npm
	// dependencies -- e.g. codex's own optional platform-native package --
	// via node_modules lookups that walk up from the running script's own
	// directory. The sealed copy above is deliberately isolated from its
	// original directory tree for integrity, which breaks that lookup for
	// any backend that needs it (observed: codex's findCodexExecutable()
	// throwing "Missing optional dependency @openai/codex-linux-x64").
	// Restore just the dependency-discovery path via a symlink -- it is not
	// re-verified/immutable, the same trust boundary the pre-sealing exec
	// path always had for the whole executable -- while the sealed backend
	// file itself stays the verified, immutable copy. Skipped silently for
	// non-Node backends that have no node_modules to find.
	if nm := nearestNodeModules(h.CanonicalPath); nm != "" {
		_ = os.Symlink(nm, filepath.Join(dir, "node_modules"))
	}
	if err := os.Chmod(dir, 0500); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("backend identity: chmod sealed exec dir: %w", err)
	}
	h.sealedDir = dir
	return outPath, nil
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

// ExtendPlanForSealedLaunch grows plan's Landlock read closure to cover the
// object that will ACTUALLY execute under a scope-wrapped launch, before
// Wrap is called. LaunchCommand's scoped branch never execs handle's
// original CanonicalPath -- it copies the verified bytes into a fresh
// sealedExecutablePath() directory and execs that copy instead (scope
// wrappers such as unshare/systemd-run reopen their argv[0] by path, so the
// fd-passing trick fdLaunchArgs uses for the unscoped case cannot reach
// them). A Plan built from CanonicalPath alone denies read/execute of that
// sealed copy, so the wrapped process fails closed on every launch attempt
// (verified: TestV6Case25 without this fix reaches QUARANTINED via "agent
// exit code 1" / VALIDATION_FAILED, never via an actual blocked secret read
// -- the backend never runs at all). Calling sealedExecutablePath() here is
// safe to repeat: it caches h.sealedDir and LaunchCommand's own later call
// returns the identical path, not a second copy. A no-op when plan is
// inactive or handle is nil -- nothing to extend for a launch Wrap will
// leave unchanged anyway.
func (h *BackendExecutionHandle) ExtendPlanForSealedLaunch(plan enforce.Plan) (enforce.Plan, error) {
	if h == nil || !plan.Active {
		return plan, nil
	}
	sealed, err := h.sealedExecutablePath()
	if err != nil {
		return enforce.Plan{}, err
	}
	return plan.WithExecutableAndReadRoots(sealed, filepath.Dir(sealed))
}

// VerifyUnchanged re-stats and re-hashes h's canonical path RIGHT NOW and
// fails closed if the file is missing or no longer matches what ResolveHandle
// captured. Used on launch paths that must exec through a wrapper binary
// (e.g. a containment.Scope launching via systemd-run/unshare, where the
// governed backend is the wrapper's child rather than this process's direct
// child, so the fd-passing trick in fdLaunchArgs cannot reach it) -- the plan's
// explicit fallback for "where fexecve-style launch isn't available."
func (h *BackendExecutionHandle) VerifyUnchanged() error {
	info, err := os.Stat(h.CanonicalPath)
	if err != nil {
		return fmt.Errorf("backend identity re-verification: %s: %w", h.CanonicalPath, err)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		wantIdent := h.FileIdentity
		gotIdent := fmt.Sprintf("dev=%d ino=%d path=%s", st.Dev, st.Ino, h.CanonicalPath)
		if wantIdent != "" && gotIdent != wantIdent {
			return fmt.Errorf("backend identity re-verification: %s changed identity between resolution and launch (was %q, now %q)", h.CanonicalPath, wantIdent, gotIdent)
		}
	}
	data, err := os.ReadFile(h.CanonicalPath)
	if err != nil {
		return fmt.Errorf("backend identity re-verification: read %s: %w", h.CanonicalPath, err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != h.SHA256 {
		return fmt.Errorf("backend identity re-verification: %s content changed between resolution and launch", h.CanonicalPath)
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
		cmd = exec.CommandContext(probeCtx, path, "--version")
		cmd.Env = controllerenv.Base()
		cmd.ExtraFiles = extra
	} else {
		cmd = exec.CommandContext(probeCtx, h.CanonicalPath, "--version")
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
// backend, given the args already-projected by the adapter and the
// containment posture in effect. It is the one place the launch decision is
// made, shared by agents.defaultExecutor and runner.LocalWorktreeRunner's
// executor so both host-launch call sites make the identical decision.
//
//   - No handle at all (Request.ResolvedBin was empty -- gov doctor probes,
//     tests, or any caller outside a governed run): plain path launch,
//     unchanged pre-Session-3 behavior.
//   - Handle present: VerifyUnchanged runs UNCONDITIONALLY first, regardless
//     of what follows. This is deliberate, not redundant: fdLaunchArgs'
//     /proc/self/fd exec closes the classic TOCTOU for a compiled binary
//     (holding the fd survives an unlink+recreate at the same path), but a
//     script backend's "#!/bin/sh" line makes the KERNEL re-open the path
//     itself to find the interpreter -- so an in-place truncate+overwrite
//     swap (os.WriteFile, cp, a non-atomic editor save; the common case,
//     and what report attack 6's fixture does) is invisible to the held fd
//     and only VerifyUnchanged's fresh re-hash catches it. After that gate
//     passes, fd-based exec is still used when available as additional
//     hardening against a swap in the sub-millisecond window between this
//     check and the actual execve.
func LaunchCommand(ctx context.Context, handle *BackendExecutionHandle, bin string, args []string, scopeCmd func(context.Context, string, []string) *exec.Cmd) (*exec.Cmd, error) {
	if handle == nil {
		if scopeCmd != nil {
			return scopeCmd(ctx, bin, args), nil
		}
		return exec.CommandContext(ctx, bin, args...), nil
	}
	if err := handle.VerifyUnchanged(); err != nil {
		return nil, err
	}
	if scopeCmd != nil {
		sealed, err := handle.sealedExecutablePath()
		if err != nil {
			return nil, err
		}
		return scopeCmd(ctx, sealed, args), nil
	}
	if path, extra, ok := handle.fdLaunchArgs(); ok {
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.ExtraFiles = extra
		// argv[0] stays the configured bin name (cosmetic only -- execve
		// resolves cmd.Path, the fd, regardless of argv[0]) so a backend
		// that inspects its own argv[0] doesn't see the fd pseudo-path.
		cmd.Args[0] = bin
		return cmd, nil
	}
	return exec.CommandContext(ctx, bin, args...), nil
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
// The launch itself is still exactly LaunchCommand's existing
// sealed-copy-or-fd logic (via a CommandFactory), including
// ExtendPlanForSealedLaunch -- this migration is about WHERE the scope,
// timeout, and extinction bookkeeping live, not about changing how the
// process is actually built or confined.
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
			extended, eerr := handle.ExtendPlanForSealedLaunch(p)
			if eerr != nil {
				return nil, eerr
			}
			p = extended
		}
		return LaunchCommand(c, handle, b, a, func(cc context.Context, launchBin string, launchArgs []string) *exec.Cmd {
			wb, wa := p.Wrap(launchBin, launchArgs)
			return s.Command(cc, wb, wa, d)
		})
	}
	res, runErr := stage.NewExecutor().Run(ctx, stage.StageSpec{
		RunID:            scope.RunID(),
		StageID:          "backend",
		Executable:       execID,
		Arguments:        args,
		WorkingDirectory: workdir,
		Environment:      stage.FrozenEnvironment{Values: envValues, Hash: controllerenv.Hash(envValues)},
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
