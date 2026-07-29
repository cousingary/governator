// Session 2 (Sol redteam v4, P0-4): the descendant-owning containment
// primitive. SysProcAttr{Setpgid: true} + Kill(-pid) only covers a process's
// own POSIX process group, and only on the ctx-cancellation path -- a
// well-behaved-looking backend that forks a setsid'd or double-forked child
// escapes the group entirely, and a normal (non-timeout) exit never proves
// the tree is actually dead. Scope replaces that assumption with a real
// kernel boundary: cgroup v2 membership (systemd transient scope, or a
// directly managed cgroup) survives setsid/double-fork/nohup, and a PID
// namespace makes escape structurally impossible rather than merely
// unlikely. Extinguish is the DESCENDANTS_TERMINATED lifecycle stage: freeze,
// kill, wait for kernel-confirmed extinction, then independently verify no
// process anywhere still holds a workspace file handle. See runtime.go's
// runOnce for where this runs -- always before S1's final-state fingerprint
// capture, never skipped, never treated as best-effort.
package containment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/toolregistry"
)

// cgroupGone reports whether err indicates the cgroup directory (or a file
// inside it) no longer exists -- the successful, expected outcome once
// extinction completes. cgroup v2 is not consistent about which errno a
// dying cgroup returns: a directory mid-teardown (e.g. torn down by
// systemd's own --collect garbage collection racing our own freeze/kill/
// wait) can surface ENOENT or ENODEV depending on exactly when the read
// lands, and both mean the same thing here: nothing is left to act on.
func cgroupGone(err error) bool {
	return err == nil || os.IsNotExist(err) || errors.Is(err, syscall.ENODEV)
}

// ScopeMethod identifies which descendant-owning primitive backs a Scope.
type ScopeMethod string

const (
	// ScopeSystemdUserScope wraps the launch in `systemd-run --user --scope`,
	// a transient cgroup v2 scope registered with the user's systemd manager.
	// Preferred: no filesystem write access to cgroupfs is required (systemd
	// already owns the delegation), and cleanup is automatic.
	ScopeSystemdUserScope ScopeMethod = "systemd-user-scope"
	// ScopeCgroupDirect creates a cgroup v2 subdirectory under the caller's
	// own cgroup and places the launched process into it atomically at
	// clone() time via CLONE_INTO_CGROUP (SysProcAttr.UseCgroupFD). Fallback
	// for hosts without a systemd user manager but where the caller's own
	// cgroup subtree is writable -- typically a container that owns its
	// whole cgroup namespace.
	ScopeCgroupDirect ScopeMethod = "cgroup-direct"
	// ScopePIDNamespace wraps the launch in `unshare --pid --fork
	// --mount-proc` with an identity uid/gid mapping so file ownership is
	// unaffected. Last resort: no cgroupfs access needed at all -- the
	// backend and everything it forks lives inside a PID namespace it cannot
	// leave, and the namespace's death is unconditional once its init
	// process (the wrapped command itself) exits or is killed.
	ScopePIDNamespace ScopeMethod = "pid-namespace"
	// scopeDegraded is the pre-S2 process-group behavior. Only ever returned
	// by NewScope for a non-high-risk run when none of the three real
	// primitives are available on the host; a high-risk run refuses instead
	// (report P0-4: "must refuse, not degrade").
	scopeDegraded ScopeMethod = "process-group-degraded"
)

// DefaultExtinctionDeadline bounds how long Extinguish waits for the kernel
// to confirm every process inside a Scope is dead before hard-failing the
// run. There is no unbounded wait path -- report P0-4 is explicit that
// "process exited, therefore done" is exactly the assumption being removed.
const DefaultExtinctionDeadline = 5 * time.Second

var unitNameSafe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,120}$`)

// Proof is the DESCENDANTS_TERMINATED stage's recorded evidence -- exactly
// what was frozen, killed, and independently confirmed dead before the run
// was allowed to proceed to S1's final-state fingerprint/tree capture.
// Approval is impossible without one of these attached to the run record.
type Proof struct {
	Method               ScopeMethod   `json:"method"`
	Frozen               bool          `json:"frozen"`
	Killed               bool          `json:"killed"`
	Waited               time.Duration `json:"waited_ns"`
	WorkspaceFDScanClean bool          `json:"workspace_fd_scan_clean"`
	Degraded             bool          `json:"degraded,omitempty"`
	Note                 string        `json:"note,omitempty"`
	// ProcessesObservedPeak (Sol P0-3/P1-15 effect ledger) is the number of
	// PIDs cgroup.procs listed for this scope at the moment it was frozen --
	// i.e. every process this launch ever spawned that was still alive right
	// before extinction began, read from the kernel's own accounting, not
	// from anything the backend reported about its own descendants. -1 when
	// the scope method has no cgroup to read (PID namespace, degraded).
	ProcessesObservedPeak int `json:"processes_observed_peak"`
}

// ContainmentEnvironment is the frozen set of descendant-owning containment
// primitives a whole run's replay identity is evaluated against (rc4 Session
// 2, Sol10 P0-2). Before this type existed, NewScope called
// toolregistry.Load() and ResolveHandle fresh on every invocation -- once for
// the run-level Scope, again for every stage's own Scope (internal/stage.
// Executor.Run) -- so the trusted-tool registry could be reloaded, and in
// principle observe different enrolled state, after the run's environment and
// replay identity were already frozen (buildRunEnvironment, called exactly
// once at the top of runOnce). ResolveEnvironment now does that resolution
// exactly once, from the SAME frozen registry every other trust decision in
// the run uses, and every NewScope call for the run's whole lifetime --
// backend and every stage -- is handed this one value rather than resolving
// its own.
//
// SystemdRun/Unshare are nil when that primitive is not enrolled/resolvable
// on this host; NewScope's existing fallback chain treats a nil handle
// exactly like the old resolution failure it replaces.
type ContainmentEnvironment struct {
	SystemdRun *toolregistry.Handle
	Unshare    *toolregistry.Handle
	Cgroup     CgroupCapabilities
}

// CgroupCapabilities is a descriptive snapshot of this process's cgroup v2
// direct-management capability, folded into ContainmentEnvironmentHash
// (internal/runtime/identity.go) so a host's cgroup capability is part of
// the run's replay identity like everything else ContainmentEnvironment
// describes. Unlike SystemdRun/Unshare, newDirectCgroupScope does NOT
// consume this to decide whether to attempt cgroup-direct: cgroup-direct
// launches the caller's own already-verified bin directly (never a
// "primitive binary" needing registry trust the way systemd-run/unshare do,
// see Command's ScopeCgroupDirect branch), so it carries none of P0-2's
// TOCTOU concern, and several legitimate callers (internal/assay.Evaluate,
// notably) construct a Scope via a bare context.Context that was never
// threaded through containment.WithEnvironment -- requiring a resolved
// CgroupCapabilities there would wrongly disable the strongest containment
// method available on hosts with a perfectly usable cgroup v2 hierarchy.
// newDirectCgroupScope always probes live, exactly as it did before this
// type existed.
type CgroupCapabilities struct {
	Available bool
	SelfPath  string
}

// ResolveEnvironment resolves every containment primitive's held handle
// exactly once from registry -- the caller's already-frozen trusted-tool
// registry (internal/runtime.RunEnvironment.ToolRegistry), never a fresh
// toolregistry.Load(). A primitive that is not enrolled or fails
// registry-verification simply resolves to a nil handle; it is not a hard
// error here, mirroring NewScope's pre-existing "try the next weaker
// primitive" fallback discipline for the whole run rather than per attempt.
func ResolveEnvironment(registry *toolregistry.Registry) (ContainmentEnvironment, error) {
	if registry == nil {
		return ContainmentEnvironment{}, fmt.Errorf("containment: tool registry is not frozen")
	}
	var env ContainmentEnvironment
	if h, err := registry.ResolveHandle("systemd-run", "systemd-run", toolregistry.KindTrustedController); err == nil {
		env.SystemdRun = h
	}
	if h, err := registry.ResolveHandle("unshare", "unshare", toolregistry.KindTrustedController); err == nil {
		env.Unshare = h
	}
	env.Cgroup = probeCgroupCapabilities()
	return env, nil
}

// probeCgroupCapabilities resolves this process's own cgroup v2 path once.
// Availability is not guaranteed by this probe alone (newDirectCgroupScope
// still must create and write to a real subdirectory to know for certain --
// a parent cgroup can be readable but not writable), so Available only
// records whether a cgroup v2 path could be resolved at all; a false here
// lets newDirectCgroupScope skip the attempt entirely instead of failing a
// mkdir on every stage.
func probeCgroupCapabilities() CgroupCapabilities {
	self, err := cgroupPathForPID(os.Getpid())
	if err != nil {
		return CgroupCapabilities{}
	}
	return CgroupCapabilities{Available: true, SelfPath: self}
}

// Close releases every handle this environment holds. The caller that
// resolved the environment (ResolveEnvironment, called exactly once before
// replay) owns this and must call it exactly once, after every Scope built
// from this environment across the run's entire lifetime -- backend and
// every stage -- has finished. Individual Scopes never close these handles;
// they only borrow them for the duration of one launch (see Scope.Command).
func (e ContainmentEnvironment) Close() error {
	var err error
	if e.SystemdRun != nil {
		if cerr := e.SystemdRun.Close(); cerr != nil {
			err = cerr
		}
	}
	if e.Unshare != nil {
		if cerr := e.Unshare.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// Scope owns the entire descendant tree spawned by one governed subprocess
// launch. Exactly one is constructed per run, before the backend is started,
// and threaded through to the launch site via WithScope/ScopeFromContext so
// every backend adapter's shared runCLI path (agents.defaultExecutor,
// runner.LocalWorktreeRunner.executor) launches inside it without each
// adapter needing to know how.
type Scope struct {
	method   ScopeMethod
	runID    string
	unitName string // ScopeSystemdUserScope only
	// primitiveHandle is the verified-open primitive binary (systemd-run for
	// ScopeSystemdUserScope, unshare for ScopePIDNamespace) this Scope
	// launches through -- Command builds every argv0 for these two methods as
	// the handle's own /proc/self/fd/<n> pseudo-path (rc4 Session 2, Sol10
	// P0-2), never a canonical pathname a same-uid process could replace
	// between resolution and exec. Scope BORROWS this handle from the run's
	// ContainmentEnvironment (see ResolveEnvironment) -- it never closes it;
	// the environment is shared across every stage's own Scope for the run's
	// whole lifetime, and only the environment's own Close, called once after
	// the run finishes, releases it.
	primitiveHandle *toolregistry.Handle

	mu         sync.Mutex
	pid        int // outer-namespace pid of the launched wrapper/process
	nsInitPid  int // ScopePIDNamespace only: the fork()'d PID-1-of-namespace child
	cgroupPath string
	resolveErr error

	cgroupFile *os.File // ScopeCgroupDirect only; keeps the dir fd alive for CLONE_INTO_CGROUP

	// sealedPrimitive is the private, verified-bytes copy of primitiveHandle
	// Command seals for ScopeSystemdUserScope/ScopePIDNamespace (rc4 Session
	// 2, Sol10 P0-2) -- see Command's doc comment for why a sealed copy, not
	// an fd-argv launch, is what actually gets exec'd. Owned by this Scope;
	// Extinguish closes it once the launched process has fully finished.
	sealedPrimitive *toolregistry.SealedCopy
}

// ForceDegradedScopeForTesting is a TEST-ONLY seam. When true, NewScope returns
// a degraded (bare process-group) scope without probing for any real
// descendant-owning primitive, so the red-team corpus can exercise Governator's
// approval/merge/replay paths end to end on hosts that lack systemd --user, a
// usable cgroup v2 subtree, or a PID namespace.
//
// It exists ONLY because the Sol11 P0-3 defect it replaces — the
// GOV_CONTAINMENT_FORCE_DEGRADED environment variable — was a production
// bypass: any launcher, wrapper or compromised shell could export that var to
// force degraded containment for a stage that should have failed closed. An
// inherited environment variable must never weaken production authority (Sol11
// P0-3 / the rc5 governing invariant); a package-level Go variable set only by
// _test.go code cannot be flipped by environment, so it is the sanctioned test
// substitute. Production code MUST NEVER set this; nothing links the setter
// into a release binary's execution path. Mirrors the established test-seam
// pattern of internal/enforce.SelfExeOverride and ForceUnsupported.
var ForceDegradedScopeForTesting atomic.Bool

// ScopeSelectionForceUnavailableForTesting is a TEST-ONLY seam (Sol12 rc5
// Session 2, P0-1). When set, newSystemdUserScope returns a deterministic
// "systemd user manager unavailable" error immediately after the nil-handle
// check -- WITHOUT touching /run/systemd/system, the live user bus, or the
// systemd-run probe -- so the scope-selection FAILURE path (and its
// descriptor-leak invariant) can be exercised on every host, including one
// that genuinely has a live systemd --user manager. Before this seam,
// TestV10Case12 (report case 12) could only run where the host truly lacked
// systemd --user, making it mutually exclusive with TestV10Case13 (the real
// live-systemd acceptance test) on any single host -- so a correct single-host
// zero-skip red-team run was structurally impossible. Production code MUST
// NEVER set this; only _test.go code in this package and the redteam corpus
// (behind the redteam build tag) flips it, exactly like
// ForceDegradedScopeForTesting. The forced error fires at the same logical
// point a genuinely-absent user bus would (after the borrowed handle is
// confirmed non-nil, before any probe), so the borrow/ownership invariant
// under test is the real one.
var ScopeSelectionForceUnavailableForTesting atomic.Bool

// UnitMaterializationForceUnobservedForTesting is a TEST-ONLY seam (Sol14 rc7
// Session 9a, P1-2). When set, resolveCgroupFromPID reports the SAME
// "generated systemd unit was never confirmed" resolve error the deadline loop
// produces when a transient scope registers with systemd but its cgroup never
// materializes for the launched pid -- immediately, without waiting out the
// 2-second deadline and without depending on this host having (or lacking) a
// live systemd --user manager.
//
// Before this seam, TestV6Case28SystemdUnitNeverMaterializingFailsClosed could
// only assert its property on a host with NO systemd --user manager, because
// forcing "unit registers but is never observed within deadline" on a host that
// genuinely has systemd requires adversarial control over systemd the red-team
// package cannot exercise. It therefore skipped on every systemd host and was
// carried as an OPEN GAP exclusion -- "excluded but happened to pass" is not
// durable release policy (Sol14 P1-2). With the seam the case is deterministic
// on both host classes: the run must fail closed rather than reach APPROVED
// backed by a scope identity it never actually confirmed.
//
// The forced error fires at the same logical point, with the same message and
// the same resolveErr field, that a genuinely non-materializing unit produces,
// so the fail-closed invariant under test is the real one -- only the trigger
// is deterministic. Production code MUST NEVER set this; only _test.go code and
// the redteam corpus (behind the redteam build tag) flip it, exactly like
// ScopeSelectionForceUnavailableForTesting above.
var UnitMaterializationForceUnobservedForTesting atomic.Bool

// ExtinguishGateForTesting is a TEST-ONLY synchronization seam (Sol12 rc5
// Session 2, P0-1). When non-nil, Scope.Extinguish invokes it and blocks until
// it returns BEFORE beginning any kill/freeze logic, so a red-team fixture can
// PROVE a descendant reached an intended state (e.g. an uninterruptible
// blocking read) BEFORE Governator begins extinction. This replaces the timing
// assumption at the heart of TestV7Case8's original flake (report case 8:
// "the timing fixture did not enter its expected blocking-read state before
// its deadline"). If the gate returns a non-nil error, Extinguish returns that
// error without killing -- the fixture uses this to surface a genuine
// host-capability failure (a kernel that kills FUSE-blocked readers) as a
// deterministic, reasoned refusal rather than a post-hoc timeout skip.
// Production code MUST NEVER set this; only _test.go / redteam-corpus code
// assigns it (and defers restoring nil), mirroring internal/enforce.SelfExeOverride.
var ExtinguishGateForTesting func() error

// NewScope selects the strongest descendant-owning primitive available on
// this host, in the order the plan specifies: systemd --user transient
// scope, then a directly managed cgroup v2 subtree, then a PID namespace.
// requireStrong callers refuse outright when none qualifies rather than
// silently falling back to a bare process group.
//
// env is the run's frozen ContainmentEnvironment (rc4 Session 2, Sol10
// P0-2), resolved exactly once via ResolveEnvironment before replay --
// NewScope never loads or resolves the trusted-tool registry itself. Every
// call for one run (the run-level Scope and every stage's own Scope) must be
// handed the SAME env value, so the primitive actually launched can never
// diverge from the one the run's replay identity was computed against.
func NewScope(runID string, requireStrong bool, env ContainmentEnvironment) (*Scope, error) {
	if ForceDegradedScopeForTesting.Load() {
		return &Scope{method: scopeDegraded, runID: runID}, nil
	}
	if s, err := newSystemdUserScope(runID, env.SystemdRun); err == nil {
		return s, nil
	}
	if s, err := newDirectCgroupScope(runID); err == nil {
		return s, nil
	}
	if s, err := newPIDNamespaceScope(runID, env.Unshare); err == nil {
		return s, nil
	}
	if requireStrong {
		return nil, fmt.Errorf("containment: no descendant-owning primitive available (tried systemd --user scope, direct cgroup v2, PID namespace); refusing authority-bearing run rather than degrading to a bare process group")
	}
	return &Scope{method: scopeDegraded, runID: runID}, nil
}

// Method reports which primitive this Scope actually uses.
func (s *Scope) Method() ScopeMethod { return s.method }

// RunID returns the identifier this Scope was constructed with -- the same
// value the caller passed to NewScope. Exposed so a per-stage caller (Sol
// redteam v7 S1: a governed backend routed through internal/stage.Executor)
// can derive its own unique per-stage scope name from the SAME run
// identity the outer, run-level Scope already carries, without needing a
// second context key threaded alongside WithScope purely to repeat a value
// this Scope already has.
func (s *Scope) RunID() string { return s.runID }

// IsStrong reports whether this Scope's underlying primitive actually owns
// its descendants (systemd-user-scope, cgroup-direct, pid-namespace) as
// opposed to the pre-S2 process-group-only degraded fallback. Exposed so a
// per-stage caller deriving a NEW, separate Scope for its own launch (Sol
// redteam v7 S1) can request the same strength the outer run-level Scope
// already achieved on this host, rather than needing its own independent
// copy of the run's requireStrong policy decision threaded through.
func (s *Scope) IsStrong() bool { return s.method != scopeDegraded }

// newSystemdUserScope probes whether this host's live systemd --user manager
// can actually accept a transient scope right now, and if so returns a Scope
// that launches through handle -- the run's frozen, held systemd-run
// descriptor (ContainmentEnvironment.SystemdRun), never a fresh registry
// resolution. handle is BORROWED: this function never closes it, on success
// or on any of the error returns below -- ownership stays with whoever
// resolved the ContainmentEnvironment, so a probe failure here (this
// particular attempt only) never costs the run its one held descriptor for
// every other stage still to come.
func newSystemdUserScope(runID string, handle *toolregistry.Handle) (*Scope, error) {
	if handle == nil {
		return nil, fmt.Errorf("containment: systemd-run is not enrolled/resolvable in this run's frozen containment environment")
	}
	if ScopeSelectionForceUnavailableForTesting.Load() {
		// Deterministic failure for the scope-selection leak invariant (Sol12
		// rc5 Session 2, P0-1): a borrowed, non-nil handle is confirmed here,
		// then this attempt fails exactly as a genuinely-absent user bus would
		// -- without probing the host -- so TestV10Case12 (report case 12) can
		// run on a host that has systemd --user instead of being its
		// mutually-exclusive partner of TestV10Case13. handle is borrowed, so
		// nothing here is closed (the invariant the test asserts).
		return nil, fmt.Errorf("containment: systemd user manager unavailable (test-forced scope-selection failure)")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil, fmt.Errorf("containment: systemd is not PID 1 (no /run/systemd/system): %w", err)
	}
	userBus := fmt.Sprintf("/run/user/%d/bus", os.Getuid())
	if _, err := os.Stat(userBus); err != nil {
		return nil, fmt.Errorf("containment: systemd user manager is not available (no %s): %w", userBus, err)
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	probeUnit := "governator-probe-" + sanitizeName(runID) + "-" + nonce()
	// --wait is redundant with --scope (a scope invocation already blocks
	// until its command exits, unlike --unit's default fire-and-forget) and
	// at least some systemd versions (confirmed: systemd on this project's
	// own dev host) reject the combination outright ("--wait may not be
	// combined with --scope"), which silently failed this probe on every
	// run and forced every containment scope down to the weaker
	// pid-namespace fallback -- never systemd-user-scope, the preferred,
	// strongest primitive -- without any test or caller noticing, since
	// NewScope's fallback chain has no logging of individual method
	// failures. Found while building Sol redteam v7 case 8's fixture: a
	// scope-selection probe (TestZZScopeProbe-shaped) showed pid-namespace
	// selected even with systemd-run enrolled and /run/systemd/system +
	// the user bus both present, which should be impossible if the probe
	// itself were succeeding.
	probe, err := handle.Command(probeCtx, "--user", "--scope", "--quiet", "--collect", "--unit="+probeUnit, "--", "/bin/true")
	if err != nil {
		return nil, fmt.Errorf("containment: systemd user scope probe: %w", err)
	}
	probe.Env = controllerenv.Base()
	if out, err := probe.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("containment: systemd user scope probe failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return &Scope{
		method:          ScopeSystemdUserScope,
		runID:           runID,
		unitName:        "governator-" + sanitizeName(runID) + "-" + nonce(),
		primitiveHandle: handle,
	}, nil
}

// nonce returns a short random hex suffix so a Scope's unit/directory name
// is unique even if the caller-supplied runID repeats (a retried run, a
// test, an id-reuse edge case). Without this, a prior run's not-yet-collected
// transient unit or cgroup directory can collide with a new one under the
// same name and make Command fail closed for reasons that have nothing to
// do with containment itself.
func nonce() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// newDirectCgroupScope always probes this process's own cgroup v2 path
// live -- see CgroupCapabilities' doc comment for why it does not consume
// the run's (possibly entirely absent) ContainmentEnvironment the way
// newSystemdUserScope/newPIDNamespaceScope do.
func newDirectCgroupScope(runID string) (*Scope, error) {
	self, err := cgroupPathForPID(os.Getpid())
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(self, "governator-"+sanitizeName(runID)+"-"+nonce()+".scope")
	if err := os.Mkdir(dir, 0755); err != nil {
		return nil, fmt.Errorf("containment: direct cgroup unavailable: %w", err)
	}
	if err := writeCgroupFile(dir, "cgroup.freeze", "0"); err != nil {
		_ = os.Remove(dir)
		return nil, fmt.Errorf("containment: direct cgroup unavailable: cannot control cgroup.freeze: %w", err)
	}
	f, err := os.Open(dir)
	if err != nil {
		_ = os.Remove(dir)
		return nil, fmt.Errorf("containment: direct cgroup unavailable: %w", err)
	}
	return &Scope{
		method:     ScopeCgroupDirect,
		runID:      runID,
		cgroupPath: dir,
		cgroupFile: f,
	}, nil
}

// newPIDNamespaceScope returns a Scope that launches through handle -- the
// run's frozen, held unshare descriptor (ContainmentEnvironment.Unshare).
// handle is BORROWED, exactly as newSystemdUserScope's is: never closed here.
func newPIDNamespaceScope(runID string, handle *toolregistry.Handle) (*Scope, error) {
	if handle == nil {
		return nil, fmt.Errorf("containment: unshare is not enrolled/resolvable in this run's frozen containment environment")
	}
	return &Scope{method: ScopePIDNamespace, runID: runID, primitiveHandle: handle}, nil
}

func sanitizeName(runID string) string {
	if unitNameSafe.MatchString(runID) {
		return runID
	}
	sum := sha256.Sum256([]byte(runID))
	return hex.EncodeToString(sum[:])[:32]
}

type scopeContextKey struct{}

// WithScope attaches s to ctx so the launch site (several packages away from
// whoever constructed the Scope) can find it without every intermediate
// call signature threading it through explicitly.
func WithScope(ctx context.Context, s *Scope) context.Context {
	return context.WithValue(ctx, scopeContextKey{}, s)
}

type environmentContextKey struct{}

// WithEnvironment attaches the run's frozen ContainmentEnvironment to ctx
// (rc4 Session 2, Sol10 P0-2), mirroring WithScope, so every NewScope call
// site for the run's whole lifetime -- the run-level Scope (constructed
// where WithEnvironment is called) and every stage's own Scope
// (internal/stage.Executor.Run, several packages and call layers away) --
// retrieves the SAME resolved handles via EnvironmentFromContext rather than
// each independently resolving the trusted-tool registry.
func WithEnvironment(ctx context.Context, env ContainmentEnvironment) context.Context {
	return context.WithValue(ctx, environmentContextKey{}, env)
}

// EnvironmentFromContext retrieves a ContainmentEnvironment attached by
// WithEnvironment. ok is false only for a launch that never went through a
// governed runtime.Runner (doctor probes, direct package tests); NewScope
// treats the resulting zero value exactly like every primitive being
// unresolvable, falling back through its normal chain.
func EnvironmentFromContext(ctx context.Context) (ContainmentEnvironment, bool) {
	env, ok := ctx.Value(environmentContextKey{}).(ContainmentEnvironment)
	return env, ok
}

// ScopeFromContext retrieves a Scope attached by WithScope. Callers must
// treat "not found" as "no containment for this launch" -- every caller in
// this codebase falls back to the pre-S2 process-group behavior when this
// returns false, which only happens for launches that never went through a
// governed runtime.Runner (doctor probes, direct adapter tests).
func ScopeFromContext(ctx context.Context) (*Scope, bool) {
	s, ok := ctx.Value(scopeContextKey{}).(*Scope)
	return s, ok && s != nil
}

// Command builds an *exec.Cmd for bin/args/dir such that the process --  and
// every descendant it forks, however it detaches -- is born inside this
// scope from the moment it starts. Callers still set Stdout/Stderr and call
// Start themselves; Command only owns argv/SysProcAttr/Dir.
//
// rc4 Session 2 (Sol10 P0-2): the ScopeSystemdUserScope/ScopePIDNamespace
// branches used to exec s.primitivePath -- a canonical pathname re-resolved
// at every launch, the same TOCTOU shape Sol v9 P0-1/P0-2 already closed for
// enforce.Plan's unshare wrapper. A same-uid process could replace the file
// at that path between NewScope's verification and this exec, and the
// replacement -- not the verified binary -- would become the thing
// responsible for establishing containment.
//
// An earlier version of this fix launched through s.primitiveHandle's own
// /proc/self/fd/<n> descriptor directly (mirroring toolregistry.Handle.
// Command). That broke every caller that composes a Scope's launch with
// enforce.Plan.Wrap's OWN independent fd-argv numbering (agents.LaunchStaged,
// internal/stage's default CommandFactory, and toolregistry.Handle.
// CommandWith's build callback all do, for backend/validator/bash launches
// under an active enforce.Plan) -- both layers independently assumed they
// would own ExtraFiles[0]/fd 3, so whichever layer's files got merged in
// second silently landed at the wrong descriptor (or, for CommandWith's
// build callback, got overwritten outright), and the argv string baked in
// by the other layer no longer pointed at what it meant to. Composing two
// independently fd-numbering launch mechanisms correctly would need every
// composition call site to thread a shared fd allocator through -- real
// production_launch_factory work belongs together, not scattered piecemeal
// under a fix for a single primitive.
//
// So instead, both branches launch through a SEALED PRIVATE COPY: a fresh,
// 0500, same-uid-only-readable copy of s.primitiveHandle's own verified
// bytes (SealedExecutablePath, sealed FROM the already-open, already-hashed
// descriptor -- never by re-reading the enrolled path), re-verified
// (Verify) immediately before this launch to catch a same-uid tamper of the
// COPY itself between sealing and exec. This is one of the plan's own
// explicitly acceptable alternatives to fd-argv launch ("a verified private
// immutable copy"), it uses an ordinary real pathname so it composes with
// enforce.Plan.Wrap/Handle.CommandWith exactly like every other
// already-verified bin these callers pass through Scope.Command, and it
// needs no signature change here. The copy is owned by this Scope
// (s.sealedPrimitive) and closed by Extinguish, once the launched process
// has fully finished with it.
//
// Sealing or verifying can fail (disk full, /tmp unwritable, or Verify
// genuinely catching a live same-uid tamper of the copy) -- Command has no
// error return, so a failure here produces a cmd that will simply fail at
// Start() with a descriptive, un-executable path, exactly the fail-closed
// outcome every caller's existing cmd.Start() error check already handles;
// it never falls back to a mutable pathname.
func (s *Scope) Command(ctx context.Context, bin string, args []string, dir string) *exec.Cmd {
	var cmd *exec.Cmd
	switch s.method {
	case ScopeSystemdUserScope:
		full := append([]string{
			"--user", "--scope", "--quiet", "--collect",
			"--unit=" + s.unitName,
			"--",
			bin,
		}, args...)
		primitive := s.sealPrimitive()
		cmd = exec.CommandContext(ctx, primitive, full...) // govratchet:exec-allow(production_launch_factory) -- primitive is a freshly sealed, re-verified private copy of s.primitiveHandle's held bytes, never the mutable enrolled path
		cmd.Env = controllerenv.Base()
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	case ScopeCgroupDirect:
		cmd = exec.CommandContext(ctx, bin, args...) // govratchet:exec-allow(production_launch_factory) -- bin is already the caller's verified/sealed path
		cmd.SysProcAttr = cgroupDirectSysProcAttr(s.cgroupFile.Fd())
	case ScopePIDNamespace:
		full := []string{
			"--user",
			fmt.Sprintf("--map-user=%d", os.Getuid()),
			fmt.Sprintf("--map-group=%d", os.Getgid()),
			"--pid", "--fork", "--mount-proc",
			"--",
			bin,
		}
		full = append(full, args...)
		primitive := s.sealPrimitive()
		cmd = exec.CommandContext(ctx, primitive, full...) // govratchet:exec-allow(production_launch_factory) -- primitive is a freshly sealed, re-verified private copy of s.primitiveHandle's held bytes, never the mutable enrolled path
		cmd.Env = controllerenv.Base()
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	default: // scopeDegraded
		cmd = exec.CommandContext(ctx, bin, args...) // govratchet:exec-allow(production_launch_factory) -- bin is already the caller's verified/sealed path
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	cmd.Dir = dir
	return cmd
}

// CommandWith is Command's composable, descriptor-backed form (Sol11 P0-5):
// a caller that must combine this Scope's own primitive launch
// (systemd-run/unshare) with another descriptor-backed layer of its own --
// concretely, enforce.Plan.WrapWith's self-exec/unshare/final-executable
// descriptors -- passes one shared alloc so every layer's
// /proc/self/fd/<n> argv string lands at the fd number Start will actually
// dup it to, instead of two independently-numbered ExtraFiles lists
// colliding at fd 3. That collision is exactly why Command above still
// falls back to a sealed pathname copy of its primitive (see Command's own
// doc comment): it has no shared allocator to compose through. CommandWith
// closes the Verify-then-replace-then-exec race a sealed copy cannot by
// never reopening a pathname for the primitive at all -- it launches
// through s.primitiveHandle's own held, already-verified descriptor
// (/proc/self/fd/<n>, via alloc), the same object NewScope resolved and
// verified once, for the run's whole lifetime.
//
// The caller must set the returned cmd's ExtraFiles to alloc.Files() once
// every composed layer -- including this one -- has finished registering.
func (s *Scope) CommandWith(ctx context.Context, alloc *toolregistry.FDAllocator, bin string, args []string, dir string) *exec.Cmd {
	var cmd *exec.Cmd
	switch s.method {
	case ScopeSystemdUserScope:
		full := append([]string{
			"--user", "--scope", "--quiet", "--collect",
			"--unit=" + s.unitName,
			"--",
			bin,
		}, args...)
		primitive := s.primitiveArg(alloc)
		cmd = exec.CommandContext(ctx, primitive, full...) // govratchet:exec-allow(production_launch_factory) -- primitive is s.primitiveHandle's own held, already-verified descriptor via /proc/self/fd/<n>, never a reopened pathname
		cmd.Env = controllerenv.Base()
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	case ScopeCgroupDirect:
		cmd = exec.CommandContext(ctx, bin, args...) // govratchet:exec-allow(production_launch_factory) -- bin is already the caller's verified/sealed path
		cmd.SysProcAttr = cgroupDirectSysProcAttr(s.cgroupFile.Fd())
	case ScopePIDNamespace:
		full := []string{
			"--user",
			fmt.Sprintf("--map-user=%d", os.Getuid()),
			fmt.Sprintf("--map-group=%d", os.Getgid()),
			"--pid", "--fork", "--mount-proc",
			"--",
			bin,
		}
		full = append(full, args...)
		primitive := s.primitiveArg(alloc)
		cmd = exec.CommandContext(ctx, primitive, full...) // govratchet:exec-allow(production_launch_factory) -- primitive is s.primitiveHandle's own held, already-verified descriptor via /proc/self/fd/<n>, never a reopened pathname
		cmd.Env = controllerenv.Base()
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	default: // scopeDegraded
		cmd = exec.CommandContext(ctx, bin, args...) // govratchet:exec-allow(production_launch_factory) -- bin is already the caller's verified/sealed path
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	cmd.Dir = dir
	return cmd
}

// primitiveArg returns the /proc/self/fd/<n> argv form of s.primitiveHandle's
// held, already-verified descriptor via alloc, for CommandWith's
// descriptor-backed primitive launch (Sol11 P0-5). On any failure to obtain
// a usable descriptor it returns a fixed, guaranteed-nonexistent path so the
// resulting exec.Cmd fails closed at Start() rather than falling back to a
// mutable pathname -- mirroring sealPrimitive's own fail-closed contract.
func (s *Scope) primitiveArg(alloc *toolregistry.FDAllocator) string {
	const failClosedPath = "/nonexistent/governator-sealed-primitive-unavailable"
	if s.primitiveHandle == nil {
		return failClosedPath
	}
	f := s.primitiveHandle.File()
	if f == nil {
		return failClosedPath
	}
	return alloc.Arg(f)
}

// sealPrimitive seals s.primitiveHandle's held, verified bytes into a fresh
// private copy, re-verifies that copy immediately, and returns its path --
// see Command's doc comment. On any failure it returns a fixed,
// guaranteed-nonexistent path so the resulting exec.Cmd fails closed at
// Start() rather than falling back to a mutable pathname; s.sealedPrimitive
// is left nil in that case, so Extinguish has nothing to close.
func (s *Scope) sealPrimitive() string {
	const failClosedPath = "/nonexistent/governator-sealed-primitive-unavailable"
	if s.primitiveHandle == nil {
		return failClosedPath
	}
	sealed, err := s.primitiveHandle.SealedExecutablePath()
	if err != nil {
		return failClosedPath
	}
	if err := sealed.Verify(); err != nil {
		_ = sealed.Close()
		return failClosedPath
	}
	s.sealedPrimitive = sealed
	return sealed.Path
}

// Started must be called with the outer-namespace PID immediately after a
// successful Start() on the *exec.Cmd Command produced. It resolves the
// exact cgroup path (systemd assigns it asynchronously via its own IPC to
// the manager, so this polls briefly) or the PID-namespace's init PID, so
// Extinguish has something concrete to act on.
//
// rc4 Session 2 (Sol10 P0-2): this used to close s.primitiveHandle here, on
// the reasoning that Start() had already dup'd the descriptor into the
// child so the parent's copy was no longer needed. That was correct when
// each Scope owned a freshly, independently resolved handle -- it is wrong
// now that primitiveHandle is BORROWED from the run's shared
// ContainmentEnvironment (every stage's own Scope launches through the same
// held descriptor across the run's whole lifetime); closing it here would
// close it out from under every later stage still to launch. Ownership of
// closing belongs solely to whoever resolved the ContainmentEnvironment
// (ResolveEnvironment's caller), once, after the run finishes.
func (s *Scope) Started(pid int) {
	s.mu.Lock()
	s.pid = pid
	s.mu.Unlock()
	switch s.method {
	case ScopeSystemdUserScope:
		s.resolveCgroupFromPID(pid)
	case ScopePIDNamespace:
		s.resolveNSInitPID(pid)
	}
}

func (s *Scope) resolveCgroupFromPID(pid int) {
	// Sol14 S9a: deterministic "unit registered but never materialized" seam.
	// Fires before the observation loop, producing the identical resolveErr the
	// loop sets when its deadline expires with the unit unconfirmed.
	if UnitMaterializationForceUnobservedForTesting.Load() {
		s.mu.Lock()
		s.resolveErr = fmt.Errorf("containment: generated systemd unit %q was never confirmed for pid %d; observed cgroup %q is not accepted as a fallback kill target", s.unitName, pid, "")
		s.mu.Unlock()
		return
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		path, err := cgroupPathForPID(pid)
		if err == nil && strings.Contains(path, s.unitName) {
			s.mu.Lock()
			s.cgroupPath = path
			s.mu.Unlock()
			return
		}
		if time.Now().After(deadline) {
			s.mu.Lock()
			if err == nil {
				s.resolveErr = fmt.Errorf("containment: generated systemd unit %q was never confirmed for pid %d; observed cgroup %q is not accepted as a fallback kill target", s.unitName, pid, path)
			} else {
				s.resolveErr = err
			}
			s.mu.Unlock()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *Scope) resolveNSInitPID(outerPid int) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		children, err := directChildren(outerPid)
		if err == nil && len(children) > 0 {
			s.mu.Lock()
			s.nsInitPid = children[0]
			s.mu.Unlock()
			return
		}
		if time.Now().After(deadline) {
			s.mu.Lock()
			s.resolveErr = fmt.Errorf("containment: pid namespace init for outer pid %d was never identified", outerPid)
			s.mu.Unlock()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Extinguish is the DESCENDANTS_TERMINATED lifecycle stage: freeze the scope
// so no new descendant is accepted, kill the whole owned tree, block until
// the kernel confirms zero surviving processes (bounded by deadline -- a
// timeout is a hard failure, never treated as "probably fine"), and finally
// scan every process's open file descriptors for a handle into workspacePath
// as an independent check that nothing escaped the primitive itself. The
// returned Proof is recorded on the run whether or not err is nil; a non-nil
// err means the run must not proceed to final-state capture.
func (s *Scope) Extinguish(ctx context.Context, deadline time.Duration, workspacePath string) (Proof, error) {
	if deadline <= 0 {
		deadline = DefaultExtinctionDeadline
	}
	// rc4 Session 2 (Sol10 P0-2): this used to close s.primitiveHandle in a
	// deferred cleanup here. Wrong for the same reason Started's doc comment
	// gives -- the handle is borrowed from the run's shared
	// ContainmentEnvironment, not owned by this Scope. s.sealedPrimitive
	// (Command's private sealed copy, see its doc comment), by contrast, IS
	// owned by this Scope -- close it once the launched process this
	// Extinguish call confirms dead can no longer need it.
	defer func() {
		s.mu.Lock()
		sealed := s.sealedPrimitive
		s.sealedPrimitive = nil
		s.mu.Unlock()
		if sealed != nil {
			_ = sealed.Close()
		}
	}()
	start := time.Now()
	proof := Proof{Method: s.method, ProcessesObservedPeak: -1}

	// Sol12 rc5 Session 2 (P0-1): test-only readiness gate. When set, block
	// here until the fixture confirms a descendant reached the state this
	// Extinguish is meant to act on (e.g. an uninterruptible blocking read),
	// so extinction can never fire before that state is reached -- the
	// explicit synchronization primitive that replaces TestV7Case8's timing
	// assumption. A non-nil gate error propagates without killing, surfacing a
	// genuine host-capability gap (a kernel that kills FUSE-blocked readers)
	// as a deterministic refusal rather than a post-hoc timeout skip.
	if gate := ExtinguishGateForTesting; gate != nil {
		if err := gate(); err != nil {
			return proof, fmt.Errorf("containment: pre-extinction readiness gate failed: %w", err)
		}
	}

	// relevant scopes scanWorkspaceFD's post-extinction sweep (Sol11 P1-3)
	// to processes this specific Extinguish call can actually attribute to
	// the scope it just tore down -- set in exactly one branch below,
	// before scanWorkspaceFD is called. See scanWorkspaceFD's doc comment
	// for why an unattributable process is out of scope entirely (never
	// fails closed) while an attributable-but-unreadable one does.
	var relevant func(pid int) bool

	switch s.method {
	case ScopeSystemdUserScope, ScopeCgroupDirect:
		s.mu.Lock()
		cg := s.cgroupPath
		rerr := s.resolveErr
		s.mu.Unlock()
		relevant = func(pid int) bool {
			if cg == "" {
				return false
			}
			p, perr := cgroupPathForPID(pid)
			return perr == nil && p == cg
		}
		if cg == "" {
			if rerr != nil {
				return proof, fmt.Errorf("containment: scope cgroup was never resolved: %w", rerr)
			}
			// Nothing was ever started in this scope (e.g. the run budget
			// was already exhausted before launch) -- vacuously nothing to
			// freeze or kill.
			proof.Frozen, proof.Killed = true, true
			proof.ProcessesObservedPeak = 0
		} else {
			if err := writeCgroupFile(cg, "cgroup.freeze", "1"); cgroupGone(err) {
				proof.Frozen = true
			} else {
				return proof, fmt.Errorf("containment: freeze failed: %w", err)
			}
			// Read cgroup.procs right after freeze (no new descendant can be
			// accepted from here on) and before kill -- the kernel's own
			// count of every PID this launch ever spawned that was still
			// alive at the extinction boundary, fed into the effect ledger
			// (Sol P1-15) independent of whatever the backend's transcript
			// claims about its own process creation. Best effort: a failed
			// read here does not block extinction, it only leaves the count
			// unobserved (-1).
			if n, cerr := countCgroupProcs(cg); cerr == nil {
				proof.ProcessesObservedPeak = n
			}
			if err := writeCgroupFile(cg, "cgroup.kill", "1"); cgroupGone(err) {
				proof.Killed = true
			} else {
				return proof, fmt.Errorf("containment: kill failed: %w", err)
			}
			if err := waitCgroupEmpty(cg, deadline); err != nil {
				return proof, fmt.Errorf("containment: descendant extinction not confirmed within %s: %w", deadline, err)
			}
			_ = os.Remove(cg) // best effort; systemd/the kernel usually already reclaimed it
		}
		if s.cgroupFile != nil {
			_ = s.cgroupFile.Close()
		}
	case ScopePIDNamespace:
		s.mu.Lock()
		target := s.nsInitPid
		pid := s.pid
		rerr := s.resolveErr
		s.mu.Unlock()
		// Descendant set rooted at whichever of target/pid actually
		// identifies this scope: a namespace init's orphaned children
		// reparent to it (namespace membership, not process-group games,
		// is what makes escape structurally impossible here), so a
		// transitive child-set walk from the root still finds them.
		root := target
		if root == 0 {
			root = pid
		}
		relevant = descendantSetPredicate(root)
		if pid != 0 && target == 0 {
			if err := waitPIDGone(pid, 0); err == nil {
				proof.Killed = true
				proof.Frozen = true
				break
			}
			if rerr != nil {
				return proof, rerr
			}
			return proof, fmt.Errorf("containment: pid namespace init was never identified and outer pid %d is still present or indeterminate", pid)
		}
		if target != 0 {
			_ = syscall.Kill(target, syscall.SIGKILL)
			proof.Killed = true
			if err := waitPIDGone(target, deadline); err != nil {
				return proof, fmt.Errorf("containment: pid namespace extinction not confirmed within %s: %w", deadline, err)
			}
		} else {
			proof.Killed = true // nothing was ever started
		}
		// Freezing has no standalone meaning without a cgroup, but namespace
		// confinement means no descendant can be accepted from outside once
		// its init is gone -- recorded true to reflect that guarantee.
		proof.Frozen = true
	default: // scopeDegraded
		s.mu.Lock()
		pid := s.pid
		s.mu.Unlock()
		if pid != 0 {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
		// Process-group membership, matching the Kill(-pid) primitive this
		// degraded fallback actually uses -- deliberately not a transitive
		// descendant walk, since this scope's own documented limitation is
		// exactly that it does not cover a setsid/double-fork escape out of
		// the group; the fd scan should not silently claim coverage this
		// primitive was never able to provide.
		relevant = func(candidate int) bool {
			if pid == 0 {
				return false
			}
			pgid, perr := syscall.Getpgid(candidate)
			return perr == nil && pgid == pid
		}
		proof.Degraded = true
		proof.Note = "no descendant-owning primitive was available; fell back to process-group kill, which does not cover setsid/double-fork escapes"
	}

	clean, err := scanWorkspaceFD(workspacePath, relevant)
	if err != nil {
		return proof, fmt.Errorf("containment: workspace fd scan failed: %w", err)
	}
	proof.WorkspaceFDScanClean = clean
	proof.Waited = time.Since(start)
	if !clean {
		return proof, fmt.Errorf("containment: a surviving process still holds an open handle into the workspace after extinction")
	}
	return proof, nil
}

func writeCgroupFile(cg, name, value string) error {
	return os.WriteFile(filepath.Join(cg, name), []byte(value), 0)
}

// countCgroupProcs reads the number of PIDs currently listed in cg's
// cgroup.procs -- used once, right after freeze, as the effect ledger's
// externally observed process-creation count for this scope.
func countCgroupProcs(cg string) (int, error) {
	data, err := os.ReadFile(filepath.Join(cg, "cgroup.procs"))
	if err != nil {
		if cgroupGone(err) {
			return 0, nil
		}
		return 0, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return 0, nil
	}
	return len(strings.Fields(trimmed)), nil
}

func waitCgroupEmpty(cg string, deadline time.Duration) error {
	end := time.Now().Add(deadline)
	for {
		data, err := os.ReadFile(filepath.Join(cg, "cgroup.procs"))
		if err != nil {
			if cgroupGone(err) {
				return nil
			}
			return err
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			return nil
		}
		if time.Now().After(end) {
			return fmt.Errorf("cgroup.procs still lists processes: %s", strings.Fields(string(data)))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitPIDGone(pid int, deadline time.Duration) error {
	if pid == 0 {
		return nil
	}
	end := time.Now().Add(deadline)
	for {
		if err := syscall.Kill(pid, 0); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			if errors.Is(err, syscall.EPERM) {
				return fmt.Errorf("pid %d still exists but is not signalable (EPERM)", pid)
			}
			return fmt.Errorf("pid %d existence check indeterminate: %w", pid, err)
		}
		if time.Now().After(end) {
			return fmt.Errorf("pid %d still alive", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// scanWorkspaceFD walks every visible process's /proc/<pid>/fd and cwd for a
// handle into workspacePath, independent of which containment primitive was
// used. This is the plan's defense-in-depth check: it catches a descendant
// that somehow survived the primitive itself, not just a descendant the
// primitive never knew about.
//
// scanWorkspaceFD sweeps /proc for any process still holding an open file
// descriptor or cwd into workspacePath after extinction. relevant reports
// whether a candidate pid is attributable to the scope Extinguish just tore
// down (governed cgroup membership, pid-namespace descendant set, or
// process-group membership -- see the three call sites in Extinguish).
//
// Sol11 P1-3: before this session, ANY error reading /proc/<pid>/fd -- the
// process having genuinely exited, a permission/hidepid restriction, or any
// other indeterminate condition -- was silently treated the same as "this
// process holds nothing," i.e. clean. That conflated "checked and clean"
// with "could not check" for a governed process, which is exactly the
// unsafe direction to guess in a proof that gates DESCENDANTS_TERMINATED.
// The fix has two parts:
//
//  1. relevant scopes the sweep to processes this call can actually
//     attribute to the just-torn-down scope. A process this proof cannot
//     attribute to the scope at all is out of scope for it entirely --
//     Governator never claimed to police every process on the host, only
//     the ones belonging to what it just launched and killed -- so it is
//     silently skipped, exactly as before, with no fail-closed penalty.
//  2. For a relevant process, a read failure is no longer collapsed into
//     one case: confirmed disappearance (ENOENT: the process was reaped
//     between the /proc listing and this read) still means absent, but any
//     other error (EACCES/EPERM from hidepid or similar, or anything else
//     unexpected) is indeterminate and now fails the scan closed -- this
//     function returns an error instead of silently continuing, so the
//     caller's WorkspaceFDScanClean can never read true over a process it
//     was unable to actually check.
func scanWorkspaceFD(workspacePath string, relevant func(pid int) bool) (bool, error) {
	if workspacePath == "" {
		return true, nil
	}
	abs, err := filepath.Abs(workspacePath)
	if err != nil {
		return false, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, err
	}
	self := os.Getpid()
	for _, e := range entries {
		pid, convErr := strconv.Atoi(e.Name())
		if convErr != nil || pid == self {
			// Governator's own control-plane process is trusted by
			// definition and may legitimately hold handles near the
			// workspace (e.g. its own cwd); this scan is only meaningful
			// for processes other than the one performing it.
			continue
		}
		if relevant == nil || !relevant(pid) {
			// Not attributable to this launch's governed scope: out of
			// scope for this proof (see doc comment above), not a
			// clean/indeterminate observation about it either way.
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, readErr := os.ReadDir(fdDir)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				// Confirmed gone between the /proc listing and this read --
				// nothing left to hold a handle.
				continue
			}
			return false, fmt.Errorf("pid %d belongs to this scope but its open file descriptors could not be read (indeterminate, not confirmed absent): %w", pid, readErr)
		}
		for _, fd := range fds {
			target, linkErr := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if linkErr != nil {
				continue
			}
			if target == abs || strings.HasPrefix(target, abs+string(filepath.Separator)) {
				return false, nil
			}
		}
		if cwd, cwdErr := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); cwdErr == nil {
			if cwd == abs || strings.HasPrefix(cwd, abs+string(filepath.Separator)) {
				return false, nil
			}
		}
	}
	return true, nil
}

// descendantSetPredicate returns a membership predicate over root and every
// transitive descendant of root, discovered via /proc/<pid>/task/<pid>/
// children (directChildren). Bounded (maxDescendantSetNodes) so a
// pathological fork bomb inside the namespace cannot make an extinction
// proof hang. root == 0 (no process was ever identified for this scope)
// always returns false -- there is nothing to attribute.
func descendantSetPredicate(root int) func(pid int) bool {
	if root == 0 {
		return func(int) bool { return false }
	}
	const maxDescendantSetNodes = 4096
	seen := map[int]bool{root: true}
	queue := []int{root}
	for len(queue) > 0 && len(seen) < maxDescendantSetNodes {
		next := queue[0]
		queue = queue[1:]
		children, err := directChildren(next)
		if err != nil {
			continue
		}
		for _, c := range children {
			if !seen[c] {
				seen[c] = true
				queue = append(queue, c)
			}
		}
	}
	return func(pid int) bool { return seen[pid] }
}

func cgroupPathForPID(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			rel := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
			if rel == "" {
				continue
			}
			return filepath.Join("/sys/fs/cgroup", rel), nil
		}
	}
	return "", fmt.Errorf("containment: no cgroup v2 (0::) entry for pid %d", pid)
}

func directChildren(pid int) ([]int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(data))
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		if n, convErr := strconv.Atoi(f); convErr == nil {
			out = append(out, n)
		}
	}
	return out, nil
}
