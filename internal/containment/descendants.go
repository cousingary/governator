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
	"syscall"
	"time"

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
	// primitivePath is the trusted-tool registry's verified canonical path
	// to this Scope's underlying primitive binary (systemd-run for
	// ScopeSystemdUserScope, unshare for ScopePIDNamespace) -- resolved
	// once when the Scope is constructed and used by Command instead of a
	// bare argv0 os/exec would resolve via ambient PATH (Session 2,
	// post-v4 hardening plan item C). Unused for ScopeCgroupDirect/
	// scopeDegraded, which never exec a controller-tool binary of their own.
	primitivePath string

	mu         sync.Mutex
	pid        int // outer-namespace pid of the launched wrapper/process
	nsInitPid  int // ScopePIDNamespace only: the fork()'d PID-1-of-namespace child
	cgroupPath string
	resolveErr error

	cgroupFile *os.File // ScopeCgroupDirect only; keeps the dir fd alive for CLONE_INTO_CGROUP
}

// NewScope selects the strongest descendant-owning primitive available on
// this host, in the order the plan specifies: systemd --user transient
// scope, then a directly managed cgroup v2 subtree, then a PID namespace.
// highRisk contracts refuse outright when none qualifies rather than
// silently falling back to a bare process group.
func NewScope(runID string, highRisk bool) (*Scope, error) {
	if s, err := newSystemdUserScope(runID); err == nil {
		return s, nil
	}
	if s, err := newDirectCgroupScope(runID); err == nil {
		return s, nil
	}
	if s, err := newPIDNamespaceScope(runID); err == nil {
		return s, nil
	}
	if highRisk {
		return nil, fmt.Errorf("containment: no descendant-owning primitive available (tried systemd --user scope, direct cgroup v2, PID namespace); refusing high-risk run rather than degrading to a bare process group")
	}
	return &Scope{method: scopeDegraded, runID: runID}, nil
}

// Method reports which primitive this Scope actually uses.
func (s *Scope) Method() ScopeMethod { return s.method }

func newSystemdUserScope(runID string) (*Scope, error) {
	identity, err := toolregistry.ResolveTrusted("systemd-run", "systemd-run")
	if err != nil {
		return nil, fmt.Errorf("containment: resolve trusted systemd-run: %w", err)
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil, fmt.Errorf("containment: systemd is not PID 1 (no /run/systemd/system): %w", err)
	}
	return &Scope{
		method:        ScopeSystemdUserScope,
		runID:         runID,
		unitName:      "governator-" + sanitizeName(runID) + "-" + nonce(),
		primitivePath: identity.CanonicalPath,
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

func newDirectCgroupScope(runID string) (*Scope, error) {
	self, err := cgroupPathForPID(os.Getpid())
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(self, "governator-"+sanitizeName(runID)+"-"+nonce()+".scope")
	if err := os.Mkdir(dir, 0755); err != nil {
		return nil, fmt.Errorf("containment: direct cgroup unavailable: %w", err)
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

func newPIDNamespaceScope(runID string) (*Scope, error) {
	identity, err := toolregistry.ResolveTrusted("unshare", "unshare")
	if err != nil {
		return nil, fmt.Errorf("containment: resolve trusted unshare: %w", err)
	}
	return &Scope{method: ScopePIDNamespace, runID: runID, primitivePath: identity.CanonicalPath}, nil
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
		cmd = exec.CommandContext(ctx, s.primitivePath, full...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	case ScopeCgroupDirect:
		cmd = exec.CommandContext(ctx, bin, args...)
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
		cmd = exec.CommandContext(ctx, s.primitivePath, full...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	default: // scopeDegraded
		cmd = exec.CommandContext(ctx, bin, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	cmd.Dir = dir
	return cmd
}

// Started must be called with the outer-namespace PID immediately after a
// successful Start() on the *exec.Cmd Command produced. It resolves the
// exact cgroup path (systemd assigns it asynchronously via its own IPC to
// the manager, so this polls briefly) or the PID-namespace's init PID, so
// Extinguish has something concrete to act on.
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
				// Process is alive but never joined the expected unit --
				// record whatever cgroup it actually landed in so
				// Extinguish still has a real target instead of trusting an
				// empty path.
				s.cgroupPath = path
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
			return // best effort; Extinguish falls back to the outer pid
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
	start := time.Now()
	proof := Proof{Method: s.method, ProcessesObservedPeak: -1}

	switch s.method {
	case ScopeSystemdUserScope, ScopeCgroupDirect:
		s.mu.Lock()
		cg := s.cgroupPath
		rerr := s.resolveErr
		s.mu.Unlock()
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
		if target == 0 {
			target = s.pid
		}
		s.mu.Unlock()
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
		proof.Degraded = true
		proof.Note = "no descendant-owning primitive was available; fell back to process-group kill, which does not cover setsid/double-fork escapes"
	}

	clean, err := scanWorkspaceFD(workspacePath)
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
			return nil // ESRCH: gone
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
func scanWorkspaceFD(workspacePath string) (bool, error) {
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
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, readErr := os.ReadDir(fdDir)
		if readErr != nil {
			continue // process exited between ReadDir(/proc) and here, or not readable by us
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
