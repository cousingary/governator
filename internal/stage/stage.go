// Package stage is Governator's common subprocess launch envelope. External
// helper stages use this executor so they share the same lifecycle: resolve an
// executable, freeze an environment, launch inside a descendant-owning scope,
// wait, prove descendant extinction, and return auditable execution evidence.
package stage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/toolregistry"
)

type ExecutableIdentity struct {
	CanonicalPath string `json:"canonical_path"`
	SHA256        string `json:"sha256,omitempty"`
}

type FrozenEnvironment struct {
	Values []string `json:"values"`
	Hash   string   `json:"hash"`
}

type NetworkPolicy string

const (
	NetworkPolicyUnspecified NetworkPolicy = "unspecified"
	NetworkPolicyDenied      NetworkPolicy = "deny"
	NetworkPolicyAllowed     NetworkPolicy = "allow"
)

type CredentialPolicy string

const (
	CredentialPolicyNone     CredentialPolicy = "none"
	CredentialPolicyDeclared CredentialPolicy = "declared"
)

type DescendantPolicy struct {
	RequireStrong bool `json:"require_strong"`
}

type StageAuthority struct {
	ReadRoots          []string         `json:"read_roots,omitempty"`
	WriteRoots         []string         `json:"write_roots,omitempty"`
	Network            NetworkPolicy    `json:"network,omitempty"`
	Credentials        CredentialPolicy `json:"credentials,omitempty"`
	RequireStrongScope bool             `json:"require_strong_scope,omitempty"`
	// ROBinds are read-only bind-mount requirements this stage's own
	// compiled enforce.Plan must carry (Sol10 P0-1). internal/stage.Executor
	// always launches host-side, through its OWN freshly compiled Plan,
	// regardless of whether the run's backend used a docker container or
	// Governator's local enforce wrap -- so a validator that reads a
	// consumed artifact staged externally needs this set explicitly by the
	// caller (runtime.go), never inherited from the backend's own plan.
	ROBinds []enforce.ROBind `json:"-"`
}

func (a StageAuthority) RequiresExternalEnforcement() bool {
	return len(a.ReadRoots) > 0 || len(a.WriteRoots) > 0 || a.Network == NetworkPolicyDenied || a.Credentials == CredentialPolicyNone || len(a.ROBinds) > 0
}

type OutputCaptureMode string

const (
	CaptureUnspecified      OutputCaptureMode = ""
	CaptureNone             OutputCaptureMode = "none"
	CaptureBounded          OutputCaptureMode = "bounded"
	CaptureRequiredComplete OutputCaptureMode = "required_complete"
)

var ErrOutputLimitExceeded = errors.New("STAGE_OUTPUT_LIMIT_EXCEEDED")

// EffectLedger mirrors observability.EnforcementRecord's three-evidence-class
// split (Sol9 P1-5) at the per-stage granularity: declared authority
// (DeclaredNetworkPolicy, DeclaredWriteRoots, DeclaredCredentialPolicy),
// applied enforcement (EnforcedNetworkPolicy, NetworkDenialMechanism,
// KernelReadEnvelope, LandlockABI), and observed effects (ActualWriteSet,
// PeakProcessCount, ObservedCredentialAccess, OutputConsequence,
// NetworkAttemptObservation). ActualWriteSet is populated by snapshotting
// every declared write root immediately before launch and reconciling
// against the same roots after the scope is extinguished -- a real
// before/after diff, not the declared roots restated as if observed.
type EffectLedger struct {
	ScopeMethod               string   `json:"scope_method,omitempty"`
	WorkspaceFDScanClean      bool     `json:"workspace_fd_scan_clean"`
	LandlockABI               int      `json:"landlock_abi,omitempty"`
	KernelReadEnvelope        []string `json:"kernel_read_envelope,omitempty"`
	DeclaredNetworkPolicy     string   `json:"declared_network_policy,omitempty"`
	EnforcedNetworkPolicy     string   `json:"enforced_network_policy,omitempty"`
	NetworkAttemptObservation string   `json:"network_attempt_observation,omitempty"`
	NetworkDenialMechanism    string   `json:"network_denial_mechanism,omitempty"`
	DeclaredWriteRoots        []string `json:"declared_write_roots,omitempty"`
	ActualWriteSet            []string `json:"actual_write_set,omitempty"`
	DeclaredCredentialPolicy  string   `json:"declared_credential_policy,omitempty"`
	ObservedCredentialAccess  string   `json:"observed_credential_access,omitempty"`
	PeakProcessCount          int      `json:"peak_process_count,omitempty"`
	OutputConsequence         string   `json:"output_consequence,omitempty"`
}

// CommandFactory lets callers with already-sealed launch logic build the exact
// *exec.Cmd while still receiving the scope the stage executor owns, plus the
// stage's EnforcementPlan so a handle-aware caller can compose the wrap
// AROUND its resolved (sealed/fd) launch target rather than having Run
// pre-wrap a bin/args pair that the caller is about to replace anyway (Sol
// redteam v7 HS2: the sealed-executable handle discarding the enforce wrap).
type CommandFactory func(ctx context.Context, scope *containment.Scope, plan enforce.Plan, bin string, args []string, dir string) (*exec.Cmd, error)

type StageSpec struct {
	RunID, StageID   string
	Executable       ExecutableIdentity
	Arguments        []string
	WorkingDirectory string
	Environment      FrozenEnvironment
	ReadRoots        []string
	WriteRoots       []string
	NetworkPolicy    NetworkPolicy
	CredentialPolicy CredentialPolicy
	Timeout          time.Duration
	OutputLimit      int64
	OutputCapture    OutputCaptureMode
	DescendantPolicy DescendantPolicy
	Authority        StageAuthority
	EnforcementPlan  enforce.Plan
	Stdin            io.Reader
	Stdout           io.Writer
	Stderr           io.Writer
	CommandFactory   CommandFactory
	ExecutableHandle *toolregistry.Handle
}

type StageResult struct {
	ExitStatus         int                `json:"exit_status"`
	ExecutableIdentity ExecutableIdentity `json:"executable_identity"`
	EnvironmentHash    string             `json:"environment_hash"`
	ObservedEffects    EffectLedger       `json:"observed_effects"`
	OutputTruncated    bool               `json:"output_truncated"`
	DescendantsGone    bool               `json:"descendants_gone"`
	Output             string             `json:"output,omitempty"`
}

type Executor struct{}

func NewExecutor() Executor { return Executor{} }

const waitAfterKillDeadline = 2 * time.Second

func (Executor) Run(ctx context.Context, spec StageSpec) (StageResult, error) {
	if strings.TrimSpace(spec.RunID) == "" {
		return StageResult{}, fmt.Errorf("stage: missing run id")
	}
	if strings.TrimSpace(spec.StageID) == "" {
		return StageResult{}, fmt.Errorf("stage: missing stage id")
	}
	if strings.TrimSpace(spec.Executable.CanonicalPath) == "" {
		return StageResult{}, fmt.Errorf("stage: missing executable path")
	}
	if spec.Environment.Values == nil {
		return StageResult{}, fmt.Errorf("stage: missing frozen environment")
	}
	if spec.Environment.Hash == "" || spec.Environment.Hash != controllerenv.Hash(spec.Environment.Values) {
		return StageResult{}, fmt.Errorf("stage: frozen environment hash mismatch")
	}
	captureMode := spec.OutputCapture
	if captureMode == CaptureUnspecified {
		captureMode = CaptureRequiredComplete
	}
	switch captureMode {
	case CaptureNone, CaptureBounded, CaptureRequiredComplete:
	default:
		return StageResult{}, fmt.Errorf("stage: unknown output capture mode %q", captureMode)
	}
	if captureMode != CaptureNone && spec.OutputLimit <= 0 {
		return StageResult{}, fmt.Errorf("stage: output limit required for capture mode %q", captureMode)
	}
	authority := spec.Authority
	authorityNetworkDeclared := authority.Network != "" && authority.Network != NetworkPolicyUnspecified
	specNetworkDeclared := spec.NetworkPolicy != "" && spec.NetworkPolicy != NetworkPolicyUnspecified
	hasAuthority := len(authority.ReadRoots) > 0 || len(authority.WriteRoots) > 0 || authorityNetworkDeclared || authority.Credentials != "" || authority.RequireStrongScope || len(spec.ReadRoots) > 0 || len(spec.WriteRoots) > 0 || specNetworkDeclared || spec.CredentialPolicy != ""
	if hasAuthority {
		if len(authority.ReadRoots) == 0 {
			authority.ReadRoots = append([]string(nil), spec.ReadRoots...)
		}
		if len(authority.WriteRoots) == 0 {
			authority.WriteRoots = append([]string(nil), spec.WriteRoots...)
		}
		if authority.Network == NetworkPolicyUnspecified {
			authority.Network = spec.NetworkPolicy
		}
		if authority.Network == NetworkPolicyUnspecified {
			authority.Network = NetworkPolicyDenied
		}
		if authority.Credentials == "" {
			authority.Credentials = spec.CredentialPolicy
		}
		if authority.Credentials == "" {
			authority.Credentials = CredentialPolicyNone
		}
	}
	if authority.RequireStrongScope && !spec.DescendantPolicy.RequireStrong {
		return StageResult{}, fmt.Errorf("stage: authority requires strong descendant scope")
	}
	if hasAuthority && spec.ExecutableHandle == nil && spec.CommandFactory == nil {
		return StageResult{}, fmt.Errorf("stage: authority-bearing stages require an executable handle or sealed command factory")
	}
	effectivePlan := spec.EnforcementPlan
	var err error
	if hasAuthority {
		if authority.RequiresExternalEnforcement() {
			compiledPlan, cerr := enforce.NewPlanForExecutable(true, spec.WorkingDirectory, true, authority.Network == NetworkPolicyAllowed, true, spec.Executable.CanonicalPath, authority.ReadRoots)
			if cerr != nil {
				return StageResult{}, fmt.Errorf("stage: construct authority plan: %w", cerr)
			}
			compiledPlan = compiledPlan.WithReadOnlyBinds(authority.ROBinds...)
			// Sol v9 P0-1/P0-2: compiledPlan may hold open descriptors (see
			// enforce.Plan.Close's doc comment) -- release them once this
			// stage's launch (below, still within this Run call) has
			// started.
			defer func() { _ = compiledPlan.Close() }()
			if effectivePlan.Active {
				if authority.Network == NetworkPolicyDenied && effectivePlan.AllowNetwork {
					return StageResult{}, fmt.Errorf("stage: authority denies network but plan allows it")
				}
				if authority.Network == NetworkPolicyAllowed && !effectivePlan.AllowNetwork {
					return StageResult{}, fmt.Errorf("stage: authority allows network but plan denies it")
				}
				if !effectivePlan.ReadOnly {
					return StageResult{}, fmt.Errorf("stage: authoritative stages require a read-only base plan plus explicit write roots")
				}
				if effectivePlan.Workspace != "" && compiledPlan.Workspace != "" && filepath.Clean(effectivePlan.Workspace) != filepath.Clean(compiledPlan.Workspace) {
					return StageResult{}, fmt.Errorf("stage: authority workspace %q contradicts supplied plan workspace %q", compiledPlan.Workspace, effectivePlan.Workspace)
				}
			}
			effectivePlan = compiledPlan
			if len(authority.WriteRoots) > 0 {
				writeDirs := make([]string, 0, len(authority.WriteRoots))
				writeFiles := make([]string, 0, len(authority.WriteRoots))
				for _, root := range authority.WriteRoots {
					abs, aerr := filepath.Abs(root)
					if aerr != nil {
						return StageResult{}, fmt.Errorf("stage: resolve write root %q: %w", root, aerr)
					}
					info, serr := os.Stat(abs)
					if serr != nil {
						return StageResult{}, fmt.Errorf("stage: stat write root %q: %w", root, serr)
					}
					if info.IsDir() {
						writeDirs = append(writeDirs, abs)
					} else {
						writeFiles = append(writeFiles, abs)
					}
				}
				effectivePlan = effectivePlan.WithWriteRoots(writeDirs, writeFiles)
			}
		} else if effectivePlan.Active {
			return StageResult{}, fmt.Errorf("stage: authority does not require an external sandbox but supplied plan is active")
		}
	} else {
		effectivePlan, err = spec.EnforcementPlan.WithExecutableAndReadRoots(spec.Executable.CanonicalPath, spec.ReadRoots...)
		if err != nil {
			return StageResult{}, fmt.Errorf("stage: resolve read policy: %w", err)
		}
	}
	if spec.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}
	// Sol9 P1-5: snapshot every declared write root before launch so
	// ActualWriteSet below is a real before/after reconciliation rather than
	// the declared roots restated as if they were observed.
	writeSnapshotBefore := snapshotWriteRoots(effectivePlan.WriteDirs, effectivePlan.WriteFiles)
	// containmentEnv (rc4 Session 2, Sol10 P0-2): the run's frozen
	// ContainmentEnvironment, resolved exactly once by runOnce
	// (buildRunEnvironment) and threaded here via ctx
	// (containment.WithEnvironment) rather than a StageSpec field -- every
	// launch reached FROM A GOVERNED RUN (shellStage for validators/
	// cleanup/Assayer, agents.LaunchStaged for the backend) has ctx already
	// carrying it, so systemd-run/unshare never diverge from what the run's
	// replay identity described.
	//
	// ok is false for a caller that never went through runOnce at all --
	// internal/assay.Evaluate is invoked directly with context.Background()
	// (both by governed Assayer stages AND by standalone callers/tests with
	// no concept of a run or replay identity to freeze anything against),
	// and gov doctor probes/direct package tests are the same shape. Such a
	// caller resolves its own environment here, scoped to just this one
	// launch -- this intentionally re-loads the registry per call, exactly
	// like every stage did before this session, but that reload is no
	// longer a defect for a caller with no frozen replay identity for it to
	// diverge from; it only mattered for the once-per-run governed path
	// above, which this fallback never touches.
	containmentEnv, ok := containment.EnvironmentFromContext(ctx)
	if !ok {
		if registry, rerr := toolregistry.Load(); rerr == nil {
			if resolved, eerr := containment.ResolveEnvironment(registry); eerr == nil {
				containmentEnv = resolved
				defer func() { _ = resolved.Close() }()
			}
		}
	}
	scope, err := containment.NewScope(spec.RunID+"-"+spec.StageID+"-"+nonce(), spec.DescendantPolicy.RequireStrong, containmentEnv)
	if err != nil {
		return StageResult{}, err
	}
	bin := spec.Executable.CanonicalPath
	args := append([]string(nil), spec.Arguments...)
	factory := spec.CommandFactory
	// sealedCopy (Sol9 P1-4) is set inside the factory below when it seals
	// spec.ExecutableHandle's bytes to a real path for the enforced-plan
	// branch. It must stay open on disk for as long as the launched
	// process can reference it by that path, so it is only closed here,
	// after this Run call's process has fully finished -- not inside the
	// factory closure itself.
	var sealedCopy *toolregistry.SealedCopy
	defer func() {
		if sealedCopy != nil {
			_ = sealedCopy.Close()
		}
	}()
	if factory == nil && spec.ExecutableHandle != nil {
		factory = func(c context.Context, s *containment.Scope, p enforce.Plan, b string, a []string, d string) (*exec.Cmd, error) {
			if p.Active {
				sealed, err := spec.ExecutableHandle.SealedExecutablePath()
				if err != nil {
					return nil, err
				}
				sealedCopy = sealed
				// Sol9 P1-4: re-verify the published copy immediately
				// before it is referenced by path below -- a private
				// read-only copy is not kernel-immutable, so this is the
				// last point Governator can catch a same-UID tamper
				// before launch.
				if verr := sealed.Verify(); verr != nil {
					return nil, fmt.Errorf("verify sealed executable before launch: %w", verr)
				}
				extended, err := p.WithExecutableAndReadRoots(sealed.Path, filepath.Dir(sealed.Path))
				if err != nil {
					return nil, err
				}
				wb, wa, wf := extended.Wrap(sealed.Path, a)
				cmd := s.Command(c, wb, wa, d)
				cmd.ExtraFiles = append(cmd.ExtraFiles, wf...)
				return cmd, nil
			}
			return spec.ExecutableHandle.CommandWith(c, a, func(cc context.Context, sealed string, sealedArgs []string) *exec.Cmd {
				return s.Command(cc, sealed, sealedArgs, d)
			})
		}
	}
	if factory == nil {
		// No handle-aware caller -- this stage's Executable is a plain
		// resolved path (validators, graph provider, Assayer's own
		// non-backend stages), so the wrap is applied directly to it here.
		factory = func(c context.Context, s *containment.Scope, p enforce.Plan, b string, a []string, d string) (*exec.Cmd, error) {
			var wrapFiles []*os.File
			if p.Active {
				b, a, wrapFiles = p.Wrap(b, a)
			}
			cmd := s.Command(c, b, a, d)
			cmd.ExtraFiles = append(cmd.ExtraFiles, wrapFiles...)
			return cmd, nil
		}
	}
	cmd, err := factory(ctx, scope, effectivePlan, bin, args, spec.WorkingDirectory)
	if err != nil {
		// Nothing was launched (a handle-aware factory's own verification --
		// e.g. agents.LaunchCommand's VerifyUnchanged detecting a swapped
		// executable -- failed before Start()), so there is nothing this
		// scope could have failed to extinguish. DescendantsGone false here
		// would misreport a pre-launch rejection as an extinction failure to
		// any caller that (correctly) treats DescendantsGone as a hard gate.
		return StageResult{DescendantsGone: true}, err
	}
	cmd.Env = append([]string(nil), spec.Environment.Values...)
	if spec.Stdin != nil {
		cmd.Stdin = spec.Stdin
	}
	// os/exec copies Stdout and Stderr from two separate goroutines, so a
	// shared destination needs its own locking: a plain bytes.Buffer isn't
	// safe for concurrent writes, and it's exactly that combination (a
	// backend writing to both stdout and stderr) that a bare bytes.Buffer
	// here used to data-race on.
	capture := &syncBuffer{}
	stdout := io.Writer(io.Discard)
	stderr := io.Writer(io.Discard)
	if spec.Stdout != nil {
		stdout = spec.Stdout
	}
	if spec.Stderr != nil {
		stderr = spec.Stderr
	}
	if captureMode != CaptureNone {
		if spec.Stdout != nil {
			stdout = io.MultiWriter(spec.Stdout, capture)
		} else {
			stdout = capture
		}
		if spec.Stderr != nil {
			stderr = io.MultiWriter(spec.Stderr, capture)
		} else {
			stderr = capture
		}
	}
	var limitCancel context.CancelFunc
	if captureMode == CaptureRequiredComplete {
		ctx, limitCancel = context.WithCancel(ctx)
		defer limitCancel()
	}
	limiter := newSharedLimitWriter(stdout, stderr, spec.OutputLimit, captureMode == CaptureRequiredComplete, limitCancel)
	if spec.OutputLimit > 0 {
		stdout = limiter.Stdout()
		stderr = limiter.Stderr()
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	exit := 0
	var runErr error
	var proof containment.Proof
	var extinctionErr error
	extinguish := func() {
		extCtx, cancel := context.WithTimeout(context.Background(), containment.DefaultExtinctionDeadline+time.Second)
		defer cancel()
		proof, extinctionErr = scope.Extinguish(extCtx, containment.DefaultExtinctionDeadline, spec.WorkingDirectory)
	}
	if err := cmd.Start(); err != nil {
		exit = -1
		runErr = err
		extinguish()
	} else {
		if cmd.Process != nil {
			scope.Started(cmd.Process.Pid)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					exit = ee.ExitCode()
				} else {
					exit = -1
					runErr = err
				}
			}
			extinguish()
		case <-ctx.Done():
			exit = -1
			if limiter.Exceeded() {
				runErr = ErrOutputLimitExceeded
			} else {
				runErr = ctx.Err()
			}
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			extinguish()
			select {
			case err := <-done:
				if err != nil && !errors.Is(runErr, ErrOutputLimitExceeded) && !errors.Is(runErr, context.DeadlineExceeded) && !errors.Is(runErr, context.Canceled) {
					runErr = err
				}
			case <-time.After(waitAfterKillDeadline):
				if extinctionErr == nil {
					extinctionErr = fmt.Errorf("stage: command wait did not complete within %s after kill", waitAfterKillDeadline)
				}
			}
		}
	}
	declaredNetwork := string(authority.Network)
	if declaredNetwork == "" || declaredNetwork == string(NetworkPolicyUnspecified) {
		declaredNetwork = string(spec.NetworkPolicy)
	}
	enforcedNetwork := "unobserved"
	if effectivePlan.Active {
		enforcedNetwork = string(NetworkPolicyDenied)
		if effectivePlan.AllowNetwork {
			enforcedNetwork = string(NetworkPolicyAllowed)
		}
	}
	declaredWrites := append([]string(nil), effectivePlan.WriteDirs...)
	declaredWrites = append(declaredWrites, effectivePlan.WriteFiles...)
	actualWriteSet := reconcileWriteSet(writeSnapshotBefore, effectivePlan.WriteDirs, effectivePlan.WriteFiles)
	declaredCredentialPolicy := "unspecified"
	if authority.Credentials == CredentialPolicyNone || spec.CredentialPolicy == CredentialPolicyNone {
		declaredCredentialPolicy = string(CredentialPolicyNone)
	} else if authority.Credentials == CredentialPolicyDeclared || spec.CredentialPolicy == CredentialPolicyDeclared {
		declaredCredentialPolicy = string(CredentialPolicyDeclared)
	}
	outputConsequence := "complete"
	if limiter.Exceeded() {
		if captureMode == CaptureRequiredComplete {
			outputConsequence = "truncated_run_aborted"
		} else {
			outputConsequence = "truncated_nonblocking"
		}
	}
	res := StageResult{
		ExitStatus:         exit,
		ExecutableIdentity: spec.Executable,
		EnvironmentHash:    spec.Environment.Hash,
		ObservedEffects: EffectLedger{
			ScopeMethod:               string(proof.Method),
			WorkspaceFDScanClean:      proof.WorkspaceFDScanClean,
			LandlockABI:               effectivePlan.LandlockABI,
			KernelReadEnvelope:        append([]string(nil), effectivePlan.ReadRoots...),
			DeclaredNetworkPolicy:     declaredNetwork,
			EnforcedNetworkPolicy:     enforcedNetwork,
			NetworkAttemptObservation: "unavailable",
			NetworkDenialMechanism:    networkDenialMechanism(effectivePlan.Active, effectivePlan.AllowNetwork),
			DeclaredWriteRoots:        declaredWrites,
			ActualWriteSet:            actualWriteSet,
			DeclaredCredentialPolicy:  declaredCredentialPolicy,
			ObservedCredentialAccess:  "unavailable",
			PeakProcessCount:          proof.ProcessesObservedPeak,
			OutputConsequence:         outputConsequence,
		},
		OutputTruncated: limiter.Exceeded(),
		DescendantsGone: extinctionErr == nil,
		Output:          capture.String(),
	}
	if extinctionErr != nil {
		return res, extinctionErr
	}
	return res, runErr
}

// networkDenialMechanism names the applied-enforcement mechanism behind a
// network-deny verdict (Sol9 P1-5). Governator's only real local network
// denial is process isolation via a network namespace, never a per-attempt
// kernel observation, so this stays constant across every deny case rather
// than implying finer-grained enforcement exists.
func networkDenialMechanism(planActive, allowNetwork bool) string {
	if planActive && !allowNetwork {
		return "isolated_namespace"
	}
	return ""
}

// writeRootStat is one file's size+mtime fingerprint within a snapshotted
// write root, cheap enough to take twice per stage run without hashing
// tree contents.
type writeRootStat struct {
	size  int64
	mtime int64
}

// snapshotWriteRoots walks every declared write directory and stats every
// declared write file, returning a fingerprint per path found. Missing
// roots (e.g. a directory a validator's `init` step is about to create) are
// silently skipped rather than treated as an error -- their absence before
// and presence after is exactly what reconcileWriteSet needs to detect a
// write.
func snapshotWriteRoots(dirs, files []string) map[string]writeRootStat {
	snap := map[string]writeRootStat{}
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			info, ierr := entry.Info()
			if ierr != nil {
				return nil
			}
			snap[path] = writeRootStat{size: info.Size(), mtime: info.ModTime().UnixNano()}
			return nil
		})
	}
	for _, f := range files {
		if info, err := os.Stat(f); err == nil && !info.IsDir() {
			snap[f] = writeRootStat{size: info.Size(), mtime: info.ModTime().UnixNano()}
		}
	}
	return snap
}

// reconcileWriteSet is the Sol9 P1-5 observed-effects reconciliation: it
// re-snapshots the same declared write roots after the stage has run and
// extinguished, and reports every path that is new or whose size/mtime
// fingerprint changed since before. Unlike the roots themselves (a declared
// fact), this is an actual before/after diff -- the closest evidence
// available without kernel-level write interposition.
func reconcileWriteSet(before map[string]writeRootStat, dirs, files []string) []string {
	after := snapshotWriteRoots(dirs, files)
	changed := make([]string, 0, len(after))
	for path, stat := range after {
		if prev, existed := before[path]; !existed || prev != stat {
			changed = append(changed, path)
		}
	}
	sort.Strings(changed)
	return changed
}

// syncBuffer is a mutex-guarded bytes.Buffer: os/exec copies a Cmd's Stdout
// and Stderr from two independent goroutines, so any single destination
// both point at needs its own locking -- a bare bytes.Buffer is not safe
// for concurrent writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type sharedLimitWriter struct {
	mu        sync.Mutex
	stdout    io.Writer
	stderr    io.Writer
	remaining int64
	exceeded  bool
	fail      bool
	cancel    context.CancelFunc
}

type streamLimitWriter struct {
	parent *sharedLimitWriter
	w      io.Writer
}

func newSharedLimitWriter(stdout, stderr io.Writer, limit int64, fail bool, cancel context.CancelFunc) *sharedLimitWriter {
	return &sharedLimitWriter{stdout: stdout, stderr: stderr, remaining: limit, fail: fail, cancel: cancel}
}

func (l *sharedLimitWriter) Stdout() io.Writer { return streamLimitWriter{parent: l, w: l.stdout} }
func (l *sharedLimitWriter) Stderr() io.Writer { return streamLimitWriter{parent: l, w: l.stderr} }

func (l *sharedLimitWriter) Exceeded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.exceeded
}

func (w streamLimitWriter) Write(p []byte) (int, error) {
	orig := len(p)
	w.parent.mu.Lock()
	allowed := len(p)
	if w.parent.remaining <= 0 {
		allowed = 0
	} else if int64(allowed) > w.parent.remaining {
		allowed = int(w.parent.remaining)
	}
	if allowed < len(p) {
		w.parent.exceeded = true
		if w.parent.cancel != nil {
			w.parent.cancel()
		}
	}
	w.parent.remaining -= int64(allowed)
	fail := w.parent.fail && w.parent.exceeded
	w.parent.mu.Unlock()
	if allowed > 0 {
		if _, err := w.w.Write(p[:allowed]); err != nil {
			return allowed, err
		}
	}
	if fail {
		return allowed, ErrOutputLimitExceeded
	}
	return orig, nil
}

func HashExecutable(path string) (ExecutableIdentity, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ExecutableIdentity{}, err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return ExecutableIdentity{}, err
	}
	sum := sha256.Sum256(b)
	return ExecutableIdentity{CanonicalPath: abs, SHA256: hex.EncodeToString(sum[:])}, nil
}

func nonce() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
