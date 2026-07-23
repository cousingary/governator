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
	// ConsumedDst/ConsumedArtifacts are Sol11 P0-7's replacement for
	// ROBinds when a validator needs to read consumed artifacts: sealed
	// memfd content projected into a private tmpfs, never a real host
	// directory. Every validator launch (both success and cleanup,
	// regardless of runner kind) sets this instead of ROBinds now -- see
	// runtime.go's consumedArtifactFDs.
	ConsumedDst       string                       `json:"-"`
	ConsumedArtifacts []enforce.ConsumedArtifactFD `json:"-"`
}

func (a StageAuthority) RequiresExternalEnforcement() bool {
	return len(a.ReadRoots) > 0 || len(a.WriteRoots) > 0 || a.Network == NetworkPolicyDenied || a.Credentials == CredentialPolicyNone || len(a.ROBinds) > 0 || len(a.ConsumedArtifacts) > 0
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
// applied enforcement (EnforcedNetworkPolicy, EnforcedWriteRoots,
// NetworkDenialMechanism, KernelReadEnvelope, LandlockABI), and observed
// effects (ActualWriteSet, PeakProcessCount, ObservedCredentialAccess,
// OutputConsequence, NetworkAttemptObservation). Sol10 P1-2: these three
// classes used to collapse to two for writes -- DeclaredWriteRoots was
// actually restating the *compiled* (applied) plan's write roots, not what
// the caller originally asked for, and ActualWriteSet was a same-size+mtime
// comparison that only ever walked the after-state, so it could never
// report a deletion. DeclaredWriteRoots is now the caller's own declared
// authority (StageAuthority.WriteRoots/StageSpec.WriteRoots, pre-compile);
// EnforcedWriteRoots is the compiled enforce.Plan's write roots (what a
// containment mechanism actually installed); ActualWriteSet is a real
// union-of-before/after reconciliation with content-addressed fingerprints,
// reported as explicit created/modified/deleted/renamed operations.
type EffectLedger struct {
	ScopeMethod               string        `json:"scope_method,omitempty"`
	WorkspaceFDScanClean      bool          `json:"workspace_fd_scan_clean"`
	LandlockABI               int           `json:"landlock_abi,omitempty"`
	KernelReadEnvelope        []string      `json:"kernel_read_envelope,omitempty"`
	DeclaredNetworkPolicy     string        `json:"declared_network_policy,omitempty"`
	EnforcedNetworkPolicy     string        `json:"enforced_network_policy,omitempty"`
	NetworkAttemptObservation string        `json:"network_attempt_observation,omitempty"`
	NetworkDenialMechanism    string        `json:"network_denial_mechanism,omitempty"`
	DeclaredWriteRoots        []string      `json:"declared_write_roots,omitempty"`
	EnforcedWriteRoots        []string      `json:"enforced_write_roots,omitempty"`
	ActualWriteSet            []WriteEffect `json:"actual_write_set,omitempty"`
	DeclaredCredentialPolicy  string        `json:"declared_credential_policy,omitempty"`
	ObservedCredentialAccess  string        `json:"observed_credential_access,omitempty"`
	PeakProcessCount          int           `json:"peak_process_count,omitempty"`
	OutputConsequence         string        `json:"output_consequence,omitempty"`
}

// WriteEffect is one path's observed filesystem effect within a stage's
// declared write roots (Sol10 P1-2): a real before/after reconciliation
// result, distinguishing created, modified, deleted and renamed paths
// rather than a flat list of "paths that look different now."
// ContentSHA256/Size/Mode/SymlinkTarget describe the path's AFTER state
// (empty/zero for a deleted path, which has no after state).
type WriteEffect struct {
	Path          string `json:"path"`
	Operation     string `json:"operation"` // created | modified | deleted | renamed
	RenamedFrom   string `json:"renamed_from,omitempty"`
	ContentSHA256 string `json:"content_sha256,omitempty"`
	Size          int64  `json:"size,omitempty"`
	Mode          string `json:"mode,omitempty"`
	SymlinkTarget string `json:"symlink_target,omitempty"`
}

// CommandFactory lets callers with already-sealed launch logic build the exact
// *exec.Cmd while still receiving the scope the stage executor owns, plus the
// stage's EnforcementPlan so a handle-aware caller can compose the wrap
// AROUND its resolved (sealed/fd) launch target rather than having Run
// pre-wrap a bin/args pair that the caller is about to replace anyway (Sol
// redteam v7 HS2: the sealed-executable handle discarding the enforce wrap).
type CommandFactory func(ctx context.Context, scope *containment.Scope, plan enforce.Plan, bin string, args []string, dir string) (*exec.Cmd, error)

// ComposeHandleLaunch is Sol11 P0-5's descriptor-only launch composition
// (previously inlined in Run's default CommandFactory below): it wires
// handle's held, already-verified descriptor into plan's own self-exec/
// unshare layers and scope's own containment primitive, all through one
// shared alloc, and returns the fully-composed *exec.Cmd with ExtraFiles
// already populated. plan.Active must already be true -- callers gate that
// themselves (Run's default factory only calls this on the p.Active branch).
//
// Exported so a caller with an additional descriptor-backed launch argument
// of its own can register it into alloc BEFORE calling this (via
// alloc.Arg), and splice the returned /proc/self/fd/<n> string into args --
// Sol11 P0-6's immutable Assayer package object (a sealed, unlinked memfd;
// see internal/assay.Evaluate's own CommandFactory) is the first such
// caller. A fresh caller with nothing of its own to register simply passes
// &toolregistry.FDAllocator{}.
func ComposeHandleLaunch(ctx context.Context, scope *containment.Scope, plan enforce.Plan, handle *toolregistry.Handle, alloc *toolregistry.FDAllocator, args []string, dir string) (*exec.Cmd, error) {
	extended, err := plan.WithExecutableAndReadRoots(handle.Identity.CanonicalPath, filepath.Dir(handle.Identity.CanonicalPath))
	if err != nil {
		return nil, err
	}
	wb, wa := extended.WrapWith(alloc, "", handle.File(), args)
	cmd := scope.CommandWith(ctx, alloc, wb, wa, dir)
	cmd.ExtraFiles = append(cmd.ExtraFiles, alloc.Files()...)
	return cmd, nil
}

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
			compiledPlan = compiledPlan.WithConsumedArtifacts(authority.ConsumedDst, authority.ConsumedArtifacts)
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
	if factory == nil && spec.ExecutableHandle != nil {
		factory = func(c context.Context, s *containment.Scope, p enforce.Plan, b string, a []string, d string) (*exec.Cmd, error) {
			if p.Active {
				return ComposeHandleLaunch(c, s, p, spec.ExecutableHandle, &toolregistry.FDAllocator{}, a, d)
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
	// Sol10 P1-2: DeclaredWriteRoots is the caller's own ask (authority.
	// WriteRoots, merged from spec.Authority/spec.WriteRoots above --
	// possibly relative, possibly a mix of dirs and files); EnforcedWriteRoots
	// is what the compiled plan actually installed (abs-resolved, split into
	// dirs/files). Distinct evidence classes, not the same list twice.
	declaredWriteRoots := append([]string(nil), authority.WriteRoots...)
	enforcedWriteRoots := append([]string(nil), effectivePlan.WriteDirs...)
	enforcedWriteRoots = append(enforcedWriteRoots, effectivePlan.WriteFiles...)
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
			DeclaredWriteRoots:        declaredWriteRoots,
			EnforcedWriteRoots:        enforcedWriteRoots,
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

// writeRootStat is one path's fingerprint within a snapshotted write root
// (Sol10 P1-2, replacing the previous size+mtime pair): size, mode,
// device+inode, ctime where the platform exposes it, and -- for a regular
// file -- a content SHA-256, or -- for a symlink -- its target. mtime is
// deliberately not part of this at all (same rationale as
// internal/snapshots.same: it is never proof of anything, and a rewrite
// that restores the original mtime, or a same-size in-place edit, must
// still be detected). Cheap enough to take twice per stage run: declared
// write roots are task-scoped output directories, not whole worktrees.
type writeRootStat struct {
	size          int64
	mode          fs.FileMode
	dev, inode    uint64
	ctimeNS       int64
	isSymlink     bool
	symlinkTarget string
	contentSHA256 string
}

func (a writeRootStat) equal(b writeRootStat) bool {
	return a.size == b.size && a.mode == b.mode && a.dev == b.dev && a.inode == b.inode &&
		a.ctimeNS == b.ctimeNS && a.isSymlink == b.isSymlink &&
		a.symlinkTarget == b.symlinkTarget && a.contentSHA256 == b.contentSHA256
}

// renameKey returns an identity key strong enough to correlate a deleted
// path with a created path as the same underlying file having moved, and
// ok=false when no such signal is available (never match on the absence of
// one). Device+inode is preferred -- a real rename(2)/hardlink-replacement
// within one write root's filesystem preserves it, so it survives even a
// content-preserving metadata-only change; content SHA-256 is the fallback
// for a symlink-free regular file when inode identity isn't exposed; a
// symlink with neither falls back to its target.
func (s writeRootStat) renameKey() (string, bool) {
	if s.dev != 0 || s.inode != 0 {
		return fmt.Sprintf("inode:%d:%d", s.dev, s.inode), true
	}
	if s.isSymlink {
		if s.symlinkTarget == "" {
			return "", false
		}
		return "symlink:" + s.symlinkTarget, true
	}
	if s.contentSHA256 != "" {
		return "hash:" + s.contentSHA256, true
	}
	return "", false
}

func contentSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// statWriteRootPath fingerprints one path already known to exist (lstat
// succeeded), without following a symlink into whatever it currently
// targets. ok=false means the path vanished or became unreadable between
// the directory walk and this call -- treated the same as "not found" by
// the caller, exactly like the prior size+mtime version's silent-skip
// contract.
func statWriteRootPath(path string) (writeRootStat, bool) {
	info, err := os.Lstat(path)
	if err != nil {
		return writeRootStat{}, false
	}
	stat := writeRootStat{size: info.Size(), mode: info.Mode()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		stat.dev = uint64(st.Dev)
		stat.inode = uint64(st.Ino)
		stat.ctimeNS = statCtimeNS(st)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		stat.isSymlink = true
		if target, err := os.Readlink(path); err == nil {
			stat.symlinkTarget = target
		}
		return stat, true
	}
	if !info.Mode().IsRegular() {
		// Devices, sockets, FIFOs etc. under a write root: identity only,
		// never attempt to read "content".
		return stat, true
	}
	hash, err := contentSHA256(path)
	if err != nil {
		return writeRootStat{}, false
	}
	stat.contentSHA256 = hash
	return stat, true
}

// snapshotWriteRoots walks every declared write directory and stats every
// declared write file, returning a fingerprint per path found. Missing
// roots (e.g. a directory a validator's `init` step is about to create) are
// silently skipped rather than treated as an error -- their absence before
// and presence after is exactly what reconcileWriteSet needs to detect a
// create.
func snapshotWriteRoots(dirs, files []string) map[string]writeRootStat {
	snap := map[string]writeRootStat{}
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			if stat, ok := statWriteRootPath(path); ok {
				snap[path] = stat
			}
			return nil
		})
	}
	for _, f := range files {
		if info, err := os.Lstat(f); err == nil && !info.IsDir() {
			if stat, ok := statWriteRootPath(f); ok {
				snap[f] = stat
			}
		}
	}
	return snap
}

// reconcileWriteSet is the Sol10 P1-2 observed-effects reconciliation: a
// real union-of-before/after diff over the declared write roots, reporting
// every path as an explicit created/modified/deleted/renamed operation --
// not, as before, a flat list restricted to paths present in the after
// state (which structurally could never report a deletion) compared by a
// size+mtime pair (which could miss a same-size rewrite with a restored
// mtime, or any purely metadata-only change).
func reconcileWriteSet(before map[string]writeRootStat, dirs, files []string) []WriteEffect {
	after := snapshotWriteRoots(dirs, files)

	var created, modified, deleted []string
	for path := range before {
		if _, ok := after[path]; !ok {
			deleted = append(deleted, path)
		}
	}
	for path, stat := range after {
		prev, existed := before[path]
		if !existed {
			created = append(created, path)
			continue
		}
		if !prev.equal(stat) {
			modified = append(modified, path)
		}
	}

	// Rename attribution: correlate a deleted path with a created path
	// sharing the same identity signal (see renameKey). Each deleted path
	// is consumed by at most one created path, so a coincidental duplicate
	// can't absorb two unrelated deletions.
	deletedByKey := map[string]string{} // renameKey -> deleted path
	for _, path := range deleted {
		if key, ok := before[path].renameKey(); ok {
			deletedByKey[key] = path
		}
	}
	consumed := map[string]bool{}
	var renamed []WriteEffect
	remainingCreated := created[:0:0]
	for _, path := range created {
		key, ok := after[path].renameKey()
		from, matched := deletedByKey[key]
		if !ok || !matched || consumed[from] {
			remainingCreated = append(remainingCreated, path)
			continue
		}
		consumed[from] = true
		stat := after[path]
		renamed = append(renamed, WriteEffect{Path: path, Operation: "renamed", RenamedFrom: from, ContentSHA256: stat.contentSHA256, Size: stat.size, Mode: stat.mode.String(), SymlinkTarget: stat.symlinkTarget})
	}
	created = remainingCreated
	remainingDeleted := deleted[:0:0]
	for _, path := range deleted {
		if !consumed[path] {
			remainingDeleted = append(remainingDeleted, path)
		}
	}
	deleted = remainingDeleted

	effects := make([]WriteEffect, 0, len(created)+len(modified)+len(deleted)+len(renamed))
	for _, path := range created {
		stat := after[path]
		effects = append(effects, WriteEffect{Path: path, Operation: "created", ContentSHA256: stat.contentSHA256, Size: stat.size, Mode: stat.mode.String(), SymlinkTarget: stat.symlinkTarget})
	}
	for _, path := range modified {
		stat := after[path]
		effects = append(effects, WriteEffect{Path: path, Operation: "modified", ContentSHA256: stat.contentSHA256, Size: stat.size, Mode: stat.mode.String(), SymlinkTarget: stat.symlinkTarget})
	}
	for _, path := range deleted {
		effects = append(effects, WriteEffect{Path: path, Operation: "deleted"})
	}
	effects = append(effects, renamed...)
	sort.Slice(effects, func(i, j int) bool { return effects[i].Path < effects[j].Path })
	return effects
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
