package agents

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/enforce"
)

// Executor overrides how a backend's CLI process is actually spawned. Nil
// (every caller before the Phase 5 Runner abstraction) uses defaultExecutor,
// an exact extraction of the previous inline host-subprocess logic. A Runner
// that needs host-level containment (DockerRunner) supplies its own executor
// so the same bin/args/workdir/timeout/output contract launches inside a
// container instead, without any backend adapter needing to change.
//
// descendantsGone (Sol redteam v7 S1 gap-closure, migrating the backend
// launch to internal/stage.Executor): true when this launch's descendant
// scope confirmed kernel-verified extinction of every process it owned, or
// when there was nothing to prove (no Scope in context -- doctor probes,
// direct adapter tests, DockerRunner's own separate container-level
// containment model). false means extinction was attempted and failed;
// callers must treat that as fatal to the run, the same posture
// runtime.runOnce already gives its own run-level Scope's Extinguish call.
type Executor func(ctx context.Context, bin string, args []string, workdir string, out io.Writer, timeout time.Duration) (exitCode int, timedOut bool, descendantsGone bool, err error)

type Request struct {
	Prompt     string
	Workdir    string
	Transcript string
	Timeout    time.Duration
	Spec       BackendSpec
	Executor   Executor
	// ResolvedBin is the canonical, PATH-resolved, symlink-evaluated absolute
	// path a caller already produced once for this run via ResolvePath (Sol
	// Finding 5) — the same record backing execution identity and any
	// attestation check. runCLI substitutes it in place of the bare
	// configured name only for the host launch (Executor nil); an injected
	// Executor (DockerRunner) launches inside a separate filesystem
	// namespace and always receives the bare in-container name instead.
	// Empty is a valid fallback (e.g. gov doctor probes, tests) that leaves
	// the pre-Finding-5 exec.Command-does-its-own-LookPath behavior intact.
	ResolvedBin string
}

type Result struct {
	ExitCode int
	TimedOut bool
	// DescendantsGone mirrors Executor's descendantsGone return (Sol
	// redteam v7 S1 gap-closure): whether the backend launch's descendant
	// scope confirmed kernel-verified extinction, or had nothing to prove.
	DescendantsGone bool
}

type Agent interface {
	Name() string
	Capabilities() Capability
	Run(context.Context, Request) (Result, error)
}

// runCLIRequest is the shared subprocess contract every adapter fills in.
// Adapters differ only in bin path and how they project the spec into flags;
// the process-group / timeout / transcript plumbing is identical, so it lives
// here once.
type runCLIRequest struct {
	bin        string
	workdir    string
	transcript string
	timeout    time.Duration
	// prompt is appended as the final positional argument — all three backends
	// (claude, codex exec, glm) take the prompt last. Required: an empty prompt
	// is a caller bug (the backend would block on stdin), so runCLI rejects it.
	prompt     string
	extraFlags []string
	// executor overrides process spawning; nil uses defaultExecutor. Threaded
	// straight from Request.Executor by every adapter's Run method.
	executor Executor
	// resolvedBin is Request.ResolvedBin, threaded straight through by every
	// adapter's Run method. Only consulted when executor is nil (the host
	// launch path) — see runCLI.
	resolvedBin string
}

// defaultExecutor is the pre-Phase-5 host subprocess launch, extracted
// unchanged from runCLI so LocalWorktreeRunner-driven runs (every caller that
// leaves Request.Executor nil) behave identically to before the Runner
// abstraction existed.
//
// Sol redteam v7 S1 gap-closure: when a descendant-owning Scope is present
// (a governed runtime.Runner is driving this launch), the backend now routes
// through internal/stage.Executor via LaunchStaged, giving it the same
// unique per-stage scope naming and descendant-extinction proof every other
// migrated stage (validators, Assayer) already has, instead of registering
// into the run's single shared Scope the way it did before this migration.
func defaultExecutor(ctx context.Context, bin string, args []string, workdir string, out io.Writer, timeout time.Duration) (int, bool, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	handle, _ := HandleFromContext(ctx)
	scope, hasScope := containment.ScopeFromContext(ctx)
	plan, _ := enforce.PlanFromContext(ctx)
	if hasScope {
		exitCode, descendantsGone, runErr := LaunchStaged(ctx, handle, bin, args, workdir, out, scope, plan)
		return exitCode, ctx.Err() != nil, descendantsGone, runErr
	}
	// No Scope in context means this launch never went through a governed
	// runtime.Runner (doctor probes, direct adapter tests) -- keep the
	// pre-S2 process-group behavior rather than requiring every caller to
	// construct a Scope. Nothing to prove extinguished, so descendantsGone
	// is trivially true (matches Executor's documented "or when there was
	// nothing to prove" case).
	cmd, err := LaunchCommand(ctx, handle, bin, args)
	if err != nil {
		return 0, false, true, err
	}
	cmd.Dir = workdir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Sol P1-14 / v6 S3: filter every launched backend environment down
	// to the fixed baseline plus the backend's declared extras. Do this even
	// when handle is nil (tests, doctor-style probes, or legacy callers),
	// because nil cmd.Env inherits LD_PRELOAD/BASH_ENV and reopens the
	// controller-injection class.
	var allowedEnv []string
	if handle != nil {
		allowedEnv = handle.AllowedEnv
	}
	cmd.Env = BuildAllowedEnv(allowedEnv)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return 0, false, true, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode(), false, true, nil
			}
			return 0, false, true, err
		}
		return 0, false, true, nil
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		<-done
		return -1, true, true, ctx.Err()
	}
}

func runCLI(parent context.Context, r runCLIRequest) (Result, error) {
	if r.prompt == "" {
		return Result{}, fmt.Errorf("runCLI: empty prompt for %s (backend would block on stdin)", r.bin)
	}
	if err := os.MkdirAll(filepath.Dir(r.transcript), 0700); err != nil {
		return Result{}, err
	}
	out, err := os.OpenFile(r.transcript, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return Result{}, err
	}
	defer out.Close()
	args := append([]string{}, r.extraFlags...)
	args = append(args, r.prompt)
	execute := r.executor
	bin := r.bin
	if execute == nil {
		execute = defaultExecutor
		// Sol Finding 5: the host launch uses the caller's already-resolved
		// canonical path instead of handing exec.Command a bare name and
		// letting it perform its own independent PATH lookup at Start() —
		// that second, later resolution is exactly the TOCTOU window the
		// finding closes. A Docker (or other injected) executor keeps r.bin,
		// the bare in-container name, unchanged.
		if r.resolvedBin != "" {
			bin = r.resolvedBin
		}
	}
	code, timedOut, descendantsGone, runErr := execute(parent, bin, args, r.workdir, out, r.timeout)
	if timedOut {
		return Result{ExitCode: -1, TimedOut: true, DescendantsGone: descendantsGone}, runErr
	}
	if runErr != nil {
		return Result{DescendantsGone: descendantsGone}, runErr
	}
	return Result{ExitCode: code, DescendantsGone: descendantsGone}, nil
}

func New(name string) (Agent, error) {
	switch name {
	case "claude-code", "claude":
		return Claude{}, nil
	case "codex":
		return Codex{}, nil
	case "glm":
		return GLM{}, nil
	case "opencode":
		return OpenCode{}, nil
	case "pi":
		return Pi{}, nil
	default:
		return nil, fmt.Errorf("unsupported agent %q", name)
	}
}

type Claude struct{}

func (Claude) Name() string { return "claude-code" }

func (Claude) Capabilities() Capability {
	return Capability{
		NativeSandbox: true, NativeReadOnly: true,
		NativeApprovalPolicy: true, NetworkControl: false,
		TranscriptFormat: TranscriptClaude,
	}
}

// project translates the abstract spec into Claude Code native flags.
// --safe-mode + --permission-mode acceptEdits already confines writes to
// --add-dir worktrees; read-only modes tighten to --permission-mode plan.
func (Claude) project(spec BackendSpec) []string {
	flags := []string{
		"-p", "--output-format", "stream-json", "--verbose",
		"--no-session-persistence", "--safe-mode",
	}
	switch spec.Sandbox {
	case SandboxReadOnly:
		flags = append(flags, "--permission-mode", "plan")
	default:
		flags = append(flags, "--permission-mode", "acceptEdits")
	}
	// "=" form binds --add-dir to exactly this one value; two separate args
	// would let the CLI's variadic parser greedily swallow the trailing
	// prompt positional as an additional directory, leaving no prompt at all.
	flags = append(flags, "--add-dir="+spec.Workdir)
	return flags
}

func (Claude) Run(parent context.Context, req Request) (Result, error) {
	bin := config.BackendBin("claude-code")
	return runCLI(parent, runCLIRequest{
		bin: bin, resolvedBin: req.ResolvedBin, workdir: req.Workdir, transcript: req.Transcript,
		timeout: req.Timeout, prompt: req.Prompt, extraFlags: Claude{}.project(req.Spec),
		executor: req.Executor,
	})
}
