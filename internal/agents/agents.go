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
type Executor func(ctx context.Context, bin string, args []string, workdir string, out io.Writer, timeout time.Duration) (exitCode int, timedOut bool, err error)

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
func defaultExecutor(ctx context.Context, bin string, args []string, workdir string, out io.Writer, timeout time.Duration) (int, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	handle, _ := HandleFromContext(ctx)
	var cmd *exec.Cmd
	var err error
	scope, hasScope := containment.ScopeFromContext(ctx)
	plan, _ := enforce.PlanFromContext(ctx)
	if hasScope {
		cmd, err = LaunchCommand(ctx, handle, bin, args, func(c context.Context, b string, a []string) *exec.Cmd {
			// Session 5 (Sol P0-3): wrap bin/args in Governator's own
			// externally enforced sandbox (Landlock + network namespace)
			// BEFORE the S2 descendant-owning Scope wraps the launch again.
			// A no-op Plan (Active false -- most runs, which never require
			// host containment) returns b/a unchanged, so this composes with
			// every Scope method identically to before Session 5 existed.
			wb, wa := plan.Wrap(b, a)
			return scope.Command(c, wb, wa, workdir)
		})
	} else {
		// No Scope in context means this launch never went through a
		// governed runtime.Runner (doctor probes, direct adapter tests) --
		// keep the pre-S2 process-group behavior rather than requiring
		// every caller to construct a Scope.
		cmd, err = LaunchCommand(ctx, handle, bin, args, nil)
		if err == nil {
			cmd.Dir = workdir
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		}
	}
	if err != nil {
		return 0, false, err
	}
	if handle != nil {
		// Sol P1-14: filter the launched process's environment down to a
		// fixed baseline plus this backend's own declared extras, applied
		// unconditionally regardless of whether this is a scoped
		// (systemd-run/unshare wrapper) or direct launch -- see
		// baselineAllowedEnvKeys' doc comment for why the wrapper's own
		// session-bus variables are part of that baseline rather than an
		// adapter concern.
		cmd.Env = BuildAllowedEnv(handle.AllowedEnv)
	}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return 0, false, err
	}
	if hasScope && cmd.Process != nil {
		scope.Started(cmd.Process.Pid)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode(), false, nil
			}
			return 0, false, err
		}
		return 0, false, nil
	case <-ctx.Done():
		// Best-effort immediate stop on cancellation; this signal alone
		// does not prove the whole descendant tree is dead (that is
		// exactly the bug report P0-4 describes) -- the runtime's
		// containment.Scope.Extinguish call after Launch returns is the
		// actual authority, run unconditionally regardless of this path.
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		<-done
		return -1, true, ctx.Err()
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
	code, timedOut, runErr := execute(parent, bin, args, r.workdir, out, r.timeout)
	if timedOut {
		return Result{ExitCode: -1, TimedOut: true}, runErr
	}
	if runErr != nil {
		return Result{}, runErr
	}
	return Result{ExitCode: code}, nil
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
