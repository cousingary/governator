package agents

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cousingary/governator/internal/config"
)

type Request struct {
	Prompt     string
	Workdir    string
	Transcript string
	Timeout    time.Duration
	Spec       BackendSpec
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
	ctx, cancel := context.WithTimeout(parent, r.timeout)
	defer cancel()
	args := append([]string{}, r.extraFlags...)
	args = append(args, r.prompt)
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Dir = r.workdir
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = cmd.Start(); err != nil {
		return Result{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		<-done
		return Result{ExitCode: -1, TimedOut: true}, ctx.Err()
	}
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return Result{}, err
		}
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
	flags = append(flags, "--add-dir", spec.Workdir)
	return flags
}

func (Claude) Run(parent context.Context, req Request) (Result, error) {
	bin := config.BackendBin("claude-code")
	return runCLI(parent, runCLIRequest{
		bin: bin, workdir: req.Workdir, transcript: req.Transcript,
		timeout: req.Timeout, prompt: req.Prompt, extraFlags: Claude{}.project(req.Spec),
	})
}
