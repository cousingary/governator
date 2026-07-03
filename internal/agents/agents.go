package agents

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

type Request struct {
	Prompt     string
	Workdir    string
	Transcript string
	Timeout    time.Duration
}

type Result struct {
	ExitCode int
	TimedOut bool
}

type Agent interface {
	Name() string
	Run(context.Context, Request) (Result, error)
}

func New(name string) (Agent, error) {
	switch name {
	case "claude-code", "claude":
		return Claude{}, nil
	default:
		return nil, fmt.Errorf("unsupported agent %q", name)
	}
}

type Claude struct{}

func (Claude) Name() string { return "claude-code" }

func (Claude) Run(parent context.Context, req Request) (Result, error) {
	bin := os.Getenv("GOV_CLAUDE_BIN")
	if bin == "" {
		bin = "claude"
	}
	if err := os.MkdirAll(filepath.Dir(req.Transcript), 0700); err != nil {
		return Result{}, err
	}
	out, err := os.OpenFile(req.Transcript, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return Result{}, err
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(parent, req.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-p", "--output-format", "stream-json", "--verbose",
		"--no-session-persistence", "--safe-mode",
		"--permission-mode", "acceptEdits",
		"--add-dir", req.Workdir,
		req.Prompt,
	)
	cmd.Dir = req.Workdir
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err = cmd.Start()
	if err != nil {
		return Result{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
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
