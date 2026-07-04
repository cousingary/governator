package agents

import (
	"context"
	"fmt"
	"github.com/cousingary/governator/internal/config"
)

// Pi can remove mutating tools entirely for read-only runs.
type Pi struct{}

func (Pi) Name() string { return "pi" }

func (Pi) Capabilities() Capability {
	return Capability{
		NativeReadOnly:   true,
		TranscriptFormat: TranscriptPi,
	}
}

func (Pi) project(spec BackendSpec) ([]string, error) {
	if spec.Workdir == "" {
		return nil, fmt.Errorf("pi: spec.Workdir is required")
	}
	flags := []string{"--print", "--mode", "json", "--no-session", "--no-extensions", "--no-skills"}
	switch spec.Sandbox {
	case SandboxReadOnly:
		flags = append(flags, "--tools", "read,grep,find,ls")
	case SandboxWorkspaceWrite:
	default:
		return nil, fmt.Errorf("pi: unsupported sandbox %q", spec.Sandbox)
	}
	return flags, nil
}

func (Pi) Run(parent context.Context, req Request) (Result, error) {
	bin := config.BackendBin("pi")
	flags, err := Pi{}.project(req.Spec)
	if err != nil {
		return Result{}, err
	}
	return runCLI(parent, runCLIRequest{
		bin: bin, workdir: req.Workdir, transcript: req.Transcript,
		timeout: req.Timeout, prompt: req.Prompt, extraFlags: flags,
	})
}
