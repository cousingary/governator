package agents

import (
	"context"
	"fmt"
	"github.com/cousingary/governator/internal/config"
)

// GLM adapter. The GLM coding CLI (glm-cli) follows the same headless pattern
// as Claude Code: stream-json output, cwd confinement, prompt as the final
// positional. It exposes a coarser policy surface than Codex (no native
// sandbox_mode), so the abstract spec's Sandbox is projected into the closest
// available native control and the runtime's fingerprint scan remains the
// authoritative write boundary.
type GLM struct{}

func (GLM) Name() string { return "glm" }

func (GLM) Capabilities() Capability {
	return Capability{
		NativeApprovalPolicy: true,
		TranscriptFormat:     TranscriptGLM,
	}
}

// project translates the abstract spec into glm-cli native flags.
func (GLM) project(spec BackendSpec) ([]string, error) {
	// Mirror Claude Code's headless surface: prompt-mode, stream-json,
	// verbose, no leftover session state, and safe-mode's additional tool
	// guards. glm-cli is Claude-Code compatible (see agents.go Claude.project
	// and the shared variadic --add-dir fix below), so the same isolation
	// flags apply. If a future glm-cli drops either flag, doctor's
	// backend flag-drift probe is the right place to surface it.
	flags := []string{"-p", "--output-format", "stream-json", "--verbose",
		"--no-session-persistence", "--safe-mode"}
	switch spec.Sandbox {
	case SandboxReadOnly:
		// No native read-only sandbox; rely on prompt-mode + the runtime's
		// post-run fingerprint scan to reject any write.
		flags = append(flags, "--permission-mode", "plan")
	case SandboxWorkspaceWrite:
		flags = append(flags, "--permission-mode", "acceptEdits")
	default:
		return nil, fmt.Errorf("glm: unsupported sandbox %q", spec.Sandbox)
	}
	if spec.Workdir == "" {
		return nil, fmt.Errorf("glm: spec.Workdir is required")
	}
	// "=" form binds --add-dir to exactly this one value; see the identical
	// fix and rationale in agents.go's Claude.project (glm-cli is Claude-Code
	// compatible and shares the same variadic-flag parsing).
	flags = append(flags, "--add-dir="+spec.Workdir)
	return flags, nil
}

func (GLM) Run(parent context.Context, req Request) (Result, error) {
	bin := config.BackendBin("glm")
	flags, err := GLM{}.project(req.Spec)
	if err != nil {
		return Result{}, err
	}
	return runCLI(parent, runCLIRequest{
		bin: bin, workdir: req.Workdir, transcript: req.Transcript,
		timeout: req.Timeout, prompt: req.Prompt, extraFlags: flags,
		executor: req.Executor,
	})
}
