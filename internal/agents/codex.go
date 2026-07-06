package agents

import (
	"context"
	"fmt"
	"github.com/cousingary/governator/internal/config"
)

// Codex adapter. Codex CLI (codex-cli) has no PreToolUse hook model, so the
// abstract spec is projected into its NATIVE controls (plan §7.3):
//
//	approval_policy = "on-request"  (the spec's ApprovalOnRequest)
//	sandbox_mode    = "workspace-write" | "read-only"
//	[sandbox_workspace_write] network_access = false
//
// The adapter cannot see what an opaque script does inside the sandbox, so the
// runtime's pre/post fingerprint scan (Enforcement reality layer 4) remains the
// mandatory detection floor — the sandbox is the first wall, not the only one.
type Codex struct{}

func (Codex) Name() string { return "codex" }

func (Codex) Capabilities() Capability {
	return Capability{
		NativeSandbox: true, NativeReadOnly: true,
		NativeApprovalPolicy: true, NetworkControl: true,
		TranscriptFormat: TranscriptCodex,
	}
}

// project translates the abstract spec into `codex exec` native flags.
func (Codex) project(spec BackendSpec) ([]string, error) {
	// Root-level flags must precede the exec subcommand.
	flags := []string{}
	switch spec.Approval {
	case ApprovalOnRequest:
		flags = append(flags, "--ask-for-approval", "on-request")
	case ApprovalNever:
		flags = append(flags, "--ask-for-approval", "never")
	default:
		return nil, fmt.Errorf("codex: unsupported approval policy %q", spec.Approval)
	}
	if !spec.Network {
		flags = append(flags, "-c", "sandbox_workspace_write.network_access=false")
	}
	// Governator owns the durable transcript; avoid duplicate Codex sessions.
	flags = append(flags, "exec", "--json", "--ephemeral")
	switch spec.Sandbox {
	case SandboxReadOnly:
		flags = append(flags, "--sandbox", "read-only")
	case SandboxWorkspaceWrite:
		flags = append(flags, "--sandbox", "workspace-write")
	default:
		return nil, fmt.Errorf("codex: unsupported sandbox %q", spec.Sandbox)
	}
	if spec.Workdir == "" {
		return nil, fmt.Errorf("codex: spec.Workdir is required")
	}
	flags = append(flags, "-C", spec.Workdir)
	return flags, nil
}

func (Codex) Run(parent context.Context, req Request) (Result, error) {
	bin := config.BackendBin("codex")
	flags, err := Codex{}.project(req.Spec)
	if err != nil {
		return Result{}, err
	}
	return runCLI(parent, runCLIRequest{
		bin: bin, workdir: req.Workdir, transcript: req.Transcript,
		timeout: req.Timeout, prompt: req.Prompt, extraFlags: flags,
	})
}
