package agents

import (
	"github.com/cousingary/governator/internal/contracts"
)

// ApprovalPolicy is the abstract, backend-neutral confirmation policy.
// Each adapter projects it into its native flag (claude --permission-mode,
// codex approval_policy, etc.). One abstract spec, three backends.
type ApprovalPolicy string

const (
	// ApprovalOnRequest confirms at the boundary of irreversible/external
	// actions. Maps to codex approval_policy="on-request" and is the default
	// for write-capable modes.
	ApprovalOnRequest ApprovalPolicy = "on-request"
	// ApprovalNever runs full-auto with no confirmation prompts. Reserved for
	// read-only scout/verifier runs inside an already-isolated worktree.
	ApprovalNever ApprovalPolicy = "never"
)

// SandboxMode is the abstract filesystem sandbox envelope.
type SandboxMode string

const (
	// SandboxWorkspaceWrite confines writes to the worktree (codex
	// sandbox_mode="workspace-write"; claude --add-dir limited to worktree).
	SandboxWorkspaceWrite SandboxMode = "workspace-write"
	// SandboxReadOnly blocks all writes (read-only modes only).
	SandboxReadOnly SandboxMode = "read-only"
)

// BackendSpec is the single abstract governance projection that every adapter
// translates into native CLI flags. Mode lock + forbidden list + network rule
// collapse into this; adapters never re-derive policy from the contract.
type BackendSpec struct {
	Approval ApprovalPolicy
	Sandbox  SandboxMode
	Network  bool // true = outbound network permitted
	Workdir  string
}

// SpecFromContract derives the abstract backend spec from a contract's mode
// lock and forbidden behaviors. This is the ONLY place policy-to-flags
// translation originates, so the three backends can never disagree.
func SpecFromContract(c contracts.Contract, workdir string) BackendSpec {
	readOnly := c.Mode == contracts.ModeScout || c.Mode == contracts.ModeVerifier || c.Mode == contracts.ModeArchitect
	spec := BackendSpec{
		Approval: ApprovalOnRequest,
		Sandbox:  SandboxWorkspaceWrite,
		Network:  false,
		Workdir:  workdir,
	}
	if readOnly {
		spec.Sandbox = SandboxReadOnly
		// Read-only modes inside an isolated worktree may run without prompts.
		spec.Approval = ApprovalNever
	}
	for _, behavior := range c.Forbidden.Behaviors {
		if behavior == "network" {
			spec.Network = false
		}
	}
	return spec
}
