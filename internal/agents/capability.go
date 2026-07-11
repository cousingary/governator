package agents

import "github.com/cousingary/governator/internal/config"

// Capability declares which parts of the governance envelope a backend can
// enforce itself. The runtime compensates for every false capability and
// always performs pre/post fingerprint scans as the universal floor.
//
// NativeSandbox/NativeReadOnly/NativeApprovalPolicy/NetworkControl/
// TranscriptFormat are fixed properties of the CLI wrapper itself, returned
// as struct literals by each Agent's Capabilities(). Vision/ToolCalling/
// LocalOnly/ContextTokens/OutputTokens are properties of whichever *model*
// the operator has pointed the wrapper at, so they are never set by
// Capabilities() (always zero there) — WithConfiguredModel overlays them
// from config.yaml at the one call site (the router) that needs them.
type Capability struct {
	NativeSandbox        bool   `json:"native_sandbox"`
	NativeReadOnly       bool   `json:"native_read_only"`
	NativeApprovalPolicy bool   `json:"native_approval_policy"`
	NetworkControl       bool   `json:"network_control"`
	TranscriptFormat     string `json:"transcript_format"`

	Vision        bool `json:"vision"`
	ToolCalling   bool `json:"tool_calling"`
	LocalOnly     bool `json:"local_only"`
	ContextTokens int  `json:"context_tokens"`
	OutputTokens  int  `json:"output_tokens"`
}

// WithConfiguredModel overlays a config.Backend's operator-declared model
// facts onto a base capability profile. base's model fields are always zero
// (Capabilities() never sets them), so an unconfigured config.Backend leaves
// every model field at its fail-closed default.
func WithConfiguredModel(base Capability, cfg config.Backend) Capability {
	base.Vision = cfg.Vision
	base.ToolCalling = cfg.ToolCalling
	base.LocalOnly = cfg.LocalOnly
	base.ContextTokens = cfg.ContextTokens
	base.OutputTokens = cfg.OutputTokens
	return base
}

const (
	TranscriptClaude   = "claude-stream-json"
	TranscriptCodex    = "codex-json"
	TranscriptGLM      = "glm-stream-json"
	TranscriptOpenCode = "opencode-json"
	TranscriptPi       = "pi-json"
)

func CapabilityMatrix() []struct {
	Name string
	Capability
} {
	names := []string{"claude-code", "codex", "glm", "opencode", "pi"}
	out := make([]struct {
		Name string
		Capability
	}, 0, len(names))
	for _, name := range names {
		agent, _ := New(name)
		out = append(out, struct {
			Name string
			Capability
		}{name, agent.Capabilities()})
	}
	return out
}
