package agents

// Capability declares which parts of the governance envelope a backend can
// enforce itself. The runtime compensates for every false capability and
// always performs pre/post fingerprint scans as the universal floor.
type Capability struct {
	NativeSandbox        bool   `json:"native_sandbox"`
	NativeReadOnly       bool   `json:"native_read_only"`
	NativeApprovalPolicy bool   `json:"native_approval_policy"`
	NetworkControl       bool   `json:"network_control"`
	TranscriptFormat     string `json:"transcript_format"`
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
