package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
)

func TestAuditTranscriptPerBackendFormat(t *testing.T) {
	tests := []struct {
		name            string
		format          string
		line            string
		cost            float64
		costUnavailable bool
	}{
		{"claude", agents.TranscriptClaude, `{"type":"tool_use","name":"Bash","input":{"command":"git status"},"total_cost_usd":0.11}`, 0.11, false},
		{"glm", agents.TranscriptGLM, `{"type":"tool_use","name":"Bash","input":{"command":"git status"},"cost_usd":0.115}`, 0.115, false},
		{"codex", agents.TranscriptCodex, `{"type":"item.completed","item":{"type":"command_execution","command":"git status"},"cost_usd":0.12}`, 0.12, false},
		{"opencode", agents.TranscriptOpenCode, `{"type":"tool","tool":"bash","state":{"input":{"command":"git status"}},"cost_usd":0.13}`, 0.13, false},
		{"pi-cost-free", agents.TranscriptPi, `{"type":"tool_execution_start","toolName":"bash","args":{"command":"git status"}}`, 0, true},
		{"unknown", "other", `{"command":"git status"}`, 0, true},
	}
	contract := contracts.Contract{
		Allowed: contracts.Permissions{Execute: []string{"*"}},
		Budget:  contracts.Budget{MaxCommands: 10},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "transcript.jsonl")
			if err := os.WriteFile(path, []byte(tc.line+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			audit := auditTranscript(path, tc.format, "", contract)
			if audit.CostUSD != tc.cost || audit.CostUnavailable != tc.costUnavailable {
				t.Fatalf("audit cost=%v unavailable=%v", audit.CostUSD, audit.CostUnavailable)
			}
			if tc.format != "other" && (len(audit.Commands) != 1 || audit.Commands[0] != "git status") {
				t.Fatalf("commands=%v", audit.Commands)
			}
			if len(audit.Violations) != 0 {
				t.Fatalf("violations=%v", audit.Violations)
			}
		})
	}
}

func TestAuditTranscriptRejectsMalformedJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex.jsonl")
	data := []byte("{\"type\":\"item.completed\",\"item\":{\"type\":\"command_execution\",\"command\":\"go test ./...\"}}\nnot-json\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := contracts.Contract{}
	c.Allowed.Execute = []string{"go test ./..."}
	c.Budget.MaxCommands = 10
	audit := auditTranscript(path, agents.TranscriptCodex, "", c)
	if len(audit.Violations) != 1 || !strings.Contains(audit.Violations[0], "malformed JSON on line 2") {
		t.Fatalf("malformed transcript must fail closed: %v", audit.Violations)
	}
}

// TestAuditGLMGoldenTranscript pins the glm-cli stream-json shape the audit
// pipeline depends on. The fixture (testdata/glm_stream.jsonl) is a richer,
// more realistic transcript than the single-line case above: it exercises
// per-message usage accumulation, a final result envelope with both cost_usd
// and total_cost_usd, assistant text + tool_use events, and a Bash tool_use
// whose command must surface in audit.Commands. If glm-cli ever drifts (field
// renames, a different tool-event envelope, cost moved out of the result
// object), this test fails loudly instead of silently under-counting commands
// or reporting cost_unavailable.
func TestAuditGLMGoldenTranscript(t *testing.T) {
	contract := contracts.Contract{
		Allowed: contracts.Permissions{Execute: []string{"test -f output/result.txt"}},
		Budget:  contracts.Budget{MaxCommands: 10},
	}
	audit := auditTranscript("testdata/glm_stream.jsonl", agents.TranscriptGLM, "", contract)
	if !audit.CostAvailable || audit.CostUSD != 0.1375 {
		t.Fatalf("glm cost not extracted from result envelope: cost=%v available=%v (drift in cost_usd/total_cost_usd field?)", audit.CostUSD, audit.CostAvailable)
	}
	wantCommand := "test -f output/result.txt"
	found := false
	for _, cmd := range audit.Commands {
		if cmd == wantCommand {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("glm Bash tool_use command not extracted (drift in tool_use/name/input.command shape?): commands=%v", audit.Commands)
	}
	if len(audit.Commands) != 1 {
		t.Fatalf("expected exactly one Bash command, got %v", audit.Commands)
	}
	if !audit.Usage.Available {
		t.Fatalf("glm usage not extracted (drift in usage/tokens envelope?): %+v", audit.Usage)
	}
	if audit.Usage.InputTokens != 3982 || audit.Usage.OutputTokens != 150 || audit.Usage.ReasoningTokens != 15 {
		t.Fatalf("glm usage mis-summed from per-message + result envelopes: %+v", audit.Usage)
	}
	if audit.ToolCalls != 3 {
		t.Fatalf("glm tool-call count (Read+Bash+Write) mis-counted: tool_calls=%d", audit.ToolCalls)
	}
	if len(audit.Violations) != 0 {
		t.Fatalf("expected no violations from the golden transcript, got: %v", audit.Violations)
	}
}
