package runtime

import (
	"os"
	"path/filepath"
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
			audit := auditTranscript(path, tc.format, contract)
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
