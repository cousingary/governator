package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
)

// writeConformanceFixture writes lines (already-JSON-encoded strings, one
// per line) to a temp transcript file and returns its path.
func writeConformanceFixture(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// permissiveContract allows everything the conforming fixtures below do, so
// only conformance findings (never allowlist/temporal-rule findings) show up
// in RuleViolations.
func permissiveContract() contracts.Contract {
	return contracts.Contract{
		Allowed: contracts.Permissions{Execute: []string{"*"}, Read: []string{"**"}},
		Budget:  contracts.Budget{MaxCommands: 100},
	}
}

// TestSol3TranscriptConformanceCorpusSingleBenignEventBlocked is the direct
// corpus reproduction for finding #15: "a malicious or incompatible wrapper
// can perform hidden operations and emit one benign event... any Codex
// item.* event or a Pi event with a tool name" used to be sufficient to
// establish transcript completeness (recognizedTranscriptEvent alone). With
// doctrine.transcript_conformance_action: block, a transcript containing
// only that one benign mid-stream event (no completion event, and for
// Claude/GLM no session-start event either) must now fail.
func TestSol3TranscriptConformanceCorpusSingleBenignEventBlocked(t *testing.T) {
	tests := []struct {
		name   string
		format string
		line   string
	}{
		{"claude-lone-tool-use", agents.TranscriptClaude, `{"type":"tool_use","name":"Bash","input":{"command":"git status"}}`},
		{"glm-lone-tool-use", agents.TranscriptGLM, `{"type":"tool_use","name":"Bash","input":{"command":"git status"}}`},
		{"codex-lone-item", agents.TranscriptCodex, `{"type":"item.completed","item":{"type":"command_execution","command":"git status"}}`},
		{"opencode-lone-tool", agents.TranscriptOpenCode, `{"type":"tool","tool":"bash","state":{"input":{"command":"git status"}}}`},
		{"pi-lone-tool-event", agents.TranscriptPi, `{"type":"tool_execution_start","toolName":"bash","args":{"command":"git status"}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConformanceFixture(t, tc.line)
			audit := auditTranscript(path, tc.format, "", permissiveContract(), nil, "", "block")
			if len(audit.Violations) == 0 {
				t.Fatalf("a lone benign %s event must not establish transcript completeness under block mode, got no violations", tc.format)
			}
			joined := strings.Join(audit.Violations, "; ")
			if !strings.Contains(joined, "transcript-completion-missing") {
				t.Fatalf("expected a missing-completion violation, got: %v", audit.Violations)
			}
		})
	}
}

// TestSol3TranscriptConformanceDefaultIsAdvisoryOnly proves the two-tier
// posture: the exact same lone-benign-event transcripts from the test above
// produce advisory RuleViolations (visible, ledgered) under the default
// config, but never fold into the blocking audit.Violations list — no
// existing run's outcome changes just because this session's checks now
// exist, mirroring Session 6's unenforceable-rule default.
func TestSol3TranscriptConformanceDefaultIsAdvisoryOnly(t *testing.T) {
	path := writeConformanceFixture(t, `{"type":"item.completed","item":{"type":"command_execution","command":"git status"}}`)
	audit := auditTranscript(path, agents.TranscriptCodex, "", permissiveContract(), nil, "", "")
	if len(audit.Violations) != 0 {
		t.Fatalf("default (flag) action must never block on a conformance gap, got: %v", audit.Violations)
	}
	found := false
	for _, rv := range audit.RuleViolations {
		if rv.Rule == ruleTranscriptCompletionMissing {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an advisory transcript-completion-missing RuleViolation, got: %+v", audit.RuleViolations)
	}
}

// TestSol3TranscriptConformanceConformingFixturesPass is the "no
// over-blocking of real backends" acceptance check: one conforming fixture
// per adapter must produce zero conformance findings, under block mode too
// (the strictest setting), for both the Claude fixture (shaped on 13 real
// `gov run` transcripts captured on this machine under
// ~/.governator/transcripts/ — session/init, a paired tool_use/tool_result,
// a trailing result with num_turns >= observed tool calls) and GLM (the
// pre-existing golden fixture, testdata/glm_stream.jsonl, which predates
// this session). Codex/OpenCode/Pi fixtures are shaped on this codebase's
// own pre-existing recognizedTranscriptEvent vocabulary — the only
// dimension checked for them (a completion event) is the one dimension that
// vocabulary names unambiguously; see the capability-table comment in
// sol3_transcript_conformance.go for what remains unattested for these
// three formats.
func TestSol3TranscriptConformanceConformingFixturesPass(t *testing.T) {
	tests := []struct {
		name   string
		format string
		path   string
		lines  []string
	}{
		{
			name:   "claude",
			format: agents.TranscriptClaude,
			lines: []string{
				`{"type":"system","subtype":"init","session_id":"sess-1","uuid":"u0"}`,
				`{"type":"assistant","session_id":"sess-1","uuid":"u1","message":{"content":[{"type":"tool_use","id":"tu-1","name":"Bash","input":{"command":"git status"}}]}}`,
				`{"type":"user","session_id":"sess-1","uuid":"u2","message":{"content":[{"type":"tool_result","tool_use_id":"tu-1","content":"clean"}]}}`,
				`{"type":"assistant","session_id":"sess-1","uuid":"u3","message":{"content":[{"type":"text","text":"done"}]}}`,
				`{"type":"result","subtype":"success","session_id":"sess-1","uuid":"u4","num_turns":2,"total_cost_usd":0.01}`,
			},
		},
		{
			name:   "glm",
			format: agents.TranscriptGLM,
			path:   "testdata/glm_stream.jsonl",
		},
		{
			name:   "codex",
			format: agents.TranscriptCodex,
			lines: []string{
				`{"type":"item.completed","item":{"type":"command_execution","command":"git status"}}`,
				`{"type":"turn.completed"}`,
			},
		},
		{
			name:   "opencode",
			format: agents.TranscriptOpenCode,
			lines: []string{
				`{"type":"tool","tool":"bash","state":{"input":{"command":"git status"}}}`,
				`{"type":"result"}`,
			},
		},
		{
			name:   "pi",
			format: agents.TranscriptPi,
			lines: []string{
				`{"type":"tool_execution_start","toolName":"bash","args":{"command":"git status"}}`,
				`{"type":"done"}`,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path
			if path == "" {
				path = writeConformanceFixture(t, tc.lines...)
			}
			audit := auditTranscript(path, tc.format, "", permissiveContract(), nil, "", "block")
			if len(audit.Violations) != 0 {
				t.Fatalf("conforming %s fixture must not be blocked even under block mode: %v", tc.name, audit.Violations)
			}
		})
	}
}

// TestSol3TranscriptConformanceSessionIdentityMixedBlocks is the
// backend-process-identity-binding regression: a transcript whose init event
// declares one session_id, but a later event carries a different one (a
// spliced/foreign line), must be caught even though every individual line is
// otherwise well-formed and recognizable.
func TestSol3TranscriptConformanceSessionIdentityMixedBlocks(t *testing.T) {
	path := writeConformanceFixture(t,
		`{"type":"system","subtype":"init","session_id":"sess-real"}`,
		`{"type":"tool_use","name":"Bash","session_id":"sess-real","input":{"command":"git status"}}`,
		`{"type":"tool_use","name":"Bash","session_id":"sess-FOREIGN","input":{"command":"rm -rf /tmp/x"}}`,
		`{"type":"result","session_id":"sess-real"}`,
	)
	audit := auditTranscript(path, agents.TranscriptClaude, "", permissiveContract(), nil, "", "block")
	joined := strings.Join(audit.Violations, "; ")
	if !strings.Contains(joined, ruleTranscriptSessionIdentityMixed) {
		t.Fatalf("expected a session-identity-mixed violation, got: %v", audit.Violations)
	}
}

// TestSol3TranscriptConformanceUnpairedToolUseBlocks is the tool-start/
// tool-result pairing regression: a tool_use with no matching tool_result
// (the agent's actual output for that call was never recorded, or was
// suppressed) must be caught even when a completion event is present.
func TestSol3TranscriptConformanceUnpairedToolUseBlocks(t *testing.T) {
	path := writeConformanceFixture(t,
		`{"type":"system","subtype":"init","session_id":"sess-1"}`,
		`{"type":"tool_use","id":"tu-1","name":"Bash","input":{"command":"git status"}}`,
		`{"type":"result","session_id":"sess-1"}`,
	)
	audit := auditTranscript(path, agents.TranscriptClaude, "", permissiveContract(), nil, "", "block")
	joined := strings.Join(audit.Violations, "; ")
	if !strings.Contains(joined, ruleTranscriptToolPairingMismatch) {
		t.Fatalf("expected a tool-pairing-mismatch violation for an unpaired tool_use, got: %v", audit.Violations)
	}
}

// TestSol3TranscriptConformanceTurnCountShortBlocks is the command/tool
// count reconciliation regression: a completion event that declares fewer
// turns than the number of distinct tool calls actually observed in the
// transcript is inconsistent with itself.
func TestSol3TranscriptConformanceTurnCountShortBlocks(t *testing.T) {
	path := writeConformanceFixture(t,
		`{"type":"system","subtype":"init","session_id":"sess-1"}`,
		`{"type":"tool_use","id":"tu-1","name":"Bash","input":{"command":"git status"}}`,
		`{"type":"tool_result","tool_use_id":"tu-1","content":"ok"}`,
		`{"type":"tool_use","id":"tu-2","name":"Bash","input":{"command":"ls"}}`,
		`{"type":"tool_result","tool_use_id":"tu-2","content":"ok"}`,
		`{"type":"result","session_id":"sess-1","num_turns":1}`,
	)
	audit := auditTranscript(path, agents.TranscriptClaude, "", permissiveContract(), nil, "", "block")
	joined := strings.Join(audit.Violations, "; ")
	if !strings.Contains(joined, ruleTranscriptTurnCountShort) {
		t.Fatalf("expected a turn-count-short violation (num_turns=1 declared, 2 tool calls observed), got: %v", audit.Violations)
	}
}

// TestSol3TranscriptConformanceOutOfScopeReadPrecedesWriteStillDenies proves
// this session's addition doesn't disturb the pre-existing Phase 6 temporal
// rule engine's own deny path when both fire on the same transcript: a
// conforming fixture (session-start + paired tool calls + completion) that
// also contains a genuine out-of-scope-read-precedes-write must still deny
// on that rule, on top of (not instead of) any conformance findings.
func TestSol3TranscriptConformanceCoexistsWithTemporalRuleDeny(t *testing.T) {
	path := writeConformanceFixture(t,
		`{"type":"system","subtype":"init","session_id":"sess-1"}`,
		`{"type":"tool_use","id":"tu-1","name":"Read","input":{"file_path":"/etc/passwd"}}`,
		`{"type":"tool_result","tool_use_id":"tu-1","content":"root:x:0:0"}`,
		`{"type":"tool_use","id":"tu-2","name":"Write","input":{"file_path":"workspace/out.go"}}`,
		`{"type":"tool_result","tool_use_id":"tu-2","content":"wrote"}`,
		`{"type":"result","session_id":"sess-1","num_turns":2}`,
	)
	c := contracts.Contract{Allowed: contracts.Permissions{Read: []string{"workspace/**"}, Execute: []string{"*"}}, Budget: contracts.Budget{MaxCommands: 100}}
	audit := auditTranscript(path, agents.TranscriptClaude, "", c, nil, "", "block")
	joined := strings.Join(audit.Violations, "; ")
	if !strings.Contains(joined, "out-of-scope-read-precedes-write") {
		t.Fatalf("expected the pre-existing temporal rule to still deny, got: %v", audit.Violations)
	}
	// No conformance finding should fire — this fixture is otherwise complete.
	for _, rv := range audit.RuleViolations {
		if strings.HasPrefix(rv.Rule, "transcript-") {
			t.Fatalf("conforming fixture unexpectedly produced a conformance finding: %+v", rv)
		}
	}
}
