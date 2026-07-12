package policy

import "testing"

// TestUnenforceableRulesCodexMissingReadWriteNetwork is the direct
// regression test for Sol High 12's finding: Codex's transcript format
// supplies only EventExec, so both rules that depend on EventRead are
// unenforceable for it, while the rule that only needs
// EventToolOutput+EventExec is also unenforceable (Codex never supplies
// EventToolOutput either).
func TestUnenforceableRulesCodexMissingReadWriteNetwork(t *testing.T) {
	got := UnenforceableRules(formatCodex)
	want := map[string]bool{
		RuleSecretPrecedesNetwork:       true,
		RuleOutOfScopeReadPrecedesWrite: true,
		RuleInjectionPrecedesExec:       true,
	}
	if len(got) != len(want) {
		t.Fatalf("UnenforceableRules(codex) = %v, want exactly %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("unexpected unenforceable rule %q for codex", name)
		}
	}
}

// TestUnenforceableRulesClaudeGLMFullCoverage pins that Claude/GLM, the two
// formats with genuine tool_use/tool_result blocks, have no coverage gap:
// every starter rule remains enforceable.
func TestUnenforceableRulesClaudeGLMFullCoverage(t *testing.T) {
	for _, format := range []string{formatClaude, formatGLM} {
		if got := UnenforceableRules(format); len(got) != 0 {
			t.Errorf("UnenforceableRules(%s) = %v, want none", format, got)
		}
	}
}

// TestUnenforceableRulesOpenCodePiMissingToolOutputOnly pins Session 6's
// generalized OpenCode/Pi event classification: once transcriptEvent mines
// generic tool calls (not just bash) for these formats, EventRead/Write/
// Network are available and only the injection-precedes-exec rule (which
// needs EventToolOutput, never available for these formats) stays
// unenforceable.
func TestUnenforceableRulesOpenCodePiMissingToolOutputOnly(t *testing.T) {
	for _, format := range []string{formatOpenCode, formatPi} {
		got := UnenforceableRules(format)
		if len(got) != 1 || got[0] != RuleInjectionPrecedesExec {
			t.Errorf("UnenforceableRules(%s) = %v, want exactly [%s]", format, got, RuleInjectionPrecedesExec)
		}
	}
}

// TestUnenforceableRulesUnknownFormatEverythingUnenforceable pins the
// fail-closed default: an unrecognized format gets no free pass — every
// rule is treated as unenforceable rather than silently assumed available.
func TestUnenforceableRulesUnknownFormatEverythingUnenforceable(t *testing.T) {
	got := UnenforceableRules("some-future-backend-format")
	if len(got) != len(starterRuleNames) {
		t.Fatalf("UnenforceableRules(unknown) = %v, want all %d starter rules", got, len(starterRuleNames))
	}
}

func TestSupportsEventKind(t *testing.T) {
	if !SupportsEventKind(formatClaude, EventToolOutput) {
		t.Error("claude must support tool_output")
	}
	if SupportsEventKind(formatCodex, EventToolOutput) {
		t.Error("codex must not support tool_output")
	}
	if SupportsEventKind("unknown", EventExec) {
		t.Error("an unrecognized format must not support any event kind")
	}
}
