package main

import (
	"testing"

	"github.com/cousingary/governator/internal/observability"
	govruntime "github.com/cousingary/governator/internal/runtime"
)

// TestRecordHookDecisionWritesHookEventsOnly is Finding #5: hook audit rows
// must land in their own hook_events table, never in `violations` — that
// table feeds Phase-4 repair packets and ClassifyFailure, and audit rows
// there would displace/corrupt real violation data.
func TestRecordHookDecisionWritesHookEventsOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)

	allowIn := govruntime.GateInput{ToolName: "Bash", ToolInput: map[string]any{"command": "ls -la"}}
	allowDecision := govruntime.GateDecision{Allow: true, Finding: "F3"}
	recordHookDecision("run-allow", allowIn, allowDecision)

	denyIn := govruntime.GateInput{ToolName: "Bash", ToolInput: map[string]any{"command": "rm -rf /tmp/x"}}
	denyDecision := govruntime.GateDecision{Allow: false, Finding: "F1", Reason: "blocked"}
	recordHookDecision("run-deny", denyIn, denyDecision)

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var hookEvents int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hook_events`).Scan(&hookEvents); err != nil {
		t.Fatal(err)
	}
	if hookEvents != 2 {
		t.Fatalf("expected 2 hook_events rows, got %d", hookEvents)
	}

	var violations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM violations`).Scan(&violations); err != nil {
		t.Fatal(err)
	}
	if violations != 0 {
		t.Fatalf("expected 0 violations rows, got %d", violations)
	}

	var decision string
	if err := db.QueryRow(`SELECT decision FROM hook_events WHERE run_id='run-deny'`).Scan(&decision); err != nil {
		t.Fatal(err)
	}
	if decision != "deny" {
		t.Fatalf("expected deny decision recorded, got %s", decision)
	}
}
