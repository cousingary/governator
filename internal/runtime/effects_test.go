package runtime

import (
	"context"
	"testing"

	"github.com/cousingary/governator/internal/observability"
)

// TestApprovedRun_RecordsKernelObservedEffectLedger is Sol redteam v4 S9's
// "kernel-observed effect ledger for high-risk local jobs" item, exercised
// end to end: a normal approved run must leave behind process_creation and
// network effect_events rows (recorded right after DESCENDANTS_TERMINATED,
// runtime.go) independent of the run's own transcript/self-report — file
// writes are covered by the pre-existing files_touched table
// (RecordCompletion), not duplicated here.
func TestApprovedRun_RecordsKernelObservedEffectLedger(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)

	c := contract(root)
	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED, got status=%s message=%s", rec.Status, rec.Message)
	}

	db, err := dbOpen(home)
	if err != nil {
		t.Fatalf("dbOpen: %v", err)
	}
	defer db.Close()
	effects, err := observability.EffectsForRun(db, rec.ID)
	if err != nil {
		t.Fatalf("EffectsForRun: %v", err)
	}
	if len(effects) == 0 {
		t.Fatal("expected at least the process_creation/network effect rows this session wires in, got none")
	}
	kinds := map[observability.EffectKind]bool{}
	for _, e := range effects {
		kinds[e.Kind] = true
		if e.RunID != rec.ID {
			t.Fatalf("effect record run_id = %q, want %q", e.RunID, rec.ID)
		}
		if e.Detail == "" {
			t.Fatalf("effect record %s has empty detail", e.Kind)
		}
	}
	if !kinds[observability.EffectProcessCreation] {
		t.Errorf("missing %s effect row", observability.EffectProcessCreation)
	}
	if !kinds[observability.EffectNetwork] {
		t.Errorf("missing %s effect row", observability.EffectNetwork)
	}
}
