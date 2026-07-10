package runtime

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

// repairContract returns the shared fixture contract with repair.auto wired
// in, so each test only has to state what differs.
func repairContract(root string, r *contracts.Repair) contracts.Contract {
	c := contract(root)
	c.Repair = r
	return c
}

func TestAutoRepairOffFiresNoRepair(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_ALWAYS_FAIL", "1")

	rec, err := New().RunWithAutoRepair(context.Background(), repairContract(root, nil))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected quarantine, got status=%s message=%s", rec.Status, rec.Message)
	}
	failures, err := observability.Failures(home, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 1 {
		t.Fatalf("repair.auto unset must not fire a repair run, got %d failure rows: %#v", len(failures), failures)
	}
}

func TestAutoRepairFiresExactlyOnceWithDefaultMaxAttempts(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_ALWAYS_FAIL", "1")

	rec, err := New().RunWithAutoRepair(context.Background(), repairContract(root, &contracts.Repair{Auto: true}))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" || rec.RepairOf == "" {
		t.Fatalf("expected the repair attempt itself to quarantine and be linked, got status=%s repair_of=%q", rec.Status, rec.RepairOf)
	}

	failures, err := observability.Failures(home, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 2 {
		t.Fatalf("expected exactly 2 quarantined runs (original + 1 repair), got %d: %#v", len(failures), failures)
	}
	// Failures is ordered created DESC: [0] is the repair, [1] is the original.
	original, repair := failures[1], failures[0]
	if original.RepairOf != "" {
		t.Fatalf("original run must not itself carry repair_of, got %q", original.RepairOf)
	}
	if repair.RepairOf != original.RunID {
		t.Fatalf("repair run repair_of=%q, want original run id %q", repair.RepairOf, original.RunID)
	}
	if repair.RunID == original.RunID {
		t.Fatalf("repair run must be a distinct run from the original")
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	attempts, err := observability.RepairAttempts(db, original.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("RepairAttempts(root) = %d, want 1", attempts)
	}
}

func TestAutoRepairClampsAtTwoAttemptsRegardlessOfYAML(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_ALWAYS_FAIL", "1")

	// max_attempts requests 5; EffectiveMaxAttempts must clamp this to 2.
	rec, err := New().RunWithAutoRepair(context.Background(), repairContract(root, &contracts.Repair{Auto: true, MaxAttempts: 5}))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected final attempt to still quarantine, got %s", rec.Status)
	}

	failures, err := observability.Failures(home, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 3 {
		t.Fatalf("expected exactly 3 quarantined runs (original + 2 repairs, clamped), got %d: %#v", len(failures), failures)
	}
	var rootID string
	for _, f := range failures {
		if f.RepairOf == "" {
			rootID = f.RunID
		}
	}
	if rootID == "" {
		t.Fatal("could not find the lineage root among the failures")
	}
	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if attempts, err := observability.RepairAttempts(db, rootID); err != nil || attempts != 2 {
		t.Fatalf("RepairAttempts(root) = %d err=%v, want 2", attempts, err)
	}
}

func TestAutoRepairStopsOnceApproved(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	marker := filepath.Join(t.TempDir(), "marker")
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_MARKER_FILE", marker) // fails once, then succeeds

	rec, err := New().RunWithAutoRepair(context.Background(), repairContract(root, &contracts.Repair{Auto: true, MaxAttempts: 2}))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected the repair to succeed and stop the loop, got status=%s message=%s", rec.Status, rec.Message)
	}
	if rec.RepairOf == "" {
		t.Fatalf("expected the approved run to still be linked to its repair lineage")
	}

	// Exactly one quarantined run (the original) must remain in evidence;
	// the loop must not have kept trying after the repair was approved.
	failures, err := observability.Failures(home, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 1 {
		t.Fatalf("expected exactly 1 quarantined run (the original), got %d: %#v", len(failures), failures)
	}
	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if attempts, err := observability.RepairAttempts(db, failures[0].RunID); err != nil || attempts != 1 {
		t.Fatalf("RepairAttempts(root) = %d err=%v, want exactly 1 (not a second attempt after approval)", attempts, err)
	}
}

func TestAutoRepairRefusedBySpendCapStopsLoopInsteadOfLooping(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	// The fixture's fake backend always reports $0.25; a $0.20 cap lets the
	// original run launch (today's spend is $0 at that point) but crosses
	// the cap on completion, halting before any repair attempt can launch.
	// The halt file must be sandboxed per test — without this override it
	// defaults to the real ~/.governator/HALT and would halt every other
	// `gov run` on the machine, not just this test's disposable ledger.
	t.Setenv("GOV_SPEND_DAILY_CAP_USD", "0.20")
	t.Setenv("GOV_SPEND_HALT_FILE", filepath.Join(t.TempDir(), "HALT"))
	t.Setenv("FAKE_ALWAYS_FAIL", "1")

	rec, err := New().RunWithAutoRepair(context.Background(), repairContract(root, &contracts.Repair{Auto: true, MaxAttempts: 2}))
	if err != nil {
		t.Fatal(err)
	}
	if rec.FailureTaxonomy != "SPEND_CAP" {
		t.Fatalf("expected the repair attempt to be refused by the spend cap, got taxonomy=%s message=%s", rec.FailureTaxonomy, rec.Message)
	}

	failures, err := observability.Failures(home, 10)
	if err != nil {
		t.Fatal(err)
	}
	// Original (VALIDATION_FAILED) + exactly one spend-refused repair
	// attempt. A refusal must not be retried as if it were an ordinary
	// quarantine that still has attempts remaining.
	if len(failures) != 2 {
		t.Fatalf("expected exactly 2 runs (original + 1 refused repair attempt), got %d: %#v", len(failures), failures)
	}
}

func TestHandoffReportsRepairAttempted(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_ALWAYS_FAIL", "1")

	if _, err := New().RunWithAutoRepair(context.Background(), repairContract(root, &contracts.Repair{Auto: true})); err != nil {
		t.Fatal(err)
	}

	failures, err := observability.Failures(home, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 2 {
		t.Fatalf("setup: expected original + 1 repair, got %d", len(failures))
	}
	var rootID, repairID string
	for _, f := range failures {
		if f.RepairOf == "" {
			rootID = f.RunID
		} else {
			repairID = f.RunID
		}
	}

	rootHandoff, err := HandoffFor(rootID)
	if err != nil {
		t.Fatal(err)
	}
	if rootHandoff.RepairAttempted != 1 {
		t.Fatalf("handoff for the original run: repair_attempted=%d, want 1", rootHandoff.RepairAttempted)
	}
	repairHandoff, err := HandoffFor(repairID)
	if err != nil {
		t.Fatal(err)
	}
	if repairHandoff.RepairAttempted != 1 {
		t.Fatalf("handoff for the repair run: repair_attempted=%d, want 1", repairHandoff.RepairAttempted)
	}
}
