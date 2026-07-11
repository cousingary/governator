package observability

import "testing"

func TestOperationalErrorAndOutboxLifecycle(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := RecordOperationalError(db, OperationalError{
		RunID: "run-1", OpKind: "breaker_record_failure", Detail: "db locked", Created: "2026-07-12T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	if err := EnqueueOutbox(db, "run-1", "breaker_record_failure", `{"agent":"claude"}`, "2026-07-12T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	pending, err := PendingOutbox(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending row, got %d: %+v", len(pending), pending)
	}
	item := pending[0]
	if item.RunID != "run-1" || item.OpKind != "breaker_record_failure" || item.Status != "pending" || item.Attempts != 0 {
		t.Fatalf("unexpected pending row: %+v", item)
	}

	// A failed retry increments attempts and records last_error, but the row
	// stays pending for the next reconcile pass.
	if err := MarkOutboxRetry(db, item.ID, "still locked", "2026-07-12T00:01:00Z"); err != nil {
		t.Fatal(err)
	}
	pending, err = PendingOutbox(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Attempts != 1 || pending[0].LastError != "still locked" {
		t.Fatalf("retry did not update attempts/last_error: %+v", pending)
	}

	// Once attempts crosses the threshold, cleanup finds it as stale.
	stale, err := StaleOutbox(db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || stale[0].ID != item.ID {
		t.Fatalf("expected the retried row to be stale at maxAttempts=1: %+v", stale)
	}
	if err := MarkOutboxDead(db, item.ID, "gave up", "2026-07-12T00:02:00Z"); err != nil {
		t.Fatal(err)
	}

	pending, err = PendingOutbox(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending rows after MarkOutboxDead, got %+v", pending)
	}
	counts, err := OutboxCounts(db)
	if err != nil {
		t.Fatal(err)
	}
	if counts["dead"] != 1 {
		t.Fatalf("expected 1 dead row, got counts=%+v", counts)
	}
}

func TestMarkOutboxDoneRemovesFromPending(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := EnqueueOutbox(db, "run-2", "quota_reset_hint", `{}`, "2026-07-12T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	pending, err := PendingOutbox(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending row, got %d", len(pending))
	}
	if err := MarkOutboxDone(db, pending[0].ID, "2026-07-12T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	pending, err = PendingOutbox(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending rows after MarkOutboxDone, got %+v", pending)
	}
	counts, err := OutboxCounts(db)
	if err != nil {
		t.Fatal(err)
	}
	if counts["done"] != 1 {
		t.Fatalf("expected 1 done row, got counts=%+v", counts)
	}
}
