package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/breaker"
	"github.com/cousingary/governator/internal/observability"
)

func TestReconcileDrainsBreakerFeedback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	db, err := dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := observability.EnqueueOutbox(db, "run-1", opBreakerFailure, `{"agent":"claude-code","failure_kind":"RATE_LIMIT"}`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	db.Close()

	report, err := Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Processed != 1 || report.Done != 1 || report.Retried != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}

	db, err = dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec := breaker.Snapshot(db, "claude-code", time.Now().UTC())
	if rec.PersistedState == breaker.Closed {
		t.Fatalf("expected breaker feedback to have opened/degraded the backend, got %+v", rec)
	}
	pending, err := observability.PendingOutbox(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected the drained row to leave no pending work, got %+v", pending)
	}
}

func TestReconcileRetriesUnknownOpKind(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	db, err := dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := observability.EnqueueOutbox(db, "run-2", "not_a_real_op", `{}`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	db.Close()

	report, err := Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Processed != 1 || report.Retried != 1 || report.Done != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}

	db, err = dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pending, err := observability.PendingOutbox(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Attempts != 1 {
		t.Fatalf("expected the unknown op_kind to stay pending with attempts incremented, got %+v", pending)
	}
}

func TestReconcileWorkspaceDestroyRemovesLeftoverWorktree(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	worktree := filepath.Join(t.TempDir(), "leftover")
	if err := os.MkdirAll(worktree, 0700); err != nil {
		t.Fatal(err)
	}

	db, err := dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"path":"` + worktree + `","approved":false}`
	if err := observability.EnqueueOutbox(db, "run-3", opWorkspaceDestroy, payload, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	db.Close()

	report, err := Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Done != 1 {
		t.Fatalf("expected the workspace destroy to succeed, got %+v", report)
	}
	if _, err := os.Stat(worktree); !os.IsNotExist(err) {
		t.Fatalf("expected leftover worktree to be removed, stat err=%v", err)
	}
}

func TestCleanupStaleMarksDeadAfterMaxAttempts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	db, err := dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := observability.EnqueueOutbox(db, "run-4", "not_a_real_op", `{}`, now); err != nil {
		t.Fatal(err)
	}
	pending, err := observability.PendingOutbox(db)
	if err != nil {
		t.Fatal(err)
	}
	id := pending[0].ID
	for i := 0; i < 3; i++ {
		if err := observability.MarkOutboxRetry(db, id, "still failing", now); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	report, err := CleanupStale(3)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deadened != 1 || len(report.IDs) != 1 || report.IDs[0] != id {
		t.Fatalf("unexpected cleanup report: %+v", report)
	}

	db, err = dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pending, err = observability.PendingOutbox(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected the dead row to no longer be pending, got %+v", pending)
	}
	counts, err := observability.OutboxCounts(db)
	if err != nil {
		t.Fatal(err)
	}
	if counts["dead"] != 1 {
		t.Fatalf("expected 1 dead row, got counts=%+v", counts)
	}

	// A row below the threshold stays pending.
	report, err = CleanupStale(100)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deadened != 0 {
		t.Fatalf("expected no rows deadened at a higher threshold, got %+v", report)
	}
}

func TestReconcileDrainsQuotaRelease(t *testing.T) {
	// A failed deferred quota.Release (runOnce's teardown) is queued as
	// quota_release work; reconcile must actually release the reservation
	// so headroom returns before the TTL would have healed it.
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	db, err := dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// Seed an open reservation directly (quota.Reserve no-ops without a
	// configured window; the dispatch under test is Release, not Reserve).
	sqlRes, err := db.Exec(`INSERT INTO quota_reservations(run_id,backend,account,usage,expires_at,created_at,settled_at) VALUES('run-q','claude-code','default',100,?,?,'')`,
		now.Add(time.Hour).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	resID, err := sqlRes.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"reservation_id":%d}`, resID)
	if err := observability.EnqueueOutbox(db, "run-q", opQuotaRelease, payload, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	db.Close()

	report, err := Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Processed != 1 || report.Done != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}

	db, err = dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var settled string
	if err := db.QueryRow(`SELECT settled_at FROM quota_reservations WHERE id=?`, resID).Scan(&settled); err != nil {
		t.Fatal(err)
	}
	if settled == "" {
		t.Fatal("expected reconcile to release (settle) the reservation")
	}
}
