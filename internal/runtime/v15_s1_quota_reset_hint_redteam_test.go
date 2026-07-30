//go:build redteam

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/observability"
)

// TestV15Case351MalformedProviderResetHintIsDroppedWithoutFailingTheRun
// (Sol15 P0-3, "validate provider reset hints before persistence"): a
// provider response is adversarial input by definition. Before this
// session, quota.ApplyResetHint routed a malformed/out-of-range hint into
// quota.mustNanos and panicked. After: it returns a typed
// quota.ErrResetHintOutOfRange, and dispatchReconcile drops the row (marks
// it done) instead of retrying it forever -- an out-of-range hint can never
// become valid on a later attempt, so retrying is pure waste and a hostile
// provider must not be able to use it to keep a maintenance_outbox row
// perpetually retrying.
func TestV15Case351MalformedProviderResetHintIsDroppedWithoutFailingTheRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	db, err := dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"agent":"claude-code","account":"default","reset_at":"9999-01-01T00:00:00Z"}`
	if err := observability.EnqueueOutbox(db, "run-351", opQuotaResetHint, payload, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	db.Close()

	report, err := Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Processed != 1 || report.Retried != 0 || report.Done != 1 {
		t.Fatalf("expected the malformed reset hint to be dropped (done, not retried), got: %+v", report)
	}
	if len(report.Outcomes) != 1 || report.Outcomes[0].Status != "done" {
		t.Fatalf("expected outcome status done, got: %+v", report.Outcomes)
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
	if len(pending) != 0 {
		t.Fatalf("malformed reset hint left a row retrying forever: %+v", pending)
	}
}
