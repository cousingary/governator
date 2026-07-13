package runtime

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/observability"
)

// TestSol3ConcurrentReconcilersNeverDoubleApplyBreakerFailure reproduces
// audit corpus #15 / finding #12: two `gov reconcile` processes racing the
// same maintenance_outbox rows. breaker.RecordFailure is a load-mutate-save
// counter increment plus an unconditional breaker_events insert — running it
// twice for the same logical failure is exactly the kind of non-idempotent
// double-apply finding #12 names. Before Sol P1.5's leasing, both goroutines
// called the unclaimed PendingOutbox() and could both dispatch the same row;
// after it, ClaimOutbox's single conditional UPDATE means only one ever
// claims a given row, so exactly one breaker_events row is written per
// enqueued failure — never two, never zero.
func TestSol3ConcurrentReconcilersNeverDoubleApplyBreakerFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)

	db, err := dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	const n = 30
	for i := 0; i < n; i++ {
		payload := `{"agent":"claude-code","failure_kind":"RATE_LIMIT"}`
		if err := observability.EnqueueOutbox(db, fmt.Sprintf("run-%d", i), opBreakerFailure, payload, now); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := Reconcile(context.Background()); err != nil {
				errs <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Reconcile: %v", err)
	}

	// A third pass proves the outbox actually drained (nothing left
	// "processing" under an expired or orphaned lease).
	if _, err := Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile (drain pass): %v", err)
	}

	db, err = dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var eventCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM breaker_events WHERE backend='claude-code'`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != n {
		t.Fatalf("breaker_events rows = %d, want exactly %d (a count above %d means at least one outbox row was double-applied by the two concurrent reconcilers)", eventCount, n, n)
	}

	pending, err := observability.PendingOutbox(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected every row drained, got %+v", pending)
	}
	var processing int
	if err := db.QueryRow(`SELECT COUNT(*) FROM maintenance_outbox WHERE status='processing'`).Scan(&processing); err != nil {
		t.Fatal(err)
	}
	if processing != 0 {
		t.Fatalf("expected no rows left claimed/processing, got %d", processing)
	}
	var done int
	if err := db.QueryRow(`SELECT COUNT(*) FROM maintenance_outbox WHERE status='done'`).Scan(&done); err != nil {
		t.Fatal(err)
	}
	if done != n {
		t.Fatalf("done rows = %d, want %d", done, n)
	}
}

// TestSol3ClaimOutboxNeverDoubleClaimsAcrossTwoConnections is a lower-level
// companion to the Reconcile-level test above: two independent *sql.DB
// connections opened against the same on-disk ledger (standing in for two
// separate gov reconcile processes, not just two goroutines sharing a pool)
// race ClaimOutbox directly. The set of claimed IDs across both must be
// exactly the enqueued set, with zero overlap.
func TestSol3ClaimOutboxNeverDoubleClaimsAcrossTwoConnections(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)

	db1, err := dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	const n = 40
	for i := 0; i < n; i++ {
		if err := observability.EnqueueOutbox(db1, fmt.Sprintf("run-%d", i), "not_a_real_op", `{}`, now); err != nil {
			t.Fatal(err)
		}
	}

	db2, err := dbOpen(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db1.Close()
	defer db2.Close()

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[int64]int{}
	claim := func(db *sql.DB, owner string) {
		defer wg.Done()
		leaseUntil := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)
		items, err := observability.ClaimOutbox(db, owner, n, time.Now().UTC().Format(time.RFC3339Nano), leaseUntil)
		if err != nil {
			mu.Lock()
			t.Errorf("ClaimOutbox(%s): %v", owner, err)
			mu.Unlock()
			return
		}
		mu.Lock()
		for _, it := range items {
			seen[it.ID]++
		}
		mu.Unlock()
	}
	wg.Add(2)
	go claim(db1, "owner-1")
	go claim(db2, "owner-2")
	wg.Wait()

	if len(seen) != n {
		t.Fatalf("claimed %d distinct ids, want %d: %+v", len(seen), n, seen)
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("outbox row %d claimed %d times by the two racing connections, want exactly 1", id, count)
		}
	}
}
