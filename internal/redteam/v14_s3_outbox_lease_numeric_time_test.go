//go:build redteam

package redteam

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/dbtime"
	"github.com/cousingary/governator/internal/observability"
	_ "modernc.org/sqlite"
)

func TestV14Case310ActiveFractionalLeaseIsNotReclaimedAtEarlierWholeSecond(t *testing.T) {
	db := openV14OutboxLedger(t)
	defer db.Close()

	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	leaseUntil := now.Add(500 * time.Millisecond)
	leaseUntilNanos, _ := dbtime.ToUnixNano(leaseUntil)
	nowNanos, _ := dbtime.ToUnixNano(now)

	if _, err := db.Exec(`INSERT INTO maintenance_outbox(run_id,op_kind,payload,status,attempts,last_error,created_at,updated_at,lease_owner,lease_until,created_unix_nano,updated_unix_nano,lease_until_unix_nano)
VALUES('run-310','breaker_record_failure','{}','processing',0,'',?,?,?, ?,?,?,?)`,
		dbtime.FormatLegacy(now), dbtime.FormatLegacy(now), "owner-A", dbtime.FormatLegacy(leaseUntil),
		nowNanos, nowNanos, leaseUntilNanos); err != nil {
		t.Fatal(err)
	}

	items, err := observability.ClaimOutbox(db, "owner-B", 10, dbtime.FormatLegacy(now), dbtime.FormatLegacy(now.Add(5*time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("active fractional lease was reclaimed at earlier whole second: claimed %d rows", len(items))
	}
}

func TestV14Case311TwoReconcilersCannotDispatchTheSameOperation(t *testing.T) {
	db := openV14OutboxLedger(t)
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := observability.EnqueueOutbox(db, "run-311", "breaker_record_failure", `{"agent":"claude-code","failure_kind":"RATE_LIMIT"}`, now); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	claimedCount := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := fmt.Sprintf("owner-%d", i)
			items, err := observability.ClaimOutbox(db, owner, 10, time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339Nano))
			if err != nil {
				t.Error(err)
				return
			}
			for _, item := range items {
				got, err := observability.ClaimOutboxExecution(db, item.ID, time.Now().UTC().Format(time.RFC3339Nano))
				if err != nil {
					t.Error(err)
					return
				}
				if got {
					mu.Lock()
					claimedCount++
					mu.Unlock()
				}
			}
		}(i)
	}
	wg.Wait()
	if claimedCount != 1 {
		t.Fatalf("execution claimed %d times, want exactly 1 (double-dispatch)", claimedCount)
	}
}

func TestV14Case312LeaseComparisonSurvivesWholeFractionalBoundary(t *testing.T) {
	db := openV14OutboxLedger(t)
	defer db.Close()

	base := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	leaseUntil := base.Add(500 * time.Millisecond)
	leaseUntilNanos, _ := dbtime.ToUnixNano(leaseUntil)
	baseNanos, _ := dbtime.ToUnixNano(base)

	if _, err := db.Exec(`INSERT INTO maintenance_outbox(run_id,op_kind,payload,status,attempts,last_error,created_at,updated_at,lease_owner,lease_until,created_unix_nano,updated_unix_nano,lease_until_unix_nano)
VALUES('run-312','quota_settle','{}','processing',0,'',?,?,?, ?,?,?,?)`,
		dbtime.FormatLegacy(base), dbtime.FormatLegacy(base), "owner-X", dbtime.FormatLegacy(leaseUntil),
		baseNanos, baseNanos, leaseUntilNanos); err != nil {
		t.Fatal(err)
	}

	reclaimTime := base.Add(250 * time.Millisecond)
	items, err := observability.ClaimOutbox(db, "owner-Y", 10, dbtime.FormatLegacy(reclaimTime), dbtime.FormatLegacy(reclaimTime.Add(5*time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatal("lease reclaimed before its true numeric expiry (whole/fractional boundary)")
	}

	afterExpiry := leaseUntil.Add(1 * time.Millisecond)
	items, err = observability.ClaimOutbox(db, "owner-Y", 10, dbtime.FormatLegacy(afterExpiry), dbtime.FormatLegacy(afterExpiry.Add(5*time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expired lease was not reclaimable after true numeric expiry: got %d items", len(items))
	}
}

func TestV14Case313DuplicateBreakerOperationIsRejected(t *testing.T) {
	db := openV14OutboxLedger(t)
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := observability.EnqueueOutbox(db, "run-313", "breaker_record_failure", `{"agent":"claude-code","failure_kind":"RATE_LIMIT"}`, now); err != nil {
		t.Fatal(err)
	}
	items, err := observability.ClaimOutbox(db, "owner-1", 10, now, time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 claimed item, got %d", len(items))
	}

	first, err := observability.ClaimOutboxExecution(db, items[0].ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Fatal("first execution claim should succeed")
	}
	second, err := observability.ClaimOutboxExecution(db, items[0].ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("duplicate breaker operation was not rejected: second execution claim succeeded")
	}
}

func TestV14Case314DuplicateQuotaSettlementIsRejected(t *testing.T) {
	db := openV14OutboxLedger(t)
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := observability.EnqueueOutbox(db, "run-314", "quota_settle", `{"reservation_id":1,"measured":5}`, now); err != nil {
		t.Fatal(err)
	}
	items, err := observability.ClaimOutbox(db, "owner-1", 10, now, time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 claimed item, got %d", len(items))
	}

	first, err := observability.ClaimOutboxExecution(db, items[0].ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Fatal("first execution claim should succeed")
	}
	second, err := observability.ClaimOutboxExecution(db, items[0].ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("duplicate quota settlement was not rejected: second execution claim succeeded")
	}
}

func TestV14Case315DuplicateSpendSettlementIsRejected(t *testing.T) {
	db := openV14OutboxLedger(t)
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := observability.EnqueueOutbox(db, "run-315", "spend_settle", `{"reservation_id":1,"actual_usd":0.5,"cost_available":true}`, now); err != nil {
		t.Fatal(err)
	}
	items, err := observability.ClaimOutbox(db, "owner-1", 10, now, time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 claimed item, got %d", len(items))
	}

	first, err := observability.ClaimOutboxExecution(db, items[0].ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Fatal("first execution claim should succeed")
	}
	second, err := observability.ClaimOutboxExecution(db, items[0].ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("duplicate spend settlement was not rejected: second execution claim succeeded")
	}
}

func TestV14Case316DuplicateWorkspaceDestructionIsRejected(t *testing.T) {
	db := openV14OutboxLedger(t)
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := observability.EnqueueOutbox(db, "run-316", "workspace_destroy", `{"path":"/tmp/ws-316","root":"/tmp/ws-316","branch":"work","git":false}`, now); err != nil {
		t.Fatal(err)
	}
	items, err := observability.ClaimOutbox(db, "owner-1", 10, now, time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 claimed item, got %d", len(items))
	}

	first, err := observability.ClaimOutboxExecution(db, items[0].ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Fatal("first execution claim should succeed")
	}
	second, err := observability.ClaimOutboxExecution(db, items[0].ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("duplicate workspace destruction was not rejected: second execution claim succeeded")
	}
}

func openV14OutboxLedger(t *testing.T) *sql.DB {
	t.Helper()
	db, err := observability.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return db
}
