//go:build redteam

package redteam

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/dbtime"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/quota"
	"github.com/cousingary/governator/internal/spend"
	_ "modernc.org/sqlite"
)

func TestV14Case304ValidFractionalSpendReservationSurvivesEarlierWholeSecondSweep(t *testing.T) {
	db := openV14SpendLedger(t)
	defer db.Close()
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	expires := now.Add(500 * time.Millisecond)
	expiresNanos, _ := dbtime.ToUnixNano(expires)
	createdNanos, _ := dbtime.ToUnixNano(now)
	if _, err := db.Exec(`INSERT INTO spend_reservations(run_id,day,estimated_usd,status,expires_at,created_at,expires_unix_nano,created_unix_nano,settled_unix_nano) VALUES('run-304','2026-07-28',1.0,'pending',?,?,?,?,?)`,
		dbtime.FormatLegacy(expires), dbtime.FormatLegacy(now), expiresNanos, createdNanos, dbtime.UnsetUnixNano); err != nil {
		t.Fatal(err)
	}
	cfg := config.BuiltIn()
	cfg.Spend.DailyCapUSD = 0
	_, ok, reason, err := spend.ReserveGlobal(db, cfg, "run-304b", 0.5, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("reservation refused after premature expiry: %s", reason)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM spend_reservations WHERE run_id='run-304'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("valid fractional reservation was expired at earlier whole second: status=%s", status)
	}
}

func TestV14Case305ValidFractionalQuotaReservationSurvivesEarlierWholeSecondSweep(t *testing.T) {
	db := openV14SpendLedger(t)
	defer db.Close()
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	reset := now.Add(24 * time.Hour)
	seedQuotaWindow(t, db, "claude", now, reset, 1000)
	expires := now.Add(500 * time.Millisecond)
	expiresNanos, _ := dbtime.ToUnixNano(expires)
	createdNanos, _ := dbtime.ToUnixNano(now)
	if _, err := db.Exec(`INSERT INTO quota_reservations(run_id,backend,account,usage,expires_at,created_at,settled_at,expires_unix_nano,created_unix_nano,settled_unix_nano) VALUES('run-305','claude','default',10,?,?,?,?,?,?)`,
		dbtime.FormatLegacy(expires), dbtime.FormatLegacy(now), "", expiresNanos, createdNanos, dbtime.UnsetUnixNano); err != nil {
		t.Fatal(err)
	}
	if err := quota.ExpireStale(db, now); err != nil {
		t.Fatal(err)
	}
	var settled string
	if err := db.QueryRow(`SELECT settled_at FROM quota_reservations WHERE run_id='run-305'`).Scan(&settled); err != nil {
		t.Fatal(err)
	}
	if settled != "" {
		t.Fatalf("valid fractional quota reservation was expired at earlier whole second: settled_at=%s", settled)
	}
}

func TestV14Case306FutureFractionalQuotaResetIsNotSelectedAtEarlierWholeSecond(t *testing.T) {
	db := openV14SpendLedger(t)
	defer db.Close()
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	resetFractional := now.Add(500 * time.Millisecond)
	seedQuotaWindow(t, db, "claude", now, resetFractional, 1000)
	if _, err := db.Exec(`UPDATE quota_windows SET measured_usage=500, reserved_usage=200 WHERE backend='claude'`); err != nil {
		t.Fatal(err)
	}
	next := quota.NextReset(db, "claude", now)
	if next.IsZero() {
		t.Fatal("future fractional reset was not found by NextReset (text ordering bug)")
	}
	if !next.Equal(resetFractional) {
		t.Fatalf("NextReset = %s, want %s", next, resetFractional)
	}
	snap, err := quota.Headroom(db, "claude", "default", now)
	if err != nil {
		t.Fatal(err)
	}
	if snap.MeasuredUsage != 500 || snap.ReservedUsage != 200 {
		t.Fatalf("rollover zeroed usage before true deadline: measured=%.0f reserved=%.0f", snap.MeasuredUsage, snap.ReservedUsage)
	}
}

func TestV14Case307TwoConcurrentReservationsAfterPrematureExpiryTrapDoNotDoubleSpend(t *testing.T) {
	db := openV14SpendLedger(t)
	defer db.Close()
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	expires := now.Add(500 * time.Millisecond)
	expiresNanos, _ := dbtime.ToUnixNano(expires)
	createdNanos, _ := dbtime.ToUnixNano(now)
	if _, err := db.Exec(`INSERT INTO spend_reservations(run_id,day,estimated_usd,status,expires_at,created_at,expires_unix_nano,created_unix_nano,settled_unix_nano) VALUES('run-307','2026-07-28',0.90,'pending',?,?,?,?,?)`,
		dbtime.FormatLegacy(expires), dbtime.FormatLegacy(now), expiresNanos, createdNanos, dbtime.UnsetUnixNano); err != nil {
		t.Fatal(err)
	}
	cfg := config.BuiltIn()
	cfg.Spend.DailyCapUSD = 1.00
	var wg sync.WaitGroup
	oks := make([]bool, 2)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			defer wg.Done()
			_, ok, _, err := spend.ReserveGlobal(db, cfg, fmt.Sprintf("run-307-%d", i), 0.50, time.Hour, now)
			if err != nil {
				t.Error(err)
				return
			}
			oks[i] = ok
		}(i)
	}
	wg.Wait()
	if oks[0] && oks[1] {
		t.Fatal("both concurrent reservations succeeded past the cap after premature expiry trap")
	}
}

func TestV14Case308DailySpendCapCannotBeExceededThroughPrematureExpiry(t *testing.T) {
	db := openV14SpendLedger(t)
	defer db.Close()
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	cfg := config.BuiltIn()
	cfg.Spend.DailyCapUSD = 1.00
	expires := now.Add(500 * time.Millisecond)
	expiresNanos, _ := dbtime.ToUnixNano(expires)
	createdNanos, _ := dbtime.ToUnixNano(now)
	if _, err := db.Exec(`INSERT INTO spend_reservations(run_id,day,estimated_usd,status,expires_at,created_at,expires_unix_nano,created_unix_nano,settled_unix_nano) VALUES('run-308','2026-07-28',0.80,'pending',?,?,?,?,?)`,
		dbtime.FormatLegacy(expires), dbtime.FormatLegacy(now), expiresNanos, createdNanos, dbtime.UnsetUnixNano); err != nil {
		t.Fatal(err)
	}
	_, ok, _, err := spend.ReserveGlobal(db, cfg, "run-308b", 0.50, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("daily spend cap exceeded through premature expiry: reserved $0.80 + $0.50 > $1.00 cap")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM spend_reservations WHERE day='2026-07-28' AND status='pending'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("pending reservations = %d, want 1 (the original valid reservation)", count)
	}
}

func TestV14Case309QuotaHeadroomCannotResetBeforeTrueDeadline(t *testing.T) {
	db := openV14SpendLedger(t)
	defer db.Close()
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	resetFractional := now.Add(500 * time.Millisecond)
	seedQuotaWindow(t, db, "claude", now, resetFractional, 100)
	if _, err := db.Exec(`UPDATE quota_windows SET measured_usage=90, reserved_usage=5 WHERE backend='claude'`); err != nil {
		t.Fatal(err)
	}
	_, err := quota.Reserve(db, "claude", "default", "run-309", 10, time.Hour, now)
	if err == nil {
		t.Fatal("quota reservation succeeded after premature rollover zeroed usage before true deadline")
	}
	snap, err := quota.Headroom(db, "claude", "default", now)
	if err != nil {
		t.Fatal(err)
	}
	if snap.MeasuredUsage != 90 || snap.ReservedUsage != 5 {
		t.Fatalf("usage was zeroed before true deadline: measured=%.0f reserved=%.0f", snap.MeasuredUsage, snap.ReservedUsage)
	}
}

func openV14SpendLedger(t *testing.T) *sql.DB {
	t.Helper()
	db, err := observability.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func seedQuotaWindow(t *testing.T, db *sql.DB, backend string, started, reset time.Time, limit float64) {
	t.Helper()
	startedNanos, _ := dbtime.ToUnixNano(started)
	resetNanos, _ := dbtime.ToUnixNano(reset)
	if _, err := db.Exec(`INSERT INTO quota_windows(backend,account,window_type,window_started_at,reset_at,estimated_limit,measured_usage,reserved_usage,confidence,source,updated_at,window_started_unix_nano,reset_unix_nano,updated_unix_nano)
VALUES(?,'default','daily',?,?,?,0,0,0.9,'config',?,?,?,?)`,
		backend, dbtime.FormatLegacy(started), dbtime.FormatLegacy(reset), limit, dbtime.FormatLegacy(started), startedNanos, resetNanos, startedNanos); err != nil {
		t.Fatal(err)
	}
}
