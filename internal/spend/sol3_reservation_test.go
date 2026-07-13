// Sol redteam v3 S9 (P1.4, audit finding #11): the old CheckBudget read
// TodaySpend (which excludes RUNNING rows) with no reservation step at all,
// so two separate `gov run`/`gov batch` processes could both pass before
// either's cost landed, and an unmetered ("cost_unavailable") run counted as
// $0 forever even under a strict cap. ReserveGlobal/SettleGlobal close both
// gaps. These tests spawn real goroutines (and, for the cross-process case,
// two independent *sql.DB connections to the same on-disk ledger, standing
// in for two separate `gov` processes) — not a mocked lock — and must be
// run with -race.
package spend

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/observability"
)

// TestSol3ReserveGlobalConcurrentAcrossTwoConnectionsNeverExceedsCap is
// corpus #8's spend half: two independent *sql.DB handles open the same
// on-disk ledger file (standing in for two separate `gov run` processes
// sharing one ledger.db), and together race 20 reservations of $0.10 each
// against a $1.00 cap. Exactly 10 must succeed.
func TestSol3ReserveGlobalConcurrentAcrossTwoConnectionsNeverExceedsCap(t *testing.T) {
	dbA, home := openLedger(t)
	dbB, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbB.Close() })

	cfg := config.BuiltIn()
	cfg.Spend.DailyCapUSD = 1.00
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	const workers = 20
	var wg sync.WaitGroup
	oks := make([]bool, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			conn := dbA
			if i%2 == 0 {
				conn = dbB
			}
			_, ok, _, err := ReserveGlobal(conn, cfg, fmt.Sprintf("run-%d", i), 0.10, time.Hour, now)
			if err != nil {
				t.Errorf("worker %d: %v", i, err)
				return
			}
			oks[i] = ok
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for _, ok := range oks {
		if ok {
			succeeded++
		}
	}
	if succeeded != 10 {
		t.Fatalf("expected exactly 10 of %d reservations to succeed ($1.00 cap / $0.10 estimate), got %d", workers, succeeded)
	}

	var pendingTotal float64
	if err := dbA.QueryRow(`SELECT COALESCE(SUM(estimated_usd),0) FROM spend_reservations WHERE day=? AND status='pending'`, now.Format("2006-01-02")).Scan(&pendingTotal); err != nil {
		t.Fatal(err)
	}
	if pendingTotal != 1.00 {
		t.Fatalf("pending reserved total=%v, want exactly 1.00 (no overshoot, no undercount)", pendingTotal)
	}
}

// TestSol3SettleGlobalUnknownCostFallsBackToEstimateNotZero verifies the
// fail-closed correction for finding #11: a run whose actual cost telemetry
// is unavailable must settle at its own conservative estimate, not 0, so a
// strict daily cap can't be blown through invisibly by an unmetered
// backend. It also proves the settled fallback actually feeds back into the
// cap: a second reservation that would only fit if the first settled at 0
// must be refused.
func TestSol3SettleGlobalUnknownCostFallsBackToEstimateNotZero(t *testing.T) {
	db, _ := openLedger(t)
	cfg := config.BuiltIn()
	cfg.Spend.DailyCapUSD = 0.30
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	res, ok, reason, err := ReserveGlobal(db, cfg, "run-unmetered", 0.30, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("expected first reservation to succeed, refused: %s", reason)
	}

	// actualUSD=0 but costAvailable=false: the ledger's runs.cost_usd for
	// this run will honestly stay 0 (see TodaySpend's doc comment), but the
	// reservation's own settled actual_usd must fall back to its $0.30
	// estimate, not 0.
	if err := SettleGlobal(db, res.ID, 0, false, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	var status string
	var actual float64
	if err := db.QueryRow(`SELECT status, actual_usd FROM spend_reservations WHERE id=?`, res.ID).Scan(&status, &actual); err != nil {
		t.Fatal(err)
	}
	if status != "settled" || actual != 0.30 {
		t.Fatalf("settled reservation status=%s actual_usd=%v, want status=settled actual_usd=0.30 (the estimate, not 0)", status, actual)
	}

	// The cap is now fully consumed by the unmetered run's settled fallback
	// even though runs.cost_usd (ground truth reporting) never saw a cent —
	// a second reservation of any size must be refused.
	_, ok2, reason2, err := ReserveGlobal(db, cfg, "run-second", 0.01, time.Hour, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ok2 {
		t.Fatal("expected second reservation to be refused: the unmetered run's settled fallback must still count against the cap")
	}
	if reason2 == "" {
		t.Fatal("expected a non-empty refusal reason")
	}
}

// TestSol3SettleGlobalKnownCostUsesActualNotEstimate is the mirror case: a
// run that DOES report a real cost lower than its conservative estimate
// must free up the difference for the rest of the day, not hold the whole
// estimate hostage.
func TestSol3SettleGlobalKnownCostUsesActualNotEstimate(t *testing.T) {
	db, _ := openLedger(t)
	cfg := config.BuiltIn()
	cfg.Spend.DailyCapUSD = 0.30
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	res, ok, reason, err := ReserveGlobal(db, cfg, "run-metered", 0.30, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("expected first reservation to succeed, refused: %s", reason)
	}
	if err := SettleGlobal(db, res.ID, 0.05, true, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	var actual float64
	if err := db.QueryRow(`SELECT actual_usd FROM spend_reservations WHERE id=?`, res.ID).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != 0.05 {
		t.Fatalf("settled actual_usd=%v, want 0.05 (the real reported cost, not the 0.30 estimate)", actual)
	}

	// 0.05 settled + 0.20 new estimate = 0.25, comfortably under the 0.30
	// cap — this only fits if the settle above actually freed the estimate
	// down to the real cost.
	_, ok2, reason2, err := ReserveGlobal(db, cfg, "run-second", 0.20, time.Hour, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !ok2 {
		t.Fatalf("expected second reservation to succeed now that the first settled at its real (lower) cost, refused: %s", reason2)
	}
}

// TestSol3SettleVersusReleaseGlobalMutualExclusion races SettleGlobal
// against ReleaseGlobal for the same reservation. Only one may win — a
// reservation must never end up both settled (counted) and released
// (freed), which would either double-book or silently drop the spend.
func TestSol3SettleVersusReleaseGlobalMutualExclusion(t *testing.T) {
	db, _ := openLedger(t)
	cfg := config.BuiltIn()
	cfg.Spend.DailyCapUSD = 0
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	res, ok, _, err := ReserveGlobal(db, cfg, "run-raced", 0.10, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected reservation to succeed (unlimited cap)")
	}

	const contendersPerSide = 5
	var wg sync.WaitGroup
	wg.Add(2 * contendersPerSide)
	for i := 0; i < contendersPerSide; i++ {
		go func() {
			defer wg.Done()
			_ = SettleGlobal(db, res.ID, 0.10, true, now.Add(time.Second))
		}()
		go func() {
			defer wg.Done()
			_ = ReleaseGlobal(db, res.ID, now.Add(time.Second))
		}()
	}
	wg.Wait()

	var status string
	if err := db.QueryRow(`SELECT status FROM spend_reservations WHERE id=?`, res.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "settled" && status != "released" {
		t.Fatalf("reservation ended in status=%q, want exactly one of settled/released", status)
	}
}

// TestSol3ReleaseForRunOnlyTouchesThatRun mirrors quota.ReleaseForRun's
// crash-recovery contract: releasing an interrupted run's reservations must
// not disturb any other run's still-open reservation.
func TestSol3ReleaseForRunOnlyTouchesThatRun(t *testing.T) {
	db, _ := openLedger(t)
	cfg := config.BuiltIn()
	cfg.Spend.DailyCapUSD = 0
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	crashed, ok, _, err := ReserveGlobal(db, cfg, "run-crashed", 0.10, time.Hour, now)
	if err != nil || !ok {
		t.Fatalf("reserve crashed: ok=%v err=%v", ok, err)
	}
	other, ok, _, err := ReserveGlobal(db, cfg, "run-other", 0.20, time.Hour, now)
	if err != nil || !ok {
		t.Fatalf("reserve other: ok=%v err=%v", ok, err)
	}

	if err := ReleaseForRun(db, "run-crashed", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	var crashedStatus, otherStatus string
	if err := db.QueryRow(`SELECT status FROM spend_reservations WHERE id=?`, crashed.ID).Scan(&crashedStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT status FROM spend_reservations WHERE id=?`, other.ID).Scan(&otherStatus); err != nil {
		t.Fatal(err)
	}
	if crashedStatus != "released" {
		t.Fatalf("crashed run's reservation status=%q, want released", crashedStatus)
	}
	if otherStatus != "pending" {
		t.Fatalf("other run's reservation status=%q, want still pending (untouched)", otherStatus)
	}
}
