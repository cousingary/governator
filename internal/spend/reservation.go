package spend

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/cousingary/governator/internal/config"
)

// GlobalReservation is one row reserved against the daily spend cap, shared
// across every Governator process. Unlike Accountant (in-process only, one
// `gov batch` invocation), a GlobalReservation is visible to every `gov run`
// / `gov batch` process reading the same ledger, closing the race the audit
// calls out: two separate processes both reading TodaySpend (which excludes
// RUNNING rows — an in-flight run's cost hasn't landed yet) and both passing
// CheckBudget before either settles.
type GlobalReservation struct {
	ID           int64
	RunID        string
	Day          string
	EstimatedUSD float64
}

// ReserveGlobal atomically reserves estimate dollars against cfg's daily cap
// in one SQLite statement (an INSERT ... SELECT ... WHERE whose WHERE clause
// re-sums the day's committed spend at write time), so two processes racing
// this call can never both succeed past the cap: SQLite serializes writers,
// the loser's WHERE condition re-evaluates against the winner's
// already-committed row and inserts nothing. ok=false means refuse — the
// caller must not launch.
//
// The committed-spend sum has three disjoint terms so nothing is
// double-counted:
//  1. runs.cost_usd for completed runs that have no reservation row for this
//     day (legacy path / anything that bypasses this gate) — ground truth.
//  2. this day's still-pending reservation estimates — in-flight cost not
//     yet in runs.cost_usd.
//  3. this day's already-settled reservation actuals — see SettleGlobal:
//     this is how an unmetered run's conservative estimate stays counted
//     even though runs.cost_usd honestly recorded it as 0.
func ReserveGlobal(ledger *sql.DB, cfg config.Config, runID string, estimate float64, ttl time.Duration, now time.Time) (GlobalReservation, bool, string, error) {
	if ledger == nil {
		return GlobalReservation{}, true, "", nil
	}
	if IsHalted(cfg) {
		return GlobalReservation{}, false, fmt.Sprintf("halt file present: %s", cfg.Spend.HaltFile), nil
	}
	if estimate < 0 {
		estimate = 0
	}
	if err := expireStaleReservations(ledger, now); err != nil {
		return GlobalReservation{}, false, "", err
	}
	day := now.UTC().Format("2006-01-02")
	expires := formatSpendTime(now.Add(ttl))
	created := formatSpendTime(now)
	if cfg.Spend.DailyCapUSD <= 0 {
		res, err := ledger.Exec(`INSERT INTO spend_reservations(run_id,day,estimated_usd,status,expires_at,created_at) VALUES(?,?,?,'pending',?,?)`,
			runID, day, estimate, expires, created)
		if err != nil {
			return GlobalReservation{}, false, "", err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return GlobalReservation{}, false, "", err
		}
		return GlobalReservation{ID: id, RunID: runID, Day: day, EstimatedUSD: estimate}, true, "", nil
	}
	res, err := ledger.Exec(`INSERT INTO spend_reservations(run_id,day,estimated_usd,status,expires_at,created_at)
SELECT ?,?,?,'pending',?,?
WHERE (
  COALESCE((SELECT SUM(cost_usd) FROM runs WHERE substr(created,1,10)=? AND status<>'RUNNING'
             AND id NOT IN (SELECT run_id FROM spend_reservations WHERE run_id<>'' AND day=?)),0)
  + COALESCE((SELECT SUM(estimated_usd) FROM spend_reservations WHERE day=? AND status='pending'),0)
  + COALESCE((SELECT SUM(actual_usd) FROM spend_reservations WHERE day=? AND status='settled'),0)
  + ?
) <= ?`,
		runID, day, estimate, expires, created,
		day, day, day, day, estimate, cfg.Spend.DailyCapUSD)
	if err != nil {
		return GlobalReservation{}, false, "", err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return GlobalReservation{}, false, "", err
	}
	if n == 0 {
		today, _ := DaySpend(ledger, now)
		return GlobalReservation{}, false, fmt.Sprintf("daily spend $%.4f (settled+reserved) + estimate $%.4f > cap $%.2f",
			today.TotalCostUSD, estimate, cfg.Spend.DailyCapUSD), nil
	}
	id, err := res.LastInsertId()
	if err != nil {
		return GlobalReservation{}, false, "", err
	}
	return GlobalReservation{ID: id, RunID: runID, Day: day, EstimatedUSD: estimate}, true, "", nil
}

// SettleGlobal finalizes a reservation with the run's actual dollar cost.
// When costAvailable is false, the reservation settles at its own
// (conservative, non-zero) estimate instead of 0: runs.cost_usd is
// deliberately left at 0 for an unmetered run (see TodaySpend's doc
// comment) so the ledger stays honest about its blind spots, but the daily
// cap must not read that honesty as "no money was spent" — a strict cost
// contract's whole point is that an unmetered backend shrinks the remaining
// budget, not bypasses it (audit finding #11). The claim is a single
// conditional UPDATE (WHERE status='pending'), so a concurrent Settle,
// Release or expiry of the same row can never double-apply.
func SettleGlobal(ledger *sql.DB, reservationID int64, actualUSD float64, costAvailable bool, now time.Time) error {
	if ledger == nil || reservationID == 0 {
		return nil
	}
	if actualUSD < 0 {
		actualUSD = 0
	}
	settleUSD := actualUSD
	if !costAvailable {
		var estimated float64
		err := ledger.QueryRow(`SELECT estimated_usd FROM spend_reservations WHERE id=? AND status='pending'`, reservationID).Scan(&estimated)
		switch {
		case err == nil:
			settleUSD = estimated
		case err == sql.ErrNoRows:
			// Already settled/released/expired by someone else — the UPDATE
			// below will correctly no-op.
		default:
			return err
		}
	}
	_, err := ledger.Exec(`UPDATE spend_reservations SET status='settled', actual_usd=?, settled_at=? WHERE id=? AND status='pending'`,
		settleUSD, formatSpendTime(now), reservationID)
	return err
}

// ReleaseGlobal cancels a reservation that never launched, or whose run
// aborted before any cost could be incurred, returning its estimate to the
// day's headroom immediately instead of waiting for the TTL.
func ReleaseGlobal(ledger *sql.DB, reservationID int64, now time.Time) error {
	if ledger == nil || reservationID == 0 {
		return nil
	}
	_, err := ledger.Exec(`UPDATE spend_reservations SET status='released', settled_at=? WHERE id=? AND status='pending'`,
		formatSpendTime(now), reservationID)
	return err
}

// ReleaseForRun releases every still-pending reservation belonging to runID.
// Mirrors quota.ReleaseForRun: crash recovery must not hold cap headroom
// hostage for an interrupted process until the TTL clears it on its own.
func ReleaseForRun(ledger *sql.DB, runID string, now time.Time) error {
	if ledger == nil || runID == "" {
		return nil
	}
	_, err := ledger.Exec(`UPDATE spend_reservations SET status='released', settled_at=? WHERE run_id=? AND status='pending'`,
		formatSpendTime(now), runID)
	return err
}

// expireStaleReservations self-heals a reservation abandoned by a process
// that crashed between reserve and settle/release, the same way
// quota.ExpireStale does — a single conditional UPDATE, so it can never
// race a concurrent Settle/Release into a double-decrement.
func expireStaleReservations(ledger *sql.DB, now time.Time) error {
	_, err := ledger.Exec(`UPDATE spend_reservations SET status='expired', settled_at=? WHERE status='pending' AND expires_at<>'' AND expires_at<?`,
		formatSpendTime(now), formatSpendTime(now))
	return err
}

func formatSpendTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
