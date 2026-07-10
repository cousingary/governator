// Package spend enforces Governator's aggregate daily spend cap and halt
// switch, on top of the existing per-job budget.max_tokens quarantine.
package spend

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cousingary/governator/internal/config"
)

// Today reports the aggregate spend recorded in the ledger for one UTC day.
type Today struct {
	Date            string  `json:"date"`
	Runs            int     `json:"runs"`
	TotalCostUSD    float64 `json:"total_cost_usd"`
	UnknownCostRuns int     `json:"unknown_cost_runs"`
}

// TodaySpend sums ledger cost for runs started today (UTC). It reuses the
// same cost-extraction result gov cost/gov usage rely on (runtime.go writes
// cost_usd=0 plus a "cost_unavailable" note when a backend's cost can't be
// parsed) so unknown-cost runs count as $0 but are surfaced as a count,
// keeping the cap honest about its blind spots.
func TodaySpend(ledger *sql.DB) (Today, error) {
	return DaySpend(ledger, time.Now().UTC())
}

// DaySpend sums ledger cost for runs started on the given UTC day.
func DaySpend(ledger *sql.DB, day time.Time) (Today, error) {
	t := Today{Date: day.UTC().Format("2006-01-02")}
	err := ledger.QueryRow(`SELECT COUNT(*), COALESCE(SUM(cost_usd),0),
COALESCE(SUM(CASE WHEN notes LIKE '%cost_unavailable%' THEN 1 ELSE 0 END),0)
FROM runs WHERE substr(created,1,10)=? AND status<>'RUNNING'`, t.Date).
		Scan(&t.Runs, &t.TotalCostUSD, &t.UnknownCostRuns)
	return t, err
}

// IsHalted reports whether the configured halt file is present.
func IsHalted(cfg config.Config) bool {
	if cfg.Spend.HaltFile == "" {
		return false
	}
	_, err := os.Stat(cfg.Spend.HaltFile)
	return err == nil
}

// Halt writes the halt file, refusing all future runs until Resume clears it.
func Halt(cfg config.Config) error {
	if cfg.Spend.HaltFile == "" {
		return fmt.Errorf("spend.halt_file is not configured")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Spend.HaltFile), 0700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(cfg.Spend.HaltFile), err)
	}
	return os.WriteFile(cfg.Spend.HaltFile, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0600)
}

// Resume removes the halt file, if present.
func Resume(cfg config.Config) error {
	if cfg.Spend.HaltFile == "" {
		return nil
	}
	if err := os.Remove(cfg.Spend.HaltFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// CheckBudget reports whether a new run may launch under cfg's spend policy.
// ok=false means refuse, with reason explaining why. A ledger read failure
// fails closed (refuses) rather than silently allowing unmetered spend.
func CheckBudget(cfg config.Config, ledger *sql.DB) (ok bool, reason string) {
	if IsHalted(cfg) {
		return false, fmt.Sprintf("halt file present: %s", cfg.Spend.HaltFile)
	}
	if cfg.Spend.DailyCapUSD <= 0 {
		return true, ""
	}
	today, err := TodaySpend(ledger)
	if err != nil {
		return false, fmt.Sprintf("spend ledger unavailable: %v", err)
	}
	if today.TotalCostUSD >= cfg.Spend.DailyCapUSD {
		return false, fmt.Sprintf("daily spend $%.4f >= cap $%.2f (runs today: %d, unknown-cost runs: %d)",
			today.TotalCostUSD, cfg.Spend.DailyCapUSD, today.Runs, today.UnknownCostRuns)
	}
	return true, ""
}

// MaybeHalt writes the halt file when today's recorded total has crossed the
// cap, so the NEXT run refuses. It runs as a post-run hook because a live
// mid-run abort is out of scope for this package.
func MaybeHalt(cfg config.Config, ledger *sql.DB) error {
	if cfg.Spend.DailyCapUSD <= 0 {
		return nil
	}
	today, err := TodaySpend(ledger)
	if err != nil {
		return err
	}
	if today.TotalCostUSD >= cfg.Spend.DailyCapUSD {
		return Halt(cfg)
	}
	return nil
}

func (t Today) String() string {
	return fmt.Sprintf("date=%s runs=%d total_cost_usd=%.4f unknown_cost_runs=%d", t.Date, t.Runs, t.TotalCostUSD, t.UnknownCostRuns)
}
