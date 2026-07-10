package spend

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/observability"
)

func openLedger(t *testing.T) (*sql.DB, string) {
	t.Helper()
	home := t.TempDir()
	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, home
}

func insertRun(t *testing.T, db *sql.DB, id, status, created string, costUSD float64, notes string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO runs(id,job_id,status,created,cost_usd,notes) VALUES(?,?,?,?,?,?)`,
		id, "job-"+id, status, created, costUSD, notes); err != nil {
		t.Fatal(err)
	}
}

func rfc(day string, hour int) string {
	ts, err := time.Parse("2006-01-02T15:04:05Z", day+"T00:00:00Z")
	if err != nil {
		panic(err)
	}
	return ts.Add(time.Duration(hour) * time.Hour).Format(time.RFC3339Nano)
}

func TestDaySpendSumsOnlyThatDay(t *testing.T) {
	db, _ := openLedger(t)
	insertRun(t, db, "r1", "APPROVED", rfc("2026-07-10", 1), 0.01, "")
	insertRun(t, db, "r2", "APPROVED", rfc("2026-07-10", 2), 0.02, "")
	insertRun(t, db, "r3", "QUARANTINED", rfc("2026-07-09", 23), 5.00, "")

	day, _ := time.Parse("2006-01-02", "2026-07-10")
	s, err := DaySpend(db, day)
	if err != nil {
		t.Fatal(err)
	}
	if s.Runs != 2 || s.TotalCostUSD != 0.03 {
		t.Fatalf("day spend=%+v", s)
	}
}

func TestDaySpendExcludesRunningStatus(t *testing.T) {
	db, _ := openLedger(t)
	insertRun(t, db, "r1", "RUNNING", rfc("2026-07-10", 1), 9.00, "")
	insertRun(t, db, "r2", "APPROVED", rfc("2026-07-10", 2), 0.02, "")

	day, _ := time.Parse("2006-01-02", "2026-07-10")
	s, err := DaySpend(db, day)
	if err != nil {
		t.Fatal(err)
	}
	if s.Runs != 1 || s.TotalCostUSD != 0.02 {
		t.Fatalf("day spend=%+v (RUNNING row should be excluded)", s)
	}
}

func TestDaySpendCountsUnknownCostRunsAsZero(t *testing.T) {
	db, _ := openLedger(t)
	insertRun(t, db, "r1", "APPROVED", rfc("2026-07-10", 1), 0, "cost_unavailable")
	insertRun(t, db, "r2", "APPROVED", rfc("2026-07-10", 2), 0.05, "")

	day, _ := time.Parse("2006-01-02", "2026-07-10")
	s, err := DaySpend(db, day)
	if err != nil {
		t.Fatal(err)
	}
	if s.Runs != 2 || s.TotalCostUSD != 0.05 || s.UnknownCostRuns != 1 {
		t.Fatalf("day spend=%+v", s)
	}
}

func TestCheckBudgetUnlimitedWhenCapZero(t *testing.T) {
	db, _ := openLedger(t)
	insertRun(t, db, "r1", "APPROVED", time.Now().UTC().Format(time.RFC3339Nano), 999, "")
	cfg := config.BuiltIn()
	cfg.Spend.DailyCapUSD = 0
	if ok, reason := CheckBudget(cfg, db); !ok {
		t.Fatalf("expected unlimited cap to allow, got refused: %s", reason)
	}
}

func TestCheckBudgetRefusesAtOrOverCap(t *testing.T) {
	db, _ := openLedger(t)
	insertRun(t, db, "r1", "APPROVED", time.Now().UTC().Format(time.RFC3339Nano), 0.02, "")
	cfg := config.BuiltIn()
	cfg.Spend.DailyCapUSD = 0.01
	ok, reason := CheckBudget(cfg, db)
	if ok {
		t.Fatal("expected refusal when today's spend exceeds cap")
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason")
	}
}

func TestCheckBudgetAllowsUnderCap(t *testing.T) {
	db, _ := openLedger(t)
	insertRun(t, db, "r1", "APPROVED", time.Now().UTC().Format(time.RFC3339Nano), 0.001, "")
	cfg := config.BuiltIn()
	cfg.Spend.DailyCapUSD = 1.00
	if ok, reason := CheckBudget(cfg, db); !ok {
		t.Fatalf("expected allow under cap, got refused: %s", reason)
	}
}

func TestHaltFileBlocksRegardlessOfCap(t *testing.T) {
	db, home := openLedger(t)
	cfg := config.BuiltIn()
	cfg.Spend.HaltFile = filepath.Join(home, "HALT")
	cfg.Spend.DailyCapUSD = 0
	if err := Halt(cfg); err != nil {
		t.Fatal(err)
	}
	if !IsHalted(cfg) {
		t.Fatal("expected IsHalted true after Halt")
	}
	if ok, reason := CheckBudget(cfg, db); ok {
		t.Fatalf("expected halt file to refuse, got ok (reason=%q)", reason)
	}
	if err := Resume(cfg); err != nil {
		t.Fatal(err)
	}
	if IsHalted(cfg) {
		t.Fatal("expected IsHalted false after Resume")
	}
	if ok, reason := CheckBudget(cfg, db); !ok {
		t.Fatalf("expected allow after resume, got refused: %s", reason)
	}
}

func TestResumeOnMissingHaltFileIsNoop(t *testing.T) {
	cfg := config.BuiltIn()
	cfg.Spend.HaltFile = filepath.Join(t.TempDir(), "nested", "HALT")
	if err := Resume(cfg); err != nil {
		t.Fatalf("resume on missing halt file should be a no-op, got: %v", err)
	}
}

func TestMaybeHaltWritesFileWhenCapCrossed(t *testing.T) {
	db, home := openLedger(t)
	insertRun(t, db, "r1", "APPROVED", time.Now().UTC().Format(time.RFC3339Nano), 0.02, "")
	cfg := config.BuiltIn()
	cfg.Spend.HaltFile = filepath.Join(home, "HALT")
	cfg.Spend.DailyCapUSD = 0.01

	if IsHalted(cfg) {
		t.Fatal("halt file should not exist yet")
	}
	if err := MaybeHalt(cfg, db); err != nil {
		t.Fatal(err)
	}
	if !IsHalted(cfg) {
		t.Fatal("expected MaybeHalt to write halt file once cap is crossed")
	}
}

func TestMaybeHaltNoopUnderCap(t *testing.T) {
	db, home := openLedger(t)
	insertRun(t, db, "r1", "APPROVED", time.Now().UTC().Format(time.RFC3339Nano), 0.001, "")
	cfg := config.BuiltIn()
	cfg.Spend.HaltFile = filepath.Join(home, "HALT")
	cfg.Spend.DailyCapUSD = 1.00

	if err := MaybeHalt(cfg, db); err != nil {
		t.Fatal(err)
	}
	if IsHalted(cfg) {
		t.Fatal("did not expect halt file when under cap")
	}
}

func TestMaybeHaltNoopWhenCapUnlimited(t *testing.T) {
	db, home := openLedger(t)
	insertRun(t, db, "r1", "APPROVED", time.Now().UTC().Format(time.RFC3339Nano), 999, "")
	cfg := config.BuiltIn()
	cfg.Spend.HaltFile = filepath.Join(home, "HALT")
	cfg.Spend.DailyCapUSD = 0

	if err := MaybeHalt(cfg, db); err != nil {
		t.Fatal(err)
	}
	if IsHalted(cfg) {
		t.Fatal("did not expect halt file when cap is unlimited")
	}
}

func TestIsHaltedFalseWhenHaltFileUnset(t *testing.T) {
	cfg := config.BuiltIn()
	cfg.Spend.HaltFile = ""
	if IsHalted(cfg) {
		t.Fatal("expected false when halt_file is unset")
	}
}

func TestHaltErrorsWhenHaltFileUnset(t *testing.T) {
	cfg := config.BuiltIn()
	cfg.Spend.HaltFile = ""
	if err := Halt(cfg); err == nil {
		t.Fatal("expected error writing halt file with unset path")
	}
}

func TestTodaySpendUsesCurrentUTCDate(t *testing.T) {
	db, _ := openLedger(t)
	insertRun(t, db, "r1", "APPROVED", time.Now().UTC().Format(time.RFC3339Nano), 0.5, "")
	s, err := TodaySpend(db)
	if err != nil {
		t.Fatal(err)
	}
	if s.Date != time.Now().UTC().Format("2006-01-02") {
		t.Fatalf("date=%s", s.Date)
	}
	if s.Runs != 1 || s.TotalCostUSD != 0.5 {
		t.Fatalf("today spend=%+v", s)
	}
}
