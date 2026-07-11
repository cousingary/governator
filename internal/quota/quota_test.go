package quota

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/observability"
)

func mustQuotaDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := observability.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestReservationLifecycleAndHeadroom(t *testing.T) {
	db := mustQuotaDB(t)
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	cfg := config.BuiltIn()
	cfg.Quotas = []config.QuotaWindow{{Backend: "codex", Account: "default", WindowType: "daily", EstimatedLimit: 1000, Confidence: 0.8}}
	if err := SeedFromConfig(db, cfg, now); err != nil {
		t.Fatal(err)
	}
	res, err := Reserve(db, "codex", DefaultAccount, "run-1", 200, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := Headroom(db, "codex", DefaultAccount, now)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Available || snap.HeadroomPct != 0.8 || snap.ReservedUsage != 200 || snap.Confidence != 0.8 {
		t.Fatalf("after reserve snapshot=%+v", snap)
	}
	if err := Settle(db, res.ID, 150, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	snap, err = Headroom(db, "codex", DefaultAccount, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snap.HeadroomPct != 0.85 || snap.MeasuredUsage != 150 || snap.ReservedUsage != 0 {
		t.Fatalf("after settle snapshot=%+v", snap)
	}
}

func TestReserveFailsWhenHeadroomInsufficient(t *testing.T) {
	db := mustQuotaDB(t)
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	cfg := config.BuiltIn()
	cfg.Quotas = []config.QuotaWindow{{Backend: "codex", WindowType: "daily", EstimatedLimit: 100}}
	if err := SeedFromConfig(db, cfg, now); err != nil {
		t.Fatal(err)
	}
	_, err := Reserve(db, "codex", DefaultAccount, "run-1", 101, time.Hour, now)
	if !errors.Is(err, ErrNoHeadroom) {
		t.Fatalf("err=%v want ErrNoHeadroom", err)
	}
}

func TestStaleReservationExpires(t *testing.T) {
	db := mustQuotaDB(t)
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	cfg := config.BuiltIn()
	cfg.Quotas = []config.QuotaWindow{{Backend: "codex", WindowType: "daily", EstimatedLimit: 1000}}
	if err := SeedFromConfig(db, cfg, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Reserve(db, "codex", DefaultAccount, "run-1", 250, time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if err := ExpireStale(db, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	snap, err := Headroom(db, "codex", DefaultAccount, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snap.ReservedUsage != 0 || snap.MeasuredUsage != 0 || snap.HeadroomPct != 1 {
		t.Fatalf("expired snapshot=%+v", snap)
	}
}

func TestMissingTelemetryUnavailableAndDefaultConfidence(t *testing.T) {
	db := mustQuotaDB(t)
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	snap, err := Headroom(db, "codex", DefaultAccount, now)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Available {
		t.Fatalf("missing telemetry should be unavailable: %+v", snap)
	}
	cfg := config.BuiltIn()
	cfg.Quotas = []config.QuotaWindow{{Backend: "codex", WindowType: "daily", EstimatedLimit: 1000}}
	if err := SeedFromConfig(db, cfg, now); err != nil {
		t.Fatal(err)
	}
	snap, err = Headroom(db, "codex", DefaultAccount, now)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Confidence != 0.6 {
		t.Fatalf("default confidence=%v want 0.6", snap.Confidence)
	}
}

func TestApplyResetHintCreatesHighConfidenceWindow(t *testing.T) {
	db := mustQuotaDB(t)
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	reset := now.Add(4 * time.Hour)
	if err := ApplyResetHint(db, "codex", DefaultAccount, reset, now); err != nil {
		t.Fatal(err)
	}
	windows, err := Windows(db, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 1 || windows[0].Source != "error_hint" || windows[0].Confidence != 0.9 || !windows[0].ResetAt.Equal(reset) {
		t.Fatalf("windows=%+v", windows)
	}
}
