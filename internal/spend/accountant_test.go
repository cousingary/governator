package spend

import (
	"sync"
	"testing"

	"github.com/cousingary/governator/internal/config"
)

func TestAccountantReserveRefusesOverCap(t *testing.T) {
	db, _ := openLedger(t)
	insertRun(t, db, "r1", "APPROVED", rfc("2026-07-10", 1), 0.15, "")
	cfg := config.Config{Spend: config.Spend{DailyCapUSD: 0.20}}

	a, err := NewAccountant(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	ok, reason := a.Reserve(0.10)
	if ok {
		t.Fatalf("expected refusal (0.15 settled + 0.10 estimate > 0.20 cap), got ok reason=%q", reason)
	}
	ok, _ = a.Reserve(0.04)
	if !ok {
		t.Fatal("expected 0.15 + 0.04 <= 0.20 to be reservable")
	}
}

func TestAccountantSettleUpdatesRunningTotalForLaterReserves(t *testing.T) {
	db, _ := openLedger(t)
	cfg := config.Config{Spend: config.Spend{DailyCapUSD: 0.30}}
	a, err := NewAccountant(cfg, db)
	if err != nil {
		t.Fatal(err)
	}

	ok, _ := a.Reserve(0.10)
	if !ok {
		t.Fatal("expected first reservation to succeed")
	}
	// Settle at a higher actual than the estimate reserved.
	a.Settle(0.10, 0.25)
	if a.Spent() != 0.25 {
		t.Fatalf("spent = %v, want 0.25", a.Spent())
	}
	ok, reason := a.Reserve(0.10)
	if ok {
		t.Fatalf("expected refusal after settling 0.25 against a 0.30 cap, got ok reason=%q", reason)
	}
}

func TestAccountantZeroCapIsUnlimited(t *testing.T) {
	db, _ := openLedger(t)
	cfg := config.Config{Spend: config.Spend{DailyCapUSD: 0}}
	a, err := NewAccountant(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := a.Reserve(1_000_000)
	if !ok {
		t.Fatal("expected unlimited cap to always reserve")
	}
}

func TestAccountantHaltFileRefusesReservation(t *testing.T) {
	db, _ := openLedger(t)
	halt := t.TempDir() + "/HALT"
	cfg := config.Config{Spend: config.Spend{DailyCapUSD: 0, HaltFile: halt}}
	if err := Halt(cfg); err != nil {
		t.Fatal(err)
	}
	a, err := NewAccountant(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := a.Reserve(0.01); ok {
		t.Fatal("expected halt file to refuse reservation regardless of cap")
	}
}

func TestAccountantConcurrentReservesAreSerialized(t *testing.T) {
	db, _ := openLedger(t)
	cfg := config.Config{Spend: config.Spend{DailyCapUSD: 1.00}}
	a, err := NewAccountant(cfg, db)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := a.Reserve(0.10); ok {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 10 {
		t.Fatalf("accepted = %d, want exactly 10 reservations of 0.10 under a 1.00 cap", accepted)
	}
}
