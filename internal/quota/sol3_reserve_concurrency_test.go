// Sol redteam v3 S9 (P1.3, audit finding #10): quota.Reserve used to check
// headroom in one read, then write unconditionally in a *separate*
// transaction, so two concurrent callers could both observe headroom and
// both commit, together exceeding estimated_limit. Settle/Release/
// ExpireStale had the matching bug: they read settled_at outside any
// transaction, then wrote unconditionally, so a race between any two of
// them could double-decrement reserved_usage or double-book measured_usage.
// These tests spawn real goroutines against one shared, on-disk SQLite
// ledger (not a mocked lock) and must be run with -race.
package quota

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/config"
)

// TestSol3ConcurrentReservationsCannotExceedHeadroom is corpus #8's quota
// half: 20 goroutines each try to reserve 100 units against a window with
// only 1000 units of headroom. Exactly 10 must succeed; the rest must see
// ErrNoHeadroom; the window's reserved_usage must never exceed the limit.
func TestSol3ConcurrentReservationsCannotExceedHeadroom(t *testing.T) {
	db := mustQuotaDB(t)
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	cfg := config.BuiltIn()
	cfg.Quotas = []config.QuotaWindow{{Backend: "codex", WindowType: "daily", EstimatedLimit: 1000}}
	if err := SeedFromConfig(db, cfg, now); err != nil {
		t.Fatal(err)
	}

	const workers = 20
	const usage = 100.0
	var wg sync.WaitGroup
	oks := make([]bool, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := Reserve(db, "codex", DefaultAccount, fmt.Sprintf("run-%d", i), usage, time.Hour, now)
			if err != nil {
				errs[i] = err
				return
			}
			oks[i] = true
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for i, ok := range oks {
		if ok {
			succeeded++
			continue
		}
		if !errors.Is(errs[i], ErrNoHeadroom) {
			t.Fatalf("worker %d: unexpected error %v", i, errs[i])
		}
	}
	if succeeded != 10 {
		t.Fatalf("expected exactly 10 of %d reservations to succeed (1000 headroom / 100 usage), got %d", workers, succeeded)
	}

	snap, err := Headroom(db, "codex", DefaultAccount, now)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ReservedUsage != 1000 {
		t.Fatalf("reserved_usage=%v, want exactly 1000 (no overshoot, no undercount)", snap.ReservedUsage)
	}
}

// TestSol3SettleVersusExpireDoesNotDoubleDecrement races Settle against
// ExpireStale for the same reservation. Only one may win; reserved_usage
// must be decremented exactly once. Several goroutines pile onto each side
// (rather than one apiece) to make a stale read-outside-the-transaction race
// window reliably observable — with only one contender per side the old
// buggy code's narrow TOCTOU window often doesn't get hit. A second,
// unrelated open reservation on the same window gives the assertion a
// floor-immune signal: MAX(x,0) clamping would hide a double-decrement of
// the raced reservation alone if nothing else were still reserved.
func TestSol3SettleVersusExpireDoesNotDoubleDecrement(t *testing.T) {
	db := mustQuotaDB(t)
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	cfg := config.BuiltIn()
	cfg.Quotas = []config.QuotaWindow{{Backend: "codex", WindowType: "daily", EstimatedLimit: 10000}}
	if err := SeedFromConfig(db, cfg, now); err != nil {
		t.Fatal(err)
	}

	raced, err := Reserve(db, "codex", DefaultAccount, "run-raced", 100, time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := Reserve(db, "codex", DefaultAccount, "run-fresh", 250, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	// now2 is past raced's TTL (1 minute) but not fresh's (1 hour), so
	// ExpireStale at now2 targets only the raced reservation.
	now2 := now.Add(2 * time.Minute)
	const contendersPerSide = 5
	var wg sync.WaitGroup
	wg.Add(2 * contendersPerSide)
	for i := 0; i < contendersPerSide; i++ {
		go func() {
			defer wg.Done()
			_ = Settle(db, raced.ID, 90, now2)
		}()
		go func() {
			defer wg.Done()
			_ = ExpireStale(db, now2)
		}()
	}
	wg.Wait()

	snap, err := Headroom(db, "codex", DefaultAccount, now2)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ReservedUsage != fresh.Usage {
		t.Fatalf("reserved_usage=%v, want exactly %v (fresh reservation only — raced must be removed exactly once, not twice)", snap.ReservedUsage, fresh.Usage)
	}

	var settledAt string
	var measured float64
	var expired int
	if err := db.QueryRow(`SELECT settled_at, expired, measured_usage FROM quota_reservations WHERE id=?`, raced.ID).Scan(&settledAt, &expired, &measured); err != nil {
		t.Fatal(err)
	}
	if settledAt == "" {
		t.Fatal("raced reservation was never claimed by either Settle or ExpireStale")
	}
	// Whichever won, the row must reflect exactly that outcome, not a mix.
	if expired == 1 && measured != 0 {
		t.Fatalf("ExpireStale won but measured_usage=%v (want 0 — Settle must not also have written)", measured)
	}
	if expired == 0 && measured != 90 {
		t.Fatalf("Settle won but measured_usage=%v (want 90)", measured)
	}
}

// TestSol3SettleVersusReleaseDoesNotDoubleDecrement mirrors the Expire race
// above for the Settle/Release pair (both reachable concurrently: Release
// fires from a defer on any abort path, Settle fires on successful
// completion — a caller bug or a reconcile retry could invoke both for the
// same reservation). Several goroutines pile onto each side for the same
// reason as the Expire race above: a single-contender-per-side race often
// doesn't hit the old code's narrow TOCTOU window.
func TestSol3SettleVersusReleaseDoesNotDoubleDecrement(t *testing.T) {
	db := mustQuotaDB(t)
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	cfg := config.BuiltIn()
	cfg.Quotas = []config.QuotaWindow{{Backend: "codex", WindowType: "daily", EstimatedLimit: 10000}}
	if err := SeedFromConfig(db, cfg, now); err != nil {
		t.Fatal(err)
	}

	raced, err := Reserve(db, "codex", DefaultAccount, "run-raced", 100, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := Reserve(db, "codex", DefaultAccount, "run-fresh", 250, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	const contendersPerSide = 5
	var wg sync.WaitGroup
	wg.Add(2 * contendersPerSide)
	for i := 0; i < contendersPerSide; i++ {
		go func() {
			defer wg.Done()
			_ = Settle(db, raced.ID, 80, now.Add(time.Second))
		}()
		go func() {
			defer wg.Done()
			_ = Release(db, raced.ID, now.Add(time.Second))
		}()
	}
	wg.Wait()

	snap, err := Headroom(db, "codex", DefaultAccount, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if snap.ReservedUsage != fresh.Usage {
		t.Fatalf("reserved_usage=%v, want exactly %v (fresh reservation only — raced must be removed exactly once, not twice)", snap.ReservedUsage, fresh.Usage)
	}

	var settledAt string
	var expired int
	var measured float64
	if err := db.QueryRow(`SELECT settled_at, expired, measured_usage FROM quota_reservations WHERE id=?`, raced.ID).Scan(&settledAt, &expired, &measured); err != nil {
		t.Fatal(err)
	}
	if settledAt == "" {
		t.Fatal("raced reservation was never claimed by either Settle or Release")
	}
	if expired == 1 && measured != 0 {
		t.Fatalf("Release won but measured_usage=%v (want 0 — Settle must not also have written)", measured)
	}
	if expired == 0 && measured != 80 {
		t.Fatalf("Settle won but measured_usage=%v (want 80)", measured)
	}
}

// TestSol3TwoRecoveryWorkersNeverDoubleApplyExpire simulates two concurrent
// `gov reconcile`/recovery passes both sweeping stale reservations at once.
// Three reservations are already stale; a fourth is not. Both workers race
// ExpireStale; the fourth reservation's headroom must be the only survivor.
func TestSol3TwoRecoveryWorkersNeverDoubleApplyExpire(t *testing.T) {
	db := mustQuotaDB(t)
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	cfg := config.BuiltIn()
	cfg.Quotas = []config.QuotaWindow{{Backend: "codex", WindowType: "daily", EstimatedLimit: 10000}}
	if err := SeedFromConfig(db, cfg, now); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if _, err := Reserve(db, "codex", DefaultAccount, fmt.Sprintf("run-stale-%d", i), 50, time.Minute, now); err != nil {
			t.Fatal(err)
		}
	}
	fresh, err := Reserve(db, "codex", DefaultAccount, "run-fresh", 300, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	now2 := now.Add(2 * time.Minute) // past the 3 stale reservations' TTL, not fresh's
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = ExpireStale(db, now2)
	}()
	go func() {
		defer wg.Done()
		_ = ExpireStale(db, now2)
	}()
	wg.Wait()

	snap, err := Headroom(db, "codex", DefaultAccount, now2)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ReservedUsage != fresh.Usage {
		t.Fatalf("reserved_usage=%v, want exactly %v (only the fresh reservation should remain — the 3 stale ones must each be removed exactly once across both workers)", snap.ReservedUsage, fresh.Usage)
	}
}
