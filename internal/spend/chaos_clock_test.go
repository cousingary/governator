package spend

import (
	"testing"
	"time"

	"github.com/cousingary/governator/internal/config"
)

// TestChaos_ClockJumpForwardExpiresReservationExactlyOnce is Sol redteam v4
// S9's "clock jumps" chaos scenario applied to the spend reservation ledger:
// a VM suspend/resume or NTP correction can move `now` hours or days between
// two calls that both take an explicit now time.Time (ReserveGlobal,
// expireStaleReservations, SettleGlobal all do — this package never calls
// time.Now() internally for reservation bookkeeping, which is exactly the
// seam this test exploits instead of needing an injectable clock). A huge
// forward jump must expire a stale pending reservation exactly once — a
// second settle attempt against the same (now expired) row must be a
// no-op, not an error and not a double-write.
func TestChaos_ClockJumpForwardExpiresReservationExactlyOnce(t *testing.T) {
	db, _ := openLedger(t)
	cfg := config.Config{Spend: config.Spend{DailyCapUSD: 100}}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	res, ok, reason, err := ReserveGlobal(db, cfg, "run-jump-fwd", 5.0, time.Hour, t0)
	if err != nil || !ok {
		t.Fatalf("ReserveGlobal: ok=%v reason=%q err=%v", ok, reason, err)
	}

	// A ~42-day forward jump (VM paused, resumed weeks later) — far past the
	// reservation's 1-hour TTL.
	jumped := t0.Add(1000 * time.Hour)
	if err := expireStaleReservations(db, jumped); err != nil {
		t.Fatalf("expireStaleReservations after forward jump: %v", err)
	}

	var status string
	if err := db.QueryRow(`SELECT status FROM spend_reservations WHERE id=?`, res.ID).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "expired" {
		t.Fatalf("status after forward clock jump = %q, want expired", status)
	}

	// A settle landing after the jump-triggered expiry must be the same safe
	// no-op SettleGlobal already guarantees for any post-transition race
	// (Sol P1-10) — not a new error mode introduced by the clock jump.
	if err := SettleGlobal(db, res.ID, 3.0, true, jumped); err != nil {
		t.Fatalf("SettleGlobal against an already-expired reservation: %v", err)
	}
	var actual float64
	if err := db.QueryRow(`SELECT actual_usd FROM spend_reservations WHERE id=?`, res.ID).Scan(&actual); err != nil {
		t.Fatalf("query actual_usd: %v", err)
	}
	if actual != 0 {
		t.Fatalf("actual_usd = %v after settling an expired reservation, want unchanged (0): a clock jump must not let cost land twice", actual)
	}

	// The day's headroom must reflect the expiry, not the original estimate,
	// so a second reservation the same "day" (by the jumped clock) can still
	// succeed against the cap.
	res2, ok2, reason2, err := ReserveGlobal(db, cfg, "run-jump-fwd-2", 5.0, time.Hour, jumped)
	if err != nil || !ok2 {
		t.Fatalf("ReserveGlobal after expiry freed headroom: ok=%v reason=%q err=%v", ok2, reason2, err)
	}
	if res2.ID == res.ID {
		t.Fatal("second reservation reused the first's row id")
	}
}

// TestChaos_ClockJumpBackwardSettleStillClaimsExactlyOnce covers the
// opposite jump direction: `now` at settle time is earlier than the
// reservation's own created_at (an NTP correction pulling the clock back).
// SettleGlobal's claim is a single conditional UPDATE keyed on status, not
// on any assumption that settled_at >= created_at, so this must still claim
// the row exactly once and a repeat call must still be the safe no-op —
// this test exists to prove that reasoning holds against the real
// implementation, not just assert it in a comment.
func TestChaos_ClockJumpBackwardSettleStillClaimsExactlyOnce(t *testing.T) {
	db, _ := openLedger(t)
	cfg := config.Config{Spend: config.Spend{DailyCapUSD: 100}}
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	res, ok, reason, err := ReserveGlobal(db, cfg, "run-jump-back", 2.0, time.Hour, t0)
	if err != nil || !ok {
		t.Fatalf("ReserveGlobal: ok=%v reason=%q err=%v", ok, reason, err)
	}

	backward := t0.Add(-24 * time.Hour)
	if err := SettleGlobal(db, res.ID, 1.5, true, backward); err != nil {
		t.Fatalf("SettleGlobal with a backward-jumped clock: %v", err)
	}
	// Second settle attempt (e.g. a retried reconcile pass) must be the
	// documented no-op, not a second write.
	if err := SettleGlobal(db, res.ID, 9.0, true, t0); err != nil {
		t.Fatalf("second SettleGlobal call: %v", err)
	}
	var status string
	var actual float64
	if err := db.QueryRow(`SELECT status,actual_usd FROM spend_reservations WHERE id=?`, res.ID).Scan(&status, &actual); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "settled" {
		t.Fatalf("status = %q, want settled", status)
	}
	if actual != 1.5 {
		t.Fatalf("actual_usd = %v, want 1.5 from the first (winning) settle — the second call's 9.0 must never land", actual)
	}
}
