package breaker

import (
	"database/sql"
	"time"

	"github.com/cousingary/governator/internal/quota"
	"github.com/cousingary/governator/internal/router"
)

// Store is the production router.HealthSource: it reads breaker state from the
// ledger and (for Session 4) quota state. A nil DB behaves like the broker's
// closedHealth stub (every backend CLOSED) so the same type is safe to pass
// before the ledger is open.
//
// Breaker reads are pure (no write): the lazy OPEN -> HALF_OPEN transition is
// computed at read time and committed only by RecordSuccess/RecordFailure, so a
// dry-run Resolve (gov route --explain) never mutates breaker state.
type Store struct {
	DB *sql.DB
	// Now is injectable for deterministic tests; nil = time.Now.
	Now func() time.Time
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// Breaker reports the effective breaker state for routing. A read error is
// swallowed as CLOSED: the breaker is an infra-optimization, and the hard
// exclusions (capability, binary presence, fingerprints) remain the safety
// floor regardless of breaker state.
func (s Store) Breaker(agent string) router.BreakerSnapshot {
	if s.DB == nil {
		return router.BreakerSnapshot{State: router.BreakerClosed}
	}
	rec := Snapshot(s.DB, agent, s.now())
	return router.BreakerSnapshot{
		State:  mapState(rec.EffectiveState),
		Reason: ReasonFor(rec),
	}
}

// Quota reports subscription headroom from quota_windows. Missing telemetry is
// unavailable (not a penalty); read errors fail soft the same way breaker reads
// do because the router must remain deterministic and fail closed only on hard
// policy/capability exclusions.
func (s Store) Quota(agent string) router.QuotaSnapshot {
	if s.DB == nil {
		return router.QuotaSnapshot{Available: false}
	}
	snap, err := quota.Headroom(s.DB, agent, quota.DefaultAccount, s.now())
	if err != nil || !snap.Available {
		return router.QuotaSnapshot{Available: false}
	}
	return router.QuotaSnapshot{Available: true, HeadroomPct: snap.HeadroomPct}
}

func mapState(s State) router.BreakerState {
	switch s {
	case Degraded:
		return router.BreakerDegraded
	case Open:
		return router.BreakerOpen
	case HalfOpen:
		// HALF_OPEN is admissible (a probe): route on it like CLOSED so the
		// broker scores it fully and can select it. The probe outcome is what
		// closes/re-opens the breaker, not the routing score.
		return router.BreakerClosed
	default:
		return router.BreakerClosed
	}
}
