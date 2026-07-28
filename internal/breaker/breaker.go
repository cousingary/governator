// Package breaker implements Governator's infrastructure circuit breakers
// (plan v1.2 Session 2). A breaker tracks, per backend, whether the backend is
// reachable and able to serve requests — the infrastructure-health twin of the
// quality scores the route broker already routes on.
//
// The defining rule (plan standing rule 3) is enforced throughout: a provider
// outage must never lower an agent's quality score, and bad output must never
// open a breaker. Only infrastructure failures (RATE_LIMIT, QUOTA_EXHAUSTED,
// AUTH_EXPIRED, BINARY_MISSING, FLAG_DRIFT, TRANSIENT_UPSTREAM) move a breaker;
// every quality taxonomy is invisible to it. Conversely a successful or
// quality-failed run means the backend was reachable, so it closes a probe.
//
// State machine: CLOSED -> DEGRADED -> OPEN -> HALF_OPEN -> CLOSED.
//   - CLOSED: healthy; the default.
//   - DEGRADED: transient upstream errors are accumulating; soft penalty only.
//   - OPEN: hard-excluded by the broker until its cooldown elapses (time-based)
//     or until a doctor pass recovers it (doctor-gated kinds).
//   - HALF_OPEN: the cooldown has elapsed; the backend is admissible again as a
//     probe. The next run's outcome closes (success) or re-opens (infra fail)
//     it. HALF_OPEN is a *virtual* read-time state (see Snapshot): the
//     persisted row stays OPEN so that dry-run reads (gov route --explain) and
//     gov health are side-effect-free. The transition is committed only when a
//     real run records its outcome.
//
// No background probe daemon: probes ride real agent: auto jobs. Single
// operator; one ledger. All persistence is additive SQLite, idempotent.
package breaker

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/dbtime"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/quota"
)

// State is the persisted circuit-breaker state for one backend.
type State string

const (
	Closed   State = "CLOSED"
	Degraded State = "DEGRADED"
	Open     State = "OPEN"
	HalfOpen State = "HALF_OPEN"
)

// Record is the persisted + effective view of one backend's breaker.
//
// EffectiveState is what the broker should route on: it folds the lazy
// OPEN -> HALF_OPEN transition in (a time-expired OPEN is reported as
// HALF_OPEN). PersistedState is the raw row. They differ only while a backend
// is OPEN-but-cooled, awaiting a probe to confirm recovery.
type Record struct {
	Backend             string
	PersistedState      State
	EffectiveState      State
	FailureKind         string
	OpenedAt            time.Time
	CooldownUntil       time.Time // zero = doctor-gated (no time-based recovery)
	ConsecutiveFailures int
	LastProbeAt         time.Time
	UpdatedAt           time.Time
}

// doctorGated reports whether a kind recovers only via a doctor pass (or a
// manual reset), never via a cooldown timer. AUTH_EXPIRED waits for a credential
// change; BINARY_MISSING / FLAG_DRIFT wait for the backend's own --help/version
// probe to pass again.
func doctorGated(kind string) bool {
	switch kind {
	case observability.InfraAuthExpired, observability.InfraBinaryMissing, observability.InfraFlagDrift:
		return true
	}
	return false
}

// Breaker policy cooldowns (plan Session 2 table). RATE_LIMIT backs off
// exponentially on repeat; QUOTA_EXHAUSTED uses a long cooldown until Session 4
// supplies a real reset_at; TRANSIENT_UPSTREAM degrades first and opens only
// after a threshold within a window.
const (
	rateLimitBaseCooldown = 5 * time.Minute
	rateLimitMaxCooldown  = 2 * time.Hour
	quotaCooldown         = 1 * time.Hour

	transientThreshold = 3
	transientWindow    = 30 * time.Minute
	transientCooldown  = 5 * time.Minute
)

var timeZero = time.Time{}

// ErrUnknownBackend is returned when a record is requested for a name that is
// not a registered Governator backend. The breaker only tracks real backends.
var ErrUnknownBackend = errors.New("breaker: unknown backend")

// validBackend mirrors router.RegisteredAgents / agents.New without importing
// either (avoids a router<->breaker import cycle). A test cross-checks this
// against agents.New so the two never drift.
var registeredBackends = []string{"claude-code", "codex", "glm", "opencode", "pi"}

func isValidBackend(name string) bool {
	for _, b := range registeredBackends {
		if b == name {
			return true
		}
	}
	return false
}

// timestamp helpers: the ledger stores RFC3339Nano strings; empty == zero.
func formatTime(t time.Time) string {
	return dbtime.FormatLegacy(t)
}

func parseTime(s string) time.Time {
	t, err := dbtime.ParseLegacy(strings.TrimSpace(s))
	if err != nil {
		return timeZero
	}
	return t
}

// load reads one backend's persisted row. A backend with no row is CLOSED with
// no history — the healthy default for a never-failed backend.
func load(db *sql.DB, backend string) (Record, error) {
	rec := Record{Backend: backend, PersistedState: Closed, EffectiveState: Closed}
	var state, kind, opened, cooldown, lastProbe, updated string
	err := db.QueryRow(`SELECT state,failure_kind,opened_at,cooldown_until,consecutive_failures,last_probe_at,updated_at FROM breaker_state WHERE backend=?`, backend).
		Scan(&state, &kind, &opened, &cooldown, &rec.ConsecutiveFailures, &lastProbe, &updated)
	if err == sql.ErrNoRows {
		return rec, nil
	}
	if err != nil {
		return rec, err
	}
	rec.PersistedState = State(state)
	rec.FailureKind = kind
	rec.OpenedAt = parseTime(opened)
	rec.CooldownUntil = parseTime(cooldown)
	rec.LastProbeAt = parseTime(lastProbe)
	rec.UpdatedAt = parseTime(updated)
	return rec, nil
}

// save upserts one backend's persisted row. It writes the persisted (not
// effective) state; HALF_OPEN is never persisted (see package doc).
func save(db *sql.DB, rec Record) error {
	_, err := db.Exec(`INSERT INTO breaker_state(backend,state,failure_kind,opened_at,cooldown_until,consecutive_failures,last_probe_at,updated_at) VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(backend) DO UPDATE SET state=excluded.state,failure_kind=excluded.failure_kind,opened_at=excluded.opened_at,cooldown_until=excluded.cooldown_until,consecutive_failures=excluded.consecutive_failures,last_probe_at=excluded.last_probe_at,updated_at=excluded.updated_at`,
		rec.Backend, string(rec.PersistedState), rec.FailureKind, formatTime(rec.OpenedAt),
		formatTime(rec.CooldownUntil), rec.ConsecutiveFailures, formatTime(rec.LastProbeAt), formatTime(rec.UpdatedAt))
	return err
}

// appendEvent writes one immutable audit row. Every state change and every
// manual reset is auditable from the ledger alone (standing rule 4).
func appendEvent(db *sql.DB, backend, event, kind, fromState, toState, detail string, now time.Time) error {
	_, err := db.Exec(`INSERT INTO breaker_events(backend,event,failure_kind,from_state,to_state,detail,created) VALUES(?,?,?,?,?,?,?)`,
		backend, event, kind, fromState, toState, detail, formatTime(now))
	return err
}

// Snapshot returns the effective breaker view of one backend at decision time.
// It is a pure read: it does NOT persist the lazy OPEN -> HALF_OPEN transition,
// so dry-run callers (gov route --explain) and gov health are side-effect-free.
// The probe transition is committed only by RecordSuccess / RecordFailure when
// a real run settles.
//
// A read error returns a CLOSED record (the breaker is an infra-optimization,
// not a safety gate — capability/binary/fingerprint exclusions remain the hard
// floor). The broker's Resolve already surfaces ledger-read errors separately.
func Snapshot(db *sql.DB, backend string, now time.Time) Record {
	rec, err := load(db, backend)
	if err != nil {
		return Record{Backend: backend, PersistedState: Closed, EffectiveState: Closed}
	}
	rec.EffectiveState = effectiveState(rec, now)
	return rec
}

// effectiveState folds the lazy OPEN -> HALF_OPEN transition. An OPEN breaker
// whose cooldown has elapsed (and that is time-based, not doctor-gated) is
// admissible again as a probe.
func effectiveState(rec Record, now time.Time) State {
	if rec.PersistedState == Open && !rec.CooldownUntil.IsZero() && !now.Before(rec.CooldownUntil) {
		return HalfOpen
	}
	return rec.PersistedState
}

// All returns the effective breaker view of every registered backend, for
// `gov health`. Backends with no row appear as CLOSED.
func All(db *sql.DB, now time.Time) ([]Record, error) {
	out := make([]Record, 0, len(registeredBackends))
	for _, b := range registeredBackends {
		rec, err := load(db, b)
		if err != nil {
			return nil, err
		}
		rec.EffectiveState = effectiveState(rec, now)
		out = append(out, rec)
	}
	return out, nil
}

// RecordSuccess closes a backend after a run that proved the backend was
// reachable — an APPROVED run, or a QUARANTINED run whose failure was a quality
// kind (the backend ran and answered; it just produced bad work, which is not
// the breaker's concern). A backend that was effectively HALF_OPEN (an OPEN row
// past its cooldown) just had its probe pass, so it closes. DEGRADED recovers
// too. Idempotent on an already-CLOSED backend.
func RecordSuccess(db *sql.DB, backend string, now time.Time) error {
	if !isValidBackend(backend) {
		return ErrUnknownBackend
	}
	rec, err := load(db, backend)
	if err != nil {
		return err
	}
	if rec.PersistedState == Closed {
		return nil
	}
	from := rec.PersistedState
	fromKind := rec.FailureKind
	wasProbe := effectiveState(rec, now) == HalfOpen
	rec.PersistedState = Closed
	rec.FailureKind = ""
	rec.OpenedAt = timeZero
	rec.CooldownUntil = timeZero
	rec.ConsecutiveFailures = 0
	if wasProbe {
		rec.LastProbeAt = now
	}
	rec.UpdatedAt = now
	if err := save(db, rec); err != nil {
		return err
	}
	event := "close"
	detail := "quality run (backend reachable)"
	if wasProbe {
		event = "probe_success"
		detail = "half-open probe succeeded; breaker closed"
	}
	// fromKind, not rec.FailureKind (already cleared): the audit row records
	// which failure kind the backend recovered from.
	return appendEvent(db, backend, event, fromKind, string(from), string(Closed), detail, now)
}

// RecordFailure applies the breaker policy for one infra failure kind. It is a
// no-op (and returns nil) for any non-infra taxonomy — the caller (runtime)
// must already have classified the failure as infra; quality failures go
// through RecordSuccess instead. This is the single chokepoint for rule 3.
func RecordFailure(db *sql.DB, backend, kind string, now time.Time) error {
	if !isValidBackend(backend) {
		return ErrUnknownBackend
	}
	if !observability.IsInfraFailure(kind) {
		return nil
	}
	rec, err := load(db, backend)
	if err != nil {
		return err
	}
	from := rec.PersistedState
	wasProbe := effectiveState(rec, now) == HalfOpen
	// applyPolicy owns all consecutive-failure bookkeeping (kind-change reset +
	// increment); prev snapshots the record before mutation for the audit diff.
	prev := rec
	applyPolicy(db, &rec, kind, now)
	if err := save(db, rec); err != nil {
		return err
	}
	event := "open"
	detail := kind
	switch rec.PersistedState {
	case Degraded:
		event = "degrade"
		detail = fmt.Sprintf("%s (%d consecutive)", kind, rec.ConsecutiveFailures)
	case Open:
		if wasProbe {
			event = "probe_fail"
			detail = fmt.Sprintf("half-open probe failed (%s); re-opened", kind)
		}
	}
	return appendEvent(db, backend, event, kind, string(from), string(rec.PersistedState), detail+" "+diffSummary(prev, rec), now)
}

// applyPolicy mutates rec in place according to the kind. The db is optional
// and used only to read Session 4 quota reset_at hints for QUOTA_EXHAUSTED.
// It owns all consecutive-failure bookkeeping
// (kind-change reset, window reset, increment) so RecordFailure stays a thin
// persistence wrapper. A kind change resets the count so the RATE_LIMIT
// exponent / TRANSIENT threshold never fire on unrelated prior failures; a probe
// failure (same kind) does NOT reset, so re-opening grows the cooldown (plan).
func applyPolicy(db *sql.DB, rec *Record, kind string, now time.Time) {
	kindChanged := rec.FailureKind != "" && rec.FailureKind != kind
	rec.FailureKind = kind
	switch kind {
	case observability.InfraTransientUpstream:
		// DEGRADED first; OPEN only after the threshold within the window. A
		// failure whose predecessor is older than the window (or of a different
		// kind) resets the count so a single blip hours later cannot trip the
		// breaker on stale history.
		if kindChanged || rec.UpdatedAt.IsZero() || now.Sub(rec.UpdatedAt) > transientWindow {
			rec.ConsecutiveFailures = 0
		}
		rec.ConsecutiveFailures++
		if rec.ConsecutiveFailures >= transientThreshold {
			rec.PersistedState = Open
			rec.CooldownUntil = now.Add(transientCooldown)
			if rec.OpenedAt.IsZero() {
				rec.OpenedAt = now
			}
		} else {
			rec.PersistedState = Degraded
			rec.CooldownUntil = timeZero
		}
	case observability.InfraRateLimit:
		// Exponential backoff on consecutive rate-limit failures of the same
		// episode, capped. A probe failure continues the episode (no reset) so
		// re-opening grows the cooldown.
		if kindChanged {
			rec.ConsecutiveFailures = 0
		}
		rec.ConsecutiveFailures++
		// Clamp the exponent before shifting: base<<n overflows int64 around
		// n=25 (5m * 2^25 > MaxInt64 ns), which would produce a NEGATIVE
		// cooldown — an instantly half-open breaker on the most rate-limited
		// backend. 5m<<5 = 160m already exceeds the 2h cap, so any larger
		// shift is the cap.
		cd := rateLimitMaxCooldown
		if shift := rec.ConsecutiveFailures - 1; shift <= 5 {
			cd = rateLimitBaseCooldown << uint(shift)
			if cd > rateLimitMaxCooldown {
				cd = rateLimitMaxCooldown
			}
		}
		rec.PersistedState = Open
		rec.CooldownUntil = now.Add(cd)
		if rec.OpenedAt.IsZero() {
			rec.OpenedAt = now
		}
	case observability.InfraQuotaExhausted:
		// Prefer a quota-window reset_at when Session 4 has one; otherwise
		// fall back to the conservative long cooldown from Session 2.
		rec.ConsecutiveFailures = 0
		rec.PersistedState = Open
		if reset := quota.NextReset(db, rec.Backend, now); reset.After(now) {
			rec.CooldownUntil = reset
		} else {
			rec.CooldownUntil = now.Add(quotaCooldown)
		}
		if rec.OpenedAt.IsZero() {
			rec.OpenedAt = now
		}
	case observability.InfraAuthExpired, observability.InfraBinaryMissing, observability.InfraFlagDrift:
		// Doctor-gated: no time-based recovery. CooldownUntil stays zero so
		// the breaker stays OPEN until gov doctor passes (gov health auto-close)
		// or an operator runs gov health reset.
		rec.ConsecutiveFailures = 0
		rec.PersistedState = Open
		rec.CooldownUntil = timeZero
		if rec.OpenedAt.IsZero() {
			rec.OpenedAt = now
		}
	}
	rec.UpdatedAt = now
}

// diffSummary is a compact human-readable note of what changed, appended to the
// audit event detail. It keeps gov health / breaker_events readable.
func diffSummary(prev, cur Record) string {
	var parts []string
	if prev.PersistedState != cur.PersistedState {
		parts = append(parts, fmt.Sprintf("state %s->%s", prev.PersistedState, cur.PersistedState))
	}
	if !cur.CooldownUntil.IsZero() {
		parts = append(parts, fmt.Sprintf("cooldown_until=%s", formatTime(cur.CooldownUntil)))
	}
	if cur.ConsecutiveFailures != prev.ConsecutiveFailures {
		parts = append(parts, fmt.Sprintf("consecutive=%d", cur.ConsecutiveFailures))
	}
	return strings.Join(parts, " ")
}

// Reset manually forces a backend to CLOSED, recording an audit row. It is the
// operator escape hatch (gov health reset <backend>) and the close path for
// doctor-gated kinds once gov doctor confirms recovery. detail is recorded
// verbatim for the audit trail.
func Reset(db *sql.DB, backend string, now time.Time, detail string) error {
	if !isValidBackend(backend) {
		return ErrUnknownBackend
	}
	rec, err := load(db, backend)
	if err != nil {
		return err
	}
	from := rec.PersistedState
	if from == Closed {
		// Still audit an explicit reset request so the operator action is
		// traceable even when it is a no-op on state.
		return appendEvent(db, backend, "reset", rec.FailureKind, string(Closed), string(Closed), detail, now)
	}
	rec.PersistedState = Closed
	rec.FailureKind = ""
	rec.OpenedAt = timeZero
	rec.CooldownUntil = timeZero
	rec.ConsecutiveFailures = 0
	rec.UpdatedAt = now
	if err := save(db, rec); err != nil {
		return err
	}
	return appendEvent(db, backend, "reset", "", string(from), string(Closed), detail, now)
}

// ReasonFor returns a short human explanation of why a backend is in its current
// state, for the broker's exclusion reason and gov health.
func ReasonFor(rec Record) string {
	if rec.FailureKind != "" {
		return rec.FailureKind
	}
	return ""
}
