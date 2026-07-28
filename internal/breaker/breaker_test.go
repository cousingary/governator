package breaker

import (
	"database/sql"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/observability"
)

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := observability.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustRecordFailure(t *testing.T, db *sql.DB, backend, kind string, now time.Time) {
	t.Helper()
	if err := RecordFailure(db, backend, kind, now); err != nil {
		t.Fatal(err)
	}
}

func mustRecordSuccess(t *testing.T, db *sql.DB, backend string, now time.Time) {
	t.Helper()
	if err := RecordSuccess(db, backend, now); err != nil {
		t.Fatal(err)
	}
}

func mustReset(t *testing.T, db *sql.DB, backend string, now time.Time) {
	t.Helper()
	if err := Reset(db, backend, now, "test"); err != nil {
		t.Fatal(err)
	}
}

func assertState(t *testing.T, db *sql.DB, backend string, now time.Time, want State) {
	t.Helper()
	rec := Snapshot(db, backend, now)
	if rec.EffectiveState != want {
		t.Fatalf("%s effective state = %s, want %s (persisted=%s cooldown=%s)",
			backend, rec.EffectiveState, want, rec.PersistedState, formatTime(rec.CooldownUntil))
	}
}

// TestRegisteredBackendsMatchesAgentsNew keeps the breaker's backend list in
// sync with the canonical agent registry (the breaker cannot import router or
// agents.New without a cycle, so a drift would silently make a real backend
// un-resettable).
func TestRegisteredBackendsMatchesAgentsNew(t *testing.T) {
	for _, name := range registeredBackends {
		if _, err := agents.New(name); err != nil {
			t.Errorf("breaker lists %q but agents.New rejects it", name)
		}
	}
	// And the reverse: every agents.New backend is tracked.
	for _, name := range []string{"claude-code", "codex", "glm", "opencode", "pi"} {
		if !isValidBackend(name) {
			t.Errorf("agents.New accepts %q but breaker does not track it", name)
		}
	}
}

// --- applyPolicy (pure) ---

func TestRateLimitOpensWithBaseCooldownThenExponential(t *testing.T) {
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	rec := Record{Backend: "codex", PersistedState: Closed}

	applyPolicy(nil, &rec, observability.InfraRateLimit, base)
	if rec.PersistedState != Open {
		t.Fatalf("first rate-limit: state=%s want OPEN", rec.PersistedState)
	}
	want := base.Add(rateLimitBaseCooldown)
	if !rec.CooldownUntil.Equal(want) {
		t.Fatalf("first rate-limit cooldown=%s want %s (base=%s)", rec.CooldownUntil, want, rateLimitBaseCooldown)
	}
	if rec.ConsecutiveFailures != 1 {
		t.Fatalf("consecutive=%d want 1", rec.ConsecutiveFailures)
	}

	// Second failure doubles the cooldown (exponential backoff).
	rec2 := rec
	applyPolicy(nil, &rec2, observability.InfraRateLimit, base)
	want2 := base.Add(rateLimitBaseCooldown * 2)
	if !rec2.CooldownUntil.Equal(want2) {
		t.Fatalf("second rate-limit cooldown=%s want %s", rec2.CooldownUntil, want2)
	}
}

func TestRateLimitCooldownCapped(t *testing.T) {
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	rec := Record{Backend: "codex", PersistedState: Open, FailureKind: observability.InfraRateLimit, ConsecutiveFailures: 20, OpenedAt: base}
	applyPolicy(nil, &rec, observability.InfraRateLimit, base)
	if rec.CooldownUntil.Sub(base) > rateLimitMaxCooldown {
		t.Fatalf("cooldown %s exceeded cap %s", rec.CooldownUntil.Sub(base), rateLimitMaxCooldown)
	}
	if !rec.CooldownUntil.Equal(base.Add(rateLimitMaxCooldown)) {
		t.Fatalf("capped cooldown=%s want exactly the cap %s", rec.CooldownUntil, base.Add(rateLimitMaxCooldown))
	}
}

func TestQuotaExhaustedOpensLong(t *testing.T) {
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	rec := Record{Backend: "glm", PersistedState: Closed}
	applyPolicy(nil, &rec, observability.InfraQuotaExhausted, base)
	if rec.PersistedState != Open {
		t.Fatalf("quota: state=%s want OPEN", rec.PersistedState)
	}
	if !rec.CooldownUntil.Equal(base.Add(quotaCooldown)) {
		t.Fatalf("quota cooldown=%s want %s", rec.CooldownUntil, base.Add(quotaCooldown))
	}
}

func TestDoctorGatedKindsOpenWithNoTimeCooldown(t *testing.T) {
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	for _, kind := range []string{
		observability.InfraAuthExpired,
		observability.InfraBinaryMissing,
		observability.InfraFlagDrift,
	} {
		rec := Record{Backend: "codex", PersistedState: Closed}
		applyPolicy(nil, &rec, kind, base)
		if rec.PersistedState != Open {
			t.Fatalf("%s: state=%s want OPEN", kind, rec.PersistedState)
		}
		if !rec.CooldownUntil.IsZero() {
			t.Fatalf("%s: doctor-gated kind must have zero cooldown, got %s", kind, rec.CooldownUntil)
		}
	}
}

func TestTransientUpstreamDegradesThenOpensAtThreshold(t *testing.T) {
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

	// First two transients -> DEGRADED.
	rec := Record{Backend: "codex", PersistedState: Closed}
	applyPolicy(nil, &rec, observability.InfraTransientUpstream, t0)
	if rec.PersistedState != Degraded || rec.ConsecutiveFailures != 1 {
		t.Fatalf("transient #1: state=%s consecutive=%d want DEGRADED/1", rec.PersistedState, rec.ConsecutiveFailures)
	}
	applyPolicy(nil, &rec, observability.InfraTransientUpstream, t0.Add(1*time.Minute))
	if rec.PersistedState != Degraded || rec.ConsecutiveFailures != 2 {
		t.Fatalf("transient #2: state=%s consecutive=%d want DEGRADED/2", rec.PersistedState, rec.ConsecutiveFailures)
	}
	// Third within the window -> OPEN.
	applyPolicy(nil, &rec, observability.InfraTransientUpstream, t0.Add(2*time.Minute))
	if rec.PersistedState != Open {
		t.Fatalf("transient #3: state=%s want OPEN (threshold reached)", rec.PersistedState)
	}
	if rec.CooldownUntil.IsZero() {
		t.Fatalf("transient OPEN must have a cooldown")
	}
}

func TestTransientWindowResetsStaleCount(t *testing.T) {
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	rec := Record{Backend: "codex", PersistedState: Degraded, FailureKind: observability.InfraTransientUpstream, ConsecutiveFailures: 2, UpdatedAt: t0}
	// A failure well outside the 30m window resets the count, so a single new
	// blip degrades rather than tripping OPEN on stale history.
	applyPolicy(nil, &rec, observability.InfraTransientUpstream, t0.Add(transientWindow+time.Minute))
	if rec.PersistedState != Degraded || rec.ConsecutiveFailures != 1 {
		t.Fatalf("stale window: state=%s consecutive=%d want DEGRADED/1", rec.PersistedState, rec.ConsecutiveFailures)
	}
}

func TestKindChangeResetsConsecutive(t *testing.T) {
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	rec := Record{Backend: "codex", PersistedState: Degraded, FailureKind: observability.InfraTransientUpstream, ConsecutiveFailures: 2, UpdatedAt: t0}
	// Switching to RATE_LIMIT: consecutive resets to 1, cooldown is base (not
	// base*4), proving the exponent did not carry over from the transient run.
	applyPolicy(nil, &rec, observability.InfraRateLimit, t0)
	if rec.ConsecutiveFailures != 1 {
		t.Fatalf("kind change: consecutive=%d want 1", rec.ConsecutiveFailures)
	}
	if !rec.CooldownUntil.Equal(t0.Add(rateLimitBaseCooldown)) {
		t.Fatalf("kind change cooldown=%s want base %s", rec.CooldownUntil, t0.Add(rateLimitBaseCooldown))
	}
}

// --- persistence + events ---

func TestRecordFailurePersistsAndAudits(t *testing.T) {
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	mustRecordFailure(t, db, "codex", observability.InfraRateLimit, t0)
	rec := Snapshot(db, "codex", t0)
	if rec.PersistedState != Open || rec.FailureKind != observability.InfraRateLimit {
		t.Fatalf("persisted=%+v", rec)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM breaker_events WHERE backend='codex'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 audit event, got %d", n)
	}
}

func TestRecordFailureRejectsQualityKind(t *testing.T) {
	// Rule 3 chokepoint: a quality taxonomy passed to RecordFailure is a no-op.
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	if err := RecordFailure(db, "codex", "SCOPE_DRIFT", t0); err != nil {
		t.Fatal(err)
	}
	assertState(t, db, "codex", t0, Closed)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM breaker_events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("quality kind must not audit or change state, got %d events", n)
	}
}

func TestRecordFailureRejectsUnknownBackend(t *testing.T) {
	db := newDB(t)
	if err := RecordFailure(db, "nope", observability.InfraRateLimit, time.Now()); err != ErrUnknownBackend {
		t.Fatalf("expected ErrUnknownBackend, got %v", err)
	}
}

// --- effective state / HALF_OPEN ---

func TestSnapshotOpenWithinCooldownStaysOpen(t *testing.T) {
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	mustRecordFailure(t, db, "codex", observability.InfraRateLimit, t0)
	// Mid-cooldown: still OPEN (excluded).
	assertState(t, db, "codex", t0.Add(rateLimitBaseCooldown/2), Open)
}

func TestSnapshotOpenPastCooldownBecomesHalfOpen(t *testing.T) {
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	mustRecordFailure(t, db, "codex", observability.InfraRateLimit, t0)
	// After cooldown: HALF_OPEN (admissible as probe).
	rec := Snapshot(db, "codex", t0.Add(rateLimitBaseCooldown+time.Minute))
	if rec.EffectiveState != HalfOpen {
		t.Fatalf("effective=%s want HALF_OPEN", rec.EffectiveState)
	}
	// Persisted stays OPEN until a real run settles (no write on read).
	if rec.PersistedState != Open {
		t.Fatalf("persisted=%s want OPEN (HALF_OPEN is virtual on read)", rec.PersistedState)
	}
}

func TestSnapshotDoctorGatedStaysOpenPastAnyTime(t *testing.T) {
	// AUTH_EXPIRED has no cooldown, so it never time-recovers to HALF_OPEN —
	// only a doctor pass / manual reset closes it.
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	mustRecordFailure(t, db, "codex", observability.InfraAuthExpired, t0)
	rec := Snapshot(db, "codex", t0.Add(365*24*time.Hour))
	if rec.EffectiveState != Open {
		t.Fatalf("doctor-gated kind must stay OPEN indefinitely, got %s", rec.EffectiveState)
	}
}

// --- probe lifecycle ---

func TestProbeSuccessClosesBreaker(t *testing.T) {
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	mustRecordFailure(t, db, "codex", observability.InfraRateLimit, t0)
	after := t0.Add(rateLimitBaseCooldown + time.Minute)
	// A successful run after cooldown = a passing probe -> CLOSED.
	mustRecordSuccess(t, db, "codex", after)
	assertState(t, db, "codex", after, Closed)
	var probeOK int
	if err := db.QueryRow(`SELECT COUNT(*) FROM breaker_events WHERE backend='codex' AND event='probe_success'`).Scan(&probeOK); err != nil {
		t.Fatal(err)
	}
	if probeOK != 1 {
		t.Fatalf("expected a probe_success audit event, got %d", probeOK)
	}
}

func TestProbeFailureReopensWithIncreasedCooldown(t *testing.T) {
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	mustRecordFailure(t, db, "codex", observability.InfraRateLimit, t0) // consecutive=1, base cooldown
	after := t0.Add(rateLimitBaseCooldown + time.Minute)
	// Probe fails (another rate limit) -> re-OPEN with doubled cooldown.
	mustRecordFailure(t, db, "codex", observability.InfraRateLimit, after)
	rec := Snapshot(db, "codex", after)
	if rec.PersistedState != Open {
		t.Fatalf("probe fail: state=%s want OPEN", rec.PersistedState)
	}
	want := after.Add(rateLimitBaseCooldown * 2)
	if !rec.CooldownUntil.Equal(want) {
		t.Fatalf("probe fail cooldown=%s want doubled %s", rec.CooldownUntil, want)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM breaker_events WHERE backend='codex' AND event='probe_fail'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected a probe_fail audit event, got %d", n)
	}
}

func TestRecordSuccessClosesDegraded(t *testing.T) {
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	mustRecordFailure(t, db, "codex", observability.InfraTransientUpstream, t0) // DEGRADED
	assertState(t, db, "codex", t0, Degraded)
	mustRecordSuccess(t, db, "codex", t0.Add(time.Minute))
	assertState(t, db, "codex", t0.Add(time.Minute), Closed)
}

func TestRecordSuccessIdempotentOnClosed(t *testing.T) {
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	mustRecordSuccess(t, db, "codex", t0) // no row yet -> no-op, no event
	mustRecordSuccess(t, db, "codex", t0) // already closed -> no-op
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM breaker_events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("success on a healthy backend must not audit, got %d", n)
	}
}

// --- rule 3: quality never opens a breaker ---

func TestQualityFailurePathIsRecordSuccess(t *testing.T) {
	// A quality failure (SCOPE_DRIFT) means the backend ran and answered, so it
	// is infra-healthy: it closes a probe, never opens a breaker. The runtime
	// routes quality failures through RecordSuccess; this test pins that a
	// directly-injected quality taxonomy never moves the breaker to OPEN.
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	// Even if mistakenly handed to RecordFailure, quality kinds are rejected.
	mustRecordFailure(t, db, "codex", "SCOPE_DRIFT", t0)
	assertState(t, db, "codex", t0, Closed)
	// And a sequence of quality failures never trips anything.
	for i := 0; i < 10; i++ {
		mustRecordFailure(t, db, "codex", "VALIDATION_FAILED", t0)
	}
	assertState(t, db, "codex", t0, Closed)
}

// --- Reset / All ---

func TestResetClosesAndAudits(t *testing.T) {
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	mustRecordFailure(t, db, "codex", observability.InfraAuthExpired, t0)
	mustReset(t, db, "codex", t0.Add(time.Minute))
	assertState(t, db, "codex", t0.Add(time.Minute), Closed)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM breaker_events WHERE backend='codex' AND event='reset'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected a reset audit event, got %d", n)
	}
}

func TestResetUnknownBackend(t *testing.T) {
	db := newDB(t)
	if err := Reset(db, "nope", time.Now(), "x"); err != ErrUnknownBackend {
		t.Fatalf("expected ErrUnknownBackend, got %v", err)
	}
}

func TestAllReturnsEveryBackend(t *testing.T) {
	db := newDB(t)
	now := time.Now().UTC()
	rows, err := All(db, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(registeredBackends) {
		t.Fatalf("All returned %d rows, want %d", len(rows), len(registeredBackends))
	}
	for _, r := range rows {
		if r.EffectiveState != Closed {
			t.Fatalf("fresh backend %s should be CLOSED, got %s", r.Backend, r.EffectiveState)
		}
	}
}

// --- HealthSource adapter ---

func TestStoreBreakerMapsStates(t *testing.T) {
	db := newDB(t)
	t0 := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	clock := t0
	store := Store{DB: db, Now: func() time.Time { return clock }}

	// CLOSED by default.
	if got := store.Breaker("codex").State; got != "CLOSED" {
		t.Fatalf("fresh backend breaker=%s want CLOSED", got)
	}

	// RATE_LIMIT -> OPEN within cooldown.
	mustRecordFailure(t, db, "codex", observability.InfraRateLimit, t0)
	if got := store.Breaker("codex").State; got != "OPEN" {
		t.Fatalf("within-cooldown breaker=%s want OPEN", got)
	}

	// Past cooldown -> HALF_OPEN maps to CLOSED (admissible probe).
	clock = t0.Add(rateLimitBaseCooldown + time.Minute)
	if got := store.Breaker("codex").State; got != "CLOSED" {
		t.Fatalf("half-open breaker=%s want CLOSED (admissible)", got)
	}

	// DEGRADED -> degraded.
	mustReset(t, db, "codex", clock)
	mustRecordFailure(t, db, "codex", observability.InfraTransientUpstream, clock)
	if got := store.Breaker("codex").State; got != "DEGRADED" {
		t.Fatalf("degraded breaker=%s want DEGRADED", got)
	}
}

func TestStoreBreakerNilDBIsClosed(t *testing.T) {
	store := Store{}
	if got := store.Breaker("codex").State; got != "CLOSED" {
		t.Fatalf("nil-DB store breaker=%s want CLOSED", got)
	}
}

func TestStoreQuotaAlwaysUnavailable(t *testing.T) {
	store := Store{}
	if store.Quota("codex").Available {
		t.Fatal("quota must report unavailable until Session 4")
	}
}

func TestQuotaExhaustedUsesQuotaResetAt(t *testing.T) {
	db := newDB(t)
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	reset := now.Add(17 * time.Minute)
	if _, err := db.Exec(`INSERT INTO quota_windows(backend,account,window_type,window_started_at,reset_at,estimated_limit,measured_usage,reserved_usage,confidence,source,updated_at,window_started_unix_nano,reset_unix_nano,updated_unix_nano) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "codex", "default", "daily", now.Format(time.RFC3339Nano), reset.Format(time.RFC3339Nano), 1000.0, 1000.0, 0.0, 0.9, "error_hint", now.Format(time.RFC3339Nano), now.UnixNano(), reset.UnixNano(), now.UnixNano()); err != nil {
		t.Fatal(err)
	}
	mustRecordFailure(t, db, "codex", observability.InfraQuotaExhausted, now)
	rec := Snapshot(db, "codex", now)
	if !rec.CooldownUntil.Equal(reset) {
		t.Fatalf("cooldown=%s want reset_at %s", rec.CooldownUntil, reset)
	}
}

func TestStoreQuotaReadsHeadroom(t *testing.T) {
	db := newDB(t)
	base := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	if _, err := db.Exec(`INSERT INTO quota_windows(backend,account,window_type,window_started_at,reset_at,estimated_limit,measured_usage,reserved_usage,confidence,source,updated_at,window_started_unix_nano,reset_unix_nano,updated_unix_nano) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "codex", "default", "daily", base.Format(time.RFC3339Nano), base.Add(24*time.Hour).Format(time.RFC3339Nano), 1000.0, 250.0, 250.0, 0.8, "config", base.Format(time.RFC3339Nano), base.UnixNano(), base.Add(24*time.Hour).UnixNano(), base.UnixNano()); err != nil {
		t.Fatal(err)
	}
	store := Store{DB: db, Now: func() time.Time { return base }}
	snap := store.Quota("codex")
	if !snap.Available || snap.HeadroomPct != 0.5 {
		t.Fatalf("quota snapshot=%+v want available headroom 0.5", snap)
	}
}

// Regression: rateLimitBaseCooldown<<n overflows int64 near n=25, which
// produced a NEGATIVE cooldown — an instantly-admissible (HALF_OPEN) breaker
// on the most persistently rate-limited backend.
func TestRateLimitCooldownNeverOverflowsToNegative(t *testing.T) {
	db := newDB(t)
	now := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 40; i++ {
		mustRecordFailure(t, db, "codex", observability.InfraRateLimit, now)
	}
	rec := Snapshot(db, "codex", now)
	if rec.PersistedState != Open {
		t.Fatalf("state = %s, want OPEN", rec.PersistedState)
	}
	want := now.Add(rateLimitMaxCooldown)
	if !rec.CooldownUntil.Equal(want) {
		t.Fatalf("cooldown_until = %s, want %s (capped)", rec.CooldownUntil, want)
	}
	assertState(t, db, "codex", now.Add(time.Minute), Open)
}

// The close/probe_success audit row must record which failure kind the
// backend recovered FROM, not the already-cleared post-close kind.
func TestRecordSuccessAuditKeepsRecoveredKind(t *testing.T) {
	db := newDB(t)
	now := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)
	mustRecordFailure(t, db, "glm", observability.InfraRateLimit, now)
	mustRecordSuccess(t, db, "glm", now.Add(10*time.Minute))
	var kind string
	if err := db.QueryRow(`SELECT failure_kind FROM breaker_events WHERE backend='glm' AND event IN ('close','probe_success') ORDER BY id DESC LIMIT 1`).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != observability.InfraRateLimit {
		t.Fatalf("audit failure_kind = %q, want %s", kind, observability.InfraRateLimit)
	}
}
