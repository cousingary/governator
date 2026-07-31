// Package quota tracks subscription-window headroom separately from dollar spend.
// Spend caps answer "how much money can this run cost?"; quota windows answer
// "how much provider-plan headroom remains in this reset window?". The router
// consumes only the deterministic headroom snapshot; reservations and
// settlements are written by runtime launch/completion paths.
package quota

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/dbtime"
	"github.com/cousingary/governator/internal/spend"
)

const DefaultAccount = "default"

var ErrNoHeadroom = errors.New("quota: insufficient headroom")

type Window struct {
	Backend         string
	Account         string
	WindowType      string
	WindowStartedAt time.Time
	ResetAt         time.Time
	EstimatedLimit  float64
	MeasuredUsage   float64
	ReservedUsage   float64
	Confidence      float64
	Source          string
	UpdatedAt       time.Time
}

type Snapshot struct {
	Available      bool
	HeadroomPct    float64
	RemainingUsage float64
	EstimatedLimit float64
	ResetAt        time.Time
	Confidence     float64
	WindowType     string
	MeasuredUsage  float64
	ReservedUsage  float64
}

type Reservation struct {
	ID      int64
	Backend string
	Account string
	Usage   float64
}

func EstimateUsage(maxTokens int) float64 {
	if maxTokens > 0 {
		return float64(maxTokens)
	}
	return float64(spend.UnboundedQuotaTokens())
}

func SeedFromConfig(db *sql.DB, cfg config.Config, now time.Time) error {
	if db == nil {
		return nil
	}
	for _, q := range cfg.Quotas {
		backend := normalize(q.Backend)
		if backend == "" || q.EstimatedLimit <= 0 {
			continue
		}
		account := normalize(q.Account)
		if account == "" {
			account = DefaultAccount
		}
		windowType := normalize(q.WindowType)
		if windowType == "" {
			windowType = "daily"
		}
		started := parseTimeOrZero(q.WindowStartedAt)
		reset := parseTimeOrZero(q.ResetAt)
		if started.IsZero() {
			started = windowStart(windowType, now)
		}
		if reset.IsZero() || !reset.After(now) {
			reset = nextReset(windowType, now)
		}
		confidence := q.Confidence
		if confidence <= 0 {
			confidence = 0.6
		}
		if confidence > 1 {
			confidence = 1
		}
		// Sol15 P0-3: config.LoadStrict already range-checks the operator's
		// window_started_at/reset_at, but SeedFromConfig also computes
		// started/reset *from* now (windowStart/nextReset above) when the
		// operator left them unset, so this still converts and returns a
		// typed error rather than trusting the check happened upstream.
		startedNanos, err := dbtime.ToUnixNano(started)
		if err != nil {
			return fmt.Errorf("quota config for backend %q account %q: window_started_at %s: %w", backend, account, formatTime(started), err)
		}
		resetNanos, err := dbtime.ToUnixNano(reset)
		if err != nil {
			return fmt.Errorf("quota config for backend %q account %q: reset_at %s: %w", backend, account, formatTime(reset), err)
		}
		nowNanos, err := dbtime.ToUnixNano(now)
		if err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT INTO quota_windows(backend,account,window_type,window_started_at,reset_at,estimated_limit,measured_usage,reserved_usage,confidence,source,updated_at,window_started_unix_nano,reset_unix_nano,updated_unix_nano)
VALUES(?,?,?,?,?,?,0,0,?,'config',?,?,?,?)
ON CONFLICT(backend,account,window_type) DO UPDATE SET estimated_limit=excluded.estimated_limit, reset_at=excluded.reset_at, confidence=excluded.confidence, source='config', updated_at=excluded.updated_at, reset_unix_nano=excluded.reset_unix_nano, updated_unix_nano=excluded.updated_unix_nano`,
			backend, account, windowType, formatTime(started), formatTime(reset), q.EstimatedLimit, confidence, formatTime(now), startedNanos, resetNanos, nowNanos); err != nil {
			return err
		}
	}
	return nil
}

// Reserve atomically checks headroom and books a reservation across every
// window the backend/account has (daily, weekly, ...): the pre-fix version
// read headroom, then opened a *separate* transaction that wrote
// unconditionally, so two concurrent Reserve calls could both observe
// sufficient headroom and both commit, together exceeding estimated_limit
// (audit finding #10). Each window's reserved_usage bump now happens inside
// one transaction via a conditional UPDATE whose WHERE clause re-checks
// headroom at write time; SQLite serializes writers, so the loser of a race
// re-evaluates against the winner's already-committed reservation and
// correctly affects zero rows instead of overshooting. windows is read
// *before* Begin (matching the pre-fix structure) purely to know which
// window_types to attempt and to word the error — every row's actual
// admission is decided by the conditional UPDATE inside the transaction, not
// by this snapshot, so a stale read here cannot cause overshoot.
func Reserve(db *sql.DB, backend, account, runID string, usage float64, ttl time.Duration, now time.Time) (Reservation, error) {
	backend = normalize(backend)
	account = normalizeAccount(account)
	if backend == "" || usage <= 0 || db == nil {
		return Reservation{}, nil
	}
	if err := ExpireStale(db, now); err != nil {
		return Reservation{}, err
	}
	windows, err := windowsFor(db, backend, account, now)
	if err != nil {
		return Reservation{}, err
	}
	if len(windows) == 0 {
		return Reservation{}, nil
	}
	nowNanos, err := dbtime.ToUnixNano(now)
	if err != nil {
		return Reservation{}, err
	}
	tx, err := db.Begin()
	if err != nil {
		return Reservation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, w := range windows {
		res, err := tx.Exec(`UPDATE quota_windows SET reserved_usage=reserved_usage+?, updated_at=?, updated_unix_nano=?
WHERE backend=? AND account=? AND window_type=?
  AND (estimated_limit<=0 OR measured_usage+reserved_usage+?<=estimated_limit)`,
			usage, formatTime(now), nowNanos, backend, account, w.WindowType, usage)
		if err != nil {
			return Reservation{}, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return Reservation{}, err
		}
		if n == 0 {
			return Reservation{}, fmt.Errorf("%w: %s/%s remaining %.0f < estimate %.0f (reset %s)", ErrNoHeadroom, backend, w.WindowType, remaining(w), usage, formatTime(w.ResetAt))
		}
	}
	// Sol15 P0-3: TTL is caller-supplied (runtime.go derives it from
	// operator config already validated > 0, but this must not trust that)
	// and now+ttl must not silently wrap; dbtime.ToUnixNano is the
	// overflow-safe boundary — a TTL large enough to push past
	// MaxSupportedTime fails the reservation instead of storing a corrupt
	// expiry.
	expires := now.Add(ttl)
	expiresNanos, err := dbtime.ToUnixNano(expires)
	if err != nil {
		return Reservation{}, fmt.Errorf("quota reservation for %s/%s: expires_at %s: %w", backend, account, formatTime(expires), err)
	}
	res, err := tx.Exec(`INSERT INTO quota_reservations(run_id,backend,account,usage,expires_at,created_at,settled_at,expires_unix_nano,created_unix_nano,settled_unix_nano) VALUES(?,?,?,?,?,?,'',?,?,?)`, runID, backend, account, usage, formatTime(expires), formatTime(now), expiresNanos, nowNanos, dbtime.UnsetUnixNano)
	if err != nil {
		return Reservation{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Reservation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Reservation{}, err
	}
	return Reservation{ID: id, Backend: backend, Account: account, Usage: usage}, nil
}

// ReleaseForRun releases every still-open (unsettled) reservation belonging
// to runID. Used by run recovery (Phase 4): an interrupted run must not hold
// quota headroom hostage until its TTL expires on its own.
func ReleaseForRun(db *sql.DB, runID string, now time.Time) error {
	if db == nil || runID == "" {
		return nil
	}
	rows, err := db.Query(`SELECT id FROM quota_reservations WHERE run_id=? AND settled_at=''`, runID)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, id := range ids {
		if err := Release(db, id, now); err != nil {
			return err
		}
	}
	return nil
}

// claimReservation atomically transitions an unsettled reservation to
// settled (the schema's settled_at column also gates Release and
// ExpireStale, not just Settle — "settled" here means "no longer open", not
// specifically "measured"). The claim and the RETURNING read happen as one
// statement, so two concurrent callers (Settle vs Release vs ExpireStale,
// or two callers of the same one) can never both believe they own the row:
// SQLite serializes the UPDATE, the loser's WHERE settled_at=” matches
// nothing, and ok=false tells it to treat the reservation as already
// resolved by someone else — the exact pre-fix double-decrement/
// double-booking race (audit finding #10) is closed by construction.
func claimReservation(tx *sql.Tx, reservationID int64, now time.Time, expired bool) (backend, account string, reserved float64, ok bool, err error) {
	expiredFlag := 0
	if expired {
		expiredFlag = 1
	}
	nowNanos, err := dbtime.ToUnixNano(now)
	if err != nil {
		return "", "", 0, false, err
	}
	err = tx.QueryRow(`UPDATE quota_reservations SET settled_at=?, settled_unix_nano=?, expired=?
WHERE id=? AND settled_at=''
RETURNING backend, account, usage`,
		formatTime(now), nowNanos, expiredFlag, reservationID).Scan(&backend, &account, &reserved)
	if err == sql.ErrNoRows {
		return "", "", 0, false, nil
	}
	if err != nil {
		return "", "", 0, false, err
	}
	return backend, account, reserved, true, nil
}

func Release(db *sql.DB, reservationID int64, now time.Time) error {
	if db == nil || reservationID == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	backend, account, reserved, ok, err := claimReservation(tx, reservationID, now, true)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	nowNanos, err := dbtime.ToUnixNano(now)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE quota_windows SET reserved_usage=MAX(reserved_usage-?,0), updated_at=?, updated_unix_nano=? WHERE backend=? AND account=?`, reserved, formatTime(now), nowNanos, backend, account); err != nil {
		return err
	}
	return tx.Commit()
}

func Settle(db *sql.DB, reservationID int64, measuredUsage float64, now time.Time) error {
	if db == nil || reservationID == 0 {
		return nil
	}
	if measuredUsage < 0 {
		measuredUsage = 0
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	backend, account, reserved, ok, err := claimReservation(tx, reservationID, now, false)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if measuredUsage == 0 {
		measuredUsage = reserved
	}
	if _, err := tx.Exec(`UPDATE quota_reservations SET measured_usage=? WHERE id=?`, measuredUsage, reservationID); err != nil {
		return err
	}
	nowNanos, err := dbtime.ToUnixNano(now)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE quota_windows SET reserved_usage=MAX(reserved_usage-?,0), measured_usage=measured_usage+?, updated_at=?, updated_unix_nano=? WHERE backend=? AND account=?`, reserved, measuredUsage, formatTime(now), nowNanos, backend, account); err != nil {
		return err
	}
	return tx.Commit()
}

func ExpireStale(db *sql.DB, now time.Time) error {
	if db == nil {
		return nil
	}
	nowNanos, err := dbtime.ToUnixNano(now)
	if err != nil {
		return err
	}
	rows, err := db.Query(`SELECT id FROM quota_reservations WHERE settled_at='' AND expires_unix_nano<>? AND expires_unix_nano<?`, dbtime.UnsetUnixNano, nowNanos)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, id := range ids {
		if err := expireOne(db, id, now); err != nil {
			return err
		}
	}
	return nil
}

func expireOne(db *sql.DB, reservationID int64, now time.Time) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	backend, account, reserved, ok, err := claimReservation(tx, reservationID, now, true)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	nowNanos, err := dbtime.ToUnixNano(now)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE quota_windows SET reserved_usage=MAX(reserved_usage-?,0), updated_at=?, updated_unix_nano=? WHERE backend=? AND account=?`, reserved, formatTime(now), nowNanos, backend, account); err != nil {
		return err
	}
	return tx.Commit()
}

func Headroom(db *sql.DB, backend, account string, now time.Time) (Snapshot, error) {
	backend = normalize(backend)
	account = normalizeAccount(account)
	if db == nil || backend == "" {
		return Snapshot{}, nil
	}
	windows, err := windowsFor(db, backend, account, now)
	if err != nil {
		return Snapshot{}, err
	}
	if len(windows) == 0 {
		return Snapshot{Available: false}, nil
	}
	best := Snapshot{Available: true, HeadroomPct: 1, RemainingUsage: math.MaxFloat64}
	for _, w := range windows {
		rem := remaining(w)
		pct := 1.0
		if w.EstimatedLimit > 0 {
			pct = clamp(rem / w.EstimatedLimit)
		}
		if pct < best.HeadroomPct || best.WindowType == "" {
			best = Snapshot{Available: true, HeadroomPct: pct, RemainingUsage: rem, EstimatedLimit: w.EstimatedLimit, ResetAt: w.ResetAt, Confidence: w.Confidence, WindowType: w.WindowType, MeasuredUsage: w.MeasuredUsage, ReservedUsage: w.ReservedUsage}
		}
	}
	return best, nil
}

func Windows(db *sql.DB, now time.Time) ([]Window, error) {
	if err := rolloverExpired(db, now); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT ` + windowSelectColumns + ` FROM quota_windows ORDER BY backend,account,window_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Window
	for rows.Next() {
		w, err := scanWindow(rows)
		if err != nil {
			// Sol15 P0-3: Windows() backs the operator-facing `gov quota`
			// listing — a read path that can afford to skip a corrupt row
			// and show the rest, rather than hiding every window's status
			// behind the one bad row. windowsFor (Reserve/Headroom, an
			// authority path whose decision the router trusts) does not
			// get this treatment: it propagates the same error and fails
			// closed.
			if errors.Is(err, dbtime.ErrCorruptTimestamp) {
				fmt.Fprintf(os.Stderr, "quota: skipping corrupt quota_windows row: %v\n", err)
				continue
			}
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ErrResetHintOutOfRange reports a provider-supplied quota reset hint whose
// timestamp falls outside dbtime's supported range (Sol15 P0-3, "validate
// provider reset hints before persistence"). A provider response is
// adversarial input by definition — a malformed or hostile hint must not be
// able to crash or stall a run, so callers should log this and drop the
// hint rather than fail whatever operation produced it.
var ErrResetHintOutOfRange = errors.New("quota: reset hint timestamp outside supported range")

func ApplyResetHint(db *sql.DB, backend, account string, resetAt time.Time, now time.Time) error {
	backend = normalize(backend)
	account = normalizeAccount(account)
	if db == nil || backend == "" || resetAt.IsZero() || !resetAt.After(now) {
		return nil
	}
	resetNanos, err := dbtime.ToUnixNano(resetAt)
	if err != nil {
		return fmt.Errorf("%w: %s/%s reset hint %s: %v", ErrResetHintOutOfRange, backend, account, formatTime(resetAt), err)
	}
	nowNanos, err := dbtime.ToUnixNano(now)
	if err != nil {
		return err
	}
	windowType := inferWindowType(now, resetAt)
	_, err = db.Exec(`INSERT INTO quota_windows(backend,account,window_type,window_started_at,reset_at,estimated_limit,measured_usage,reserved_usage,confidence,source,updated_at,window_started_unix_nano,reset_unix_nano,updated_unix_nano)
VALUES(?,?,?,?,?,0,0,0,0.9,'error_hint',?,?,?,?)
ON CONFLICT(backend,account,window_type) DO UPDATE SET reset_at=excluded.reset_at, confidence=MAX(confidence,0.9), source='error_hint', updated_at=excluded.updated_at, reset_unix_nano=excluded.reset_unix_nano, updated_unix_nano=excluded.updated_unix_nano`,
		backend, account, windowType, formatTime(now), formatTime(resetAt), formatTime(now), nowNanos, resetNanos, nowNanos)
	return err
}

func NextReset(db *sql.DB, backend string, now time.Time) time.Time {
	if db == nil {
		return time.Time{}
	}
	nowNanos, err := dbtime.ToUnixNano(now)
	if err != nil {
		return time.Time{}
	}
	var raw string
	err = db.QueryRow(`SELECT reset_at FROM quota_windows WHERE backend=? AND reset_unix_nano>? ORDER BY reset_unix_nano ASC LIMIT 1`, normalize(backend), nowNanos).Scan(&raw)
	if err != nil {
		return time.Time{}
	}
	return parseTimeOrZero(raw)
}

func windowsFor(db *sql.DB, backend, account string, now time.Time) ([]Window, error) {
	if err := rolloverExpired(db, now); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT `+windowSelectColumns+` FROM quota_windows WHERE backend=? AND account=? ORDER BY window_type`, backend, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Window
	for rows.Next() {
		w, err := scanWindow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(dest ...any) error }

// windowSelectColumns is shared by Windows and windowsFor. Sol15 P0-3
// ("database values outside the valid range" / "corrupt database numeric
// timestamp"): scanWindow reads both the legacy text columns and the
// numeric _unix_nano columns so it can cross-check them — a bare range
// check on the numeric column alone can never fail (MinSupportedTime..
// MaxSupportedTime spans the full int64 range apart from the reserved
// sentinel), so the only way to detect a genuinely corrupt numeric value is
// dbtime.VerifyLegacyRoundTrip against the text mirror every writer sets in
// the same statement.
const windowSelectColumns = "backend,account,window_type,window_started_at,reset_at,estimated_limit,measured_usage,reserved_usage,confidence,source,updated_at,window_started_unix_nano,reset_unix_nano,updated_unix_nano"

func scanWindow(s scanner) (Window, error) {
	var w Window
	var started, reset, updated string
	var startedNanos, resetNanos, updatedNanos int64
	if err := s.Scan(&w.Backend, &w.Account, &w.WindowType, &started, &reset, &w.EstimatedLimit, &w.MeasuredUsage, &w.ReservedUsage, &w.Confidence, &w.Source, &updated, &startedNanos, &resetNanos, &updatedNanos); err != nil {
		return Window{}, err
	}
	if err := dbtime.VerifyLegacyRoundTrip(started, startedNanos); err != nil {
		return Window{}, fmt.Errorf("quota_windows %s/%s/%s.window_started_unix_nano: %w", w.Backend, w.Account, w.WindowType, err)
	}
	if err := dbtime.VerifyLegacyRoundTrip(reset, resetNanos); err != nil {
		return Window{}, fmt.Errorf("quota_windows %s/%s/%s.reset_unix_nano: %w", w.Backend, w.Account, w.WindowType, err)
	}
	if err := dbtime.VerifyLegacyRoundTrip(updated, updatedNanos); err != nil {
		return Window{}, fmt.Errorf("quota_windows %s/%s/%s.updated_unix_nano: %w", w.Backend, w.Account, w.WindowType, err)
	}
	w.WindowStartedAt = dbtime.FromUnixNano(startedNanos)
	w.ResetAt = dbtime.FromUnixNano(resetNanos)
	w.UpdatedAt = dbtime.FromUnixNano(updatedNanos)
	return w, nil
}

func rolloverExpired(db *sql.DB, now time.Time) error {
	nowNanos, err := dbtime.ToUnixNano(now)
	if err != nil {
		return err
	}
	rows, err := db.Query(`SELECT backend,account,window_type FROM quota_windows WHERE reset_unix_nano<>? AND reset_unix_nano<=?`, dbtime.UnsetUnixNano, nowNanos)
	if err != nil {
		return err
	}
	defer rows.Close()
	type key struct{ backend, account, windowType string }
	var keys []key
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.backend, &k.account, &k.windowType); err != nil {
			return err
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		newStart := windowStart(k.windowType, now)
		newReset := nextReset(k.windowType, now)
		newStartNanos, err := dbtime.ToUnixNano(newStart)
		if err != nil {
			return err
		}
		newResetNanos, err := dbtime.ToUnixNano(newReset)
		if err != nil {
			return err
		}
		if _, err := db.Exec(`UPDATE quota_windows SET window_started_at=?, reset_at=?, measured_usage=0, reserved_usage=0, updated_at=?, window_started_unix_nano=?, reset_unix_nano=?, updated_unix_nano=? WHERE backend=? AND account=? AND window_type=?`, formatTime(newStart), formatTime(newReset), formatTime(now), newStartNanos, newResetNanos, nowNanos, k.backend, k.account, k.windowType); err != nil {
			return err
		}
	}
	return nil
}

func remaining(w Window) float64 {
	rem := w.EstimatedLimit - w.MeasuredUsage - w.ReservedUsage
	if rem < 0 {
		return 0
	}
	return rem
}

func normalizeAccount(a string) string {
	a = normalize(a)
	if a == "" {
		return DefaultAccount
	}
	return a
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func formatTime(t time.Time) string {
	return dbtime.FormatLegacy(t)
}

func parseTimeOrZero(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func windowStart(windowType string, now time.Time) time.Time {
	now = now.UTC()
	switch normalize(windowType) {
	case "monthly":
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	case "weekly":
		weekday := int(now.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		d := now.AddDate(0, 0, -(weekday - 1))
		return time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC)
	case "5h":
		hour := (now.Hour() / 5) * 5
		return time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, time.UTC)
	default:
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	}
}

func nextReset(windowType string, now time.Time) time.Time {
	start := windowStart(windowType, now)
	switch normalize(windowType) {
	case "monthly":
		return start.AddDate(0, 1, 0)
	case "weekly":
		return start.AddDate(0, 0, 7)
	case "5h":
		for !start.After(now.UTC()) {
			start = start.Add(5 * time.Hour)
		}
		return start
	default:
		return start.AddDate(0, 0, 1)
	}
}

func inferWindowType(now, reset time.Time) string {
	d := reset.Sub(now)
	switch {
	case d <= 6*time.Hour:
		return "5h"
	case d <= 36*time.Hour:
		return "daily"
	case d <= 9*24*time.Hour:
		return "weekly"
	default:
		return "monthly"
	}
}
