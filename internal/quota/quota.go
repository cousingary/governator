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
	"strings"
	"time"

	"github.com/cousingary/governator/internal/config"
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
		if _, err := db.Exec(`INSERT INTO quota_windows(backend,account,window_type,window_started_at,reset_at,estimated_limit,measured_usage,reserved_usage,confidence,source,updated_at)
VALUES(?,?,?,?,?,?,0,0,?,'config',?)
ON CONFLICT(backend,account,window_type) DO UPDATE SET estimated_limit=excluded.estimated_limit, reset_at=excluded.reset_at, confidence=excluded.confidence, source='config', updated_at=excluded.updated_at`,
			backend, account, windowType, formatTime(started), formatTime(reset), q.EstimatedLimit, confidence, formatTime(now)); err != nil {
			return err
		}
	}
	return nil
}

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
	for _, w := range windows {
		if w.EstimatedLimit > 0 && w.MeasuredUsage+w.ReservedUsage+usage > w.EstimatedLimit {
			return Reservation{}, fmt.Errorf("%w: %s/%s remaining %.0f < estimate %.0f (reset %s)", ErrNoHeadroom, backend, w.WindowType, remaining(w), usage, formatTime(w.ResetAt))
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return Reservation{}, err
	}
	defer tx.Rollback()
	expires := now.Add(ttl)
	res, err := tx.Exec(`INSERT INTO quota_reservations(run_id,backend,account,usage,expires_at,created_at,settled_at) VALUES(?,?,?,?,?,?,'')`, runID, backend, account, usage, formatTime(expires), formatTime(now))
	if err != nil {
		return Reservation{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Reservation{}, err
	}
	if _, err := tx.Exec(`UPDATE quota_windows SET reserved_usage=reserved_usage+?, updated_at=? WHERE backend=? AND account=?`, usage, formatTime(now), backend, account); err != nil {
		return Reservation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Reservation{}, err
	}
	return Reservation{ID: id, Backend: backend, Account: account, Usage: usage}, nil
}

func Release(db *sql.DB, reservationID int64, now time.Time) error {
	if db == nil || reservationID == 0 {
		return nil
	}
	var backend, account string
	var reserved float64
	var settled string
	err := db.QueryRow(`SELECT backend,account,usage,COALESCE(settled_at,'') FROM quota_reservations WHERE id=?`, reservationID).Scan(&backend, &account, &reserved, &settled)
	if err == sql.ErrNoRows || settled != "" {
		return nil
	}
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE quota_reservations SET settled_at=?, expired=1 WHERE id=?`, formatTime(now), reservationID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE quota_windows SET reserved_usage=MAX(reserved_usage-?,0), updated_at=? WHERE backend=? AND account=?`, reserved, formatTime(now), backend, account); err != nil {
		return err
	}
	return tx.Commit()
}

func Settle(db *sql.DB, reservationID int64, measuredUsage float64, now time.Time) error {
	if db == nil || reservationID == 0 {
		return nil
	}
	var backend, account string
	var reserved float64
	var settled string
	err := db.QueryRow(`SELECT backend,account,usage,COALESCE(settled_at,'') FROM quota_reservations WHERE id=?`, reservationID).Scan(&backend, &account, &reserved, &settled)
	if err == sql.ErrNoRows || settled != "" {
		return nil
	}
	if err != nil {
		return err
	}
	if measuredUsage < 0 {
		measuredUsage = 0
	}
	if measuredUsage == 0 {
		measuredUsage = reserved
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE quota_reservations SET settled_at=?, measured_usage=? WHERE id=?`, formatTime(now), measuredUsage, reservationID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE quota_windows SET reserved_usage=MAX(reserved_usage-?,0), measured_usage=measured_usage+?, updated_at=? WHERE backend=? AND account=?`, reserved, measuredUsage, formatTime(now), backend, account); err != nil {
		return err
	}
	return tx.Commit()
}

func ExpireStale(db *sql.DB, now time.Time) error {
	rows, err := db.Query(`SELECT id,backend,account,usage FROM quota_reservations WHERE settled_at='' AND expires_at<>'' AND expires_at<?`, formatTime(now))
	if err != nil {
		return err
	}
	defer rows.Close()
	type stale struct {
		id               int64
		backend, account string
		usage            float64
	}
	var staleRows []stale
	for rows.Next() {
		var s stale
		if err := rows.Scan(&s.id, &s.backend, &s.account, &s.usage); err != nil {
			return err
		}
		staleRows = append(staleRows, s)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, s := range staleRows {
		if _, err := db.Exec(`UPDATE quota_reservations SET settled_at=?, expired=1 WHERE id=?`, formatTime(now), s.id); err != nil {
			return err
		}
		if _, err := db.Exec(`UPDATE quota_windows SET reserved_usage=MAX(reserved_usage-?,0), updated_at=? WHERE backend=? AND account=?`, s.usage, formatTime(now), s.backend, s.account); err != nil {
			return err
		}
	}
	return nil
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
	rows, err := db.Query(`SELECT backend,account,window_type,window_started_at,reset_at,estimated_limit,measured_usage,reserved_usage,confidence,source,updated_at FROM quota_windows ORDER BY backend,account,window_type`)
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

func ApplyResetHint(db *sql.DB, backend, account string, resetAt time.Time, now time.Time) error {
	backend = normalize(backend)
	account = normalizeAccount(account)
	if db == nil || backend == "" || resetAt.IsZero() || !resetAt.After(now) {
		return nil
	}
	windowType := inferWindowType(now, resetAt)
	_, err := db.Exec(`INSERT INTO quota_windows(backend,account,window_type,window_started_at,reset_at,estimated_limit,measured_usage,reserved_usage,confidence,source,updated_at)
VALUES(?,?,?,?,?,0,0,0,0.9,'error_hint',?)
ON CONFLICT(backend,account,window_type) DO UPDATE SET reset_at=excluded.reset_at, confidence=MAX(confidence,0.9), source='error_hint', updated_at=excluded.updated_at`,
		backend, account, windowType, formatTime(now), formatTime(resetAt), formatTime(now))
	return err
}

func NextReset(db *sql.DB, backend string, now time.Time) time.Time {
	if db == nil {
		return time.Time{}
	}
	var raw string
	err := db.QueryRow(`SELECT reset_at FROM quota_windows WHERE backend=? AND reset_at>? ORDER BY reset_at ASC LIMIT 1`, normalize(backend), formatTime(now)).Scan(&raw)
	if err != nil {
		return time.Time{}
	}
	return parseTimeOrZero(raw)
}

func windowsFor(db *sql.DB, backend, account string, now time.Time) ([]Window, error) {
	if err := rolloverExpired(db, now); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT backend,account,window_type,window_started_at,reset_at,estimated_limit,measured_usage,reserved_usage,confidence,source,updated_at FROM quota_windows WHERE backend=? AND account=? ORDER BY window_type`, backend, account)
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

func scanWindow(s scanner) (Window, error) {
	var w Window
	var started, reset, updated string
	err := s.Scan(&w.Backend, &w.Account, &w.WindowType, &started, &reset, &w.EstimatedLimit, &w.MeasuredUsage, &w.ReservedUsage, &w.Confidence, &w.Source, &updated)
	w.WindowStartedAt = parseTimeOrZero(started)
	w.ResetAt = parseTimeOrZero(reset)
	w.UpdatedAt = parseTimeOrZero(updated)
	return w, err
}

func rolloverExpired(db *sql.DB, now time.Time) error {
	rows, err := db.Query(`SELECT backend,account,window_type FROM quota_windows WHERE reset_at<>'' AND reset_at<=?`, formatTime(now))
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
		if _, err := db.Exec(`UPDATE quota_windows SET window_started_at=?, reset_at=?, measured_usage=0, reserved_usage=0, updated_at=? WHERE backend=? AND account=? AND window_type=?`, formatTime(windowStart(k.windowType, now)), formatTime(nextReset(k.windowType, now)), formatTime(now), k.backend, k.account, k.windowType); err != nil {
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
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
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
