package observability

import (
	"database/sql"
	"time"

	"github.com/cousingary/governator/internal/dbtime"
)

// OperationalError is an append-only audit row for a best-effort post-run
// operation (breaker feedback, quota reset hints, spend-halt recalculation,
// workspace/container destruction, ...) that failed inline. Recording it here
// must never itself fail the run whose outcome was already decided — callers
// treat a write error from RecordOperationalError as a last-resort stderr
// log, never as a reason to abort (see internal/runtime's
// noteOperationalFailure).
type OperationalError struct {
	RunID   string
	OpKind  string
	Detail  string
	Created string
}

// RecordOperationalError appends one operational_errors row. Session 4 (Sol
// Phase 3): pairs with an OutboxItem so the failure is both visible in the
// audit trail and durably retryable, instead of vanishing with the swallowed
// error it used to be.
func RecordOperationalError(db *sql.DB, e OperationalError) error {
	_, err := db.Exec(`INSERT INTO operational_errors(run_id,op_kind,detail,created) VALUES(?,?,?,?)`,
		e.RunID, e.OpKind, e.Detail, e.Created)
	return err
}

// OutboxItem is one unit of durable retry work in maintenance_outbox.
// Status is "pending" (awaiting claim), "processing" (claimed by lease_owner
// until lease_until — Sol P1.5, finding #12), "done" (the operation
// eventually succeeded), or "dead" (gov cleanup --stale gave up after too
// many attempts — the operational_errors trail is what survives, this row
// is just marked so `gov reconcile` stops retrying it).
type OutboxItem struct {
	ID         int64
	RunID      string
	OpKind     string
	Payload    string
	Status     string
	Attempts   int
	LastError  string
	CreatedAt  string
	UpdatedAt  string
	LeaseOwner string
	LeaseUntil string
}

// EnqueueOutbox records one retryable unit of work. payload is op-kind
// specific JSON carrying everything a later `gov reconcile` needs to attempt
// the operation again without any in-memory state from the original run.
func EnqueueOutbox(db *sql.DB, runID, opKind, payload, now string) error {
	nowNanos, err := dbtime.LegacyToUnixNano(now)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO maintenance_outbox(run_id,op_kind,payload,status,attempts,last_error,created_at,updated_at,created_unix_nano,updated_unix_nano,lease_until_unix_nano)
VALUES(?,?,?,'pending',0,'',?,?,?,?,?)`, runID, opKind, payload, now, now, nowNanos, nowNanos, dbtime.UnsetUnixNano)
	return err
}

func scanOutboxRows(rows *sql.Rows) ([]OutboxItem, error) {
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		var item OutboxItem
		if err := rows.Scan(&item.ID, &item.RunID, &item.OpKind, &item.Payload, &item.Status, &item.Attempts, &item.LastError, &item.CreatedAt, &item.UpdatedAt, &item.LeaseOwner, &item.LeaseUntil); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

const outboxColumns = "id,run_id,op_kind,payload,status,attempts,last_error,created_at,updated_at,lease_owner,lease_until"

// ClaimOutbox atomically leases up to limit rows for owner: every "pending"
// row, plus any "processing" row whose lease_until_unix_nano has already
// expired (the lease_owner that claimed it crashed or was killed before
// finishing). The claim is a single conditional UPDATE with no preceding
// SELECT in its own transaction — deliberately, for the same reason
// internal/spend.ReserveGlobal (Session 9) uses one bare statement instead
// of Begin/SELECT/UPDATE/Commit: a SELECT as the first statement of a
// deferred SQLite transaction takes only a SHARED lock, and a later write in
// that same transaction has to upgrade SHARED->RESERVED, which is exactly
// the TOCTOU window two concurrent `gov reconcile` processes could otherwise
// both win. A single UPDATE's subquery is evaluated and applied atomically
// under SQLite's single-writer model, so two processes racing this call can
// never both claim the same row: whichever commits first flips the row to
// "processing" with a lease_until_unix_nano in the future, and the loser's
// subquery (evaluated after waiting for the write lock) no longer matches it.
//
// rc7 Session 3 (Sol14 P0-1 D): the lease comparison now uses the numeric
// lease_until_unix_nano column instead of the RFC3339Nano text lease_until.
// Text comparison of RFC3339Nano is not chronologically sortable (trailing
// fractional zeros are stripped), so a still-valid ".5Z" lease could be
// reclaimed at a whole-second "Z" instant that is textually greater but
// chronologically earlier. Ordering is by id ASC (insertion order), copying
// the rc6 pattern at attest.go:613.
func ClaimOutbox(db *sql.DB, owner string, limit int, now, leaseUntil string) ([]OutboxItem, error) {
	if limit <= 0 {
		return nil, nil
	}
	nowNanos, err := dbtime.LegacyToUnixNano(now)
	if err != nil {
		return nil, err
	}
	leaseUntilNanos, err := dbtime.LegacyToUnixNano(leaseUntil)
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`UPDATE maintenance_outbox
SET status='processing', lease_owner=?, lease_until=?, updated_at=?, lease_until_unix_nano=?, updated_unix_nano=?
WHERE id IN (
  SELECT id FROM maintenance_outbox
  WHERE status='pending' OR (status='processing' AND lease_until_unix_nano<>? AND lease_until_unix_nano<?)
  ORDER BY id ASC
  LIMIT ?
)
RETURNING `+outboxColumns, owner, leaseUntil, now, leaseUntilNanos, nowNanos, dbtime.UnsetUnixNano, nowNanos, limit)
	if err != nil {
		return nil, err
	}
	return scanOutboxRows(rows)
}

// PendingOutbox returns every "pending" row, oldest first — unclaimed, for
// callers (`gov doctor`/status summaries, tests) that want to observe outbox
// depth without taking a lease. `gov reconcile` itself claims via
// ClaimOutbox, never this.
func PendingOutbox(db *sql.DB) ([]OutboxItem, error) {
	rows, err := db.Query(`SELECT ` + outboxColumns + ` FROM maintenance_outbox WHERE status='pending' ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	return scanOutboxRows(rows)
}

// StaleOutbox returns "pending" rows that have already failed at least
// maxAttempts retries, for `gov cleanup --stale` to terminalize. A row
// currently leased ("processing") is never stale by this definition even if
// its attempts count is high — it is actively being retried, not stuck.
func StaleOutbox(db *sql.DB, maxAttempts int) ([]OutboxItem, error) {
	rows, err := db.Query(`SELECT `+outboxColumns+` FROM maintenance_outbox WHERE status='pending' AND attempts>=? ORDER BY id ASC`, maxAttempts)
	if err != nil {
		return nil, err
	}
	return scanOutboxRows(rows)
}

// MarkOutboxDone marks a claimed outbox row as successfully drained and
// releases its lease. Scoped to id AND lease_owner (rc7 Session 3, Sol14
// P0-1 D): a stale owner whose lease expired and was reclaimed by a
// different reconciler must not be able to finalize a row it no longer
// holds. The structural guarantee against double-dispatch comes from
// ClaimOutboxExecution's applied-marker, not from this finalization step;
// an owner that lost its lease will find RowsAffected==0 here and simply
// stop, while the new owner completes the operation under its own lease.
func MarkOutboxDone(db *sql.DB, id int64, owner, now string) error {
	nowNanos, err := dbtime.LegacyToUnixNano(now)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE maintenance_outbox SET status='done', lease_owner='', lease_until='', updated_at=?, updated_unix_nano=?, lease_until_unix_nano=? WHERE id=? AND lease_owner=?`, now, nowNanos, dbtime.UnsetUnixNano, id, owner)
	return err
}

// MarkOutboxRetry records a failed retry attempt and releases the row back
// to "pending" (rather than leaving it "processing" until the lease expires)
// so the very next `gov reconcile` pass — by this owner or another — can
// retry immediately instead of waiting out the lease window.
func MarkOutboxRetry(db *sql.DB, id int64, lastError, now string) error {
	nowNanos, err := dbtime.LegacyToUnixNano(now)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE maintenance_outbox SET status='pending', attempts=attempts+1, last_error=?, lease_owner='', lease_until='', updated_at=?, updated_unix_nano=?, lease_until_unix_nano=? WHERE id=?`, lastError, now, nowNanos, dbtime.UnsetUnixNano, id)
	return err
}

// ClaimOutboxExecution atomically claims the right to execute outboxID's
// operation by inserting into maintenance_outbox_applied. PRIMARY
// KEY(outbox_id) is the structural uniqueness constraint: of two concurrent
// reconcilers racing the same row, exactly one INSERT succeeds (RowsAffected
// ==1) and the other is a no-op (ON CONFLICT DO NOTHING, RowsAffected==0).
// The winner proceeds with the operation; the loser skips it. This makes
// double-dispatch structurally impossible rather than merely unlikely (Sol14
// P0-1 D).
func ClaimOutboxExecution(db *sql.DB, outboxID int64, now string) (bool, error) {
	res, err := db.Exec(`INSERT INTO maintenance_outbox_applied(outbox_id,applied_at) VALUES(?,?) ON CONFLICT(outbox_id) DO NOTHING`, outboxID, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// ReleaseOutboxExecution removes a previously claimed applied-marker so the
// operation can be retried on a future reconcile pass. Called only when the
// operation itself failed after the marker was claimed — without this
// release, a deterministic failure would permanently block the row.
func ReleaseOutboxExecution(db *sql.DB, outboxID int64) error {
	_, err := db.Exec(`DELETE FROM maintenance_outbox_applied WHERE outbox_id=?`, outboxID)
	return err
}

// OutboxAlreadyApplied reports whether outboxID's operation is recorded as
// having already run to completion. Retained for read-only callers (gov
// doctor, status summaries); the Reconcile loop uses ClaimOutboxExecution
// for its atomic claim-or-skip semantics.
func OutboxAlreadyApplied(db *sql.DB, outboxID int64) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM maintenance_outbox_applied WHERE outbox_id=?`, outboxID).Scan(&n)
	return n > 0, err
}

// MarkOutboxApplied records outboxID as executed. Retained for callers that
// need a non-atomic idempotent write; the Reconcile loop uses
// ClaimOutboxExecution instead.
func MarkOutboxApplied(db *sql.DB, outboxID int64, now string) error {
	_, err := db.Exec(`INSERT INTO maintenance_outbox_applied(outbox_id,applied_at) VALUES(?,?) ON CONFLICT(outbox_id) DO NOTHING`, outboxID, now)
	return err
}

// MarkOutboxDead terminalizes a row `gov cleanup --stale` has given up on.
func MarkOutboxDead(db *sql.DB, id int64, reason, now string) error {
	nowNanos, err := dbtime.LegacyToUnixNano(now)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE maintenance_outbox SET status='dead', last_error=?, updated_at=?, updated_unix_nano=? WHERE id=?`, reason, now, nowNanos, id)
	return err
}

// OutboxCounts groups every maintenance_outbox row by status, for `gov
// doctor` / `gov reconcile` summaries.
func OutboxCounts(db *sql.DB) (map[string]int, error) {
	rows, err := db.Query(`SELECT status, COUNT(*) FROM maintenance_outbox GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}

// OutboxLeaseExpired reports whether a lease with the given numeric expiry
// has expired relative to now. Exposed for tests that verify the numeric
// comparison directly.
func OutboxLeaseExpired(leaseUntilNanos, nowNanos int64) bool {
	return leaseUntilNanos != dbtime.UnsetUnixNano && leaseUntilNanos < nowNanos
}

// NowNanos converts a time.Time to the ledger's authoritative numeric form.
func NowNanos(t time.Time) int64 {
	n, _ := dbtime.ToUnixNano(t)
	return n
}
