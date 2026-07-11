package observability

import "database/sql"

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
// Status is "pending" (awaiting a retry), "done" (the operation eventually
// succeeded), or "dead" (gov cleanup --stale gave up after too many
// attempts — the operational_errors trail is what survives, this row is
// just marked so `gov reconcile` stops retrying it).
type OutboxItem struct {
	ID        int64
	RunID     string
	OpKind    string
	Payload   string
	Status    string
	Attempts  int
	LastError string
	CreatedAt string
	UpdatedAt string
}

// EnqueueOutbox records one retryable unit of work. payload is op-kind
// specific JSON carrying everything a later `gov reconcile` needs to attempt
// the operation again without any in-memory state from the original run.
func EnqueueOutbox(db *sql.DB, runID, opKind, payload, now string) error {
	_, err := db.Exec(`INSERT INTO maintenance_outbox(run_id,op_kind,payload,status,attempts,last_error,created_at,updated_at)
VALUES(?,?,?,'pending',0,'',?,?)`, runID, opKind, payload, now, now)
	return err
}

func scanOutboxRows(rows *sql.Rows) ([]OutboxItem, error) {
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		var item OutboxItem
		if err := rows.Scan(&item.ID, &item.RunID, &item.OpKind, &item.Payload, &item.Status, &item.Attempts, &item.LastError, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// PendingOutbox returns every "pending" row, oldest first, for `gov
// reconcile` to drain.
func PendingOutbox(db *sql.DB) ([]OutboxItem, error) {
	rows, err := db.Query(`SELECT id,run_id,op_kind,payload,status,attempts,last_error,created_at,updated_at FROM maintenance_outbox WHERE status='pending' ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	return scanOutboxRows(rows)
}

// StaleOutbox returns "pending" rows that have already failed at least
// maxAttempts retries, for `gov cleanup --stale` to terminalize.
func StaleOutbox(db *sql.DB, maxAttempts int) ([]OutboxItem, error) {
	rows, err := db.Query(`SELECT id,run_id,op_kind,payload,status,attempts,last_error,created_at,updated_at FROM maintenance_outbox WHERE status='pending' AND attempts>=? ORDER BY created_at ASC, id ASC`, maxAttempts)
	if err != nil {
		return nil, err
	}
	return scanOutboxRows(rows)
}

// MarkOutboxDone marks an outbox row as successfully drained.
func MarkOutboxDone(db *sql.DB, id int64, now string) error {
	_, err := db.Exec(`UPDATE maintenance_outbox SET status='done', updated_at=? WHERE id=?`, now, id)
	return err
}

// MarkOutboxRetry records a failed retry attempt: attempts increments and
// last_error is updated, but the row stays "pending" so the next `gov
// reconcile` tries again.
func MarkOutboxRetry(db *sql.DB, id int64, lastError, now string) error {
	_, err := db.Exec(`UPDATE maintenance_outbox SET attempts=attempts+1, last_error=?, updated_at=? WHERE id=?`, lastError, now, id)
	return err
}

// MarkOutboxDead terminalizes a row `gov cleanup --stale` has given up on.
func MarkOutboxDead(db *sql.DB, id int64, reason, now string) error {
	_, err := db.Exec(`UPDATE maintenance_outbox SET status='dead', last_error=?, updated_at=? WHERE id=?`, reason, now, id)
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
