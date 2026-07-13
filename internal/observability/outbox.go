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
	_, err := db.Exec(`INSERT INTO maintenance_outbox(run_id,op_kind,payload,status,attempts,last_error,created_at,updated_at)
VALUES(?,?,?,'pending',0,'',?,?)`, runID, opKind, payload, now, now)
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
// row, plus any "processing" row whose lease_until has already expired (the
// lease_owner that claimed it crashed or was killed before finishing — Sol
// P1.5, finding #13's Docker-crash scenario is exactly this case feeding
// back into the outbox via the opWorkspaceDestroy row destroyLeftoverWorkspace
// enqueues on a failed teardown). The claim is a single conditional UPDATE
// with no preceding SELECT in its own transaction — deliberately, for the
// same reason internal/spend.ReserveGlobal (Session 9) uses one bare
// statement instead of Begin/SELECT/UPDATE/Commit: a SELECT as the first
// statement of a deferred SQLite transaction takes only a SHARED lock, and a
// later write in that same transaction has to upgrade SHARED->RESERVED,
// which is exactly the TOCTOU window two concurrent `gov reconcile`
// processes could otherwise both win. A single UPDATE's subquery is
// evaluated and applied atomically under SQLite's single-writer model, so
// two processes racing this call can never both claim the same row: whichever
// commits first flips the row to "processing" with a lease_until in the
// future, and the loser's subquery (evaluated after waiting for the write
// lock) no longer matches it.
func ClaimOutbox(db *sql.DB, owner string, limit int, now, leaseUntil string) ([]OutboxItem, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := db.Query(`UPDATE maintenance_outbox
SET status='processing', lease_owner=?, lease_until=?, updated_at=?
WHERE id IN (
  SELECT id FROM maintenance_outbox
  WHERE status='pending' OR (status='processing' AND lease_until<>'' AND lease_until<?)
  ORDER BY created_at ASC, id ASC
  LIMIT ?
)
RETURNING `+outboxColumns, owner, leaseUntil, now, now, limit)
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
	rows, err := db.Query(`SELECT ` + outboxColumns + ` FROM maintenance_outbox WHERE status='pending' ORDER BY created_at ASC, id ASC`)
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
	rows, err := db.Query(`SELECT `+outboxColumns+` FROM maintenance_outbox WHERE status='pending' AND attempts>=? ORDER BY created_at ASC, id ASC`, maxAttempts)
	if err != nil {
		return nil, err
	}
	return scanOutboxRows(rows)
}

// MarkOutboxDone marks a claimed outbox row as successfully drained and
// releases its lease. Scoped to id alone (not id+owner) deliberately: by the
// time dispatchReconcile returns success the operation has already run, so
// finalizing must not be refused just because a lease expired and was
// reclaimed by a different owner mid-dispatch — that would leave a
// successfully-applied row stuck retrying forever.
func MarkOutboxDone(db *sql.DB, id int64, now string) error {
	_, err := db.Exec(`UPDATE maintenance_outbox SET status='done', lease_owner='', lease_until='', updated_at=? WHERE id=?`, now, id)
	return err
}

// MarkOutboxRetry records a failed retry attempt and releases the row back
// to "pending" (rather than leaving it "processing" until the lease expires)
// so the very next `gov reconcile` pass — by this owner or another — can
// retry immediately instead of waiting out the lease window.
func MarkOutboxRetry(db *sql.DB, id int64, lastError, now string) error {
	_, err := db.Exec(`UPDATE maintenance_outbox SET status='pending', attempts=attempts+1, last_error=?, lease_owner='', lease_until='', updated_at=? WHERE id=?`, lastError, now, id)
	return err
}

// OutboxAlreadyApplied reports whether outboxID's operation is recorded as
// having already run to completion (Sol P1.5, finding #12's idempotency-key
// requirement): a lease can expire and be reclaimed after the underlying
// operation succeeded but before MarkOutboxDone's write landed (process
// killed in between), and several of the retried operations — breaker
// counters, policy-rule-event rows — are not naturally safe to run twice.
// dispatchReconcile checks this before attempting the operation at all.
func OutboxAlreadyApplied(db *sql.DB, outboxID int64) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM maintenance_outbox_applied WHERE outbox_id=?`, outboxID).Scan(&n)
	return n > 0, err
}

// MarkOutboxApplied records outboxID as executed. PRIMARY KEY(outbox_id) is
// the actual uniqueness constraint enforcing "at most once recorded";
// ON CONFLICT DO NOTHING makes a duplicate call (e.g. a retry that reruns
// this after a partial failure between the operation and this write) a
// harmless no-op rather than an error.
func MarkOutboxApplied(db *sql.DB, outboxID int64, now string) error {
	_, err := db.Exec(`INSERT INTO maintenance_outbox_applied(outbox_id,applied_at) VALUES(?,?) ON CONFLICT(outbox_id) DO NOTHING`, outboxID, now)
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
