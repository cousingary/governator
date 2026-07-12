package observability

import "database/sql"

// PolicyCheckpoint is one Session 5 (Sol Phase 4) checkpointed ASK: a run
// paused before an action the layered policy engine could not resolve to
// ALLOW or DENY on its own, waiting on an operator response. It persists
// everything the operator needs to decide (Reason/Sources/PolicyHash) and
// everything a resumed run needs to proceed without re-deriving in-memory
// state from the original process — the same durability rule the Session 4
// outbox follows. Target names which candidate ASK target fired (see
// docs/contracts.md): network_enablement, write_out_of_scope, cost_threshold,
// fallback_after_infra_failure, or a custom rule ID for anything else a
// declarative policy rule chose to ASK about. Kept as a plain struct with
// string Sources (not internal/policy's Go types) so observability stays the
// generic ledger layer, matching PolicyRuleEventRecord's existing rationale.
type PolicyCheckpoint struct {
	ID         int64
	RunID      string
	JobID      string
	Target     string
	Reason     string
	Sources    string
	PolicyHash string
	CostUSD    float64
	Detail     string
	Status     string // pending, approved, denied, expired
	ResolvedBy string
	Resolution string
	CreatedAt  string
	ResolvedAt string
}

// RecordPolicyCheckpoint persists one pending ASK checkpoint and returns its
// id, the handle `gov ask approve/deny` and a resumed run key off.
func RecordPolicyCheckpoint(db *sql.DB, c PolicyCheckpoint) (int64, error) {
	res, err := db.Exec(`INSERT INTO policy_checkpoints(run_id,job_id,target,reason,sources,policy_hash,cost_usd,detail,status,created_at) VALUES(?,?,?,?,?,?,?,?,'pending',?)`,
		c.RunID, c.JobID, c.Target, c.Reason, c.Sources, c.PolicyHash, c.CostUSD, c.Detail, c.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func scanPolicyCheckpointRows(rows *sql.Rows) ([]PolicyCheckpoint, error) {
	defer rows.Close()
	var out []PolicyCheckpoint
	for rows.Next() {
		var c PolicyCheckpoint
		if err := rows.Scan(&c.ID, &c.RunID, &c.JobID, &c.Target, &c.Reason, &c.Sources, &c.PolicyHash, &c.CostUSD, &c.Detail, &c.Status, &c.ResolvedBy, &c.Resolution, &c.CreatedAt, &c.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const policyCheckpointColumns = `id,run_id,job_id,target,reason,sources,policy_hash,cost_usd,detail,status,resolved_by,resolution,created_at,resolved_at`

// PendingPolicyCheckpoints returns every "pending" row, oldest first, for
// `gov ask list` / `gov ask show`.
func PendingPolicyCheckpoints(db *sql.DB) ([]PolicyCheckpoint, error) {
	rows, err := db.Query(`SELECT ` + policyCheckpointColumns + ` FROM policy_checkpoints WHERE status='pending' ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	return scanPolicyCheckpointRows(rows)
}

// PolicyCheckpointByID returns one checkpoint by id, or sql.ErrNoRows.
func PolicyCheckpointByID(db *sql.DB, id int64) (PolicyCheckpoint, error) {
	rows, err := db.Query(`SELECT `+policyCheckpointColumns+` FROM policy_checkpoints WHERE id=?`, id)
	if err != nil {
		return PolicyCheckpoint{}, err
	}
	items, err := scanPolicyCheckpointRows(rows)
	if err != nil {
		return PolicyCheckpoint{}, err
	}
	if len(items) == 0 {
		return PolicyCheckpoint{}, sql.ErrNoRows
	}
	return items[0], nil
}

// ResolvePolicyCheckpoint transitions a pending checkpoint to a terminal
// status ("approved", "denied", or "expired"). The WHERE clause only ever
// matches a still-pending row, so resolving an already-resolved checkpoint
// twice is a no-op (RowsAffected 0) rather than silently overwriting the
// first operator's decision — callers should treat 0 rows affected as an
// error ("already resolved").
func ResolvePolicyCheckpoint(db *sql.DB, id int64, status, resolvedBy, resolution, now string) (int64, error) {
	res, err := db.Exec(`UPDATE policy_checkpoints SET status=?, resolved_by=?, resolution=?, resolved_at=? WHERE id=? AND status='pending'`,
		status, resolvedBy, resolution, now, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PolicyOverride is a narrowly scoped, expiring temporary rule an operator
// creates while resolving a PolicyCheckpoint (or proactively): "for
// ScopeKey, Target is Verdict until ExpiresAt." It is the durable form of
// the session/operator override policy layer (the highest-precedence layer
// in internal/policy.EvaluateLayers) — internal/runtime loads
// ActivePolicyOverrides at evaluation time and turns each into a
// policy.LayerResult{Source: policy.SourceSessionOverride, ...}. ScopeKey is
// matched verbatim by the caller building facts (e.g. "job_id:<id>" or
// "backend:<name>"), never glob-matched here — the override table stays a
// dumb lookup, all pattern logic stays in internal/policy.
type PolicyOverride struct {
	ID        int64
	ScopeKey  string
	Target    string
	Verdict   string
	Reason    string
	CreatedBy string
	CreatedAt string
	ExpiresAt string // RFC3339; empty means never expires
}

// RecordPolicyOverride persists one temporary override rule.
func RecordPolicyOverride(db *sql.DB, o PolicyOverride) error {
	_, err := db.Exec(`INSERT INTO policy_overrides(scope_key,target,verdict,reason,created_by,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`,
		o.ScopeKey, o.Target, o.Verdict, o.Reason, o.CreatedBy, o.CreatedAt, o.ExpiresAt)
	return err
}

// ActivePolicyOverrides returns every override for scopeKey that has not
// expired as of now (an empty ExpiresAt never expires), newest first so a
// caller folding multiple matching overrides into one LayerResult naturally
// prefers the most recent operator decision.
func ActivePolicyOverrides(db *sql.DB, scopeKey, now string) ([]PolicyOverride, error) {
	rows, err := db.Query(`SELECT id,scope_key,target,verdict,reason,created_by,created_at,expires_at FROM policy_overrides WHERE scope_key=? AND (expires_at='' OR expires_at>?) ORDER BY created_at DESC, id DESC`, scopeKey, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyOverride
	for rows.Next() {
		var o PolicyOverride
		if err := rows.Scan(&o.ID, &o.ScopeKey, &o.Target, &o.Verdict, &o.Reason, &o.CreatedBy, &o.CreatedAt, &o.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
