package observability

import (
	"database/sql"
	"time"
)

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
	// OneShot marks a bare `gov ask approve/deny` (no --rule): the override
	// applies to exactly one subsequent evaluation of its job+rule, then is
	// marked consumed (ConsumedAt set) and never matches again. A durable
	// --rule override has OneShot false and is never reserved, consumed, or
	// expired — it always matches (subject only to ExpiresAt).
	//
	// A one-shot override's lifecycle (Sol P1.1, finding #8) is:
	//
	//	available -> reserved -> consumed | released (-> available again) | expired
	//
	// ClaimActivePolicyOverrides RESERVES a one-shot row (ReservedAt set) the
	// moment a policy gate evaluation might use it — this closes the
	// select-then-consume race without deciding the override's fate yet.
	// ConsumePolicyOverrideReservation terminalizes it (ConsumedAt set) only
	// at the actual authorized transition: immediately before the governed
	// action crosses its execution boundary. ReleasePolicyOverrideReservation
	// clears ReservedAt back to '' (available again) when the reservation
	// turns out not to have authorized anything — another rule still blocked
	// the run, evaluation errored, or the run aborted before launch. This is
	// the fix for the reproduced bug: rule A approved, rule B still blocks ->
	// A's approval must survive for the retry that actually goes through,
	// not be burned on an evaluation that never executed anything.
	//
	// A reservation left ReservedAt-but-unresolved past
	// oneShotReservationTTL (the caller process crashed between reserve and
	// consume/release) self-heals into ExpiredAt on the next claim/active
	// query — never back to available, since we cannot tell whether the
	// crashed process's governed action actually started. Losing a stale
	// approval is the fail-closed outcome; silently returning it to
	// available risks a double-authorization.
	OneShot    bool
	ConsumedAt string // RFC3339; empty means not yet consumed
	ReservedAt string // RFC3339; empty means not currently reserved
	ExpiredAt  string // RFC3339; empty means not expired
}

// oneShotReservationTTL bounds how long a reserved one-shot override may sit
// unresolved (reserved but neither consumed nor released) before it
// self-heals into ExpiredAt rather than silently returning to available.
// 30 minutes generously covers the gate-evaluation-to-launch window (quota
// reservation, workspace prep, prompt compile) P1.1 introduces between
// reserve and consume.
const oneShotReservationTTL = 30 * time.Minute

// reclaimStaleOneShotReservations expires (never releases) reservations
// older than oneShotReservationTTL as of now. Runs inside the caller's
// transaction so the reclaim and the subsequent claim/select see a
// consistent view.
func reclaimStaleOneShotReservations(tx *sql.Tx, now string) error {
	nowT, err := time.Parse(time.RFC3339Nano, now)
	if err != nil {
		return err
	}
	cutoff := nowT.Add(-oneShotReservationTTL).Format(time.RFC3339Nano)
	_, err = tx.Exec(`UPDATE policy_overrides SET expired_at=? WHERE one_shot=1 AND consumed_at='' AND expired_at='' AND reserved_at<>'' AND reserved_at<?`, now, cutoff)
	return err
}

// RecordPolicyOverride persists one temporary override rule.
func RecordPolicyOverride(db *sql.DB, o PolicyOverride) error {
	oneShot := 0
	if o.OneShot {
		oneShot = 1
	}
	_, err := db.Exec(`INSERT INTO policy_overrides(scope_key,target,verdict,reason,created_by,created_at,expires_at,one_shot) VALUES(?,?,?,?,?,?,?,?)`,
		o.ScopeKey, o.Target, o.Verdict, o.Reason, o.CreatedBy, o.CreatedAt, o.ExpiresAt, oneShot)
	return err
}

// activePolicyOverrideColumns/scanActivePolicyOverrideRows are shared by
// ActivePolicyOverrides and ClaimActivePolicyOverrides so both read the
// identical row shape.
const activePolicyOverrideColumns = `id,scope_key,target,verdict,reason,created_by,created_at,expires_at,one_shot,consumed_at,reserved_at,expired_at`

func scanActivePolicyOverrideRows(rows *sql.Rows) ([]PolicyOverride, error) {
	var out []PolicyOverride
	for rows.Next() {
		var o PolicyOverride
		var oneShot int
		if err := rows.Scan(&o.ID, &o.ScopeKey, &o.Target, &o.Verdict, &o.Reason, &o.CreatedBy, &o.CreatedAt, &o.ExpiresAt, &oneShot, &o.ConsumedAt, &o.ReservedAt, &o.ExpiredAt); err != nil {
			return nil, err
		}
		o.OneShot = oneShot != 0
		out = append(out, o)
	}
	return out, rows.Err()
}

// ActivePolicyOverrides returns every override for scopeKey that has not
// expired as of now (an empty ExpiresAt never expires), has not been
// consumed, is not currently reserved by another in-flight evaluation, and
// has not self-healed into ExpiredAt (only one-shot overrides are ever
// reserved/consumed/expired — durable rows always qualify), newest first so
// a caller folding multiple matching overrides into one LayerResult
// naturally prefers the most recent operator decision.
func ActivePolicyOverrides(db *sql.DB, scopeKey, now string) ([]PolicyOverride, error) {
	rows, err := db.Query(`SELECT `+activePolicyOverrideColumns+` FROM policy_overrides WHERE scope_key=? AND (expires_at='' OR expires_at>?) AND consumed_at='' AND expired_at='' AND reserved_at='' ORDER BY created_at DESC, id DESC`, scopeKey, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanActivePolicyOverrideRows(rows)
}

// ClaimActivePolicyOverrides returns active overrides for scopeKey and
// atomically RESERVES (not consumes) any one-shot rows before the caller
// evaluates policy — see the state-machine doc on PolicyOverride. This
// closes the select-then-reserve race: two concurrent evaluations can never
// both reserve the same one-shot approval. It is the caller's
// responsibility to, after evaluation, consume each reserved override that
// actually authorized the governed action (via
// ConsumePolicyOverrideReservation, at the execution boundary) and release
// every other reserved override (via ReleasePolicyOverrideReservation) so it
// remains available for a future evaluation — never leave a claimed
// reservation unresolved.
func ClaimActivePolicyOverrides(db *sql.DB, scopeKey, now string) ([]PolicyOverride, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := reclaimStaleOneShotReservations(tx, now); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT `+activePolicyOverrideColumns+` FROM policy_overrides WHERE scope_key=? AND (expires_at='' OR expires_at>?) AND consumed_at='' AND expired_at='' AND reserved_at='' ORDER BY created_at DESC, id DESC`, scopeKey, now)
	if err != nil {
		return nil, err
	}
	out, err := scanActivePolicyOverrideRows(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	claimed := out[:0]
	for _, o := range out {
		if !o.OneShot {
			claimed = append(claimed, o)
			continue
		}
		res, err := tx.Exec(`UPDATE policy_overrides SET reserved_at=? WHERE id=? AND one_shot=1 AND consumed_at='' AND expired_at='' AND reserved_at=''`, now, o.ID)
		if err != nil {
			return nil, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n == 1 {
			o.ReservedAt = now
			claimed = append(claimed, o)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claimed, nil
}

// ConsumePolicyOverrideReservation terminalizes a reserved one-shot override
// at the moment the governed action it authorized actually crosses its
// execution boundary — never earlier (see PolicyOverride's state-machine
// doc). The WHERE clause only matches a still-reserved, unconsumed row, so
// double-consumption (two racing callers) is impossible. Returns rows
// affected so a caller can fail closed (abort the launch) if the reservation
// it expected to consume was already released or self-healed into expired
// by a race, rather than silently proceeding without a real consumption.
func ConsumePolicyOverrideReservation(db *sql.DB, id int64, now string) (int64, error) {
	res, err := db.Exec(`UPDATE policy_overrides SET consumed_at=? WHERE id=? AND one_shot=1 AND reserved_at<>'' AND consumed_at=''`, now, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ReleasePolicyOverrideReservation returns a reserved one-shot override to
// available: the rule it targeted did not end up authorizing the governed
// action to execute this evaluation (another rule still blocked the run,
// gate evaluation errored, or the run aborted before reaching the execution
// boundary). Clearing ReservedAt is what makes the exact bug in finding #8
// impossible: rule A's approval survives for the retry that actually goes
// through. The WHERE clause only matches a still-reserved row, so a release
// racing a consume or an expiry reclaim is a safe no-op.
func ReleasePolicyOverrideReservation(db *sql.DB, id int64, now string) error {
	_, err := db.Exec(`UPDATE policy_overrides SET reserved_at='' WHERE id=? AND one_shot=1 AND reserved_at<>'' AND consumed_at='' AND expired_at=''`, id)
	return err
}
