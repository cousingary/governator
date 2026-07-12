package runtime

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cousingary/governator/internal/observability"
)

// AskList returns every pending policy checkpoint, oldest first, for `gov
// ask list`.
func AskList() ([]observability.PolicyCheckpoint, error) {
	db, err := dbOpen(Home())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return observability.PendingPolicyCheckpoints(db)
}

// AskShow returns one checkpoint by id, for `gov ask show`.
func AskShow(id int64) (observability.PolicyCheckpoint, error) {
	db, err := dbOpen(Home())
	if err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	defer db.Close()
	return observability.PolicyCheckpointByID(db, id)
}

// AskResolution is what `gov ask approve|deny` does with one checkpoint: a
// bare resolution ("approve just this one run") or, with CreateRule set, a
// durable expiring rule ("approve every future run this same job's rule
// would otherwise ASK about, for the next TTL").
type AskResolution struct {
	Verdict    string // "ALLOW" or "DENY"
	ResolvedBy string
	Note       string
	CreateRule bool
	TTL        time.Duration // zero = never expires; only meaningful with CreateRule
}

// AskResolve marks checkpoint id resolved and persists the operator's
// decision as a policy_overrides row scoped to the checkpoint's job, so a
// subsequent run of the same job re-evaluates the same rule as an immediate
// ALLOW/DENY instead of pausing again. With res.CreateRule the override is
// durable (optionally expiring via TTL); without it the override is
// one-shot: it authorizes exactly one subsequent evaluation and is then
// consumed (see observability.ConsumePolicyOverride) — this is what makes a
// bare "approve once" actually unblock the re-run instead of the same rule
// immediately re-ASKing. This is the session/operator override policy layer
// (see internal/policy.SourceSessionOverride / EvaluateLayers /
// ResolveOverrides): "resume from the checkpoint" here means re-running the
// job — nothing expensive happened before the checkpoint, so there is
// nothing to replay.
func AskResolve(id int64, res AskResolution) (observability.PolicyCheckpoint, error) {
	if res.Verdict != "ALLOW" && res.Verdict != "DENY" {
		return observability.PolicyCheckpoint{}, fmt.Errorf("ask resolve: verdict must be ALLOW or DENY, got %q", res.Verdict)
	}
	db, err := dbOpen(Home())
	if err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	defer tx.Rollback()

	var cp observability.PolicyCheckpoint
	row := tx.QueryRow(`SELECT id,run_id,job_id,target,reason,sources,policy_hash,cost_usd,detail,status,resolved_by,resolution,created_at,resolved_at FROM policy_checkpoints WHERE id=?`, id)
	if err := row.Scan(&cp.ID, &cp.RunID, &cp.JobID, &cp.Target, &cp.Reason, &cp.Sources, &cp.PolicyHash, &cp.CostUSD, &cp.Detail, &cp.Status, &cp.ResolvedBy, &cp.Resolution, &cp.CreatedAt, &cp.ResolvedAt); err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	if cp.Status != "pending" {
		return cp, fmt.Errorf("ask resolve: checkpoint %d is already %s (resolved_by=%q at %s)", id, cp.Status, cp.ResolvedBy, cp.ResolvedAt)
	}

	scopeKey, overrideTarget, err := checkpointOverrideIdentity(cp)
	if err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	status := "denied"
	if res.Verdict == "ALLOW" {
		status = "approved"
	}
	rows, err := tx.Exec(`UPDATE policy_checkpoints SET status=?, resolved_by=?, resolution=?, resolved_at=? WHERE id=? AND status='pending'`, status, res.ResolvedBy, res.Note, now, id)
	if err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	affected, err := rows.RowsAffected()
	if err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	if affected == 0 {
		return observability.PolicyCheckpoint{}, fmt.Errorf("ask resolve: checkpoint %d was already resolved by another caller", id)
	}

	expiresAt := ""
	if res.CreateRule && res.TTL > 0 {
		expiresAt = time.Now().UTC().Add(res.TTL).Format(time.RFC3339Nano)
	}
	oneShot := 0
	if !res.CreateRule {
		oneShot = 1
	}
	if _, err := tx.Exec(`INSERT INTO policy_overrides(scope_key,target,verdict,reason,created_by,created_at,expires_at,one_shot) VALUES(?,?,?,?,?,?,?,?)`,
		scopeKey, overrideTarget, res.Verdict, res.Note, res.ResolvedBy, now, expiresAt, oneShot); err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	if err := tx.Commit(); err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	cp.Status = status
	cp.ResolvedBy = res.ResolvedBy
	cp.Resolution = res.Note
	cp.ResolvedAt = now
	return cp, nil
}

func checkpointOverrideIdentity(cp observability.PolicyCheckpoint) (scopeKey, overrideTarget string, err error) {
	scopeKey = policyOverrideScope(cp.JobID)
	overrideTarget = cp.Target
	if cp.Detail == "" {
		return scopeKey, overrideTarget, nil
	}
	var detail map[string]string
	if err := json.Unmarshal([]byte(cp.Detail), &detail); err != nil {
		return "", "", fmt.Errorf("ask resolve: invalid checkpoint policy identity detail: %w", err)
	}
	if ph := detail["policy_hash"]; ph != "" && ph != cp.PolicyHash {
		return "", "", fmt.Errorf("ask resolve: checkpoint policy identity mismatch: detail policy_hash=%s row policy_hash=%s", ph, cp.PolicyHash)
	}
	if v := detail["scope_key"]; v != "" {
		scopeKey = v
	}
	if v := detail["override_target"]; v != "" {
		overrideTarget = v
	}
	return scopeKey, overrideTarget, nil
}
