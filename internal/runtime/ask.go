package runtime

import (
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

// AskResolve marks checkpoint id resolved and, when res.CreateRule is set,
// persists a matching expiring policy_overrides row scoped to the
// checkpoint's job — so a subsequent run of the same job re-evaluates the
// same rule as an immediate ALLOW/DENY instead of pausing again. This is the
// durable form of the session/operator override policy layer (see
// internal/policy.SourceSessionOverride / EvaluateLayers / ResolveOverrides):
// "resume from the checkpoint" here means re-running the job — nothing
// expensive happened before the checkpoint, so there is nothing to replay.
func AskResolve(id int64, res AskResolution) (observability.PolicyCheckpoint, error) {
	if res.Verdict != "ALLOW" && res.Verdict != "DENY" {
		return observability.PolicyCheckpoint{}, fmt.Errorf("ask resolve: verdict must be ALLOW or DENY, got %q", res.Verdict)
	}
	db, err := dbOpen(Home())
	if err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	defer db.Close()

	cp, err := observability.PolicyCheckpointByID(db, id)
	if err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	if cp.Status != "pending" {
		return cp, fmt.Errorf("ask resolve: checkpoint %d is already %s (resolved_by=%q at %s)", id, cp.Status, cp.ResolvedBy, cp.ResolvedAt)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	status := "denied"
	if res.Verdict == "ALLOW" {
		status = "approved"
	}
	rows, err := observability.ResolvePolicyCheckpoint(db, id, status, res.ResolvedBy, res.Note, now)
	if err != nil {
		return observability.PolicyCheckpoint{}, err
	}
	if rows == 0 {
		return observability.PolicyCheckpoint{}, fmt.Errorf("ask resolve: checkpoint %d was already resolved by another caller", id)
	}

	if res.CreateRule {
		expiresAt := ""
		if res.TTL > 0 {
			expiresAt = time.Now().UTC().Add(res.TTL).Format(time.RFC3339Nano)
		}
		if err := observability.RecordPolicyOverride(db, observability.PolicyOverride{
			ScopeKey: policyOverrideScope(cp.JobID), Target: cp.Target, Verdict: res.Verdict,
			Reason: res.Note, CreatedBy: res.ResolvedBy, CreatedAt: now, ExpiresAt: expiresAt,
		}); err != nil {
			return observability.PolicyCheckpoint{}, err
		}
	}
	cp.Status = status
	cp.ResolvedBy = res.ResolvedBy
	cp.Resolution = res.Note
	cp.ResolvedAt = now
	return cp, nil
}
