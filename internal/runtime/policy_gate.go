package runtime

import (
	"database/sql"
	"strconv"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/policy"
)

// policyDeniedTaxonomy and policyAskPendingTaxonomy are Session 5's failure
// taxonomies for a run quarantined by the layered policy engine — neither is
// an infra failure (IsInfraFailure/IsUnusualInfraFailure both exclude them):
// a policy verdict says nothing about backend reachability, so it must never
// open a circuit breaker (Session 2's "quality evidence stays separate from
// infra health" rule generalizes to policy evidence too).
const (
	policyDeniedTaxonomy     = "POLICY_DENIED"
	policyAskPendingTaxonomy = "POLICY_ASK_PENDING"
)

// quarantineForPolicy records the same shape of refusal runOnce already uses
// for SPEND_CAP/QUOTA_EXHAUSTED (insertRun, RecordIdentity, RecordCompletion,
// a QUARANTINED stage checkpoint) for a run the Session 5 policy gate
// blocked. FailureTaxonomy distinguishes a terminal DENY from a pending ASK;
// for the latter, the message names every checkpoint id `gov ask
// approve/deny` can act on.
func (r *Runner) quarantineForPolicy(db *sql.DB, c contracts.Contract, agent, root, id, hash, head string, decision policy.PolicyDecision, checkpoints []observability.PolicyCheckpoint) (RunRecord, error) {
	taxonomy := policyDeniedTaxonomy
	if decision.Verdict == policy.VerdictAsk {
		taxonomy = policyAskPendingTaxonomy
	}
	msg := taxonomy + ": " + strings.Join(decision.Reasons, "; ")
	if len(checkpoints) > 0 {
		ids := make([]string, 0, len(checkpoints))
		for _, cp := range checkpoints {
			ids = append(ids, strconv.FormatInt(cp.ID, 10))
		}
		msg += " (checkpoint ids: " + strings.Join(ids, ",") + " — resolve with `gov ask approve/deny`, then re-run)"
	}
	refused := RunRecord{
		ID: id, JobID: c.JobID, JobType: c.JobType, Agent: agent, Mode: string(c.Mode),
		Status: "QUARANTINED", Root: root, Created: time.Now().UTC().Format(time.RFC3339Nano),
		Message: msg, FailureTaxonomy: taxonomy, RepairOf: c.RepairLineage,
	}
	if err := insertRun(db, refused, hash, head); err != nil {
		return refused, err
	}
	if err := observability.RecordIdentity(db, c.JobID, c.JobType, agent, refused.Created); err != nil {
		return refused, err
	}
	if err := observability.RecordCompletion(db, observability.Completion{
		RunID: refused.ID, Agent: refused.Agent, JobType: refused.JobType, Status: refused.Status,
		FailureTaxonomy: refused.FailureTaxonomy, Notes: refused.Message, Violations: decision.Reasons,
	}); err != nil {
		return refused, err
	}
	if err := observability.RecordStage(db, id, "QUARANTINED", "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return refused, err
	}
	return refused, nil
}

// policyOverrideScope is the scope key Session 5's session/operator override
// layer is keyed on: one job_id's overrides never leak into another job's
// evaluation. A future `gov ask allow --backend` style broader scope can
// extend this without changing the checkpoint/override schema — ScopeKey is
// just a string the caller builds and looks up verbatim.
func policyOverrideScope(jobID string) string { return "job_id:" + jobID }

// evaluatePolicyGate runs the Session 5 (Sol Phase 4) layered policy engine
// for one gate call: organization (config.PolicyRules) -> project doctrine
// (workspaceRoot/.governator-doctrine.yaml) -> job contract (c.Policy.Rules)
// -> session/operator override (active internal/observability policy_overrides
// rows scoped to this job). Any rule whose effective verdict is still ASK
// after override resolution gets a durable policy_checkpoints row so `gov
// ask` can list/resolve it — persisted before this function returns, so a
// crash between evaluation and the caller quarantining the run never loses
// the checkpoint. Returns the combined decision and every checkpoint
// created for this call (empty when the decision isn't ASK).
func evaluatePolicyGate(db *sql.DB, cfg config.Config, c contracts.Contract, workspaceRoot, runID string, facts map[string]any) (policy.PolicyDecision, []observability.PolicyCheckpoint, error) {
	var results []policy.LayerResult
	results = append(results, policy.EvaluateConditionRules(policy.SourceOrgPolicy, cfg.PolicyRules, facts)...)

	projectRules, err := policy.LoadProjectDoctrine(workspaceRoot)
	if err != nil {
		return policy.PolicyDecision{}, nil, err
	}
	results = append(results, policy.EvaluateConditionRules(policy.SourceProjectDoctrine, projectRules, facts)...)

	contractRules, err := policy.ContractRules(c)
	if err != nil {
		return policy.PolicyDecision{}, nil, err
	}
	results = append(results, policy.EvaluateConditionRules(policy.SourceJobContract, contractRules, facts)...)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	scope := policyOverrideScope(c.JobID)
	overrideRows, err := observability.ActivePolicyOverrides(db, scope, now)
	if err != nil {
		return policy.PolicyDecision{}, nil, err
	}
	overrides := make([]policy.Override, 0, len(overrideRows))
	for _, o := range overrideRows {
		overrides = append(overrides, policy.Override{ID: o.ID, RuleID: o.Target, Verdict: policy.Verdict(o.Verdict), OneShot: o.OneShot})
	}
	resolved, applied := policy.ResolveOverrides(results, overrides)
	decision := policy.EvaluateLayers(resolved...)

	// Consume applied one-shot overrides (a bare `gov ask approve/deny`,
	// no --rule): an ALLOW one-shot is spent only when the whole gate stops
	// blocking — if another rule still ASKs or DENYs, the run never proceeded
	// and the operator's single approval must survive for the retry that
	// actually goes through. A DENY one-shot is spent the moment it is
	// applied: its entire purpose ("deny this one") is fulfilled by denying
	// this evaluation, after which the job returns to ASKing.
	for _, o := range applied {
		if !o.OneShot {
			continue
		}
		if o.Verdict == policy.VerdictDeny || !decision.Blocks() {
			if err := observability.ConsumePolicyOverride(db, o.ID, now); err != nil {
				return policy.PolicyDecision{}, nil, err
			}
		}
	}

	var checkpoints []observability.PolicyCheckpoint
	if decision.Verdict != policy.VerdictAsk {
		return decision, nil, nil
	}
	costUSD, _ := facts[policy.FactEstimatedCostUSD].(float64)
	for _, res := range resolved {
		if res.Verdict != policy.VerdictAsk {
			continue
		}
		cp := observability.PolicyCheckpoint{
			RunID: runID, JobID: c.JobID, Target: res.RuleID, Reason: res.Reason,
			Sources: res.Source, PolicyHash: decision.PolicyHash, CostUSD: costUSD, CreatedAt: now,
		}
		id, err := observability.RecordPolicyCheckpoint(db, cp)
		if err != nil {
			return policy.PolicyDecision{}, checkpoints, err
		}
		cp.ID = id
		checkpoints = append(checkpoints, cp)
	}
	return decision, checkpoints, nil
}
