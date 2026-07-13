package runtime

import (
	"database/sql"
	"encoding/json"
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

// policyOverrideScope is the legacy fallback scope for checkpoints created
// before Sol Session 5 hardened override identity.
func policyOverrideScope(jobID string) string { return "job_id:" + jobID }

func policyOverrideScopeFor(c contracts.Contract, cfg config.Config, facts map[string]any, orgRules, projectRules, contractRules []policy.ConditionRule) string {
	contractHash, _ := contracts.ContractHash(c)
	doc := map[string]any{
		"version": "override-scope-v2", "job_id": c.JobID, "contract_hash": contractHash,
		"config_hash": cfg.Hash(), "org_rules": orgRules, "project_rules": projectRules,
		"contract_rules": contractRules, "facts": facts,
	}
	b, _ := json.Marshal(doc)
	return "policy_identity:" + policy.Hash(string(b))
}

func policyHashForGate(facts map[string]any, orgRules, projectRules, contractRules []policy.ConditionRule, resolved []policy.LayerResult, overrideRows []observability.PolicyOverride) string {
	doc := map[string]any{
		"evaluator": "layered-policy-v2", "layer_order": []string{policy.SourceOrgPolicy, policy.SourceProjectDoctrine, policy.SourceJobContract, policy.SourceSessionOverride},
		"facts": facts, "org_rules": orgRules, "project_rules": projectRules, "contract_rules": contractRules,
		"resolved_results": resolved, "overrides": overrideRows,
	}
	b, _ := json.Marshal(doc)
	return policy.Hash(string(b))
}

func checkpointDetail(scope, target, policyHash string) string {
	b, _ := json.Marshal(map[string]string{"scope_key": scope, "override_target": target, "policy_hash": policyHash})
	return string(b)
}

func overrideTargetForResult(res policy.LayerResult) string {
	if res.OverrideTarget != "" {
		return res.OverrideTarget
	}
	return res.RuleID
}

// evaluatePolicyGate runs the Session 5 (Sol Phase 4) layered policy engine
// for one gate call: organization (config.PolicyRules) -> project doctrine
// (workspaceRoot/.governator-doctrine.yaml) -> job contract (c.Policy.Rules)
// -> session/operator override (active internal/observability policy_overrides
// rows scoped to this job). Any rule whose effective verdict is still ASK
// after override resolution gets a durable policy_checkpoints row so `gov
// ask` can list/resolve it — persisted before this function returns, so a
// crash between evaluation and the caller quarantining the run never loses
// the checkpoint. Returns the combined decision, every checkpoint created
// for this call (empty when the decision isn't ASK), and every reserved
// one-shot override ID this evaluation did NOT already resolve (empty
// unless decision.Blocks() is false) — see pendingOneShotIDs doc below.
func evaluatePolicyGate(db *sql.DB, cfg config.Config, c contracts.Contract, workspaceRoot, runID string, facts map[string]any) (policy.PolicyDecision, []observability.PolicyCheckpoint, []int64, error) {
	var results []policy.LayerResult
	results = append(results, policy.EvaluateConditionRules(policy.SourceOrgPolicy, cfg.PolicyRules, facts)...)

	projectRules, err := policy.LoadProjectDoctrine(workspaceRoot)
	if err != nil {
		return policy.PolicyDecision{}, nil, nil, err
	}
	results = append(results, policy.EvaluateConditionRules(policy.SourceProjectDoctrine, projectRules, facts)...)

	contractRules, err := policy.ContractRules(c)
	if err != nil {
		return policy.PolicyDecision{}, nil, nil, err
	}
	results = append(results, policy.EvaluateConditionRules(policy.SourceJobContract, contractRules, facts)...)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	scope := policyOverrideScopeFor(c, cfg, facts, cfg.PolicyRules, projectRules, contractRules)
	overrideRows, err := observability.ClaimActivePolicyOverrides(db, scope, now)
	if err != nil {
		return policy.PolicyDecision{}, nil, nil, err
	}
	overrides := make([]policy.Override, 0, len(overrideRows))
	for _, o := range overrideRows {
		overrides = append(overrides, policy.Override{ID: o.ID, RuleID: o.Target, Verdict: policy.Verdict(o.Verdict), OneShot: o.OneShot})
	}
	resolved, applied := policy.ResolveOverrides(results, overrides)
	decision := policy.EvaluateLayers(resolved...)
	decision.PolicyHash = policyHashForGate(facts, cfg.PolicyRules, projectRules, contractRules, resolved, overrideRows)

	// Release every reserved one-shot row ClaimActivePolicyOverrides claimed
	// but ResolveOverrides never matched to any rule this evaluation
	// (applied only lists overrides that actually substituted a result) —
	// holding an unused reservation would needlessly starve a future
	// evaluation of an approval that was never even relevant here.
	appliedIDs := make(map[int64]bool, len(applied))
	for _, o := range applied {
		appliedIDs[o.ID] = true
	}
	for _, o := range overrideRows {
		if o.OneShot && !appliedIDs[o.ID] {
			if err := observability.ReleasePolicyOverrideReservation(db, o.ID, now); err != nil {
				return policy.PolicyDecision{}, nil, nil, err
			}
		}
	}

	// Resolve every APPLIED one-shot override (Sol P1.1, finding #8). A DENY
	// one-shot is spent the moment it is applied — its entire purpose ("deny
	// this one") is fulfilled by denying this evaluation, and it never
	// authorizes any execution to wait for, so it is consumed immediately.
	// An ALLOW one-shot is different: applying it to its own rule can still
	// leave the overall decision blocked by another, unrelated rule (the
	// exact reproduction in finding #8 — rule A approved, rule B still
	// blocks). If the whole gate still blocks, this evaluation authorized
	// nothing and the reservation is released back to available for the
	// retry that might actually go through. If the whole gate does NOT
	// block, this override may be the thing that let a real execution
	// happen — but "may" is not "did": containment, quota, spend, or any
	// later pre-launch failure can still abort the run before the governed
	// action ever crosses its execution boundary. So an unblocking ALLOW
	// one-shot stays RESERVED here; the caller (runOnce) is responsible for
	// consuming it via ConsumePolicyOverrideReservation immediately before
	// launch, or releasing it via ReleasePolicyOverrideReservation on every
	// abort path in between — see pendingOneShotIDs below.
	var pendingOneShotIDs []int64
	for _, o := range applied {
		if !o.OneShot {
			continue
		}
		if o.Verdict == policy.VerdictDeny {
			// A DENY one-shot's effect (denying this evaluation) already
			// happened via the resolved LayerResult above regardless of
			// this bookkeeping call, so an unexpected zero-rows race here
			// is not fatal to the decision — only the ledger's record of
			// consumption, which is not this evaluation's job to enforce.
			if _, err := observability.ConsumePolicyOverrideReservation(db, o.ID, now); err != nil {
				return policy.PolicyDecision{}, nil, nil, err
			}
			continue
		}
		if decision.Blocks() {
			if err := observability.ReleasePolicyOverrideReservation(db, o.ID, now); err != nil {
				return policy.PolicyDecision{}, nil, nil, err
			}
			continue
		}
		pendingOneShotIDs = append(pendingOneShotIDs, o.ID)
	}

	var checkpoints []observability.PolicyCheckpoint
	if decision.Verdict != policy.VerdictAsk {
		return decision, nil, pendingOneShotIDs, nil
	}
	costUSD, _ := facts[policy.FactEstimatedCostUSD].(float64)
	for _, res := range resolved {
		if res.Verdict != policy.VerdictAsk {
			continue
		}
		cp := observability.PolicyCheckpoint{
			RunID: runID, JobID: c.JobID, Target: res.RuleID, Reason: res.Reason,
			Sources: res.Source, PolicyHash: decision.PolicyHash, CostUSD: costUSD, Detail: checkpointDetail(scope, overrideTargetForResult(res), decision.PolicyHash), CreatedAt: now,
		}
		id, err := observability.RecordPolicyCheckpoint(db, cp)
		if err != nil {
			return policy.PolicyDecision{}, checkpoints, pendingOneShotIDs, err
		}
		cp.ID = id
		checkpoints = append(checkpoints, cp)
	}
	return decision, checkpoints, pendingOneShotIDs, nil
}
