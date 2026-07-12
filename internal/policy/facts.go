package policy

import (
	"fmt"

	"github.com/cousingary/governator/internal/contracts"
)

// Well-known fact names ConditionRule.When conditions compare against. Kept
// as constants (not just doc-comment strings) so a Go call site building a
// facts map and a rule file's "field:" values can't drift on spelling.
const (
	FactRiskClass = "risk_class"
	FactMode      = "mode"
	FactBackend   = "backend"
	// FactNetworkEnabled is a bool: true when the contract's runner config
	// or allowed.execute would let the run reach the network (Session 5
	// candidate target: "network enablement").
	FactNetworkEnabled = "network_enabled"
	// FactWriteOutOfScope is a bool: true when a preflight-declared intended
	// write targets a path the contract never declared reading (Session 5
	// candidate target: "write outside intended scope"). Distinct from (and
	// narrower than) Preflight's existing hard "exceeds allowed.write" DENY.
	FactWriteOutOfScope = "write_out_of_scope"
	// FactEstimatedCostUSD is a float64: the pre-launch worst-case cost
	// estimate for this run (Session 5 candidate target: "cost threshold").
	// Populated by the caller (internal/runtime), not BuildContractFacts —
	// it depends on the resolved backend's rate table, a runtime concern.
	FactEstimatedCostUSD = "estimated_cost_usd"
	// FactDailyCapUSD is a float64: the operator's configured
	// spend.daily_cap_usd, so a cost-threshold rule can compare against a
	// fraction of it instead of a hardcoded dollar figure.
	FactDailyCapUSD = "daily_cap_usd"
	// FactUnusualInfraRetry is a bool and FactInfraFailureKind a string:
	// set only when evaluating whether to auto-launch a fallback attempt
	// after an infra failure (Session 5 candidate target: "fallback after
	// unusual infra failure" — see internal/runtime's fallbackEligible).
	FactUnusualInfraRetry = "unusual_infra_retry"
	FactInfraFailureKind  = "infra_failure_kind"
)

// BuildContractFacts derives the policy engine's static, contract-only
// facts: everything a ConditionRule can evaluate from the contract alone,
// with no run-time signal (cost estimate, infra failure kind, ...) — those
// are the caller's job to add via MergeFacts. Keeping the two separate lets
// a rule author write contract-only rules that evaluate identically at
// `gov validate` time and at real run time.
func BuildContractFacts(c contracts.Contract, backend string) map[string]any {
	return map[string]any{
		FactRiskClass:       c.RiskClass,
		FactMode:            string(c.Mode),
		FactBackend:         backend,
		FactNetworkEnabled:  contractEnablesNetwork(c),
		FactWriteOutOfScope: contractWritesOutsideReadScope(c),
	}
}

// contractEnablesNetwork reports whether the contract's own declarations
// (not its transcript) would let the run reach the network: an explicit
// docker network: allow, or an allowed.execute pattern that looks like a
// network command (reuses events.go's networkCommandRE, the same
// classifier ClassifyEvent uses for the temporal rule engine).
func contractEnablesNetwork(c contracts.Contract) bool {
	if c.Docker != nil && c.Docker.EffectiveNetwork() == "allow" {
		return true
	}
	for _, cmd := range c.Allowed.Execute {
		if networkCommandRE.MatchString(cmd) {
			return true
		}
	}
	return false
}

// contractWritesOutsideReadScope reports whether any preflight-declared
// intended write targets a location outside the contract's declared read
// scope — a scope-creep signal worth an operator's attention even when the
// write is well within allowed.write.
func contractWritesOutsideReadScope(c contracts.Contract) bool {
	if len(c.Allowed.Read) == 0 || len(c.Preflight.IntendedWrites) == 0 {
		return false
	}
	for _, w := range c.Preflight.IntendedWrites {
		if !patternWithin(w, c.Allowed.Read) {
			return true
		}
	}
	return false
}

// ContractRules converts a job contract's own Policy.Rules (a plain data
// mirror living in internal/contracts to avoid an import cycle — see
// contracts.Contract.Policy) into this package's ConditionRule, validating
// each one. c.Validate has already structurally checked these (see
// contracts.validatePolicy); this is a second, authoritative validation
// pass against the real Verdict/op definitions, run at evaluation time so a
// drift between the two packages' duplicated enum lists would surface here
// rather than silently miscompiling a rule.
func ContractRules(c contracts.Contract) ([]ConditionRule, error) {
	if c.Policy == nil {
		return nil, nil
	}
	rules := make([]ConditionRule, 0, len(c.Policy.Rules))
	for _, spec := range c.Policy.Rules {
		when := make([]Condition, 0, len(spec.When))
		for _, cond := range spec.When {
			when = append(when, Condition{Field: cond.Field, Op: cond.Op, Value: cond.Value})
		}
		rule := ConditionRule{ID: spec.ID, When: when, Verdict: Verdict(spec.Verdict), Reason: spec.Reason}
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("contract %s: %w", c.JobID, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// MergeFacts overlays extra onto base (extra wins on key collision) into a
// new map, so callers never mutate a shared facts base across evaluations.
func MergeFacts(base, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
