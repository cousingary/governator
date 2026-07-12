package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Verdict is the Session 5 (Sol Phase 4) four-way policy outcome. DENY and
// ASK both stop an action from proceeding (see Blocks); the difference is
// that DENY is terminal (fail-closed, no operator escape hatch inside this
// evaluation) while ASK is a checkpoint waiting on a human. FLAG never stops
// anything — it is the same advisory posture rules.go's RuleFlag already
// uses for the temporal-rule engine, generalized to every policy layer.
type Verdict string

const (
	VerdictAllow Verdict = "ALLOW"
	VerdictDeny  Verdict = "DENY"
	VerdictAsk   Verdict = "ASK"
	VerdictFlag  Verdict = "FLAG"
)

// verdictRank orders verdicts from least to most restrictive so combining
// layers is a simple "take the max" — DENY always wins over ASK, ASK always
// wins over FLAG, FLAG always wins over ALLOW. An unrecognized/empty Verdict
// ranks as ALLOW (rank 0): it consulted nothing and objected to nothing.
var verdictRank = map[Verdict]int{
	VerdictAllow: 0,
	VerdictFlag:  1,
	VerdictAsk:   2,
	VerdictDeny:  3,
}

func (v Verdict) rank() int { return verdictRank[v] }

// Blocks reports whether d prevents the action from proceeding without
// further resolution. DENY is terminal; ASK blocks until a
// SourceSessionOverride layer resolves it (approve once, deny once, or an
// expiring temporary rule) on a later evaluation. ALLOW and FLAG both let
// the action proceed — FLAG only adds an audit trail.
func (d PolicyDecision) Blocks() bool {
	return d.Verdict == VerdictDeny || d.Verdict == VerdictAsk
}

// LayerResult is one policy layer's contribution to a single gate call: the
// layer that was consulted (one of the Source* constants), the verdict it
// reached, and — for any non-ALLOW verdict — why. A layer that has no
// opinion (the common case) reports VerdictAllow (or leaves Verdict empty,
// treated identically) with an empty Reason.
type LayerResult struct {
	Source  string
	Verdict Verdict
	Reason  string
	// RuleID names the ConditionRule that produced this result (empty for a
	// LayerResult built directly via Deny/Ask/Flag rather than a rule set).
	// A session/operator override is scoped to a specific RuleID — see
	// ResolveOverrides — so the same job's rules can be individually
	// approved without approving every other ASK the job might trigger.
	RuleID string
}

// layerPrecedence is the Session 5 deterministic evaluation order:
// organization policy first (least specific, most authoritative — nothing
// below it can loosen a DENY), then project doctrine, then the job
// contract's own declared rules, then session/operator override (most
// specific, evaluated last, and the only layer a human directly authors at
// run time). EvaluateLayers sorts by this order regardless of the order
// results are passed in, so precedence never depends on call-site ordering.
var layerPrecedence = []string{SourceOrgPolicy, SourceProjectDoctrine, SourceJobContract, SourceSessionOverride}

func precedenceRank(source string) int {
	for i, s := range layerPrecedence {
		if s == source {
			return i
		}
	}
	// An unknown source sorts after every known layer rather than panicking
	// or silently ranking first — a typo'd source name still gets evaluated
	// and recorded, just last.
	return len(layerPrecedence)
}

// EvaluateLayers combines one verdict per policy layer into a single
// PolicyDecision. Every layer that was actually consulted is recorded in
// Consulted regardless of its verdict (mirrors Allow's existing
// "sources consulted, no objection" convention). The effective Verdict is
// the most restrictive one seen across all layers (see verdictRank): a DENY
// from any layer — most importantly organization policy, which no lower
// layer can override — is final. An ASK is the effective verdict only while
// no layer denies; resolving it is EvaluateLayers's caller's job (persist a
// checkpoint, then re-evaluate later with a SourceSessionOverride
// LayerResult once the operator responds — see internal/observability's
// policy_checkpoints/policy_overrides tables). This function performs no
// resolution itself, it only consults whatever layer results it is given.
func EvaluateLayers(results ...LayerResult) PolicyDecision {
	sorted := append([]LayerResult(nil), results...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return precedenceRank(sorted[i].Source) < precedenceRank(sorted[j].Source)
	})

	out := PolicyDecision{Allowed: true, Verdict: VerdictAllow}
	var consulted []string
	for _, res := range sorted {
		if res.Source != "" {
			consulted = append(consulted, res.Source)
		}
		if res.Verdict == "" || res.Verdict == VerdictAllow {
			continue
		}
		out.Reasons = append(out.Reasons, res.Reason)
		out.Sources = append(out.Sources, res.Source)
		if res.Verdict.rank() > out.Verdict.rank() {
			out.Verdict = res.Verdict
		}
	}
	out.Allowed = out.Verdict == VerdictAllow || out.Verdict == VerdictFlag
	out.Consulted = uniqueSorted(consulted)
	out.Sources = uniqueSorted(out.Sources)
	out.PolicyHash = Hash(string(out.Verdict) + "|" + strings.Join(out.Sources, ",") + "|" + strings.Join(out.Reasons, "|"))
	return out
}

// Override is a resolved session/operator decision for one rule, scoped by
// whatever key the caller used (job_id, backend, ...). It mirrors
// internal/observability's PolicyOverride without this package depending on
// that package's Go types or database/sql — internal/runtime is what
// actually loads active overrides from the ledger and converts them here.
type Override struct {
	RuleID  string
	Verdict Verdict
}

// ResolveOverrides substitutes an active session/operator override for any
// result whose Verdict is ASK and whose RuleID matches an override in the
// given list. DENY is terminal and FLAG never blocks (see Blocks), so
// neither is eligible for override — only ASK, the verdict explicitly
// designed to be resolved by a human, can be resolved this way. A result
// with no matching override (or no RuleID at all, e.g. one built directly
// via Deny/Ask/Flag rather than a rule set) passes through unchanged. Pass
// overrides newest-first (ActivePolicyOverrides already orders this way) so
// the most recent operator decision wins when more than one exists for the
// same rule.
func ResolveOverrides(results []LayerResult, overrides []Override) []LayerResult {
	if len(overrides) == 0 {
		return results
	}
	byRule := make(map[string]Override, len(overrides))
	for _, o := range overrides {
		if _, exists := byRule[o.RuleID]; !exists {
			byRule[o.RuleID] = o
		}
	}
	out := make([]LayerResult, len(results))
	for i, r := range results {
		out[i] = r
		if r.Verdict != VerdictAsk || r.RuleID == "" {
			continue
		}
		if o, ok := byRule[r.RuleID]; ok {
			out[i] = LayerResult{
				Source:  SourceSessionOverride,
				Verdict: o.Verdict,
				Reason:  fmt.Sprintf("%s: resolved by session/operator override to %s", r.RuleID, o.Verdict),
				RuleID:  r.RuleID,
			}
		}
	}
	return out
}
