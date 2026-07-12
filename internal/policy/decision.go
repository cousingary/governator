package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Source names the policy layer that produced an allow/deny outcome, so a
// denial can say not just WHAT blocked it but WHICH governing layer decided:
// the individual job's own contract, this project's standing conventions, or
// a hardcoded org-wide rule no contract can override.
const (
	SourceJobContract     = "job_contract"
	SourceProjectDoctrine = "project_doctrine"
	SourceOrgPolicy       = "org_policy"
	// SourceSessionOverride names the operator's own in-session decisions: a
	// checkpointed ASK approved/denied once, or a narrowly scoped expiring
	// temporary rule created in response to one. It is the most specific and
	// most recent layer, and the only one a human directly authors at run
	// time — see EvaluateLayers and internal/observability's
	// policy_overrides table.
	SourceSessionOverride = "session_override"
)

// gatePolicyVersion bumps whenever the F1-F7 rule set itself changes shape
// (a new finding axis, a new fallback-danger pattern, a reclassified command)
// so two PolicyHash values only ever compare equal when both the active
// protected-path manifest AND the compiled rule logic actually matched.
const gatePolicyVersion = "gate-f1-f7-v1"

// PolicyDecision is the provenance-carrying result of one policy evaluation:
// not just allow/deny, but every reason, which layer(s) produced each reason,
// and a hash identifying the exact policy configuration that was consulted.
// Sources and Reasons stay index-independent (a denial may be produced by
// several layers at once, e.g. a command that is both outside the contract's
// allowlist AND on the hardcoded fallback-danger list) — callers that want a
// per-reason source pairing should keep Reasons and Sources the same length
// and in the same order; Combine does this for its inputs.
type PolicyDecision struct {
	Allowed bool
	Reasons []string
	Sources []string
	// Verdict is the Session 5 (Phase 4) four-way outcome: ALLOW/DENY/ASK/
	// FLAG. Allowed stays the boolean projection existing callers already
	// read (Allowed == Verdict == VerdictAllow); Verdict is additive and
	// carries the richer ASK/FLAG distinction Allowed alone can't express.
	// A zero-value Verdict (decisions built before this field existed, or
	// via a raw struct literal) is treated as VerdictAllow/VerdictDeny by
	// Allowed's value wherever code still branches on rank — see Combine.
	Verdict Verdict
	// Consulted lists every policy layer source that was evaluated to reach
	// this decision, regardless of verdict — a superset of Sources (which
	// only names layers that produced a non-ALLOW reason). Lets a caller
	// reconstruct "what did we check" even along the pure-allow path.
	Consulted  []string
	PolicyHash string
}

// Allow returns a permissive decision. sources records which layers were
// actually consulted (and found no objection), so a caller reconstructing
// "what did we check" doesn't have to special-case the allow path.
func Allow(sources ...string) PolicyDecision {
	return PolicyDecision{Allowed: true, Verdict: VerdictAllow, Sources: uniqueSorted(sources), Consulted: uniqueSorted(sources)}
}

// Deny returns a single-reason denial attributed to one policy source.
func Deny(source, reason string) PolicyDecision {
	return PolicyDecision{Allowed: false, Verdict: VerdictDeny, Reasons: []string{reason}, Sources: []string{source}, Consulted: []string{source}}
}

// Ask returns a decision that pauses the action pending a checkpointed
// operator resolution (see EvaluateLayers and internal/observability's
// policy_checkpoints table). Like Deny, Allowed is false — an ASK blocks
// forward progress exactly like a DENY until a SourceSessionOverride layer
// resolves it on a later evaluation.
func Ask(source, reason string) PolicyDecision {
	return PolicyDecision{Allowed: false, Verdict: VerdictAsk, Reasons: []string{reason}, Sources: []string{source}, Consulted: []string{source}}
}

// Flag returns an advisory-only decision: Allowed stays true (mirrors
// RuleFlag's existing "never changes the run's outcome" posture in
// rules.go), but the reason and source are kept for operator review.
func Flag(source, reason string) PolicyDecision {
	return PolicyDecision{Allowed: true, Verdict: VerdictFlag, Reasons: []string{reason}, Sources: []string{source}, Consulted: []string{source}}
}

// Combine merges independent sub-decisions evaluated for the same gate call
// into one fail-closed result: any denial makes the combined decision a
// denial, and every denying layer's reason and source are kept — never
// collapsed to a single "first wins" verdict — so downstream tooling (ledger
// rows, `gov route explain`-style inspection) can show the full set of
// policies that bounded or overrode the call. PolicyHash is recomputed over
// the combined Sources+Reasons material.
func Combine(decisions ...PolicyDecision) PolicyDecision {
	out := PolicyDecision{Allowed: true, Verdict: VerdictAllow}
	for _, d := range decisions {
		if !d.Allowed {
			out.Allowed = false
		}
		v := d.Verdict
		if v == "" {
			// Pre-Session-5 callers (or a raw struct literal in a test) never
			// set Verdict; fall back to the boolean so Combine still ranks
			// correctly against decisions that do carry one.
			v = VerdictAllow
			if !d.Allowed {
				v = VerdictDeny
			}
		}
		if v.rank() > out.Verdict.rank() {
			out.Verdict = v
		}
		out.Reasons = append(out.Reasons, d.Reasons...)
		out.Sources = append(out.Sources, d.Sources...)
		out.Consulted = append(out.Consulted, d.Consulted...)
		if len(d.Consulted) == 0 {
			out.Consulted = append(out.Consulted, d.Sources...)
		}
	}
	out.Sources = uniqueSorted(out.Sources)
	out.Consulted = uniqueSorted(out.Consulted)
	out.PolicyHash = Hash(strings.Join(out.Sources, ",") + "|" + strings.Join(out.Reasons, "|"))
	return out
}

// Hash fingerprints arbitrary policy material to a short hex digest, the same
// truncated-sha256 idiom internal/router uses for its route policy hash: long
// enough to catch drift, short enough for a ledger column or CLI table.
func Hash(material string) string {
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:8])
}

// GatePolicyHash fingerprints the exact gate configuration behind an F1-F7
// decision — the compiled rule-set version plus the active protected-path
// manifest — so two GateDecision rows sharing a hash are provably comparing
// the same policy, not just the same code version with a manifest that has
// since changed underneath it.
func GatePolicyHash(protectedPatterns []string) string {
	sorted := append([]string(nil), protectedPatterns...)
	sort.Strings(sorted)
	return Hash(gatePolicyVersion + "|" + strings.Join(sorted, ","))
}

// SourcesForFinding maps an F1-F7 gate finding axis to the policy layer(s)
// that axis represents: F2/F4 enforce the operator-configured protected-path
// manifest (a per-project convention → project doctrine); F1/F3 enforce the
// hardcoded fallback-danger list and command classifier (compiled into the
// binary, not configurable per project → org policy). "default" (no axis
// fired, tool allowed outright) consults no policy layer.
func SourcesForFinding(finding string) []string {
	switch finding {
	case "F2", "F4":
		return []string{SourceProjectDoctrine}
	case "F1", "F3":
		return []string{SourceOrgPolicy}
	default:
		return nil
	}
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
