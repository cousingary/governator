package policy

import (
	"fmt"
	"strconv"
	"strings"
)

// ConditionRule is the Session 5 constrained, declarative condition
// language: rules stay data (loadable from YAML in org config, a project
// doctrine file, or a job contract's own policy block — see docs/contracts.md)
// so extending the policy engine never means shipping new Go or Python code
// per rule. Every field is a plain comparable value; there is no expression
// evaluator, no arbitrary code path, and no way for a rule file to do
// anything but compare a named fact against a literal.
type ConditionRule struct {
	// ID names the rule for ledger rows and `gov policy explain`-style
	// inspection. Required — an unnamed rule can't be pointed to later.
	ID string `yaml:"id" json:"id"`
	// When is the conjunction (AND) of conditions that must all match for
	// the rule to fire. An empty When never matches (a rule must say what
	// it's for) rather than matching everything by omission.
	When []Condition `yaml:"when" json:"when"`
	// Verdict is what the rule contributes when it fires: ASK, DENY, or
	// FLAG. ALLOW is rejected by Validate — a rule that never objects has
	// nothing to declare (the default, no rule firing, already means
	// allow).
	Verdict Verdict `yaml:"verdict" json:"verdict"`
	// Reason is a human-readable explanation shown to the operator (ASK
	// checkpoint) or recorded on the ledger (DENY/FLAG). Required.
	Reason string `yaml:"reason" json:"reason"`
}

// Condition compares one named fact (see BuildFacts) against a literal
// value. Op is one of: eq, ne, gt, gte, lt, lte, contains, matches_any (the
// fact, itself a []string, intersected against Value's comma-split glob
// patterns via MatchesAny). Numeric comparisons (gt/gte/lt/lte) coerce both
// sides with ToFloat; a fact that won't coerce makes the condition not
// match (fail-closed rules still require an explicit DENY elsewhere — a
// malformed condition simply never fires, it never panics or matches
// everything).
type Condition struct {
	Field string `yaml:"field" json:"field"`
	Op    string `yaml:"op" json:"op"`
	Value string `yaml:"value" json:"value"`
}

var validConditionOps = map[string]bool{
	"eq": true, "ne": true, "gt": true, "gte": true, "lt": true, "lte": true,
	"contains": true, "matches_any": true,
}

// validConditionFields is the closed fact vocabulary (facts.go's Fact*
// constants). Validate rejects any other field name: since an unresolvable
// field makes a condition silently never match (see Condition's doc), a
// typo'd field in a DENY rule would otherwise disarm that rule forever
// without anyone noticing — the rule file loads clean, the rule just never
// fires. Fail loudly at load time instead.
var validConditionFields = map[string]bool{
	FactRiskClass: true, FactMode: true, FactBackend: true,
	FactNetworkEnabled: true, FactWriteOutOfScope: true,
	FactEstimatedCostUSD: true, FactDailyCapUSD: true,
	FactUnusualInfraRetry: true, FactInfraFailureKind: true,
}

// Validate reports every structural problem with r: empty ID, empty When,
// an unrecognized Verdict/Op, or a request for VerdictAllow (see the
// ConditionRule doc comment). Called at load time (config decode, project
// doctrine file read, contract validation) so a malformed rule fails
// loudly before it's ever silently skipped at evaluation time.
func (r ConditionRule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("policy rule: id is required")
	}
	if len(r.When) == 0 {
		return fmt.Errorf("policy rule %q: at least one \"when\" condition is required", r.ID)
	}
	switch r.Verdict {
	case VerdictDeny, VerdictAsk, VerdictFlag:
	case VerdictAllow:
		return fmt.Errorf("policy rule %q: verdict ALLOW is not permitted (a rule that never fires already allows)", r.ID)
	default:
		return fmt.Errorf("policy rule %q: verdict must be one of DENY, ASK, FLAG (got %q)", r.ID, r.Verdict)
	}
	if strings.TrimSpace(r.Reason) == "" {
		return fmt.Errorf("policy rule %q: reason is required", r.ID)
	}
	for i, c := range r.When {
		if strings.TrimSpace(c.Field) == "" {
			return fmt.Errorf("policy rule %q: when[%d].field is required", r.ID, i)
		}
		if !validConditionFields[c.Field] {
			return fmt.Errorf("policy rule %q: when[%d].field %q is not a known fact (see internal/policy/facts.go: risk_class, mode, backend, network_enabled, write_out_of_scope, estimated_cost_usd, daily_cap_usd, unusual_infra_retry, infra_failure_kind); an unknown field would silently never match", r.ID, i, c.Field)
		}
		if !validConditionOps[c.Op] {
			return fmt.Errorf("policy rule %q: when[%d].op %q is not one of eq, ne, gt, gte, lt, lte, contains, matches_any", r.ID, i, c.Op)
		}
	}
	return nil
}

// ToFloat parses s as a float64 for numeric condition comparisons.
func ToFloat(s string) (float64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f, err == nil
}

func factString(facts map[string]any, field string) (string, bool) {
	v, ok := facts[field]
	if !ok {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case int:
		return strconv.Itoa(t), true
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64), true
	default:
		return "", false
	}
}

func factFloat(facts map[string]any, field string) (float64, bool) {
	v, ok := facts[field]
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case string:
		return ToFloat(t)
	default:
		return 0, false
	}
}

func factStringSlice(facts map[string]any, field string) ([]string, bool) {
	v, ok := facts[field]
	if !ok {
		return nil, false
	}
	if s, ok := v.([]string); ok {
		return s, true
	}
	return nil, false
}

// matches reports whether c holds against facts. An unresolvable field or
// type mismatch is a non-match, never an error and never a wildcard match —
// keeps a rule file's blast radius exactly what it declares.
func (c Condition) matches(facts map[string]any) bool {
	switch c.Op {
	case "eq", "ne", "contains":
		got, ok := factString(facts, c.Field)
		if !ok {
			return false
		}
		switch c.Op {
		case "eq":
			return got == c.Value
		case "ne":
			return got != c.Value
		case "contains":
			return strings.Contains(got, c.Value)
		}
	case "gt", "gte", "lt", "lte":
		got, ok := factFloat(facts, c.Field)
		if !ok {
			return false
		}
		want, ok := ToFloat(c.Value)
		if !ok {
			return false
		}
		switch c.Op {
		case "gt":
			return got > want
		case "gte":
			return got >= want
		case "lt":
			return got < want
		case "lte":
			return got <= want
		}
	case "matches_any":
		got, ok := factStringSlice(facts, c.Field)
		if !ok {
			return false
		}
		patterns := strings.Split(c.Value, ",")
		for i := range patterns {
			patterns[i] = strings.TrimSpace(patterns[i])
		}
		for _, g := range got {
			if MatchesAny(patterns, g) {
				return true
			}
		}
		return false
	}
	return false
}

// Fires reports whether every condition in r.When matches facts (AND).
func (r ConditionRule) Fires(facts map[string]any) bool {
	for _, c := range r.When {
		if !c.matches(facts) {
			return false
		}
	}
	return true
}

// EvaluateConditionRules runs every rule in rules against facts, in order,
// and returns one LayerResult per firing rule attributed to source (the
// caller's policy layer — org/project/contract). A rule set with no firing
// rule yields no results, meaning that layer contributed no objection.
func EvaluateConditionRules(source string, rules []ConditionRule, facts map[string]any) []LayerResult {
	var out []LayerResult
	for _, rule := range rules {
		if rule.Fires(facts) {
			out = append(out, LayerResult{Source: source, Verdict: rule.Verdict, Reason: fmt.Sprintf("%s: %s", rule.ID, rule.Reason), RuleID: rule.ID})
		}
	}
	return out
}
