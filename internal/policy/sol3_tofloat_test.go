package policy

import "testing"

// TestSol3ToFloatRejectsNaNAndInf closes the audit's "reject NaN and
// infinities ... for every parsed usage/cost field" requirement
// (Sol P1.2, finding #9) for policy rule condition literals:
// strconv.ParseFloat accepts "nan"/"inf" spellings without error, so a
// numeric-operator rule with a literal like `value: ".nan"` used to pass
// validateConditionValue's numeric-literal check and could reach a live
// comparison at evaluation time, where NaN compares false against
// everything (silently disarming the rule) or Inf trivially wins/loses.
func TestSol3ToFloatRejectsNaNAndInf(t *testing.T) {
	for _, s := range []string{".nan", "NaN", "nan", ".inf", "-.inf", "Inf", "-Inf", "infinity"} {
		if _, ok := ToFloat(s); ok {
			t.Fatalf("expected ToFloat(%q) to reject a non-finite literal, got ok=true", s)
		}
	}
}

func TestSol3ToFloatAcceptsFiniteNumbers(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want float64
	}{
		{"0", 0}, {"1.5", 1.5}, {"-3", -3}, {"1e10", 1e10},
	} {
		got, ok := ToFloat(tc.in)
		if !ok || got != tc.want {
			t.Fatalf("ToFloat(%q) = (%v, %v), want (%v, true)", tc.in, got, ok, tc.want)
		}
	}
}

// TestSol3ConditionRuleValidateRejectsNaNLiteralForNumericOperator proves
// the fix reaches the actual validation path a config-loaded org policy
// rule goes through, not just the ToFloat unit in isolation.
func TestSol3ConditionRuleValidateRejectsNaNLiteralForNumericOperator(t *testing.T) {
	r := ConditionRule{
		ID:      "cost-check",
		When:    []Condition{{Field: FactEstimatedCostUSD, Op: "gt", Value: ".nan"}},
		Verdict: VerdictAsk,
		Reason:  "cost too high",
	}
	if err := r.Validate(); err == nil {
		t.Fatal("expected Validate to reject a NaN literal for a numeric operator, got nil")
	}
}
