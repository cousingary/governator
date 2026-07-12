package policy

import "testing"

func TestEvaluateLayersOrgDenyIsFinalOverAnyLaterLayer(t *testing.T) {
	decision := EvaluateLayers(
		LayerResult{Source: SourceOrgPolicy, Verdict: VerdictDeny, Reason: "org says no"},
		LayerResult{Source: SourceSessionOverride, Verdict: VerdictAsk, Reason: "operator asked anyway"},
	)
	if decision.Verdict != VerdictDeny {
		t.Fatalf("expected DENY to be final, got %s", decision.Verdict)
	}
	if decision.Allowed {
		t.Fatal("a DENY decision must not be Allowed")
	}
	if !decision.Blocks() {
		t.Fatal("DENY must Blocks()")
	}
}

func TestEvaluateLayersAskWithNoDenyStaysAsk(t *testing.T) {
	decision := EvaluateLayers(
		LayerResult{Source: SourceOrgPolicy, Verdict: VerdictAllow},
		LayerResult{Source: SourceJobContract, Verdict: VerdictAsk, Reason: "needs a human", RuleID: "cost-threshold"},
	)
	if decision.Verdict != VerdictAsk {
		t.Fatalf("expected ASK, got %s", decision.Verdict)
	}
	if !decision.Blocks() {
		t.Fatal("ASK must Blocks() until resolved")
	}
	if decision.Allowed {
		t.Fatal("an unresolved ASK must not be Allowed")
	}
}

func TestEvaluateLayersFlagNeverBlocks(t *testing.T) {
	decision := EvaluateLayers(LayerResult{Source: SourceOrgPolicy, Verdict: VerdictFlag, Reason: "fyi"})
	if decision.Verdict != VerdictFlag {
		t.Fatalf("expected FLAG, got %s", decision.Verdict)
	}
	if decision.Blocks() {
		t.Fatal("FLAG must never Blocks()")
	}
	if !decision.Allowed {
		t.Fatal("FLAG must stay Allowed")
	}
}

func TestEvaluateLayersConsultedIncludesEveryLayerRegardlessOfVerdict(t *testing.T) {
	decision := EvaluateLayers(
		LayerResult{Source: SourceOrgPolicy, Verdict: VerdictAllow},
		LayerResult{Source: SourceProjectDoctrine, Verdict: VerdictAllow},
		LayerResult{Source: SourceJobContract, Verdict: VerdictAsk, Reason: "ask", RuleID: "r1"},
	)
	if len(decision.Consulted) != 3 {
		t.Fatalf("expected all 3 layers consulted, got %v", decision.Consulted)
	}
}

func TestEvaluateLayersOrderIndependentOfCallArgOrder(t *testing.T) {
	a := EvaluateLayers(
		LayerResult{Source: SourceSessionOverride, Verdict: VerdictAsk, Reason: "x", RuleID: "r"},
		LayerResult{Source: SourceOrgPolicy, Verdict: VerdictDeny, Reason: "y"},
	)
	b := EvaluateLayers(
		LayerResult{Source: SourceOrgPolicy, Verdict: VerdictDeny, Reason: "y"},
		LayerResult{Source: SourceSessionOverride, Verdict: VerdictAsk, Reason: "x", RuleID: "r"},
	)
	if a.Verdict != b.Verdict || a.PolicyHash != b.PolicyHash {
		t.Fatalf("expected identical decisions regardless of call order: %+v vs %+v", a, b)
	}
}

func TestResolveOverridesOnlyResolvesMatchingAskRuleID(t *testing.T) {
	results := []LayerResult{
		{Source: SourceOrgPolicy, Verdict: VerdictAsk, Reason: "cost", RuleID: "cost-threshold"},
		{Source: SourceOrgPolicy, Verdict: VerdictAsk, Reason: "network", RuleID: "network-enablement"},
	}
	resolved := ResolveOverrides(results, []Override{{RuleID: "cost-threshold", Verdict: VerdictAllow}})
	if resolved[0].Verdict != VerdictAllow || resolved[0].Source != SourceSessionOverride {
		t.Fatalf("expected cost-threshold resolved to ALLOW via session override, got %+v", resolved[0])
	}
	if resolved[1].Verdict != VerdictAsk {
		t.Fatalf("expected network-enablement to remain ASK (no matching override), got %+v", resolved[1])
	}
	decision := EvaluateLayers(resolved...)
	if decision.Verdict != VerdictAsk {
		t.Fatalf("expected overall decision to still be ASK (one rule unresolved), got %s", decision.Verdict)
	}
}

func TestResolveOverridesNeverResolvesDeny(t *testing.T) {
	results := []LayerResult{{Source: SourceOrgPolicy, Verdict: VerdictDeny, Reason: "no", RuleID: "hard-deny"}}
	resolved := ResolveOverrides(results, []Override{{RuleID: "hard-deny", Verdict: VerdictAllow}})
	if resolved[0].Verdict != VerdictDeny {
		t.Fatalf("DENY must never be resolved by an override, got %+v", resolved[0])
	}
}

func TestResolveOverridesDenyOverride(t *testing.T) {
	results := []LayerResult{{Source: SourceJobContract, Verdict: VerdictAsk, Reason: "ask", RuleID: "r1"}}
	resolved := ResolveOverrides(results, []Override{{RuleID: "r1", Verdict: VerdictDeny}})
	decision := EvaluateLayers(resolved...)
	if decision.Verdict != VerdictDeny {
		t.Fatalf("expected an operator DENY override to produce a final DENY, got %s", decision.Verdict)
	}
}
