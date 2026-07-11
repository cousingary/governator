package policy

import "testing"

func TestCombineIsFailClosedAndKeepsEveryReason(t *testing.T) {
	allow := Allow(SourceOrgPolicy)
	deny1 := Deny(SourceProjectDoctrine, "protected path")
	deny2 := Deny(SourceOrgPolicy, "destructive command")

	combined := Combine(allow, deny1, deny2)
	if combined.Allowed {
		t.Fatal("Combine of allow+deny+deny must be a denial")
	}
	if len(combined.Reasons) != 2 {
		t.Fatalf("expected both denying reasons kept, got %v", combined.Reasons)
	}
	if len(combined.Sources) != 2 {
		t.Fatalf("expected sources deduped to the 2 distinct layers, got %v", combined.Sources)
	}
	if combined.PolicyHash == "" {
		t.Fatal("Combine must compute a PolicyHash")
	}
}

func TestCombineAllAllowIsAllow(t *testing.T) {
	combined := Combine(Allow(SourceOrgPolicy), Allow(SourceProjectDoctrine))
	if !combined.Allowed {
		t.Fatalf("all-allow combine must be allowed, got %+v", combined)
	}
}

func TestGatePolicyHashStableAcrossPatternOrder(t *testing.T) {
	a := GatePolicyHash([]string{"a/**", "b/**"})
	b := GatePolicyHash([]string{"b/**", "a/**"})
	if a != b {
		t.Fatalf("hash must not depend on pattern order: %s != %s", a, b)
	}
	c := GatePolicyHash([]string{"a/**", "b/**", "c/**"})
	if a == c {
		t.Fatal("hash must change when the pattern set actually changes")
	}
}

func TestSourcesForFinding(t *testing.T) {
	tests := []struct {
		finding string
		want    string
	}{
		{"F2", SourceProjectDoctrine},
		{"F4", SourceProjectDoctrine},
		{"F1", SourceOrgPolicy},
		{"F3", SourceOrgPolicy},
	}
	for _, test := range tests {
		got := SourcesForFinding(test.finding)
		if len(got) != 1 || got[0] != test.want {
			t.Errorf("SourcesForFinding(%s) = %v, want [%s]", test.finding, got, test.want)
		}
	}
	if got := SourcesForFinding("default"); got != nil {
		t.Errorf("SourcesForFinding(default) = %v, want nil (no policy layer consulted)", got)
	}
}
