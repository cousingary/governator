package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
)

func TestConditionRuleValidateRejectsMalformedRules(t *testing.T) {
	tests := []struct {
		name string
		rule ConditionRule
		want string
	}{
		{"empty id", ConditionRule{When: []Condition{{Field: "x", Op: "eq", Value: "y"}}, Verdict: VerdictAsk, Reason: "r"}, "id is required"},
		{"empty when", ConditionRule{ID: "r1", Verdict: VerdictAsk, Reason: "r"}, "at least one"},
		{"verdict allow rejected", ConditionRule{ID: "r1", When: []Condition{{Field: "x", Op: "eq", Value: "y"}}, Verdict: VerdictAllow, Reason: "r"}, "ALLOW is not permitted"},
		{"bad verdict", ConditionRule{ID: "r1", When: []Condition{{Field: "x", Op: "eq", Value: "y"}}, Verdict: "MAYBE", Reason: "r"}, "must be one of DENY, ASK, FLAG"},
		{"empty reason", ConditionRule{ID: "r1", When: []Condition{{Field: "x", Op: "eq", Value: "y"}}, Verdict: VerdictAsk}, "reason is required"},
		{"bad op", ConditionRule{ID: "r1", When: []Condition{{Field: "x", Op: "regex", Value: "y"}}, Verdict: VerdictAsk, Reason: "r"}, "op"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestConditionRuleValidateAcceptsWellFormedRule(t *testing.T) {
	rule := ConditionRule{
		ID:      "cost-threshold",
		When:    []Condition{{Field: FactEstimatedCostUSD, Op: "gt", Value: "5"}},
		Verdict: VerdictAsk,
		Reason:  "estimated cost exceeds $5",
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("expected a well-formed rule to validate, got %v", err)
	}
}

func TestConditionFiresNumericComparisons(t *testing.T) {
	rule := ConditionRule{ID: "r", When: []Condition{{Field: "cost", Op: "gt", Value: "5"}}, Verdict: VerdictAsk, Reason: "r"}
	if !rule.Fires(map[string]any{"cost": 6.0}) {
		t.Fatal("expected 6 > 5 to fire")
	}
	if rule.Fires(map[string]any{"cost": 5.0}) {
		t.Fatal("expected 5 > 5 to NOT fire")
	}
	if rule.Fires(map[string]any{"cost": "not-a-number"}) {
		t.Fatal("expected an unparseable fact to never fire, not panic or wildcard-match")
	}
	if rule.Fires(map[string]any{}) {
		t.Fatal("expected a missing fact to never fire")
	}
}

func TestConditionFiresBooleanEquality(t *testing.T) {
	rule := ConditionRule{ID: "r", When: []Condition{{Field: "network_enabled", Op: "eq", Value: "true"}}, Verdict: VerdictAsk, Reason: "r"}
	if !rule.Fires(map[string]any{"network_enabled": true}) {
		t.Fatal("expected bool fact true to eq \"true\"")
	}
	if rule.Fires(map[string]any{"network_enabled": false}) {
		t.Fatal("expected bool fact false to not eq \"true\"")
	}
}

func TestConditionFiresMatchesAny(t *testing.T) {
	rule := ConditionRule{ID: "r", When: []Condition{{Field: "writes", Op: "matches_any", Value: "docs/**, *.md"}}, Verdict: VerdictAsk, Reason: "r"}
	if !rule.Fires(map[string]any{"writes": []string{"src/main.go", "docs/readme.txt"}}) {
		t.Fatal("expected docs/** to match one of the writes")
	}
	if rule.Fires(map[string]any{"writes": []string{"src/main.go", "src/other.go"}}) {
		t.Fatal("expected no match when nothing falls under the patterns")
	}
}

func TestEvaluateConditionRulesAttributesSourceAndRuleID(t *testing.T) {
	rules := []ConditionRule{
		{ID: "net-ask", When: []Condition{{Field: "network_enabled", Op: "eq", Value: "true"}}, Verdict: VerdictAsk, Reason: "network is risky"},
		{ID: "never-fires", When: []Condition{{Field: "network_enabled", Op: "eq", Value: "false"}}, Verdict: VerdictDeny, Reason: "n/a"},
	}
	results := EvaluateConditionRules(SourceOrgPolicy, rules, map[string]any{"network_enabled": true})
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 fired rule, got %d: %+v", len(results), results)
	}
	if results[0].RuleID != "net-ask" || results[0].Source != SourceOrgPolicy || results[0].Verdict != VerdictAsk {
		t.Fatalf("unexpected result: %+v", results[0])
	}
}

func baseContract(t *testing.T) contracts.Contract {
	t.Helper()
	return contracts.Contract{
		JobID:     "job-1",
		JobType:   "test",
		Agent:     "claude-code",
		Mode:      contracts.ModeSurgeon,
		Allowed:   contracts.Permissions{Read: []string{"src/**"}, Write: []string{"src/**"}, Execute: []string{"go test ./..."}},
		Preflight: contracts.Preflight{IntendedWrites: []string{"src/**"}},
	}
}

func TestBuildContractFactsNetworkEnabledFromExecute(t *testing.T) {
	c := baseContract(t)
	c.Allowed.Execute = []string{"curl https://example.com"}
	facts := BuildContractFacts(c, "claude-code")
	if facts[FactNetworkEnabled] != true {
		t.Fatalf("expected network_enabled true from a curl allowlist entry, got %+v", facts)
	}
}

func TestBuildContractFactsNetworkEnabledFromDocker(t *testing.T) {
	c := baseContract(t)
	c.Docker = &contracts.DockerRunnerConfig{Network: "allow"}
	facts := BuildContractFacts(c, "claude-code")
	if facts[FactNetworkEnabled] != true {
		t.Fatalf("expected network_enabled true from docker.network: allow, got %+v", facts)
	}
}

func TestBuildContractFactsNetworkDisabledByDefault(t *testing.T) {
	c := baseContract(t)
	facts := BuildContractFacts(c, "claude-code")
	if facts[FactNetworkEnabled] != false {
		t.Fatalf("expected network_enabled false for an ordinary contract, got %+v", facts)
	}
}

func TestBuildContractFactsWriteOutOfScope(t *testing.T) {
	c := baseContract(t)
	c.Allowed.Read = []string{"src/**"}
	c.Preflight.IntendedWrites = []string{"config/secrets.yaml"}
	facts := BuildContractFacts(c, "claude-code")
	if facts[FactWriteOutOfScope] != true {
		t.Fatalf("expected write_out_of_scope true when the intended write falls outside allowed.read, got %+v", facts)
	}
}

func TestBuildContractFactsWriteInScope(t *testing.T) {
	c := baseContract(t)
	facts := BuildContractFacts(c, "claude-code")
	if facts[FactWriteOutOfScope] != false {
		t.Fatalf("expected write_out_of_scope false when intended writes fall under allowed.read, got %+v", facts)
	}
}

func TestContractRulesConvertsAndValidates(t *testing.T) {
	c := baseContract(t)
	c.Policy = &contracts.Policy{Rules: []contracts.PolicyRuleSpec{
		{ID: "tight-cost", When: []contracts.PolicyConditionSpec{{Field: FactEstimatedCostUSD, Op: "gt", Value: "1"}}, Verdict: "DENY", Reason: "this job must stay cheap"},
	}}
	rules, err := ContractRules(c)
	if err != nil {
		t.Fatalf("expected valid contract rules to convert cleanly, got %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "tight-cost" || rules[0].Verdict != VerdictDeny {
		t.Fatalf("unexpected converted rules: %+v", rules)
	}
}

func TestContractRulesNilPolicyIsEmpty(t *testing.T) {
	rules, err := ContractRules(baseContract(t))
	if err != nil || rules != nil {
		t.Fatalf("expected no rules and no error for a contract with no Policy block, got %v, %v", rules, err)
	}
}

func TestLoadProjectDoctrineMissingFileIsNotAnError(t *testing.T) {
	rules, err := LoadProjectDoctrine(t.TempDir())
	if err != nil || rules != nil {
		t.Fatalf("expected (nil, nil) for a missing doctrine file, got (%v, %v)", rules, err)
	}
}

func TestLoadProjectDoctrineValidFile(t *testing.T) {
	dir := t.TempDir()
	content := "policy_rules:\n  - id: net-ask\n    when:\n      - field: network_enabled\n        op: eq\n        value: \"true\"\n    verdict: ASK\n    reason: network access needs review\n"
	if err := os.WriteFile(filepath.Join(dir, ProjectDoctrineFilename), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadProjectDoctrine(dir)
	if err != nil {
		t.Fatalf("expected a well-formed doctrine file to load, got %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "net-ask" {
		t.Fatalf("unexpected rules: %+v", rules)
	}
}

func TestLoadProjectDoctrineInvalidRuleIsAnError(t *testing.T) {
	dir := t.TempDir()
	content := "policy_rules:\n  - id: bad\n    when: []\n    verdict: ASK\n    reason: x\n"
	if err := os.WriteFile(filepath.Join(dir, ProjectDoctrineFilename), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProjectDoctrine(dir); err == nil {
		t.Fatal("expected an empty when list to fail validation rather than silently loading")
	}
}

func TestMergeFactsExtraWinsOnCollision(t *testing.T) {
	out := MergeFacts(map[string]any{"a": 1, "b": 2}, map[string]any{"b": 3, "c": 4})
	if out["a"] != 1 || out["b"] != 3 || out["c"] != 4 {
		t.Fatalf("unexpected merge result: %+v", out)
	}
}
