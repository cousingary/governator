package contracts

import (
	"strings"
	"testing"
)

func validPolicyTestContract() Contract {
	return Contract{
		JobID:   "job-1",
		JobType: "test",
		Agent:   "claude-code",
		Mode:    ModeSurgeon,
		Workspace: Workspace{
			Root:     "/workspace",
			Worktree: "auto",
		},
		Allowed:     Permissions{Read: []string{"**"}, Write: []string{"src/**"}, Execute: []string{"go test ./..."}},
		Budget:      Budget{MaxMinutes: 1, MaxCommands: 1, MaxFilesChanged: 1, MaxLinesChanged: 1},
		Preflight:   Preflight{IntendedWrites: []string{"src/**"}},
		Success:     Success{RequiredFiles: []string{"src/out.txt"}, Validators: []string{"true"}},
		OnViolation: "quarantine",
	}
}

func TestValidatePolicyAbsentBlockIsFine(t *testing.T) {
	c := validPolicyTestContract()
	if err := c.Validate(); err != nil {
		t.Fatalf("expected a contract with no Policy block to validate, got %v", err)
	}
}

func TestValidatePolicyWellFormedRule(t *testing.T) {
	c := validPolicyTestContract()
	c.Policy = &Policy{Rules: []PolicyRuleSpec{
		{ID: "tight-cost", When: []PolicyConditionSpec{{Field: "estimated_cost_usd", Op: "gt", Value: "1"}}, Verdict: "DENY", Reason: "must stay cheap"},
	}}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected a well-formed policy rule to validate, got %v", err)
	}
}

func TestValidatePolicyRejectsMissingID(t *testing.T) {
	c := validPolicyTestContract()
	c.Policy = &Policy{Rules: []PolicyRuleSpec{
		{When: []PolicyConditionSpec{{Field: "x", Op: "eq", Value: "y"}}, Verdict: "ASK", Reason: "r"},
	}}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "policy.rules[0].id") {
		t.Fatalf("expected a policy.rules[0].id error, got %v", err)
	}
}

func TestValidatePolicyRejectsBadVerdict(t *testing.T) {
	c := validPolicyTestContract()
	c.Policy = &Policy{Rules: []PolicyRuleSpec{
		{ID: "r1", When: []PolicyConditionSpec{{Field: "x", Op: "eq", Value: "y"}}, Verdict: "MAYBE", Reason: "r"},
	}}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "policy.rules[0].verdict") {
		t.Fatalf("expected a policy.rules[0].verdict error, got %v", err)
	}
}

func TestValidatePolicyRejectsBadOp(t *testing.T) {
	c := validPolicyTestContract()
	c.Policy = &Policy{Rules: []PolicyRuleSpec{
		{ID: "r1", When: []PolicyConditionSpec{{Field: "x", Op: "regex", Value: "y"}}, Verdict: "ASK", Reason: "r"},
	}}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "policy.rules[0].when[0].op") {
		t.Fatalf("expected a policy.rules[0].when[0].op error, got %v", err)
	}
}

func TestValidatePolicyRejectsEmptyWhen(t *testing.T) {
	c := validPolicyTestContract()
	c.Policy = &Policy{Rules: []PolicyRuleSpec{
		{ID: "r1", Verdict: "ASK", Reason: "r"},
	}}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "policy.rules[0].when") {
		t.Fatalf("expected a policy.rules[0].when error, got %v", err)
	}
}
