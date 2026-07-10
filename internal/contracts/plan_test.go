package contracts

import (
	"strings"
	"testing"
)

func planJob(root, jobID string) Contract {
	return Contract{
		Task: "do the thing", JobID: jobID, JobType: "code_change", Agent: "claude-code", Mode: ModeSurgeon,
		Workspace: Workspace{Root: root, Worktree: "auto"},
		Allowed:   Permissions{Read: []string{"**"}, Write: []string{"internal/**"}, Execute: []string{"go build ./..."}},
		Forbidden: Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}, Behaviors: []string{"network"}},
		Budget:    Budget{MaxMinutes: 10, MaxCommands: 10, MaxFilesChanged: 3, MaxLinesChanged: 100, MaxNewFiles: 1, MaxDeleted: 0, MaxTokens: 10000},
		Preflight: Preflight{IntendedWrites: []string{"internal/**"}},
		Success:   Success{RequiredFiles: []string{"internal/x.go"}, Validators: []string{"go build ./..."}},
		OnViolation: "quarantine",
		RiskClass:   "low",
	}
}

func TestValidatePlanAcceptsAWellFormedPlan(t *testing.T) {
	root := "/repo"
	a := planJob(root, "job-a")
	b := planJob(root, "job-b")
	b.DependsOn = []string{"job-a"}

	levels, err := ValidatePlan([]Contract{a, b}, root, []string{"internal/**"}, 25000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(levels) != 2 || len(levels[0]) != 1 || levels[0][0].JobID != "job-a" {
		t.Fatalf("expected job-a alone in level 0, got %+v", levels)
	}
	if len(levels[1]) != 1 || levels[1][0].JobID != "job-b" {
		t.Fatalf("expected job-b alone in level 1, got %+v", levels)
	}
}

func TestValidatePlanRejectsMalformedSubContract(t *testing.T) {
	root := "/repo"
	bad := planJob(root, "job-a")
	bad.Mode = "not-a-real-mode"

	_, err := ValidatePlan([]Contract{bad}, root, []string{"internal/**"}, 25000)
	if err == nil {
		t.Fatal("expected an error for an invalid sub-contract mode")
	}
	if !strings.Contains(err.Error(), "jobs[0]") {
		t.Fatalf("expected the error to be attributed to jobs[0], got %v", err)
	}
}

func TestValidatePlanRejectsOverBudgetTotal(t *testing.T) {
	root := "/repo"
	a := planJob(root, "job-a")
	a.Budget.MaxTokens = 20000
	b := planJob(root, "job-b")
	b.Budget.MaxTokens = 20000

	_, err := ValidatePlan([]Contract{a, b}, root, []string{"internal/**"}, 25000)
	if err == nil {
		t.Fatal("expected an error when the sum of budget.max_tokens exceeds --max-total-tokens")
	}
	if !strings.Contains(err.Error(), "exceeds --max-total-tokens") {
		t.Fatalf("expected a budget-cap error, got %v", err)
	}
}

func TestValidatePlanRejectsWriteOutsideDeclaredEnvelope(t *testing.T) {
	root := "/repo"
	escapee := planJob(root, "job-a")
	escapee.Allowed.Write = []string{"secrets/**"}
	escapee.Preflight.IntendedWrites = []string{"secrets/**"}

	_, err := ValidatePlan([]Contract{escapee}, root, []string{"internal/**"}, 25000)
	if err == nil {
		t.Fatal("expected an error when a job's write pattern escapes the declared envelope")
	}
	if !strings.Contains(err.Error(), "escapes the declared envelope") {
		t.Fatalf("expected an envelope-escape error, got %v", err)
	}
}

func TestValidatePlanRejectsDependsOnCycle(t *testing.T) {
	root := "/repo"
	a := planJob(root, "job-a")
	a.DependsOn = []string{"job-b"}
	b := planJob(root, "job-b")
	b.DependsOn = []string{"job-a"}

	_, err := ValidatePlan([]Contract{a, b}, root, []string{"internal/**"}, 25000)
	if err == nil {
		t.Fatal("expected an error for a depends_on cycle")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected a cycle error, got %v", err)
	}
}

func TestValidatePlanRejectsDanglingDependsOn(t *testing.T) {
	root := "/repo"
	a := planJob(root, "job-a")
	a.DependsOn = []string{"job-ghost"}

	_, err := ValidatePlan([]Contract{a}, root, []string{"internal/**"}, 25000)
	if err == nil {
		t.Fatal("expected an error for a depends_on reference to an unknown job_id")
	}
	if !strings.Contains(err.Error(), "unknown job_id") {
		t.Fatalf("expected a dangling-reference error, got %v", err)
	}
}

func TestValidatePlanRejectsDuplicateJobID(t *testing.T) {
	root := "/repo"
	a := planJob(root, "job-a")
	dup := planJob(root, "job-a")

	_, err := ValidatePlan([]Contract{a, dup}, root, []string{"internal/**"}, 25000)
	if err == nil {
		t.Fatal("expected an error for a duplicate job_id")
	}
	if !strings.Contains(err.Error(), "duplicate job_id") {
		t.Fatalf("expected a duplicate job_id error, got %v", err)
	}
}

func TestValidatePlanRejectsWrongWorkspaceRoot(t *testing.T) {
	a := planJob("/repo", "job-a")
	a.Workspace.Root = "/somewhere-else"

	_, err := ValidatePlan([]Contract{a}, "/repo", []string{"internal/**"}, 25000)
	if err == nil {
		t.Fatal("expected an error when a job's workspace.root diverges from the plan root")
	}
	if !strings.Contains(err.Error(), "workspace.root") {
		t.Fatalf("expected a workspace.root error, got %v", err)
	}
}

func TestValidatePlanRejectsMissingRiskClass(t *testing.T) {
	a := planJob("/repo", "job-a")
	a.RiskClass = ""

	_, err := ValidatePlan([]Contract{a}, "/repo", []string{"internal/**"}, 25000)
	if err == nil {
		t.Fatal("expected an error when a job omits risk_class")
	}
	if !strings.Contains(err.Error(), "risk_class") {
		t.Fatalf("expected a risk_class error, got %v", err)
	}
}

func TestValidatePlanRejectsZeroBudgetTokens(t *testing.T) {
	a := planJob("/repo", "job-a")
	a.Budget.MaxTokens = 0

	_, err := ValidatePlan([]Contract{a}, "/repo", []string{"internal/**"}, 25000)
	if err == nil {
		t.Fatal("expected an error when a job declares no budget.max_tokens")
	}
	if !strings.Contains(err.Error(), "budget.max_tokens") {
		t.Fatalf("expected a budget.max_tokens error, got %v", err)
	}
}

func TestTopologicalLevelsParallelWithinLevelSerialAcross(t *testing.T) {
	root := "/repo"
	a := planJob(root, "a")
	b := planJob(root, "b")
	c := planJob(root, "c")
	c.DependsOn = []string{"a", "b"}

	levels, err := TopologicalLevels([]Contract{a, b, c})
	if err != nil {
		t.Fatal(err)
	}
	if len(levels) != 2 {
		t.Fatalf("expected 2 levels, got %d: %+v", len(levels), levels)
	}
	if len(levels[0]) != 2 {
		t.Fatalf("expected a and b in parallel in level 0, got %+v", levels[0])
	}
	if len(levels[1]) != 1 || levels[1][0].JobID != "c" {
		t.Fatalf("expected c alone in level 1, got %+v", levels[1])
	}
}

func TestTopologicalLevelsDetectsCycle(t *testing.T) {
	root := "/repo"
	a := planJob(root, "a")
	a.DependsOn = []string{"b"}
	b := planJob(root, "b")
	b.DependsOn = []string{"a"}

	if _, err := TopologicalLevels([]Contract{a, b}); err == nil {
		t.Fatal("expected a cycle error")
	}
}

func TestParsePlanRoundTripsAndRejectsUnknownFields(t *testing.T) {
	data := []byte(`jobs:
  - task: "x"
    job_id: job-a
    job_type: code_change
    agent: claude-code
    mode: surgeon
    workspace: {root: /repo, worktree: auto}
    allowed: {read: ["**"], write: ["internal/**"], execute: []}
    forbidden: {paths: [], commands: [], behaviors: []}
    budget: {max_minutes: 10, max_commands: 10, max_files_changed: 3, max_lines_changed: 100, max_new_files: 1, max_deleted: 0, max_tokens: 10000}
    preflight: {intended_writes: ["internal/**"]}
    success: {required_files: ["internal/x.go"], validators: ["go build ./..."]}
    on_violation: quarantine
    risk_class: low
    depends_on: []
`)
	plan, err := ParsePlan(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Jobs) != 1 || plan.Jobs[0].JobID != "job-a" || plan.Jobs[0].RiskClass != "low" {
		t.Fatalf("unexpected plan: %+v", plan)
	}

	if _, err := ParsePlan([]byte("jobs:\n  - job_id: job-a\n    bogus_field: 1\n")); err == nil {
		t.Fatal("expected strict decoding to reject an unknown field")
	}
}

func TestParsePlanRejectsLiteralSecret(t *testing.T) {
	data := []byte("jobs:\n  - task: \"use API_KEY=sk-abcdefghijklmnopqrstuvwxyz\"\n")
	if _, err := ParsePlan(data); err == nil {
		t.Fatal("expected literal-secret detection to reject the plan")
	}
}
