package policy

import (
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
)

func TestCleanupDoctrineIssueAppliesOnlyToCodeWritingModes(t *testing.T) {
	applies := []contracts.Mode{contracts.ModeSurgeon, contracts.ModeBatchWorker, contracts.ModeRepair}
	exempt := []contracts.Mode{contracts.ModeScout, contracts.ModeVerifier, contracts.ModeArchitect, contracts.ModePlanner}
	for _, m := range applies {
		if !CleanupDoctrineApplies(m) {
			t.Fatalf("%s: expected cleanup doctrine to apply", m)
		}
	}
	for _, m := range exempt {
		if CleanupDoctrineApplies(m) {
			t.Fatalf("%s: expected cleanup doctrine to be exempt", m)
		}
	}
}

func TestCleanupDoctrineIssueFlagsMissingCleanupCoverage(t *testing.T) {
	c := contracts.Contract{
		JobID: "surgeon-job", Mode: contracts.ModeSurgeon,
		Success: contracts.Success{Validators: []string{"go test ./..."}},
	}
	issue := CleanupDoctrineIssue(c)
	if issue == "" || !strings.Contains(issue, "surgeon-job") {
		t.Fatalf("expected a doctrine issue naming the job, got %q", issue)
	}
}

func TestCleanupDoctrineIssueSatisfiedByCleanupBlock(t *testing.T) {
	c := contracts.Contract{
		JobID: "surgeon-job", Mode: contracts.ModeSurgeon,
		Success: contracts.Success{Validators: []string{"go test ./..."}},
		Cleanup: &contracts.Cleanup{Validators: []string{"gofmt -l ."}},
	}
	if issue := CleanupDoctrineIssue(c); issue != "" {
		t.Fatalf("expected no issue with an explicit cleanup block, got %q", issue)
	}
}

func TestCleanupDoctrineIssueSatisfiedByLintValidator(t *testing.T) {
	cases := []string{
		"gofmt -l .",
		"go vet ./...",
		"eslint .",
		"npx prettier --check .",
		"golangci-lint run",
		"black --check .",
	}
	for _, v := range cases {
		c := contracts.Contract{
			JobID: "surgeon-job", Mode: contracts.ModeSurgeon,
			Success: contracts.Success{Validators: []string{"go test ./...", v}},
		}
		if issue := CleanupDoctrineIssue(c); issue != "" {
			t.Fatalf("validator %q: expected no issue, got %q", v, issue)
		}
	}
}

func TestCleanupDoctrineIssueExemptModesNeverFlagged(t *testing.T) {
	for _, m := range []contracts.Mode{contracts.ModeScout, contracts.ModeVerifier, contracts.ModeArchitect, contracts.ModePlanner} {
		c := contracts.Contract{JobID: "j", Mode: m, Success: contracts.Success{Validators: []string{"go test ./..."}}}
		if issue := CleanupDoctrineIssue(c); issue != "" {
			t.Fatalf("%s: expected exempt mode to never be flagged, got %q", m, issue)
		}
	}
}
