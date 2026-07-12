package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

func networkContract(root string) contracts.Contract {
	c := contract(root)
	c.Allowed.Execute = append([]string{}, c.Allowed.Execute...)
	c.Allowed.Execute = append(c.Allowed.Execute, "curl https://example.com")
	return c
}

func TestPolicyGateOrgAskQuarantinesBeforeLaunchAndRecordsCheckpoint(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`policy_rules:
  - id: network-enablement
    when:
      - field: network_enabled
        op: eq
        value: "true"
    verdict: ASK
    reason: network access needs operator review
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", cfgPath)

	rec, err := New().Run(context.Background(), networkContract(root))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" || rec.FailureTaxonomy != policyAskPendingTaxonomy {
		t.Fatalf("expected a policy ASK quarantine, got status=%s taxonomy=%s message=%s", rec.Status, rec.FailureTaxonomy, rec.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatal("backend ran despite a pending policy ASK")
	}

	checkpoints, err := AskList()
	if err != nil {
		t.Fatal(err)
	}
	if len(checkpoints) != 1 || checkpoints[0].Target != "network-enablement" || checkpoints[0].JobID != networkContract(root).JobID {
		t.Fatalf("expected exactly 1 pending checkpoint for network-enablement, got %+v", checkpoints)
	}
}

func TestPolicyGateApprovedOverrideLetsSubsequentRunProceed(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`policy_rules:
  - id: network-enablement
    when:
      - field: network_enabled
        op: eq
        value: "true"
    verdict: ASK
    reason: network access needs operator review
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", cfgPath)

	c := networkContract(root)
	first, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "QUARANTINED" || first.FailureTaxonomy != policyAskPendingTaxonomy {
		t.Fatalf("expected the first run to pause on a policy ASK, got status=%s taxonomy=%s", first.Status, first.FailureTaxonomy)
	}

	checkpoints, err := AskList()
	if err != nil {
		t.Fatal(err)
	}
	if len(checkpoints) != 1 {
		t.Fatalf("expected exactly 1 pending checkpoint, got %d", len(checkpoints))
	}

	if _, err := AskResolve(checkpoints[0].ID, AskResolution{Verdict: "ALLOW", ResolvedBy: "operator", Note: "reviewed, fine", CreateRule: true}); err != nil {
		t.Fatal(err)
	}

	second, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != "APPROVED" {
		t.Fatalf("expected the re-run to proceed past the now-overridden ASK, got status=%s taxonomy=%s message=%s", second.Status, second.FailureTaxonomy, second.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); err != nil {
		t.Fatalf("expected the backend to actually run once the override was in place: %v", err)
	}
}

func TestPolicyGateContractLevelDenyQuarantinesWithoutCheckpoint(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	c := networkContract(root)
	c.Policy = &contracts.Policy{Rules: []contracts.PolicyRuleSpec{
		{ID: "no-network-ever", When: []contracts.PolicyConditionSpec{{Field: "network_enabled", Op: "eq", Value: "true"}},
			Verdict: "DENY", Reason: "this job must never touch the network"},
	}}

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" || rec.FailureTaxonomy != policyDeniedTaxonomy {
		t.Fatalf("expected a terminal policy DENY quarantine, got status=%s taxonomy=%s", rec.Status, rec.FailureTaxonomy)
	}

	checkpoints, err := AskList()
	if err != nil {
		t.Fatal(err)
	}
	if len(checkpoints) != 0 {
		t.Fatalf("a DENY must never create a checkpoint (nothing to ask), got %+v", checkpoints)
	}
}

func TestFallbackEligibleConsultsPolicyGateForUnusualInfraFailure(t *testing.T) {
	root, _ := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`policy_rules:
  - id: unusual-infra-fallback
    when:
      - field: unusual_infra_retry
        op: eq
        value: "true"
    verdict: DENY
    reason: do not auto-retry after a binary-missing failure
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", cfgPath)
	_ = config.Current()

	r := New()
	c := contract(root)
	rec := RunRecord{
		ID: "run-1", Agent: "claude-code", FailureTaxonomy: observability.InfraBinaryMissing,
		Notes: "fallback_worktree_unchanged", Created: time.Now().UTC().Format(time.RFC3339Nano),
	}
	eligible, _, err := r.fallbackEligible(c, rec)
	if err != nil {
		t.Fatal(err)
	}
	if eligible {
		t.Fatal("expected the org DENY rule to suppress auto-fallback for an unusual infra failure")
	}
}

func TestFallbackEligibleSkipsPolicyGateForRoutineInfraFailure(t *testing.T) {
	root, _ := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`policy_rules:
  - id: unusual-infra-fallback
    when:
      - field: unusual_infra_retry
        op: eq
        value: "true"
    verdict: DENY
    reason: do not auto-retry after a binary-missing failure
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", cfgPath)

	r := New()
	c := contract(root)
	rec := RunRecord{
		ID: "run-1", Agent: "claude-code", FailureTaxonomy: observability.InfraRateLimit,
		Notes: "fallback_worktree_unchanged", Created: time.Now().UTC().Format(time.RFC3339Nano),
	}
	eligible, _, err := r.fallbackEligible(c, rec)
	if err != nil {
		t.Fatal(err)
	}
	if !eligible {
		t.Fatal("expected routine RATE_LIMIT fallback to stay unattended (never consults the policy gate)")
	}
}

func TestPolicyGateBareApproveUnblocksExactlyOnce(t *testing.T) {
	// The "approve once" contract (plan Session 5 item 3): a bare `gov ask
	// approve` (no --rule) must actually let the NEXT run of the job proceed
	// — before this worked, only --rule ever unblocked anything and a bare
	// approve was a silent no-op (the re-run just re-ASKed) — and must
	// authorize exactly ONE run: the one-shot override is consumed by the
	// evaluation it unblocks, so a third run pauses on a fresh checkpoint.
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`policy_rules:
  - id: network-enablement
    when:
      - field: network_enabled
        op: eq
        value: "true"
    verdict: ASK
    reason: network access needs operator review
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", cfgPath)

	c := networkContract(root)
	first, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "QUARANTINED" || first.FailureTaxonomy != policyAskPendingTaxonomy {
		t.Fatalf("expected the first run to pause on a policy ASK, got status=%s taxonomy=%s", first.Status, first.FailureTaxonomy)
	}
	checkpoints, err := AskList()
	if err != nil {
		t.Fatal(err)
	}
	if len(checkpoints) != 1 {
		t.Fatalf("expected exactly 1 pending checkpoint, got %d", len(checkpoints))
	}

	// Bare approve: no --rule, no TTL.
	if _, err := AskResolve(checkpoints[0].ID, AskResolution{Verdict: "ALLOW", ResolvedBy: "operator", Note: "this once"}); err != nil {
		t.Fatal(err)
	}

	second, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != "APPROVED" {
		t.Fatalf("bare approve must unblock the re-run, got status=%s taxonomy=%s message=%s", second.Status, second.FailureTaxonomy, second.Message)
	}

	// Vary the task so the third run isn't served by the "already approved
	// this exact contract at this head" memoization — the point is that the
	// policy gate itself, when re-evaluated, no longer sees the consumed
	// one-shot. Same job_id, so the override scope is identical.
	c3 := c
	c3.Task = c.Task + " (third attempt)"
	third, err := New().Run(context.Background(), c3)
	if err != nil {
		t.Fatal(err)
	}
	if third.Status != "QUARANTINED" || third.FailureTaxonomy != policyAskPendingTaxonomy {
		t.Fatalf("the one-shot must be consumed after one run — third run should ASK again, got status=%s taxonomy=%s", third.Status, third.FailureTaxonomy)
	}
	remaining, err := AskList()
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected a fresh pending checkpoint from the third run, got %d", len(remaining))
	}
}
