package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/policy"
	"github.com/cousingary/governator/internal/prompts"
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

// TestEvaluatePolicyGateOrgRuleAppearsExactlyOnce is the P1-4 triage
// regression test (Sol redteam v4, S0): Sol suspected cfg.PolicyRules might
// be evaluated twice — once at policy_gate.go:120 (evaluatePolicyGate's
// SourceOrgPolicy layer) and once via preflight.go's SourceOrgPolicy-tagged
// heuristic denials. The findings log
// (agents/governator-sol-upgrade4-findings.md) records the triage verdict:
// false positive — Preflight never reads cfg.PolicyRules at all; its
// SourceOrgPolicy denials come from hardcoded contract-shape heuristics
// (destructive Allowed.Execute entries, oversized write envelopes), a
// disjoint rule set on a disjoint code path (Preflight runs once, before
// evaluatePolicyGate, and a Preflight refusal never reaches evaluatePolicyGate
// at all — it aborts Run with an error before the lock/quota/policy-gate
// stage). This test proves both halves: a configured org rule's DENY reason
// appears exactly once in the quarantine message (never duplicated by a
// second read of cfg.PolicyRules), and Preflight's own heuristic DENY fires
// with cfg.PolicyRules completely unset.
func TestEvaluatePolicyGateOrgRuleAppearsExactlyOnce(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	const reason = "surgeon mode blocked for this test"
	if err := os.WriteFile(cfgPath, []byte(`policy_rules:
  - id: surgeon-mode-test-marker
    when:
      - field: mode
        op: eq
        value: surgeon
    verdict: DENY
    reason: `+reason+`
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", cfgPath)

	c := contract(root)
	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" || rec.FailureTaxonomy != policyDeniedTaxonomy {
		t.Fatalf("expected a terminal policy DENY quarantine, got status=%s taxonomy=%s message=%s", rec.Status, rec.FailureTaxonomy, rec.Message)
	}
	if n := strings.Count(rec.Message, reason); n != 1 {
		t.Fatalf("org policy rule reason must appear exactly once (cfg.PolicyRules evaluated exactly once), appeared %d times in message=%q", n, rec.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatal("backend ran despite a terminal policy DENY")
	}
}

// TestPreflightOrgDenialIndependentOfConfiguredPolicyRules proves the other
// half of the P1-4 triage: Preflight's SourceOrgPolicy-tagged destructive-
// command denial fires with cfg.PolicyRules completely unset — it is a
// hardcoded contract-shape heuristic, not a read of the configured rule
// set. A Preflight refusal aborts Run with an error, never a QUARANTINED
// RunRecord, confirming it is a wholly separate code path from
// evaluatePolicyGate (which produces QUARANTINED/policyDeniedTaxonomy).
func TestPreflightOrgDenialIndependentOfConfiguredPolicyRules(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	c := contract(root)
	c.Allowed.Execute = append([]string{}, c.Allowed.Execute...)
	c.Allowed.Execute = append(c.Allowed.Execute, "rm -rf /some/path")

	_, err := New().Run(context.Background(), c)
	if err == nil {
		t.Fatal("expected Preflight to refuse a destructive allowed.execute entry even with no org policy_rules configured")
	}
	if !strings.Contains(err.Error(), "destructive command allowed") {
		t.Fatalf("expected Preflight's destructive-command heuristic, got: %v", err)
	}
}

// TestPolicyBundleSharedBetweenGateAndIdentityIgnoresLaterDoctrineEdit is Sol
// P1-3's regression test. Before the fix, evaluatePolicyGate and
// computeExecutionIdentity each independently called
// policy.LoadProjectDoctrine at two different points during a single
// runOnce attempt, separated by spend/quota reservation, prompt resolution
// and handle resolution — a doctrine file edited in that window meant the
// recorded ExecutionIdentity described a different doctrine than the one the
// policy gate actually evaluated against. Proves the fix: a PolicyBundle
// loaded once and passed to both keeps the identity's ProjectDoctrineHash
// locked to what the gate saw. Also proves the file edit itself IS real and
// would be picked up by an independent load — so this isn't passing because
// the edit silently failed to land.
func TestPolicyBundleSharedBetweenGateAndIdentityIgnoresLaterDoctrineEdit(t *testing.T) {
	root := t.TempDir()
	doctrinePath := filepath.Join(root, policy.ProjectDoctrineFilename)
	original := []byte(`policy_rules:
  - id: doctrine-v1
    when:
      - field: network_enabled
        op: eq
        value: "true"
    verdict: ASK
    reason: v1
`)
	if err := os.WriteFile(doctrinePath, original, 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.BuiltIn()
	c := contract(root)

	bundleAtGateTime, err := loadPolicyBundle(cfg, c, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundleAtGateTime.ProjectRules) != 1 || bundleAtGateTime.ProjectRules[0].ID != "doctrine-v1" {
		t.Fatalf("expected the v1 doctrine rule in the loaded bundle, got %+v", bundleAtGateTime.ProjectRules)
	}

	// Simulate a doctrine edit landing during the pre-launch work that
	// separates the gate call from computeExecutionIdentity in runOnce.
	mutated := []byte(`policy_rules:
  - id: doctrine-v2
    when:
      - field: network_enabled
        op: eq
        value: "true"
    verdict: DENY
    reason: v2
`)
	if err := os.WriteFile(doctrinePath, mutated, 0644); err != nil {
		t.Fatal(err)
	}

	// The edit is real and would be visible to a fresh, independent load —
	// this is exactly what the pre-fix code did, and is the mechanism of the
	// bug this test guards against.
	bundleAfterEdit, err := loadPolicyBundle(cfg, c, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundleAfterEdit.ProjectRules) != 1 || bundleAfterEdit.ProjectRules[0].ID != "doctrine-v2" {
		t.Fatalf("expected the doctrine edit to be visible to a fresh load, got %+v", bundleAfterEdit.ProjectRules)
	}

	agent, err := agents.New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	pv := prompts.Version{ID: "builtin"}
	res, err := agents.ResolvePath(agent)
	if err != nil {
		t.Fatal(err)
	}

	// computeExecutionIdentity is called with bundleAtGateTime — the SAME
	// object a gate call would already have evaluated against — never a
	// fresh load. Its ProjectDoctrineHash must reflect v1, not the v2 that is
	// now on disk.
	identity := computeExecutionIdentity(cfg, c, agent, res, agents.BackendIdentity{}, nil, "", "dead", "ch", pv, "attest-1", bundleAtGateTime, containment.ContainmentEnvironment{})
	if identity.ProjectDoctrineHash != hashJSON(bundleAtGateTime.ProjectRules) {
		t.Fatal("identity's project doctrine hash did not match the bundle it was given")
	}
	if identity.ProjectDoctrineHash == hashJSON(bundleAfterEdit.ProjectRules) {
		t.Fatal("identity's project doctrine hash matched the POST-edit doctrine — computeExecutionIdentity re-read the file instead of using the shared bundle")
	}
}
