package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

// networkAndScopeContract triggers two independent org-policy ASK facts at
// once: network_enabled (via an execute pattern that looks like network
// access) and write_out_of_scope (an intended write outside the declared
// read scope) — two unrelated rules, each resolvable by its own operator
// override.
func networkAndScopeContract(root string) contracts.Contract {
	c := networkContract(root)
	c.Allowed.Read = []string{"other/**"}
	return c
}

const twoAskRulesConfig = `policy_rules:
  - id: network-enablement
    when:
      - field: network_enabled
        op: eq
        value: "true"
    verdict: ASK
    reason: network access needs operator review
  - id: write-out-of-scope
    when:
      - field: write_out_of_scope
        op: eq
        value: "true"
    verdict: ASK
    reason: write target falls outside the declared read scope
`

// TestSol3OneShotApprovalSurvivesWhenAnotherRuleStillBlocks reproduces the
// audit's finding #8 exploit and proves the P1.1 fix (corpus #9): rule A is
// approved via a one-shot override while rule B still ASKs, so the run stays
// blocked. Under the pre-fix code, ClaimActivePolicyOverrides consumed rule
// A's one-shot the instant it was claimed — regardless of whether the
// overall gate decision actually unblocked — so the operator's approval was
// burned on an evaluation that authorized no execution at all, and the next
// run (even after resolving rule B too) would ASK for rule A again. This
// test drives three real runs end to end through New().Run() and asserts
// the operator's single approval for rule A is still effective once rule B
// is also resolved.
func TestSol3OneShotApprovalSurvivesWhenAnotherRuleStillBlocks(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(twoAskRulesConfig), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", cfgPath)

	c := networkAndScopeContract(root)

	// Run 1: both rules ASK -> quarantined, two pending checkpoints.
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
	if len(checkpoints) != 2 {
		t.Fatalf("expected exactly 2 pending checkpoints (network-enablement, write-out-of-scope), got %d: %+v", len(checkpoints), checkpoints)
	}
	var networkCP, scopeCP observability.PolicyCheckpoint
	for _, cp := range checkpoints {
		switch cp.Target {
		case "network-enablement":
			networkCP = cp
		case "write-out-of-scope":
			scopeCP = cp
		}
	}
	if networkCP.ID == 0 || scopeCP.ID == 0 {
		t.Fatalf("expected one checkpoint per rule, got %+v", checkpoints)
	}

	// Approve ONLY rule A (network-enablement), bare one-shot.
	if _, err := AskResolve(networkCP.ID, AskResolution{Verdict: "ALLOW", ResolvedBy: "operator", Note: "network reviewed, fine for now"}); err != nil {
		t.Fatal(err)
	}

	// Run 2: rule A resolves to ALLOW via the override, but rule B
	// (write-out-of-scope) is still unresolved and ASKs -> the whole gate
	// still blocks -> still quarantined. This is the exact moment the
	// pre-fix code would have already burned rule A's one-shot approval.
	second, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != "QUARANTINED" || second.FailureTaxonomy != policyAskPendingTaxonomy {
		t.Fatalf("expected the second run to still be blocked by the unresolved write-out-of-scope rule, got status=%s taxonomy=%s", second.Status, second.FailureTaxonomy)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatal("backend ran despite write-out-of-scope still pending — rule B must still block the whole gate")
	}

	// Now approve rule B too.
	if _, err := AskResolve(scopeCP.ID, AskResolution{Verdict: "ALLOW", ResolvedBy: "operator", Note: "scope reviewed, fine for now"}); err != nil {
		t.Fatal(err)
	}

	// Run 3: this is the corpus #9 assertion. If rule A's approval survived
	// run 2 (the fix), both rules now resolve to ALLOW and the run proceeds.
	// If rule A's approval had been silently burned during run 2 (the bug),
	// this run would ASK for network-enablement again and stay quarantined.
	third, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if third.Status != "APPROVED" {
		t.Fatalf("expected rule A's approval to have survived run 2 and the run to now proceed, got status=%s taxonomy=%s message=%s", third.Status, third.FailureTaxonomy, third.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); err != nil {
		t.Fatalf("expected the backend to actually run once both overrides were in effect: %v", err)
	}

	// Both one-shots are now genuinely spent: a fourth run (varied task, same
	// job_id/scope) must ASK again for both, not silently replay or reuse
	// either override.
	c4 := c
	c4.Task = c.Task + " (fourth attempt)"
	fourth, err := New().Run(context.Background(), c4)
	if err != nil {
		t.Fatal(err)
	}
	if fourth.Status != "QUARANTINED" || fourth.FailureTaxonomy != policyAskPendingTaxonomy {
		t.Fatalf("expected both one-shots to be consumed after the run they actually authorized, got status=%s taxonomy=%s", fourth.Status, fourth.FailureTaxonomy)
	}
	// Each evaluation records a fresh checkpoint row for any rule still
	// unresolved at that moment (unrelated pre-existing behavior — run 2
	// already left one for write-out-of-scope), so assert on the fourth
	// run's own checkpoints specifically rather than the total pending
	// count.
	remaining, err := AskList()
	if err != nil {
		t.Fatal(err)
	}
	var fourthRunTargets []string
	for _, cp := range remaining {
		if cp.RunID == fourth.ID {
			fourthRunTargets = append(fourthRunTargets, cp.Target)
		}
	}
	if len(fourthRunTargets) != 2 {
		t.Fatalf("expected the fourth run to ASK fresh for both now-consumed rules (network-enablement, write-out-of-scope), got %v (all pending: %+v)", fourthRunTargets, remaining)
	}
}
