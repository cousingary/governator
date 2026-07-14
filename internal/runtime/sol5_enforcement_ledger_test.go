package runtime

import (
	"context"
	"testing"

	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/observability"
)

// TestSol5EnforcementLedgerRecordsExternalObservation is the P0-3/P1-15
// effect-ledger acceptance check: a high-risk local run that actually goes
// through Governator's own externally enforced sandbox must leave behind
// independently observed evidence of that -- which enforcement method ran,
// whether the network was namespaced away, and how many processes the
// kernel's own cgroup accounting saw -- not just whatever the backend's own
// transcript happened to claim.
func TestSol5EnforcementLedgerRecordsExternalObservation(t *testing.T) {
	if !enforce.Supported() {
		t.Skip("this host cannot provide external enforcement (Landlock/unshare unavailable)")
	}
	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()

	root, _ := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	bin := writeFakeBackend(t, `if [ "${1:-}" = "--version" ]; then echo "claude-code fake 1.0"; exit 0; fi
mkdir -p output
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	c := contract(root)
	c.RiskClass = "high"

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED, got status=%s message=%s", rec.Status, rec.Message)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	enf, ok, err := observability.EnforcementForRun(db, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected an enforcement_events row for a high-risk local run that went through external enforcement")
	}
	if enf.Method != "landlock+netns" {
		t.Fatalf("expected landlock+netns (contract forbids network), got %q", enf.Method)
	}
	if !enf.NetworkNamespaced {
		t.Fatal("expected NetworkNamespaced=true (contract forbids network)")
	}
	if enf.ProcessesObservedPeak < 0 {
		t.Fatalf("expected a non-negative kernel-observed process count, got %d", enf.ProcessesObservedPeak)
	}
}
