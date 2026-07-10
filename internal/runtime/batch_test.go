package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

// failingFixture is like fixture() but the fake backend fails (leaves
// output/result.txt missing, quarantining the run) whenever a ".fail-me"
// file is present in the worktree — letting one shared binary drive
// per-job pass/fail behavior via what's committed into each job's own repo,
// which is the only thing that differs between jobs running concurrently in
// the same test process (env vars are process-global, so they can't be used
// to make one concurrent job fail and another succeed).
func failingFixture(t *testing.T) (string, string) {
	t.Helper()
	root, _ := fixture(t)
	bin := filepath.Join(t.TempDir(), "fake-claude-batch")
	s := `#!/bin/sh
mkdir -p output
printf '{"type":"result","total_cost_usd":0.25}\n'
if [ -f .fail-me ]; then exit 0; fi
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
`
	if err := os.WriteFile(bin, []byte(s), 0755); err != nil {
		t.Fatal(err)
	}
	return root, bin
}

func seedFailure(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".fail-me"), []byte("1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", ".fail-me")
	git(t, root, "commit", "-m", "seed failure")
}

func TestRunBatchThreeJobsInParallelProduceAttributedLedgerRuns(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	_, bin := fixture(t)
	t.Setenv("GOV_CLAUDE_BIN", bin)

	var jobs []contracts.Contract
	for i := 0; i < 3; i++ {
		root, _ := fixture(t)
		c := contract(root)
		c.JobID = fmt.Sprintf("batch-job-%d", i)
		jobs = append(jobs, c)
	}

	summary, err := New().RunBatch(context.Background(), jobs, BatchOptions{Parallel: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Jobs) != 3 {
		t.Fatalf("expected 3 job results, got %d: %+v", len(summary.Jobs), summary.Jobs)
	}
	for _, j := range summary.Jobs {
		if j.Status != "APPROVED" {
			t.Fatalf("job %s: expected APPROVED, got %s (%s)", j.JobID, j.Status, j.Error)
		}
	}
	if summary.Quarantined != 0 {
		t.Fatalf("expected 0 quarantined, got %d", summary.Quarantined)
	}
	if summary.TotalCostUSD != 0.75 {
		t.Fatalf("expected total cost 0.75, got %v", summary.TotalCostUSD)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var runCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM runs WHERE status='APPROVED'`).Scan(&runCount); err != nil {
		t.Fatal(err)
	}
	if runCount != 3 {
		t.Fatalf("expected 3 approved runs in the ledger, got %d", runCount)
	}
	b, err := observability.BatchByID(db, summary.BatchID)
	if err != nil {
		t.Fatal(err)
	}
	if b.Jobs != 3 || b.Quarantined != 0 || b.TotalCostUSD != 0.75 || b.Finished == "" {
		t.Fatalf("unexpected batch row: %+v", b)
	}
}

func TestRunBatchBudgetExhaustionMidBatchSkipsLaterJobs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	t.Setenv("GOV_SPEND_DAILY_CAP_USD", "0.30")
	_, bin := fixture(t)
	t.Setenv("GOV_CLAUDE_BIN", bin)

	var jobs []contracts.Contract
	for i := 0; i < 3; i++ {
		root, _ := fixture(t)
		c := contract(root)
		c.JobID = fmt.Sprintf("cap-job-%d", i)
		jobs = append(jobs, c)
	}

	// Parallel:1 keeps dispatch order deterministic: each job's own $0.25
	// flat estimate (no budget.max_tokens set) is reserved before it runs,
	// so job 1 fits under the $0.30 cap but jobs 2 and 3 don't once job 1's
	// real cost has settled.
	summary, err := New().RunBatch(context.Background(), jobs, BatchOptions{Parallel: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Jobs) != 3 {
		t.Fatalf("expected 3 job results, got %d", len(summary.Jobs))
	}
	if summary.Jobs[0].Status != "APPROVED" {
		t.Fatalf("expected job 0 approved before the cap was hit, got %+v", summary.Jobs[0])
	}
	for _, j := range summary.Jobs[1:] {
		if j.Status != "SKIPPED" || j.Taxonomy != "SPEND_CAP" {
			t.Fatalf("expected later jobs skipped on SPEND_CAP, got %+v", j)
		}
		if j.RunID != "" {
			t.Fatalf("a skipped job must never have launched a run: %+v", j)
		}
	}
	if summary.TotalCostUSD != 0.25 {
		t.Fatalf("expected total cost 0.25 (only job 0 ran), got %v", summary.TotalCostUSD)
	}
}

func TestRunBatchHaltOnFirstQuarantineSkipsLaterJobs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	failRoot, bin := failingFixture(t)
	seedFailure(t, failRoot)
	t.Setenv("GOV_CLAUDE_BIN", bin)

	okRoot1, _ := fixture(t)
	okRoot2, _ := fixture(t)

	c0 := contract(failRoot)
	c0.JobID = "halt-job-0-fails"
	c1 := contract(okRoot1)
	c1.JobID = "halt-job-1-should-skip"
	c2 := contract(okRoot2)
	c2.JobID = "halt-job-2-should-skip"

	// Parallel:1 makes halt-on-first-quarantine deterministic: a single
	// worker processes jobs strictly in order, so job 0's quarantine is
	// fully settled (including the halted flag) before job 1 is dequeued.
	summary, err := New().RunBatch(context.Background(), []contracts.Contract{c0, c1, c2}, BatchOptions{
		Parallel: 1, HaltOnFirstQuarantine: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Jobs) != 3 {
		t.Fatalf("expected 3 job results, got %d", len(summary.Jobs))
	}
	if summary.Jobs[0].Status != "QUARANTINED" {
		t.Fatalf("expected job 0 quarantined, got %+v", summary.Jobs[0])
	}
	for _, j := range summary.Jobs[1:] {
		if j.Status != "SKIPPED" {
			t.Fatalf("expected job skipped after the halt, got %+v", j)
		}
	}
	if summary.Quarantined != 1 {
		t.Fatalf("expected 1 quarantined job, got %d", summary.Quarantined)
	}
}
