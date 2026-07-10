package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

func TestPostRunValidatePassingApprovesNormally(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)

	c := contract(root)
	called := false
	c.PostRunValidate = func(worktree string) error {
		called = true
		if _, err := os.Stat(filepath.Join(worktree, "output", "result.txt")); err != nil {
			t.Fatalf("expected PostRunValidate to see the worktree before merge: %v", err)
		}
		return nil
	}

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expected PostRunValidate to run")
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED, got status=%s message=%s", rec.Status, rec.Message)
	}
}

func TestPostRunValidateFailingQuarantinesBeforeMerge(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)

	c := contract(root)
	c.PostRunValidate = func(worktree string) error {
		return fmt.Errorf("manifest failed structural checks")
	}

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected QUARANTINED, got status=%s", rec.Status)
	}
	if !strings.Contains(rec.Message, "manifest failed structural checks") {
		t.Fatalf("expected the PostRunValidate error in the quarantine message, got %q", rec.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected no merge into the live root when PostRunValidate fails, stat err=%v", err)
	}
}

func TestRunBatchOrderedRunsLevelsSeriallyAndParallelWithin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	_, bin := fixture(t)
	t.Setenv("GOV_CLAUDE_BIN", bin)

	rootA, _ := fixture(t)
	rootB, _ := fixture(t)
	rootC, _ := fixture(t)
	a := contract(rootA)
	a.JobID = "ordered-a"
	b := contract(rootB)
	b.JobID = "ordered-b"
	c := contract(rootC)
	c.JobID = "ordered-c"
	c.DependsOn = []string{"ordered-a", "ordered-b"}

	levels := [][]contracts.Contract{{a, b}, {c}}
	summary, err := New().RunBatchOrdered(context.Background(), levels, BatchOptions{Parallel: 2})
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
	// Jobs are flattened in level order: level 0 (a, b) before level 1 (c).
	if summary.Jobs[len(summary.Jobs)-1].JobID != "ordered-c" {
		t.Fatalf("expected the dependent job last in the flattened result, got %+v", summary.Jobs)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var levelARun, levelCRun struct{ Created string }
	if err := db.QueryRow(`SELECT created FROM runs WHERE job_id='ordered-a'`).Scan(&levelARun.Created); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT created FROM runs WHERE job_id='ordered-c'`).Scan(&levelCRun.Created); err != nil {
		t.Fatal(err)
	}
	if levelCRun.Created < levelARun.Created {
		t.Fatalf("expected the dependent job's run to start after level 0 finished: a=%s c=%s", levelARun.Created, levelCRun.Created)
	}
	var batchRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM batches`).Scan(&batchRows); err != nil {
		t.Fatal(err)
	}
	if batchRows != 2 {
		t.Fatalf("expected one batch ledger row per level (2), got %d", batchRows)
	}
}

func TestRunBatchOrderedHaltPropagatesAcrossLevels(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	failRoot, bin := failingFixture(t)
	seedFailure(t, failRoot)
	t.Setenv("GOV_CLAUDE_BIN", bin)

	okRoot, _ := fixture(t)
	a := contract(failRoot)
	a.JobID = "halt-level0-fails"
	b := contract(okRoot)
	b.JobID = "halt-level1-should-skip"
	b.DependsOn = []string{"halt-level0-fails"}

	levels := [][]contracts.Contract{{a}, {b}}
	summary, err := New().RunBatchOrdered(context.Background(), levels, BatchOptions{Parallel: 1, HaltOnFirstQuarantine: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Jobs) != 2 {
		t.Fatalf("expected 2 job results, got %d", len(summary.Jobs))
	}
	if summary.Jobs[0].Status != "QUARANTINED" {
		t.Fatalf("expected level 0 job quarantined, got %+v", summary.Jobs[0])
	}
	if summary.Jobs[1].Status != "SKIPPED" || summary.Jobs[1].RunID != "" {
		t.Fatalf("expected level 1 job skipped without launching after the halt, got %+v", summary.Jobs[1])
	}
	if summary.Quarantined != 1 {
		t.Fatalf("expected 1 quarantined job, got %d", summary.Quarantined)
	}
}
