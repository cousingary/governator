package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func fixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	git(t, root, "init", "-b", "main")
	git(t, root, "config", "user.email", "test@example.invalid")
	git(t, root, "config", "user.name", "Governator Test")
	if err := os.WriteFile(filepath.Join(root, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", ".")
	git(t, root, "commit", "-m", "seed")
	bin := filepath.Join(t.TempDir(), "fake-claude")
	s := `#!/bin/sh
mkdir -p output
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","secret":"sk-abcdefghijklmnopqrstuvwxyz","total_cost_usd":0.25}\n'
if [ "$FAKE_ALLOWED_COMMAND" = 1 ]; then printf '{"type":"tool_use","name":"Bash","input":{"command":"test"}}\n'; fi
if [ "$FAKE_COMMAND" = 1 ]; then printf '{"type":"tool_use","name":"Bash","input":{"command":"rm -rf /tmp/x"}}\n'; fi
if [ "$FAKE_TRIPWIRE" = 1 ]; then printf '{"type":"assistant","text":"I should inspect the broader project."}\n'; fi
if [ "$FAKE_CANARY" = 1 ]; then chmod 600 .governator-canary; printf 'mutated\n' > .governator-canary; fi
if [ "$FAKE_BIG" = 1 ]; then printf '1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n' > output/result.txt; fi
if [ "$FAKE_SCOPE" = 1 ]; then printf 'drift\n' > output/extra.txt; fi
if [ "$FAKE_LEAK" = 1 ]; then printf 'leak\n' > "$FAKE_LIVE_ROOT/leak.txt"; fi
`
	if err := os.WriteFile(bin, []byte(s), 0755); err != nil {
		t.Fatal(err)
	}
	return root, bin
}

func contract(root string) contracts.Contract {
	return contracts.Contract{
		Task: "write deterministic test output", JobID: "phase1-test", JobType: "test", Agent: "claude-code", Mode: contracts.ModeSurgeon,
		Workspace:   contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:     contracts.Permissions{Read: []string{"**"}, Write: []string{"output/**"}, Execute: []string{"test"}},
		Forbidden:   contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}, Behaviors: []string{"network"}},
		Budget:      contracts.Budget{MaxMinutes: 1, MaxCommands: 5, MaxFilesChanged: 5, MaxLinesChanged: 20, MaxNewFiles: 2, MaxDeleted: 0},
		Preflight:   contracts.Preflight{IntendedWrites: []string{"output/**"}},
		Success:     contracts.Success{RequiredFiles: []string{"output/result.txt"}, Validators: []string{"test -f output/result.txt"}},
		OnViolation: "quarantine",
	}
}

func TestApprovedReplayRedactionAndRollback(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_ALLOWED_COMMAND", "1")
	r, err := New().Run(context.Background(), contract(root))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "APPROVED" {
		t.Fatalf("%s: %s", r.Status, r.Message)
	}
	if !r.ValidOutput || r.CostUSD != 0.25 {
		t.Fatalf("unexpected output metrics: valid=%v cost=%v", r.ValidOutput, r.CostUSD)
	}
	if r.SelfReview == nil || r.SelfReview.Status != "complete" {
		t.Fatalf("structured self-review missing: %#v", r.SelfReview)
	}
	scores, err := observability.ScoreAgents(home, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(scores) != 1 || scores[0].Runs != 1 || scores[0].ValidOutputs != 1 || scores[0].CostPerValidUSD != 0.25 {
		t.Fatalf("unexpected score: %#v", scores)
	}
	cost, err := observability.CostPerValidOutput(home)
	if err != nil {
		t.Fatal(err)
	}
	if cost.Runs != 1 || cost.ValidOutputs != 1 || cost.CostPerValidUSD != 0.25 {
		t.Fatalf("unexpected cost summary: %#v", cost)
	}
	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for table, want := range map[string]int{"jobs": 1, "agents": 1, "files_touched": 2, "commands_run": 1} {
		var got int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s count: got %d want %d", table, got, want)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(r.Transcript)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "sk-") {
		t.Fatal("transcript retained secret")
	}
	replay, err := New().Run(context.Background(), contract(root))
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed {
		t.Fatal("replay flag was false")
	}
	if replay.ID != r.ID {
		t.Fatalf("expected replay %s, got %s", r.ID, replay.ID)
	}
	rolled, err := Rollback(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Status != "ROLLED_BACK" {
		t.Fatal(rolled.Status)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatalf("rollback left output: %v", err)
	}
}

func TestCageLeakIsQuarantined(t *testing.T) {
	root, bin := fixture(t)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_LEAK", "1")
	t.Setenv("FAKE_LIVE_ROOT", root)
	r, err := New().Run(context.Background(), contract(root))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || !strings.Contains(r.Message, "out-of-worktree mutation") {
		t.Fatalf("%s: %s", r.Status, r.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatalf("quarantined work merged: %v", err)
	}
}

func TestProtectedPathLeakIsQuarantined(t *testing.T) {
	root, bin := fixture(t)
	protected := t.TempDir()
	manifest := filepath.Join(t.TempDir(), "protected_paths.txt")
	if err := os.WriteFile(manifest, []byte(filepath.Join(protected, "leak.txt")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("GOV_PROTECTED_PATHS", manifest)
	t.Setenv("FAKE_LEAK", "1")
	t.Setenv("FAKE_LIVE_ROOT", protected)
	r, err := New().Run(context.Background(), contract(root))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || !strings.Contains(r.Message, "protected path mutation") {
		t.Fatalf("%s: %s", r.Status, r.Message)
	}
}

func TestNonGitRecallRollback(t *testing.T) {
	_, bin := fixture(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)
	r, err := New().Run(context.Background(), contract(root))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "APPROVED" {
		t.Fatalf("%s: %s", r.Status, r.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); err != nil {
		t.Fatal(err)
	}
	rolled, err := Rollback(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Status != "ROLLED_BACK" {
		t.Fatal(rolled.Status)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatalf("rollback left output: %v", err)
	}
}

func TestForbiddenCommandTranscriptIsQuarantined(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_COMMAND", "1")
	r, err := New().Run(context.Background(), contract(root))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || !strings.Contains(r.Message, "forbidden command") {
		t.Fatalf("%s: %s", r.Status, r.Message)
	}
	if r.FailureTaxonomy != "DESTRUCTIVE_COMMAND" {
		t.Fatalf("unexpected taxonomy: %s", r.FailureTaxonomy)
	}
	failures, err := observability.Failures(home, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 1 || failures[0].Taxonomy != "DESTRUCTIVE_COMMAND" {
		t.Fatalf("unexpected failures: %#v", failures)
	}
}

func TestCanaryMutationIsQuarantined(t *testing.T) {
	root, bin := fixture(t)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_CANARY", "1")
	r, err := New().Run(context.Background(), contract(root))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || !strings.Contains(r.Message, "canary mutation") {
		t.Fatalf("%s: %s", r.Status, r.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatalf("quarantined work merged: %v", err)
	}
}

func TestScopeExpansionTripwireIsQuarantined(t *testing.T) {
	root, bin := fixture(t)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_TRIPWIRE", "1")
	r, err := New().Run(context.Background(), contract(root))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || !strings.Contains(r.Message, "scope-expansion tripwire") {
		t.Fatalf("%s: %s", r.Status, r.Message)
	}
}

func TestDiffLineBudgetOverflowIsQuarantined(t *testing.T) {
	root, bin := fixture(t)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_BIG", "1")
	c := contract(root)
	c.Budget.MaxLinesChanged = 5
	r, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || !strings.Contains(r.Message, "max_lines_changed exceeded") {
		t.Fatalf("%s: %s", r.Status, r.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatalf("budget overflow merged: %v", err)
	}
}

func TestNewFileBudgetOverflowIsQuarantined(t *testing.T) {
	root, bin := fixture(t)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)
	c := contract(root)
	c.Budget.MaxNewFiles = 1
	r, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || !strings.Contains(r.Message, "max_new_files exceeded") {
		t.Fatalf("%s: %s", r.Status, r.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatalf("new-file budget overflow merged: %v", err)
	}
}

func TestWriteOutsideIntendedScopeIsQuarantined(t *testing.T) {
	root, bin := fixture(t)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_SCOPE", "1")
	c := contract(root)
	c.Preflight.IntendedWrites = []string{"output/result.txt"}
	c.Budget.MaxNewFiles = 3
	r, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || !strings.Contains(r.Message, "write outside intended_writes") {
		t.Fatalf("%s: %s", r.Status, r.Message)
	}
}
