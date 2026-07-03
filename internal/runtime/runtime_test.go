package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
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
printf '{"status":"ok","summary":"fake","files":["output/result.txt"],"commands":[]}\n' > RESULT.json
printf '{"type":"result","secret":"sk-abcdefghijklmnopqrstuvwxyz"}\n'
if [ "$FAKE_COMMAND" = 1 ]; then printf '{"type":"tool_use","name":"Bash","input":{"command":"rm -rf /tmp/x"}}\n'; fi
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
		Budget:      contracts.Budget{MaxMinutes: 1, MaxCommands: 5, MaxFilesChanged: 5, MaxDeleted: 0},
		Success:     contracts.Success{RequiredFiles: []string{"output/result.txt"}, Validators: []string{"test -f output/result.txt"}},
		OnViolation: "quarantine",
	}
}

func TestApprovedReplayRedactionAndRollback(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
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
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CLAUDE_BIN", bin)
	t.Setenv("FAKE_COMMAND", "1")
	r, err := New().Run(context.Background(), contract(root))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "QUARANTINED" || !strings.Contains(r.Message, "forbidden command") {
		t.Fatalf("%s: %s", r.Status, r.Message)
	}
}
