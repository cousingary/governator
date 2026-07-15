package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/enforce"
)

// TestSol3MediumEffectfulLocalDeniedBeforeLaunch: Session 5 (Sol P0-3) moved
// "local" containment authorization onto Governator's own externally
// enforced sandbox (enforce.Supported()), not the backend's declared native
// sandbox -- glm alone no longer denies this on a host that can actually
// provide external enforcement, so the denial this test checks now needs
// ForceUnsupported to construct the "this host cannot provide it" case.
func TestSol3MediumEffectfulLocalDeniedBeforeLaunch(t *testing.T) {
	root, _ := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	external := filepath.Join(t.TempDir(), "external-target")
	if err := os.WriteFile(external, []byte("safe\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c := contract(root)
	c.JobID = "sol3-medium-local-denied"
	c.Agent = "glm"
	c.RiskClass = "medium"

	enforce.ForceUnsupported = true
	defer func() { enforce.ForceUnsupported = false }()
	_, err := New().Run(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "risk_class \"medium\"") {
		t.Fatalf("expected medium-risk effectful local containment denial, got %v", err)
	}
	data, err := os.ReadFile(external)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "safe\n" {
		t.Fatalf("external target changed before launch: %q", data)
	}
	if _, err := os.Lstat(filepath.Join(root, "output", "escape")); !os.IsNotExist(err) {
		t.Fatalf("backend appears to have launched, output/escape stat err=%v", err)
	}
}

func TestSol3RuntimeCreatedSymlinkQuarantinesBeforeMerge(t *testing.T) {
	root, _ := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	bin := writeFakeBackend(t, `mkdir -p output
ln -s ../seed.txt output/escape
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt","output/escape"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.01}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)
	c := contract(root)
	c.JobID = "sol3-created-symlink"
	c.Budget.MaxNewFiles = 5
	c.Budget.MaxFilesChanged = 5

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" || !strings.Contains(rec.Message, "symlink/junction path") {
		t.Fatalf("status=%s message=%s", rec.Status, rec.Message)
	}
	if _, err := os.Lstat(filepath.Join(root, "output", "escape")); !os.IsNotExist(err) {
		t.Fatalf("symlink merged into source root, stat err=%v", err)
	}
	sol3AssertGitClean(t, root)
}

func TestSol3RuntimeCreatedSpecialFileQuarantines(t *testing.T) {
	if _, err := exec.LookPath("mkfifo"); err != nil {
		t.Skip("mkfifo not available")
	}
	root, _ := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	bin := writeFakeBackend(t, `mkdir -p output
mkfifo output/pipe
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt","output/pipe"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.01}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)
	c := contract(root)
	c.JobID = "sol3-created-special-file"
	c.Budget.MaxNewFiles = 5
	c.Budget.MaxFilesChanged = 5

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" || !strings.Contains(rec.Message, "special file path") {
		t.Fatalf("status=%s message=%s", rec.Status, rec.Message)
	}
	sol3AssertGitClean(t, root)
}

func TestSol3ProducedArtifactSymlinkRefusedNoCopy(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	external := filepath.Join(t.TempDir(), "sensitive.json")
	if err := os.WriteFile(external, []byte(`{"summary":"secret"}`), 0644); err != nil {
		t.Fatal(err)
	}
	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
ln -s "`+external+`" .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.01}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)
	c := artifactProducerContract(root)
	c.JobID = "sol3-artifact-symlink"
	c.Budget.MaxNewFiles = 5
	c.Budget.MaxFilesChanged = 5

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" || !(strings.Contains(rec.Message, "artifact no-follow read") || strings.Contains(rec.Message, "symlink/junction path")) {
		t.Fatalf("status=%s message=%s", rec.Status, rec.Message)
	}
	sol3AssertNoFileContains(t, filepath.Join(home, "artifacts"), "secret")
	if _, err := os.Lstat(filepath.Join(root, ".governator", "artifacts", "scout.json")); !os.IsNotExist(err) {
		t.Fatalf("artifact symlink merged into source root, stat err=%v", err)
	}
}

func sol3AssertGitClean(t *testing.T, root string) {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "status", "--porcelain").CombinedOutput()
	if err != nil {
		t.Fatalf("git status --porcelain: %v: %s", err, out)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("source root is dirty after quarantine:\n%s", out)
	}
}

func sol3AssertNoFileContains(t *testing.T, root, needle string) {
	t.Helper()
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return
	}
	if err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), needle) {
			t.Fatalf("artifact store copied sensitive content into %s", p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
