package assay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// realAssayerRepo is the sibling Python repo built alongside this package
// for Phase 3A. Tests that exercise the real `evaluate` subcommand copy its
// cli.py + assayer/ package into a t.TempDir() (hermetic: nothing here
// mutates the real checkout) and skip if it isn't present on the machine.
const realAssayerRepo = "/mnt/e/downloads/assayer"

func setupRealAssayerRepo(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat(filepath.Join(realAssayerRepo, "cli.py")); err != nil {
		t.Skipf("real assayer repo not found at %s: %v", realAssayerRepo, err)
	}
	dst := t.TempDir()
	copyFileForTest(t, filepath.Join(realAssayerRepo, "cli.py"), filepath.Join(dst, "cli.py"))
	if err := os.MkdirAll(filepath.Join(dst, "assayer"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"__init__.py", "checks.py", "profiles.py", "store.py"} {
		copyFileForTest(t, filepath.Join(realAssayerRepo, "assayer", name), filepath.Join(dst, "assayer", name))
	}
	return dst
}

func copyFileForTest(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func requirePython3(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
}

func writeArtifact(t *testing.T, dir, content string) (path, sha string) {
	t.Helper()
	path = filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:])
}

func baseRequest(sha string) Request {
	payload, _ := json.Marshal(map[string]any{
		"content": "This is a sufficiently long piece of real generated content for the check.",
	})
	return Request{
		RunID: "run-1", AttemptID: "run-1", JobID: "job-1", ContractHash: "deadbeef",
		JobType: "coding", Backend: "claude-code", Model: "",
		ArtifactName: "output", ArtifactSHA256: sha, Payload: payload,
		CheckProfile: "coding-output-v1", PolicyVersion: "test-v1",
	}
}

func TestEvaluateShaMismatchBeforeEvaluationIsError(t *testing.T) {
	dir := t.TempDir()
	path, sha := writeArtifact(t, dir, `{"content":"real content, long enough to pass"}`)
	req := baseRequest(sha)
	req.ArtifactSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

	v := Evaluate(context.Background(), Config{Repo: dir, Python: "python3"}, req, path)
	if v.Verdict != VerdictError {
		t.Fatalf("expected error verdict, got %+v", v)
	}
	if !v.HadError {
		t.Fatalf("expected had_error=true, got %+v", v)
	}
	if want := "before evaluation"; !strings.Contains(v.Reason, want) {
		t.Fatalf("expected reason to mention %q, got %q", want, v.Reason)
	}
}

// TestEvaluateShaMismatchAfterEvaluationIsError proves the post-evaluation
// re-check catches a TOCTOU mutation of the artifact that happens *during*
// the subprocess call. The stub subprocess sleeps long enough for the test
// goroutine to mutate the artifact file mid-flight, deterministically
// landing the race (sleep duration is an order of magnitude longer than a
// single file write).
func TestEvaluateShaMismatchAfterEvaluationIsError(t *testing.T) {
	requirePython3(t)
	stubDir := t.TempDir()
	stub := `import sys, time, json
time.sleep(0.3)
print(json.dumps({"verdict":"pass","failed_checks":[],"had_error":False,"trace_id":"t","quarantine_id":"","checks_hash":"h","policy_version":"v"}))
`
	if err := os.WriteFile(filepath.Join(stubDir, "cli.py"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}

	artifactDir := t.TempDir()
	path, sha := writeArtifact(t, artifactDir, "original content")
	req := baseRequest(sha)

	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = os.WriteFile(path, []byte("mutated content"), 0o644)
	}()

	v := Evaluate(context.Background(), Config{Repo: stubDir, Python: "python3"}, req, path)
	if v.Verdict != VerdictError {
		t.Fatalf("expected error verdict, got %+v", v)
	}
	if want := "after evaluation"; !strings.Contains(v.Reason, want) {
		t.Fatalf("expected reason to mention %q, got %q", want, v.Reason)
	}
}

func TestEvaluateNonzeroExitIsError(t *testing.T) {
	requirePython3(t)
	stubDir := t.TempDir()
	stub := "import sys\nsys.stderr.write('boom')\nsys.exit(1)\n"
	if err := os.WriteFile(filepath.Join(stubDir, "cli.py"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, sha := writeArtifact(t, dir, "content")
	req := baseRequest(sha)

	v := Evaluate(context.Background(), Config{Repo: stubDir, Python: "python3"}, req, path)
	if v.Verdict != VerdictError || !v.HadError {
		t.Fatalf("expected error verdict, got %+v", v)
	}
	if !strings.Contains(v.Reason, "boom") {
		t.Fatalf("expected stderr captured into reason, got %q", v.Reason)
	}
}

func TestEvaluateTimeout(t *testing.T) {
	requirePython3(t)
	stubDir := t.TempDir()
	stub := "import time\ntime.sleep(5)\n"
	if err := os.WriteFile(filepath.Join(stubDir, "cli.py"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, sha := writeArtifact(t, dir, "content")
	req := baseRequest(sha)

	start := time.Now()
	v := Evaluate(context.Background(), Config{Repo: stubDir, Python: "python3", Timeout: 150 * time.Millisecond}, req, path)
	elapsed := time.Since(start)
	if v.Verdict != VerdictError || !strings.Contains(v.Reason, "timed out") {
		t.Fatalf("expected timeout error verdict, got %+v", v)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("expected Evaluate to return promptly after timeout, took %s", elapsed)
	}
}

func TestEvaluateUnparseableStdoutIsError(t *testing.T) {
	requirePython3(t)
	stubDir := t.TempDir()
	stub := "print('not json')\n"
	if err := os.WriteFile(filepath.Join(stubDir, "cli.py"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, sha := writeArtifact(t, dir, "content")
	req := baseRequest(sha)

	v := Evaluate(context.Background(), Config{Repo: stubDir, Python: "python3"}, req, path)
	if v.Verdict != VerdictError || !v.HadError {
		t.Fatalf("expected error verdict, got %+v", v)
	}
}

func TestEvaluateAgainstRealCLIPassAndFail(t *testing.T) {
	requirePython3(t)
	repo := setupRealAssayerRepo(t)

	dir := t.TempDir()
	content := `{"content":"This is a real, sufficiently long piece of generated content."}`
	path, sha := writeArtifact(t, dir, content)
	req := baseRequest(sha)
	req.Payload = json.RawMessage(`{"content":"This is a real, sufficiently long piece of generated content."}`)

	v := Evaluate(context.Background(), Config{Repo: repo, Python: "python3"}, req, path)
	if v.Verdict != VerdictPass {
		t.Fatalf("expected pass verdict against real assayer CLI, got %+v", v)
	}
	if v.ChecksHash == "" {
		t.Fatal("expected a non-empty checks_hash")
	}

	// Now a payload missing the required field -> fail.
	badContent := `{}`
	badPath, badSHA := writeArtifact(t, dir, badContent)
	badReq := baseRequest(badSHA)
	badReq.Payload = json.RawMessage(`{}`)

	badV := Evaluate(context.Background(), Config{Repo: repo, Python: "python3"}, badReq, badPath)
	if badV.Verdict != VerdictFail {
		t.Fatalf("expected fail verdict for missing required field, got %+v", badV)
	}
	if len(badV.FailedChecks) == 0 {
		t.Fatal("expected at least one failed check name")
	}
}

func TestConfiguredReflectsRepoField(t *testing.T) {
	if (Config{}).Configured() {
		t.Fatal("empty Config must report Configured()==false")
	}
	if !(Config{Repo: "/some/path"}).Configured() {
		t.Fatal("Config with a Repo must report Configured()==true")
	}
}

func TestBlocks(t *testing.T) {
	cases := []struct {
		verdict, enforcement string
		want                 bool
	}{
		{VerdictFail, EnforcementBlocking, true},
		{VerdictError, EnforcementBlocking, true},
		{VerdictPass, EnforcementBlocking, false},
		{VerdictAdvisory, EnforcementBlocking, false},
		{VerdictFail, EnforcementAdvisory, false},
		{VerdictError, EnforcementAdvisory, false},
		{VerdictFail, EnforcementTelemetry, false},
		{VerdictError, EnforcementTelemetry, false},
	}
	for _, c := range cases {
		got := Blocks(c.verdict, c.enforcement)
		if got != c.want {
			t.Errorf("Blocks(%q,%q) = %v, want %v", c.verdict, c.enforcement, got, c.want)
		}
	}
}



