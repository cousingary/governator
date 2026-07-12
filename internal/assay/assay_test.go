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
		// Fail-closed at the subprocess trust boundary: any verdict string
		// that isn't a known-good pass/advisory must block under blocking
		// enforcement — an unrecognized verdict means "not verified," not
		// "fine." (The Python side only emits the four canonical lowercase
		// values today; this guards drift, wrong-case, and truncation.)
		{"", EnforcementBlocking, true},
		{"PASS", EnforcementBlocking, true},
		{"quarantine", EnforcementBlocking, true},
		{VerdictSkipped, EnforcementBlocking, true},
		{"", EnforcementAdvisory, false},
		{"PASS", EnforcementTelemetry, false},
	}
	for _, c := range cases {
		got := Blocks(c.verdict, c.enforcement)
		if got != c.want {
			t.Errorf("Blocks(%q,%q) = %v, want %v", c.verdict, c.enforcement, got, c.want)
		}
	}
}

// TestDescribeEnvironmentUnconfiguredIsZeroValue proves an unconfigured
// Config (no Repo, the "assay not configured" case runtime.runAssayStep
// already handles) never runs any probe — a zero-value Environment, not a
// half-populated one from a stray git/file lookup with an empty path.
func TestDescribeEnvironmentUnconfiguredIsZeroValue(t *testing.T) {
	if got := DescribeEnvironment(Config{}); got != (Environment{}) {
		t.Fatalf("expected zero-value Environment for unconfigured cfg, got %+v", got)
	}
}

// TestDescribeEnvironmentAgainstFixture is the load-bearing regression for
// the "git -C walks up to the enclosing repo" bug: testdata/assayer_fixture
// has no .git of its own and lives inside governator's own git working
// tree, so a naive `git -C <fixture> rev-parse HEAD` would silently report
// *governator's* commit as "the Assayer commit" — wrong and misleading
// metadata, worse than reporting none. AssayerCommit must fall back to the
// fixture's checked-in PINNED_COMMIT marker instead.
func TestDescribeEnvironmentAgainstFixture(t *testing.T) {
	repo := filepath.Join("testdata", "assayer_fixture")
	env := DescribeEnvironment(Config{Repo: repo, Python: "python3"})

	pinned, err := os.ReadFile(filepath.Join(repo, "PINNED_COMMIT"))
	if err != nil {
		t.Fatal(err)
	}
	wantCommit := strings.TrimSpace(string(pinned))
	if env.AssayerCommit != wantCommit {
		t.Fatalf("AssayerCommit = %q, want pinned fixture commit %q (did it fall through to governator's own git repo instead?)", env.AssayerCommit, wantCommit)
	}

	if len(env.ProfileHash) != 64 {
		t.Fatalf("expected a 64-hex-char sha256 ProfileHash, got %q", env.ProfileHash)
	}
	if len(env.ValidatorsHash) != 64 {
		t.Fatalf("expected a 64-hex-char sha256 ValidatorsHash, got %q", env.ValidatorsHash)
	}
	if env.ProfileHash == env.ValidatorsHash {
		t.Fatalf("profiles.py and checks.py must not hash identically, got %q for both", env.ProfileHash)
	}
}

// TestDescribeEnvironmentPythonVersion proves PythonVersion is populated
// from a real interpreter invocation, not just echoed from cfg.Python.
func TestDescribeEnvironmentPythonVersion(t *testing.T) {
	requirePython3(t)
	env := DescribeEnvironment(Config{Repo: filepath.Join("testdata", "assayer_fixture"), Python: "python3"})
	if !strings.Contains(strings.ToLower(env.PythonVersion), "python") {
		t.Fatalf("expected PythonVersion to mention python, got %q", env.PythonVersion)
	}
}
