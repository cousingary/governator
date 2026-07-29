//go:build integration

package assay

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These were historically skipped in the ordinary unit harness because it
// intentionally lacks a real Governator sandbox. They are S6's mandatory
// bridge inventory: they now execute under the S5 TestMain and are named in
// release.sh's exact integration manifest.
func TestEvaluateShaMismatchAfterEvaluationIsError(t *testing.T) {
	stubDir := t.TempDir()
	stub := "import time, json\ntime.sleep(0.3)\nprint(json.dumps({'verdict':'pass','failed_checks':[],'had_error':False,'checks_result_hash':'h','profile_definition_hash':'p','validator_implementation_hash':'i','validator_config_hash':'c'}))\n"
	if err := os.WriteFile(filepath.Join(stubDir, "cli.py"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	path, sha := writeArtifact(t, t.TempDir(), "original content")
	req := baseRequest(sha)
	snap := buildTestSnapshot(t, stubDir)
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = os.WriteFile(path, []byte("mutated content"), 0o644)
	}()
	v := Evaluate(context.Background(), Config{Repo: stubDir, Python: "python3"}, req, path, snap)
	if v.Verdict != VerdictError || !strings.Contains(v.Reason, "after evaluation") {
		t.Fatalf("expected post-evaluation mutation error, got %+v", v)
	}
}

func TestEvaluateNonzeroExitIsError(t *testing.T) {
	stubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stubDir, "cli.py"), []byte("import sys\nsys.stderr.write('boom')\nsys.exit(1)\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path, sha := writeArtifact(t, t.TempDir(), "content")
	v := Evaluate(context.Background(), Config{Repo: stubDir, Python: "python3"}, baseRequest(sha), path, buildTestSnapshot(t, stubDir))
	if v.Verdict != VerdictError || !v.HadError || !strings.Contains(v.Reason, "boom") {
		t.Fatalf("expected nonzero-exit error, got %+v", v)
	}
}

func TestEvaluateTimeout(t *testing.T) {
	stubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stubDir, "cli.py"), []byte("import time\ntime.sleep(5)\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path, sha := writeArtifact(t, t.TempDir(), "content")
	start := time.Now()
	v := Evaluate(context.Background(), Config{Repo: stubDir, Python: "python3", Timeout: 150 * time.Millisecond}, baseRequest(sha), path, buildTestSnapshot(t, stubDir))
	if v.Verdict != VerdictError || !strings.Contains(v.Reason, "timed out") || time.Since(start) > 3*time.Second {
		t.Fatalf("expected prompt timeout error, got %+v", v)
	}
}

func TestEvaluateUnparseableStdoutIsError(t *testing.T) {
	stubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stubDir, "cli.py"), []byte("print('not json')\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path, sha := writeArtifact(t, t.TempDir(), "content")
	v := Evaluate(context.Background(), Config{Repo: stubDir, Python: "python3"}, baseRequest(sha), path, buildTestSnapshot(t, stubDir))
	if v.Verdict != VerdictError || !v.HadError {
		t.Fatalf("expected malformed-output error, got %+v", v)
	}
}

func TestSol3ArtifactDeclaredPathReachesRealAssayerFilePathCheck(t *testing.T) {
	repo := releasedAssayerRepo(t)
	content := `{"content":"def add(a, b):\n    return a + b\n","language":"python"}`
	path, sha := writeArtifact(t, t.TempDir(), content)
	req := Request{RunID: "run-1", AttemptID: "run-1", JobID: "job-1", ContractHash: "deadbeef", JobType: "coding", Backend: "claude-code", ArtifactName: "code", ArtifactSHA256: sha, ArtifactDeclaredPath: "result.py", Payload: json.RawMessage(content), CheckProfile: "coding-output-v2"}
	v := Evaluate(context.Background(), Config{Repo: repo, Python: "python3"}, req, path, buildTestSnapshot(t, repo))
	if v.Verdict != VerdictPass {
		t.Fatalf("expected real Assayer declared-path pass, got %+v", v)
	}

	mismatched := req
	mismatched.ArtifactDeclaredPath = "result.js"
	badV := Evaluate(context.Background(), Config{Repo: repo, Python: "python3"}, mismatched, path, buildTestSnapshot(t, repo))
	if badV.Verdict != VerdictFail {
		t.Fatalf("expected fail verdict for a declared-path/language mismatch, got %+v", badV)
	}
	found := false
	for _, fc := range badV.FailedChecks {
		if fc == "file_path_consistency" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected file_path_consistency in failed_checks, got %v", badV.FailedChecks)
	}
}
