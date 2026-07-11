package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/observability"
	govruntime "github.com/cousingary/governator/internal/runtime"
)

func batchGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

// batchJobFixture creates a disposable git repo (a valid gov batch run
// target's workspace.root) and a job YAML file inside jobsDir pointing at
// it. Mirrors examples/jobs/code_surgical_fix.yaml's shape.
func batchJobFixture(t *testing.T, jobsDir, jobID string) string {
	t.Helper()
	root := t.TempDir()
	batchGit(t, root, "init", "-b", "main")
	batchGit(t, root, "config", "user.email", "test@example.invalid")
	batchGit(t, root, "config", "user.name", "Governator Test")
	if err := os.WriteFile(filepath.Join(root, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	batchGit(t, root, "add", ".")
	batchGit(t, root, "commit", "-m", "seed")

	yaml := fmt.Sprintf(`task: write deterministic test output
job_id: %s
job_type: test
agent: claude-code
mode: surgeon
workspace:
  root: %s
  worktree: auto
allowed:
  read: ["**"]
  write: ["output/**"]
  execute: ["test"]
forbidden:
  paths: [".git/**"]
  commands: ["rm -rf"]
  behaviors: [network]
budget: {max_minutes: 1, max_commands: 5, max_files_changed: 5, max_lines_changed: 20, max_new_files: 2, max_deleted: 0}
preflight:
  intended_writes: ["output/**"]
success:
  required_files: ["output/result.txt"]
  validators: ["test -f output/result.txt"]
on_violation: quarantine
`, jobID, root)
	path := filepath.Join(jobsDir, jobID+".yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// batchFakeBin is the same minimal fake claude backend runtime_test.go's
// fixture() uses: it always succeeds, writing output/result.txt and a
// $0.25 cost line.
func batchFakeBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fake-claude")
	s := `#!/bin/sh
mkdir -p output
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`
	if err := os.WriteFile(bin, []byte(s), 0755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func captureHook(t *testing.T, script string) string {
	t.Helper()
	return captureHookWith(t, script, `{"tool_name":"Read","tool_input":{}}`)
}

func captureHookWith(t *testing.T, script, payload string) string {
	t.Helper()
	oldIn, oldOut := os.Stdin, os.Stdout
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	_, _ = inW.WriteString(payload)
	_ = inW.Close()
	os.Stdin, os.Stdout = inR, outW
	code := run([]string{"hook", "pre-tool-use", "--shadow", script})
	_ = outW.Close()
	os.Stdin, os.Stdout = oldIn, oldOut
	data, _ := io.ReadAll(outR)
	if code != 0 {
		t.Fatalf("hook exit=%d", code)
	}
	return string(data)
}

func captureRunInput(t *testing.T, args []string, input string) (int, string) {
	t.Helper()
	oldIn, oldOut := os.Stdin, os.Stdout
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	_, _ = inW.WriteString(input)
	_ = inW.Close()
	os.Stdin, os.Stdout = inR, outW
	code := run(args)
	_ = outW.Close()
	os.Stdin, os.Stdout = oldIn, oldOut
	data, _ := io.ReadAll(outR)
	return code, string(data)
}

func TestBatchRunRejectsWholeBatchOnInvalidContract(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	t.Setenv("GOV_CLAUDE_BIN", batchFakeBin(t))

	jobsDir := t.TempDir()
	batchJobFixture(t, jobsDir, "valid-job")
	invalidPath := filepath.Join(jobsDir, "invalid-job.yaml")
	if err := os.WriteFile(invalidPath, []byte("task: missing everything else\n"), 0644); err != nil {
		t.Fatal(err)
	}

	code, output := captureRunInput(t, []string{"batch", "run", jobsDir}, "")
	if code == 0 {
		t.Fatalf("expected non-zero exit for a batch containing an invalid contract, got 0: %s", output)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var runCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM runs`).Scan(&runCount); err != nil {
		t.Fatal(err)
	}
	if runCount != 0 {
		t.Fatalf("expected zero runs launched when any contract in the batch is invalid, got %d", runCount)
	}
}

func TestBatchRunResolvesDirectoryAndPrintsSummary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	t.Setenv("GOV_CLAUDE_BIN", batchFakeBin(t))

	jobsDir := t.TempDir()
	batchJobFixture(t, jobsDir, "dir-job-a")
	batchJobFixture(t, jobsDir, "dir-job-b")

	code, output := captureRunInput(t, []string{"batch", "run", jobsDir, "--parallel", "2"}, "")
	if code != 0 {
		t.Fatalf("exit=%d output=%s", code, output)
	}
	if !strings.Contains(output, "batch_id:") {
		t.Fatalf("expected batch_id header, got %s", output)
	}
	if !strings.Contains(output, "dir-job-a") || !strings.Contains(output, "dir-job-b") {
		t.Fatalf("expected both job ids in summary, got %s", output)
	}
	if !strings.Contains(output, "jobs=2 quarantined=0") {
		t.Fatalf("expected aggregate summary line, got %s", output)
	}
}

func TestGateCheckDialectRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		allow bool
	}{
		{"allow", `{"tool":"bash","command":"git status","cwd":"/tmp"}`, true},
		{"deny", `{"tool":"bash","command":"rm -rf /tmp/example","cwd":"/tmp"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, output := captureRunInput(t, []string{"gate", "check"}, tc.input)
			if code != 0 {
				t.Fatalf("exit=%d", code)
			}
			var decision struct {
				Allow   bool   `json:"allow"`
				Reason  string `json:"reason"`
				Finding string `json:"finding"`
			}
			if err := json.Unmarshal([]byte(output), &decision); err != nil {
				t.Fatalf("output=%q: %v", output, err)
			}
			if decision.Allow != tc.allow || decision.Finding == "" {
				t.Fatalf("decision=%+v", decision)
			}
			if !tc.allow && !strings.Contains(decision.Reason, "forbidden") {
				t.Fatalf("deny reason=%q", decision.Reason)
			}
		})
	}
	code, output := captureRunInput(t, []string{"gate", "check"}, "{")
	if code != 0 || output != "" {
		t.Fatalf("malformed: exit=%d output=%q", code, output)
	}

	neutral := govruntime.NeutralGateDecide(govruntime.NeutralGateInput{
		Tool: "bash", Command: "rm -rf /tmp/example", CWD: "/tmp",
	})
	hook := govruntime.GateDecide(govruntime.GateInput{
		ToolName: "Bash", ToolInput: map[string]any{"command": "rm -rf /tmp/example"}, CWD: "/tmp",
	})
	if neutral.Allow != hook.Allow || neutral.Finding != hook.Finding || neutral.Reason != hook.Reason {
		t.Fatalf("dialects diverged: neutral=%+v hook=%+v", neutral, hook)
	}
}

func TestShadowParityMatchMismatchUnavailable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	allow := write("allow.py", "import sys\nsys.stdin.read()\n")
	deny := write("deny.py", "import sys\nsys.stdin.read()\nsys.stdout.write('DENY')\n")
	crash := write("crash.py", "raise SystemExit(1)\n")
	// A legacy gate that denies with DIFFERENT reason wording than the Go gate.
	// Parity compares the decision, not the prose — both deny ⇒ match (the raw
	// byte comparison this replaced counted every deny as a mismatch, making
	// the zero-mismatch cutover criterion unreachable).
	wordedDeny := write("worded_deny.py", "import sys\nsys.stdin.read()\n"+
		`sys.stdout.write('{"hookSpecificOutput": {"hookEventName": "PreToolUse", `+
		`"permissionDecision": "deny", "permissionDecisionReason": "HARNESS AUTHORITY - nope"}}')`+"\n")

	if got := captureHook(t, allow); got != "" {
		t.Fatalf("allow output=%q", got)
	}
	if got := captureHook(t, deny); got != "DENY" {
		t.Fatalf("deny output=%q", got)
	}
	if got := captureHook(t, crash); got != "" {
		t.Fatalf("fallback output=%q", got)
	}
	denyPayload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/example"},"cwd":"/tmp"}`
	if got := captureHookWith(t, wordedDeny, denyPayload); !strings.Contains(got, "HARNESS AUTHORITY") {
		t.Fatalf("legacy deny must stay authoritative, got %q", got)
	}

	report, err := observability.ParitySummary(home)
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 4 || report.Matches != 2 || report.Mismatches != 1 || report.Unavailable != 1 {
		t.Fatalf("report=%+v", report)
	}
}

func TestHandoffCommandReturnsCompactRunEvidence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", "")
	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO runs(id,job_id,job_type,agent,mode,status,root,worktree,branch,diff,transcript,message,commit_hash,created,total_tokens,usage_available,graph_provider,graph_fingerprint,graph_files,graph_nodes,graph_edges) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"run-handoff", "job-handoff", "code_change", "codex", "surgeon", "APPROVED", "/tmp/project", "", "",
		"diff --git a/a.go b/a.go\n", strings.Repeat("bulk", 1000), "verified", "",
		"2026-07-05T00:00:00Z", 120, 1, "codegraph", strings.Repeat("a", 64), 1, 2, 3)
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	code, output := captureRunInput(t, []string{"handoff", "run-handoff"}, "")
	if code != 0 {
		t.Fatalf("exit=%d output=%s", code, output)
	}
	var handoff govruntime.Handoff
	if err := json.Unmarshal([]byte(output), &handoff); err != nil {
		t.Fatalf("output=%q: %v", output, err)
	}
	if handoff.RunID != "run-handoff" || handoff.Usage.TotalTokens != 120 || handoff.Graph.NodeCount != 2 || strings.Contains(output, "bulkbulk") {
		t.Fatalf("handoff=%+v output=%s", handoff, output)
	}
}

// TestHookDecisionRecordsProvenance is the Phase 6 acceptance check: every
// gate denial ledgered via `gov hook pre-tool-use --run` carries the
// Sources+PolicyHash provenance GateDecide attached (internal/policy,
// internal/runtime/gate.go attachProvenance), not just the bare
// allow/deny+finding the pre-Phase-6 hook_events schema recorded.
func TestHookDecisionRecordsProvenance(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	payload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf dist"}}`
	code, _ := captureRunInput(t, []string{"hook", "pre-tool-use", "--run", "provenance-run"}, payload)
	if code != 0 {
		t.Fatalf("hook exit=%d", code)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var decision, finding, sources, policyHash string
	if err := db.QueryRow(`SELECT decision,finding,sources,policy_hash FROM hook_events WHERE run_id=?`, "provenance-run").
		Scan(&decision, &finding, &sources, &policyHash); err != nil {
		t.Fatalf("hook_events row: %v", err)
	}
	if decision != "deny" || finding != "F3" {
		t.Fatalf("decision=%s finding=%s, want deny/F3", decision, finding)
	}
	if !strings.Contains(sources, "org_policy") {
		t.Fatalf("sources=%q, want it to contain org_policy", sources)
	}
	if policyHash == "" {
		t.Fatal("policy_hash was not recorded")
	}
}
