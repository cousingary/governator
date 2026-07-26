package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"

	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/observability"
	govruntime "github.com/cousingary/governator/internal/runtime"
	"github.com/cousingary/governator/internal/toolregistry"
)

// cmdGovShellReadRootsOnce/cmdGovShellReadRootsList/cmdGovShellReadRootsForFixtures
// mirror internal/redteam/harness_test.go's helper of the same name: batch
// job fixtures below bake a #!/bin/sh fake backend, and real Landlock
// enforcement (Sol v7 S1/S2 -- every job here forbids network, which always
// requires the enforcement wrap) refuses to open /bin/sh (or the coreutils
// it shells out to) unless the job's declared local.read_roots covers their
// exact read closure.
var (
	cmdGovShellReadRootsOnce sync.Once
	cmdGovShellReadRootsList []string
)

func cmdGovShellReadRootsForFixtures() []string {
	cmdGovShellReadRootsOnce.Do(func() {
		var out []string
		add := func(path string) {
			closure, err := enforce.ExecutableReadClosure(path)
			if err != nil {
				return
			}
			out = append(out, closure...)
		}
		add("/bin/sh")
		for _, tool := range []string{"mkdir", "cat", "chmod", "find", "ls", "rm", "sed", "sleep", "dd", "setsid", "timeout", "printf", "grep", "git", "ln", "mkfifo", "touch"} {
			if resolved, lerr := exec.LookPath(tool); lerr == nil {
				add(resolved)
			}
		}
		cmdGovShellReadRootsList = out
	})
	return cmdGovShellReadRootsList
}

// readRootsYAML renders cmdGovShellReadRootsForFixtures() as a local.read_roots
// YAML block, indented to sit under a job fixture's top-level keys.
func readRootsYAML() string {
	var b strings.Builder
	b.WriteString("local:\n  read_roots:\n")
	for _, root := range cmdGovShellReadRootsForFixtures() {
		b.WriteString("    - \"" + root + "\"\n")
	}
	return b.String()
}

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
  validators:
    - command: test -f output/result.txt
      tools: [test]
on_violation: quarantine
%s`, jobID, root, readRootsYAML())
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

func enrollValidatorTools(t *testing.T, names ...string) {
	t.Helper()
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	base := []string{"git", "bash", "unshare", "test", "true", "printf", "rm", "sleep"}
	seen := map[string]bool{}
	for _, name := range append(base, names...) {
		if seen[name] {
			continue
		}
		seen[name] = true
		bin, err := lookPathPreferCanonical(name)
		if err != nil {
			t.Fatalf("resolve validator tool %s: %v", name, err)
		}
		if _, err := toolregistry.Enroll(name, bin); err != nil {
			t.Fatalf("enroll validator tool %s: %v", name, err)
		}
	}
}

func lookPathPreferCanonical(name string) (string, error) {
	if name == "git" {
		if _, err := os.Stat("/usr/bin/git"); err == nil {
			return "/usr/bin/git", nil
		}
	}
	return exec.LookPath(name)
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

var (
	cmdGovBinaryOnce sync.Once
	cmdGovBinaryPath string
	cmdGovBinaryErr  error
)

func cmdGovBinary(t *testing.T) string {
	t.Helper()
	cmdGovBinaryOnce.Do(func() {
		_, thisFile, _, _ := goruntime.Caller(0)
		repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
		dir, err := os.MkdirTemp("", "gov-cmd-test-bin")
		if err != nil {
			cmdGovBinaryErr = err
			return
		}
		out := filepath.Join(dir, "gov")
		cmd := exec.Command("go", "build", "-o", out, "./cmd/gov")
		cmd.Dir = repoRoot
		if combined, err := cmd.CombinedOutput(); err != nil {
			cmdGovBinaryErr = err
			cmdGovBinaryPath = string(combined)
			return
		}
		cmdGovBinaryPath = out
	})
	if cmdGovBinaryErr != nil {
		t.Fatalf("build gov binary: %v: %s", cmdGovBinaryErr, cmdGovBinaryPath)
	}
	return cmdGovBinaryPath
}

func captureRunInput(t *testing.T, args []string, input string) (int, string) {
	t.Helper()
	oldSelfExeOverride := enforce.SelfExeOverride
	if oldSelfExeOverride == "" {
		enforce.SelfExeOverride = cmdGovBinary(t)
	}
	defer func() { enforce.SelfExeOverride = oldSelfExeOverride }()
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

func TestVersionJSONReportsBuildIdentityFields(t *testing.T) {
	code, output := captureRunInput(t, []string{"version", "--json"}, "")
	if code != 0 {
		t.Fatalf("exit=%d output=%s", code, output)
	}
	var got struct {
		Version                string `json:"version"`
		SourceCommit           string `json:"source_commit"`
		BuildTimestamp         string `json:"build_timestamp"`
		ClaimsHash             string `json:"claims_hash"`
		AdapterProtocolVersion string `json:"adapter_protocol_version"`
		Dirty                  *bool  `json:"dirty"`
		GoToolchain            string `json:"go_toolchain"`
		Platform               string `json:"platform"`
	}
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("version JSON %q: %v", output, err)
	}
	if got.Version == "" || got.SourceCommit == "" || got.BuildTimestamp == "" || got.ClaimsHash == "" || got.AdapterProtocolVersion == "" {
		t.Fatalf("missing build identity field: %+v", got)
	}
	// Sol v7 S7 (report RB1): "the binary must report version, Git commit,
	// dirty state, build timestamp ..., Go toolchain, target platform."
	// dirty is a real bool key (must decode, not just be absent-and-zero);
	// go_toolchain/platform must be non-empty and self-consistent.
	if got.Dirty == nil {
		t.Fatalf("version JSON missing dirty field: %+v", got)
	}
	if got.GoToolchain == "" || !strings.HasPrefix(got.GoToolchain, "go") {
		t.Fatalf("version JSON go_toolchain %q does not look like a Go toolchain version", got.GoToolchain)
	}
	if got.Platform != goruntime.GOOS+"/"+goruntime.GOARCH {
		t.Fatalf("version JSON platform %q does not match the running process's %s/%s", got.Platform, goruntime.GOOS, goruntime.GOARCH)
	}
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
	enrollValidatorTools(t, "test")

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
	// Sol P1-11 / report §9 attack 15: malformed input must fail closed --
	// nonzero exit, a structured DENY carrying an explicit PROTOCOL_ERROR
	// finding, never the old exit=0/output="" shape a caller could mistake
	// for "no decision" (== approval). See TestAttack15GateCheckMalformedInputFailsClosed
	// for the full contract (also durable audit record).
	code, output := captureRunInput(t, []string{"gate", "check"}, "{")
	if code == 0 {
		t.Fatalf("malformed: expected nonzero exit, got exit=%d output=%q", code, output)
	}
	var malformed struct {
		Allow   bool   `json:"allow"`
		Reason  string `json:"reason"`
		Finding string `json:"finding"`
	}
	if err := json.Unmarshal([]byte(output), &malformed); err != nil {
		t.Fatalf("malformed: output=%q: %v", output, err)
	}
	if malformed.Allow {
		t.Fatalf("malformed: expected allow=false, got %+v", malformed)
	}
	if !strings.Contains(malformed.Finding, "PROTOCOL_ERROR") || !strings.Contains(malformed.Reason, "DENY") {
		t.Fatalf("malformed: expected a PROTOCOL_ERROR finding and a DENY reason, got %+v", malformed)
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
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("python3", python); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	allow := write("allow.py", "import sys\nsys.stdin.read()\n")
	deny := write("deny.py", "import sys\nsys.stdin.read()\n"+
		`sys.stdout.write('{"hookSpecificOutput": {"hookEventName": "PreToolUse", `+
		`"permissionDecision": "deny", "permissionDecisionReason": "HARNESS AUTHORITY - nope"}}')`+"\n")
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
	if got := captureHook(t, deny); !strings.Contains(got, "shadow parity denied") {
		t.Fatalf("shadow deny must not be ignored, got %q", got)
	}
	if got := captureHook(t, crash); got != "" {
		t.Fatalf("fallback output=%q", got)
	}
	denyPayload := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/example"},"cwd":"/tmp"}`
	if got := captureHookWith(t, wordedDeny, denyPayload); !strings.Contains(got, "GOVERNATOR GATE") || strings.Contains(got, "HARNESS AUTHORITY") {
		t.Fatalf("Go deny must stay authoritative over shadow wording, got %q", got)
	}

	report, err := observability.ParitySummary(home)
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 4 || report.Matches != 1 || report.Mismatches != 1 || report.Unavailable != 2 {
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

// --- Sol redteam v3 S1 — P0.7 hook protocol fail-closed (corpus #6) --------
// governator-sol-upgrade3.md finding #7: `printf '{broken' | gov hook
// pre-tool-use` returned exit 0, no denial, no useful error, no audit
// record. hookDenyJSON below decodes the real PreToolUse deny contract
// (exit 0 + hookSpecificOutput.permissionDecision=deny — see
// docs.claude.com/en/docs/claude-code/hooks: JSON is only parsed on exit 0,
// and exit 2 discards stdout JSON entirely, so exit 0 is the only channel
// that can carry a distinguishable HOOK_PROTOCOL_ERROR/HOOK_VERSION_MISMATCH
// reason).
func hookDenyJSON(t *testing.T, output string) (permissionDecision, reason string) {
	t.Helper()
	var parsed struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("output=%q is not valid hook JSON: %v", output, err)
	}
	return parsed.HookSpecificOutput.PermissionDecision, parsed.HookSpecificOutput.PermissionDecisionReason
}

func TestSol3HookProtocolMalformedInputDenies(t *testing.T) {
	cases := []struct {
		name     string
		payload  string
		wantCode string
	}{
		{"truncated brace (audit reproduction)", `{broken`, "HOOK_PROTOCOL_ERROR"},
		{"truncated valid-looking prefix", `{"tool_name":"Bash","tool_in`, "HOOK_PROTOCOL_ERROR"},
		{"empty payload", ``, "HOOK_PROTOCOL_ERROR"},
		{"missing tool_name", `{"tool_input":{"command":"ls"}}`, "HOOK_PROTOCOL_ERROR"},
		{"tool_input wrong type", `{"tool_name":"Bash","tool_input":"not-an-object"}`, "HOOK_PROTOCOL_ERROR"},
		{"concatenated second document", `{"tool_name":"Read","tool_input":{}}{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`, "HOOK_PROTOCOL_ERROR"},
		{"unsupported hook_event_name", `{"tool_name":"Bash","tool_input":{"command":"ls"},"hook_event_name":"PostToolUse"}`, "HOOK_VERSION_MISMATCH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("GOV_HOME", home)
			t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
			runID := "sol3-s1-" + strings.Map(func(r rune) rune {
				if r == ' ' || r == '(' || r == ')' {
					return '-'
				}
				return r
			}, tc.name)

			code, output := captureRunInput(t, []string{"hook", "pre-tool-use", "--run", runID}, tc.payload)
			if code != 0 {
				t.Fatalf("exit=%d, want 0 (Claude Code only parses hook JSON on exit 0)", code)
			}
			decision, reason := hookDenyJSON(t, output)
			if decision != "deny" {
				t.Fatalf("payload %q must not be ALLOW: permissionDecision=%q output=%q", tc.payload, decision, output)
			}
			if !strings.Contains(reason, tc.wantCode) {
				t.Fatalf("reason=%q, want it to contain %s", reason, tc.wantCode)
			}

			db, err := observability.Open(home)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var dbDecision, finding string
			if err := db.QueryRow(`SELECT decision,finding FROM hook_events WHERE run_id=?`, runID).Scan(&dbDecision, &finding); err != nil {
				t.Fatalf("hook_events row missing for run %s: %v", runID, err)
			}
			if dbDecision != "deny" || finding != tc.wantCode {
				t.Fatalf("hook_events decision=%q finding=%q, want deny/%s", dbDecision, finding, tc.wantCode)
			}
		})
	}
}

// captureRunInputAsync is captureRunInput's pipe-fed sibling for payloads
// that exceed the OS pipe buffer (~64KB): unlike captureRunInput, it writes
// stdin from a goroutine concurrently with run(args) so a multi-megabyte
// payload can't deadlock the writer against a reader that hasn't started yet.
func captureRunInputAsync(t *testing.T, args []string, input string) (int, string) {
	t.Helper()
	oldIn, oldOut := os.Stdin, os.Stdout
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	go func() {
		_, _ = inW.WriteString(input)
		_ = inW.Close()
	}()
	os.Stdin, os.Stdout = inR, outW
	code := run(args)
	_ = outW.Close()
	os.Stdin, os.Stdout = oldIn, oldOut
	data, _ := io.ReadAll(outR)
	return code, string(data)
}

// TestSol3HookProtocolOversizedPayloadDenies is corpus #6's "oversized"
// variant: a payload past hookProtocolMaxBytes must be rejected before an
// attempt to decode it, not just fail JSON parsing incidentally.
func TestSol3HookProtocolOversizedPayloadDenies(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	padding := strings.Repeat("a", hookProtocolMaxBytes+1)
	payload := `{"tool_name":"Bash","tool_input":{"command":"` + padding + `"}}`
	code, output := captureRunInputAsync(t, []string{"hook", "pre-tool-use", "--run", "sol3-s1-oversized"}, payload)
	if code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	decision, reason := hookDenyJSON(t, output)
	if decision != "deny" {
		t.Fatalf("oversized payload must not be ALLOW: permissionDecision=%q", decision)
	}
	if !strings.Contains(reason, "HOOK_PROTOCOL_ERROR") {
		t.Fatalf("reason=%q, want HOOK_PROTOCOL_ERROR", reason)
	}
}

// TestSol3HookProtocolValidPayloadsNotOverBlocked is the no-over-blocking
// half of corpus #6: the fail-closed fix must not turn legitimate PreToolUse
// invocations into denials. Covers a normal allow, a normal policy deny
// (pre-existing F3 behavior), a payload carrying the extra common fields
// Claude Code actually sends (session_id/transcript_path/permission_mode
// plus a matching hook_event_name), and a payload with a trailing newline
// (common from JSON-line writers) — none of these are "strict schema
// decoding" violations.
func TestSol3HookProtocolValidPayloadsNotOverBlocked(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	cases := []struct {
		name      string
		payload   string
		wantAllow bool
	}{
		{"plain allow", `{"tool_name":"Read","tool_input":{"file_path":"README.md"}}`, true},
		{"plain deny (F3 rm -rf)", `{"tool_name":"Bash","tool_input":{"command":"rm -rf dist"}}`, false},
		{"real Claude Code common fields, allow", `{"session_id":"abc123","transcript_path":"/tmp/t.jsonl","cwd":"/tmp","hook_event_name":"PreToolUse","permission_mode":"default","tool_name":"Read","tool_input":{"file_path":"README.md"}}`, true},
		{"trailing newline", "{\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"README.md\"}}\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, output := captureRunInput(t, []string{"hook", "pre-tool-use"}, tc.payload)
			if code != 0 {
				t.Fatalf("exit=%d, want 0", code)
			}
			if tc.wantAllow {
				if strings.TrimSpace(output) != "" {
					t.Fatalf("want silent allow, got output=%q", output)
				}
				return
			}
			decision, _ := hookDenyJSON(t, output)
			if decision != "deny" {
				t.Fatalf("want deny, got permissionDecision=%q output=%q", decision, output)
			}
		})
	}
}

// TestSol3HookProtocolEmergencyJournal is the audit's "Policy hook emergency
// journal": when the ledger write fails, the decision must land in the
// append-only fallback file instead of being silently swallowed. Forces the
// ledger open to fail by pre-creating ledger.db as a directory.
func TestSol3HookProtocolEmergencyJournal(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "ledger.db"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	code, output := captureRunInput(t, []string{"hook", "pre-tool-use", "--run", "sol3-s1-journal"}, `{broken`)
	if code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	decision, reason := hookDenyJSON(t, output)
	if decision != "deny" || !strings.Contains(reason, "HOOK_PROTOCOL_ERROR") {
		t.Fatalf("decision=%q reason=%q, want deny/HOOK_PROTOCOL_ERROR even though the ledger is unavailable", decision, reason)
	}

	journalPath := filepath.Join(home, "hook_emergency_journal.jsonl")
	info, err := os.Stat(journalPath)
	if err != nil {
		t.Fatalf("emergency journal not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("journal perms=%o, want 0600", perm)
	}
	raw, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		RunID    string `json:"run_id"`
		Decision string `json:"decision"`
		Finding  string `json:"finding"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &rec); err != nil {
		t.Fatalf("journal line not valid JSON: %v (raw=%q)", err, raw)
	}
	if rec.RunID != "sol3-s1-journal" || rec.Decision != "deny" || rec.Finding != "HOOK_PROTOCOL_ERROR" {
		t.Fatalf("journal record=%+v, want run_id=sol3-s1-journal decision=deny finding=HOOK_PROTOCOL_ERROR", rec)
	}
}

// TestAttack15GateCheckMalformedInputFailsClosed is Sol P1-11's regression
// test / report §9 attack 15: `printf '{broken' | gov gate check` used to
// exit 0 with empty output -- a caller reading "no denial" as approval would
// silently ALLOW. Proves the full fixed contract: nonzero exit, a structured
// DENY on stdout with an explicit PROTOCOL_ERROR finding, and a durable audit
// record in the hook_events ledger (the emergency journal is the fallback
// for when that ledger itself is unavailable -- TestSol3HookProtocolEmergencyJournal
// above covers that path; this test exercises the normal, healthy-ledger case).
func TestAttack15GateCheckMalformedInputFailsClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	code, output := captureRunInput(t, []string{"gate", "check"}, "{broken")
	if code == 0 {
		t.Fatalf("expected nonzero exit for malformed gate check input, got exit=0 output=%q", output)
	}
	var decision struct {
		Allow   bool   `json:"allow"`
		Reason  string `json:"reason"`
		Finding string `json:"finding"`
	}
	if err := json.Unmarshal([]byte(output), &decision); err != nil {
		t.Fatalf("output=%q: %v", output, err)
	}
	if decision.Allow {
		t.Fatalf("expected allow=false, got %+v", decision)
	}
	if !strings.Contains(decision.Finding, "PROTOCOL_ERROR") {
		t.Fatalf("expected a PROTOCOL_ERROR finding, got %+v", decision)
	}
	if !strings.Contains(decision.Reason, "DENY") {
		t.Fatalf("expected an explicit DENY in the reason, got %+v", decision)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var tool, dbDecision, finding string
	if err := db.QueryRow(`SELECT tool, decision, finding FROM hook_events ORDER BY rowid DESC LIMIT 1`).Scan(&tool, &dbDecision, &finding); err != nil {
		t.Fatalf("expected a durable hook_events audit record, got: %v", err)
	}
	if dbDecision != "deny" || !strings.Contains(finding, "PROTOCOL_ERROR") {
		t.Fatalf("audit record tool=%q decision=%q finding=%q, want decision=deny finding containing PROTOCOL_ERROR", tool, dbDecision, finding)
	}
}
