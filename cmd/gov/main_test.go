package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/observability"
	govruntime "github.com/cousingary/governator/internal/runtime"
)

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
