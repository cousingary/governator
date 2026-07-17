package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeGovConfigDoctrine writes a minimal config.yaml declaring only
// doctrine.unenforceable_rule_action.
func writeGovConfigDoctrine(t *testing.T, path, action string) {
	t.Helper()
	content := "doctrine:\n  unenforceable_rule_action: " + action + "\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// TestSol3ConfigMutationDuringRunDoesNotAlterDoctrineEnforcement is the
// corpus #3 regression test for Sol Finding 2 (governator-sol3-repair-plan.md
// Session 3, P0.2 immutable RunEnvironment).
//
// Reproduces the audit's exact scenario: doctrine.unenforceable_rule_action
// starts at "block" (a job whose transcript audit finds a starter policy
// rule the backend's transcript format cannot possibly satisfy must fail
// closed, not just be advised). The backend itself — standing in for "the
// file was changed while the backend was sleeping" — rewrites config.yaml to
// "flag" before it exits. The transcript audit runs strictly AFTER the
// backend process has already exited, so if anything in that audit re-read
// configuration from disk at that point, it would see "flag" and approve a
// run that started life as "block". codex is used as the backend because its
// transcript format has at least one starter rule it structurally cannot
// satisfy (policy.UnenforceableRules("codex") is never empty — see
// events_test.go), so the coverage-gap violation fires unconditionally,
// independent of the transcript's actual content.
//
// Before this session, auditTranscript called config.Current() itself, at
// audit time, to decide unenforceableVerdict — so this exact scenario
// approved the run (Sol's reproduction). auditTranscript now takes
// unenforceableRuleAction as an explicit parameter sourced from the run's
// RunEnvironment, frozen before the backend ever launched.
func TestSol3ConfigMutationDuringRunDoesNotAlterDoctrineEnforcement(t *testing.T) {
	t.Run("block frozen despite mid-run edit to flag", func(t *testing.T) {
		root, _ := fixture(t)
		home := t.TempDir()
		t.Setenv("GOV_HOME", home)
		promptRoot := t.TempDir()
		writePrompt(t, promptRoot, "codex", "surgeon")
		t.Setenv("GOV_PROMPTS", promptRoot)

		cfgPath := filepath.Join(t.TempDir(), "config.yaml")
		writeGovConfigDoctrine(t, cfgPath, "block")
		t.Setenv("GOV_CONFIG", cfgPath)

		// The mutation is now performed by the test process itself, not by
		// the confined backend script: a governed job writing to a path
		// outside its workspace (this config file lives in its own
		// t.TempDir()) is now correctly refused by real Landlock enforcement
		// (Sol v7 S1/S2) rather than silently allowed, which is exactly what
		// this test wants to prove doesn't matter -- an EXTERNAL mid-run
		// mutation (an operator editing config.yaml while a job is running)
		// is the realistic version of this scenario anyway.
		codex := writeFakeBackend(t, `mkdir -p output
sleep 0.3
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"item.completed","item":{"type":"command_execution","command":"git status"}}\n'
`)
		t.Setenv("GOV_CODEX_BIN", codex)

		c := contract(root)
		c.Agent = "codex"
		c.Allowed.Execute = append(c.Allowed.Execute, "*")

		recCh := make(chan RunRecord, 1)
		errCh := make(chan error, 1)
		go func() {
			rec, err := New().Run(context.Background(), c)
			recCh <- rec
			errCh <- err
		}()
		time.Sleep(50 * time.Millisecond)
		writeGovConfigDoctrine(t, cfgPath, "flag")
		rec, err := <-recCh, <-errCh
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !strings.Contains(rec.Message, "unenforceable") {
			t.Fatalf("expected the frozen 'block' doctrine to fold the codex coverage gap into a violation despite the mid-run config edit to 'flag', got status=%s message=%q", rec.Status, rec.Message)
		}
		if rec.Status != "QUARANTINED" {
			t.Fatalf("expected QUARANTINED (frozen doctrine: block), got status=%s message=%q", rec.Status, rec.Message)
		}
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "flag") {
			t.Fatalf("expected the config file to actually have been rewritten to 'flag' by the backend (proving this is a real mid-run mutation, not a no-op), got: %s", data)
		}
	})

	t.Run("flag frozen despite mid-run edit to block", func(t *testing.T) {
		root, _ := fixture(t)
		home := t.TempDir()
		t.Setenv("GOV_HOME", home)
		promptRoot := t.TempDir()
		writePrompt(t, promptRoot, "codex", "surgeon")
		t.Setenv("GOV_PROMPTS", promptRoot)

		cfgPath := filepath.Join(t.TempDir(), "config.yaml")
		writeGovConfigDoctrine(t, cfgPath, "flag")
		t.Setenv("GOV_CONFIG", cfgPath)

		// See the sibling subtest above for why this mutation now happens
		// from the test process rather than the confined backend script.
		codex := writeFakeBackend(t, `mkdir -p output
sleep 0.3
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"item.completed","item":{"type":"command_execution","command":"git status"}}\n'
`)
		t.Setenv("GOV_CODEX_BIN", codex)

		c := contract(root)
		c.Agent = "codex"
		c.Allowed.Execute = append(c.Allowed.Execute, "*")

		recCh := make(chan RunRecord, 1)
		errCh := make(chan error, 1)
		go func() {
			rec, err := New().Run(context.Background(), c)
			recCh <- rec
			errCh <- err
		}()
		time.Sleep(50 * time.Millisecond)
		writeGovConfigDoctrine(t, cfgPath, "block")
		rec, err := <-recCh, <-errCh
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		// This is the reverse direction the audit also observed: a mid-run
		// edit tightening flag -> block must NOT retroactively quarantine a
		// run that was evaluated against "flag" throughout.
		if strings.Contains(rec.Message, "unenforceable") {
			t.Fatalf("expected the frozen 'flag' doctrine NOT to block on the codex coverage gap despite the mid-run config edit to 'block', got status=%s message=%q", rec.Status, rec.Message)
		}
		if rec.Status != "APPROVED" {
			t.Fatalf("expected APPROVED (frozen doctrine: flag, advisory only), got status=%s message=%q", rec.Status, rec.Message)
		}
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "block") {
			t.Fatalf("expected the config file to actually have been rewritten to 'block' by the backend (proving this is a real mid-run mutation, not a no-op), got: %s", data)
		}
	})
}
