//go:build redteam

// v6_s4_shadow_authority_test.go is the Sol redteam v6 Permanent Regression
// Corpus, cases 19-21, owned by Session 4 (Phase 4: the Go PreToolUse gate
// must stay authoritative -- shadow Python can measure parity but never
// change the verdict). See agents/governator-sol-upgrade6-plan.md Session 4
// and agents/governator-sol-upgrade6.md P0-3. These tests drive the real
// compiled `gov hook pre-tool-use --shadow <script>` CLI (govBinary), since
// this is CLI-protocol behavior cmd/gov/main.go's hookCmd implements, not
// something internal/runtime.RunWithAutoRepair exercises. Every test here is
// scaffolding only (Session 0): t.Skip(...) is the literal first statement,
// before any fixture construction.
package redteam

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/toolregistry"
)

// hookDenyInput is the report's own example of a command the Go gate
// definitely denies (F3: irreversible/bulk rm -rf is unconditionally denied
// on the interactive plane -- see internal/runtime/gate.go's GateDecide).
const hookDenyInput = `{"tool_name":"Bash","tool_input":{"command":"rm -rf dist"}}`

// runShadowHook invokes the real compiled gov CLI's `hook pre-tool-use
// --shadow <script>` with payload on stdin and home as GOV_HOME/GOV_LEDGER_DIR
// (so observability.Open(home) in this test process reads back the exact
// same ledger the subprocess wrote to), returning combined stdout.
func runShadowHook(t *testing.T, home, payload, shadowScript string) []byte {
	t.Helper()
	bin := govBinary(t)
	cmd := exec.Command(bin, "hook", "pre-tool-use", "--shadow", shadowScript)
	cmd.Env = append(os.Environ(), "GOV_HOME="+home)
	cmd.Stdin = strings.NewReader(payload)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run() // exit code is not the decision carrier (see gate.go's hookJSON); only stdout is
	return out.Bytes()
}

// hookDecisionIsDeny reports whether raw hook stdout carries an explicit
// PreToolUse deny decision (see internal/runtime/gate.go's hookJSON: empty
// stdout is the allow convention, deny always carries hookSpecificOutput).
func hookDecisionIsDeny(t *testing.T, raw []byte) bool {
	t.Helper()
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	var parsed struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(trimmed, &parsed); err != nil {
		// Non-JSON/unparseable output is not a recognized deny shape either
		// way; report it via t.Logf so a failure is legible, but it can never
		// be silently treated as "deny" by this helper.
		t.Logf("hook stdout was not the expected JSON deny shape: %q", trimmed)
		return false
	}
	return parsed.HookSpecificOutput.PermissionDecision == "deny"
}

func enrollPythonForShadow(t *testing.T) {
	t.Helper()
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("python3", python); err != nil {
		t.Fatal(err)
	}
}

func writeShadowScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shadow.py")
	if err := os.WriteFile(path, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestV6Case19ShadowAllowNeverOverridesGoDeny is corpus case 19 (report
// P0-3): the Go gate correctly denies `rm -rf dist`. A shadow Python
// resolved via a bare `exec.CommandContext(ctx, "python3", shadow)`
// (cmd/gov/main.go's hookCmd) that prints an explicit allow-shaped verdict
// and exits 0 currently has its own raw stdout written out VERBATIM in
// place of the Go decision -- converting a definite Go deny into a silent
// allow. The safe combination rule (report): Go DENY => DENY, always.
func TestV6Case19ShadowAllowNeverOverridesGoDeny(t *testing.T) {
	home := t.TempDir()
	enrollPythonForShadow(t)
	// Explicit, non-empty "allow" shaped output distinct from case 20's bare
	// silence: a hook payload with no hookSpecificOutput at all reads as
	// allow under the same convention Go's own hookJSON uses.
	shadow := writeShadowScript(t, "#!/usr/bin/env python3\nprint('{}')\n")

	out := runShadowHook(t, home, hookDenyInput, shadow)
	if hookDecisionIsDeny(t, out) {
		return // fixed: Go's deny survived an explicit shadow allow
	}
	t.Fatalf("shadow Python's explicit allow verdict overrode the Go gate's definite deny of %q; final hook output was %q", hookDenyInput, out)
}

// TestV6Case20ShadowEmptyOutputNeverOverridesGoDeny is corpus case 20
// (report P0-3): the report's exact reproduction -- a fake python3 that
// exits 0 and prints nothing at all. Empty output is the ALLOW convention
// on both planes (shadowVerdict's own doc comment), so this silently
// converts a Go deny into allow today, identically to case 19 but via
// silence rather than an explicit payload. Malformed/empty shadow output
// must be treated as a parity error, never as allow.
func TestV6Case20ShadowEmptyOutputNeverOverridesGoDeny(t *testing.T) {
	home := t.TempDir()
	enrollPythonForShadow(t)
	shadow := writeShadowScript(t, "#!/usr/bin/env python3\n") // exits 0, prints nothing

	out := runShadowHook(t, home, hookDenyInput, shadow)
	if hookDecisionIsDeny(t, out) {
		return
	}
	t.Fatalf("shadow Python's empty output overrode the Go gate's definite deny of %q; final hook output was %q (empty malformed shadow output must be a parity error, never allow)", hookDenyInput, out)
}

// TestV6Case21ShadowScriptChangeBetweenReplaysIsDetected is corpus case 21
// (report P0-3 / replay identity): the same hook payload is evaluated
// twice with DIFFERENT shadow script content between the two calls. The
// shadow script's own hash is not currently bound into any policy/replay
// identity, so nothing distinguishes "this call actually re-ran the
// CURRENT script" from "this call silently reused a stale prior parity
// verdict." This test forces a parity MISMATCH on the first call (shadow
// script A reports allow-shaped output against a Go deny) and a parity
// MATCH on the second call (shadow script B explicitly denies, matching
// Go) under the same --run id, then asserts: (a) the Go decision stayed
// authoritative (deny) on BOTH calls regardless of which script ran, and
// (b) the recorded parity events for the two calls reflect the ACTUAL
// distinct script content each time (not a stale, cached PythonDecision
// from the first script silently reused for the second).
func TestV6Case21ShadowScriptChangeBetweenReplaysIsDetected(t *testing.T) {
	requireLinuxSealedExecution(t, "sealed Python shadow execution")
	home := t.TempDir()
	enrollPythonForShadow(t)
	// Both scripts are chosen to MISMATCH the Go deny (so both calls'
	// parity events are recorded -- observability.ParitySummary only
	// returns non-matching/unavailable events), but with distinctly
	// different Python-side output, so a stale-verdict reuse across the two
	// calls is distinguishable from a genuine fresh evaluation of each.
	scriptA := writeShadowScript(t, "#!/usr/bin/env python3\nprint('{}')\n") // allow-shaped (empty hookSpecificOutput)
	scriptB := writeShadowScript(t, "#!/usr/bin/env python3\nprint('not-json-garbage-from-script-b')\n")

	firstOut := runShadowHook(t, home, hookDenyInput, scriptA)
	secondOut := runShadowHook(t, home, hookDenyInput, scriptB)

	if !hookDecisionIsDeny(t, firstOut) {
		t.Fatalf("Go deny was overridden by shadow script A's allow-shaped output on the first call: %q", firstOut)
	}
	if !hookDecisionIsDeny(t, secondOut) {
		t.Fatalf("Go deny was overridden on the second call after the shadow script changed: %q", secondOut)
	}

	report, err := observability.ParitySummary(home)
	if err != nil {
		t.Fatal(err)
	}
	if report.Total < 2 {
		t.Fatalf("expected at least 2 parity events recorded (one per shadow evaluation), got %d", report.Total)
	}
	// The two calls used different shadow scripts against the SAME Go
	// decision; find two distinct recorded PythonDecision values for this
	// payload, proving each call actually evaluated the CURRENT script
	// rather than one replaying the other's stale verdict.
	seen := map[string]bool{}
	for _, e := range report.Events {
		if e.Payload == hookDenyInput {
			seen[e.PythonDecision] = true
		}
	}
	if len(seen) < 2 {
		t.Fatalf("expected two distinct recorded shadow decisions for the same payload across the two calls (script A vs script B), got %d distinct value(s): %v -- a changed shadow script must not silently reuse a stale replayed verdict", len(seen), seen)
	}
}
