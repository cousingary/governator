package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGateParityF1F7 is the Phase 5 DONE criterion: the Go gate must reproduce
// the Python harness_gate.py decision matrix across the F1-F7 finding set before
// the Python hooks retire. Every case documents the finding it exercises and the
// expected verdict (allow/deny + which axis decided). A mismatch here blocks the
// cutover — Python stays the live enforcer until this table is green.
func TestGateParityF1F7(t *testing.T) {
	// Build a protected-paths manifest the F2/F4 cases reference.
	protected := t.TempDir()
	protectedFile := filepath.Join(protected, "feed.xml")
	if err := os.WriteFile(protectedFile, []byte("finished\n"), 0600); err != nil {
		t.Fatal(err)
	}
	protectedDir := filepath.Join(protected, "done")
	if err := os.MkdirAll(protectedDir, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "protected_paths.txt")
	content := protectedFile + "\n" + protectedDir + "/\n"
	if err := os.WriteFile(manifest, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_PATHS", manifest)
	t.Setenv("HARNESS_UNLOCK", "")

	cwd, _ := os.Getwd()
	tests := []struct {
		name      string
		input     GateInput
		wantAllow bool
		wantAxis  string // which F-axis must decide (empty = don't assert)
	}{
		// --- F3: hardened classify_shell_command (high_danger_only) ---------
		{"F3 rm -rf blocks", GateInput{"Bash", map[string]any{"command": "rm -rf dist"}, cwd, ""}, false, "F3"},
		{"F3 find -exec rm blocks", GateInput{"Bash", map[string]any{"command": "find . -exec rm {} +"}, cwd, ""}, false, "F3"},
		{"F3 git push main blocks", GateInput{"Bash", map[string]any{"command": "git push origin main"}, cwd, ""}, false, "F3"},
		{"F3 git force push blocks", GateInput{"Bash", map[string]any{"command": "git push --force origin feat"}, cwd, ""}, false, "F3"},
		{"F3 DROP TABLE blocks", GateInput{"Bash", map[string]any{"command": "psql -c 'DROP TABLE users'"}, cwd, ""}, false, "F3"},
		{"F3 dd to device blocks", GateInput{"Bash", map[string]any{"command": "dd if=/dev/zero of=/dev/sda"}, cwd, ""}, false, "F3"},
		{"F3 routine rm file allows", GateInput{"Bash", map[string]any{"command": "rm scratch.txt"}, cwd, ""}, true, "F3"},
		{"F3 go test allows", GateInput{"Bash", map[string]any{"command": "go test ./..."}, cwd, ""}, true, "F3"},
		{"F3 ls allows", GateInput{"Bash", map[string]any{"command": "ls -la"}, cwd, ""}, true, "F3"},

		// --- F2: protected-path Write/Edit/MultiEdit gate -------------------
		{"F2 Write to protected file blocks", GateInput{"Write", map[string]any{"file_path": protectedFile}, cwd, ""}, false, "F2"},
		{"F2 Edit to protected file blocks", GateInput{"Edit", map[string]any{"file_path": protectedFile}, cwd, ""}, false, "F2"},
		{"F2 MultiEdit to protected file blocks", GateInput{"MultiEdit", map[string]any{"file_path": protectedFile}, cwd, ""}, false, "F2"},
		{"F2 Write to scratch allows", GateInput{"Write", map[string]any{"file_path": filepath.Join(t.TempDir(), "x.go")}, cwd, ""}, true, "F2"},

		// --- F4: Bash-plane protected-path enforcement (args + redirects) ---
		// The actual 86-file class: an opaque script naming the protected dir.
		{"F4 opaque script on protected dir blocks", GateInput{"Bash", map[string]any{"command": "python build.py --dir " + protectedDir}, cwd, ""}, false, "F4"},
		{"F4 rm protected file blocks", GateInput{"Bash", map[string]any{"command": "rm " + protectedFile}, cwd, ""}, false, "F4"},
		{"F4 redirect into protected file blocks", GateInput{"Bash", map[string]any{"command": "echo x > " + protectedFile}, cwd, ""}, false, "F4"},
		{"F4 read-only cat of protected allows", GateInput{"Bash", map[string]any{"command": "cat " + protectedFile}, cwd, ""}, true, "F3"},
		{"F4 ls of protected dir allows", GateInput{"Bash", map[string]any{"command": "ls " + protectedDir}, cwd, ""}, true, "F3"},
		{"F4 unprotected rm allows", GateInput{"Bash", map[string]any{"command": "rm " + filepath.Join(t.TempDir(), "scratch.txt")}, cwd, ""}, true, "F3"},

		// --- F1: degraded denylist (fail-closed when full eval unavailable) -
		{"F1 degraded rm -rf blocks", GateInput{"Bash", map[string]any{"command": "rm -rf /tmp/x"}, cwd, ""}, false, "F1"},
		{"F1 degraded shred blocks", GateInput{"Bash", map[string]any{"command": "shred secret.key"}, cwd, ""}, false, "F1"},
		{"F1 degraded mkfs blocks", GateInput{"Bash", map[string]any{"command": "mkfs.ext4 /dev/sda1"}, cwd, ""}, false, "F1"},
		{"F1 degraded routine allows", GateInput{"Bash", map[string]any{"command": "echo hello"}, cwd, ""}, true, "F1"},

		// --- default: non-Bash non-mutating tools always allow --------------
		{"default Read allows", GateInput{"Read", map[string]any{"file_path": protectedFile}, cwd, ""}, true, "default"},
		{"default Grep allows", GateInput{"Grep", map[string]any{"pattern": "x"}, cwd, ""}, true, "default"},

		// --- HARNESS_UNLOCK escape hatch (mirrors Python) -------------------
		{"unlock Write to protected allows", GateInput{"Write", map[string]any{"file_path": protectedFile}, cwd, ""}, true, "F2"},
	}

	for i, tc := range tests {
		// Special-case the unlock test by setting the env for just that case.
		if tc.name == "unlock Write to protected allows" {
			t.Setenv("HARNESS_UNLOCK", "all")
		}
		t.Run(tc.name, func(t *testing.T) {
			var decision GateDecision
			if tc.wantAxis == "F1" {
				decision = GateDegradedDecide(tc.input, "test degradation")
			} else {
				decision = GateDecide(tc.input)
			}
			if decision.Allow != tc.wantAllow {
				t.Fatalf("case %d: allow=%v want %v (axis=%s reason=%s)", i, decision.Allow, tc.wantAllow, decision.Finding, decision.Reason)
			}
			if tc.wantAxis != "" && decision.Finding != tc.wantAxis {
				t.Fatalf("case %d: deciding axis=%s want %s", i, decision.Finding, tc.wantAxis)
			}
		})
		if tc.name == "unlock Write to protected allows" {
			// HARNESS_UNLOCK was set via t.Setenv; the deferred restore handles cleanup,
			// but we must not leak it into subsequent cases in this loop. t.Setenv is
			// test-scoped so it only affects this goroutine; reset explicitly for safety.
			os.Unsetenv("HARNESS_UNLOCK")
		}
	}
}

// TestGateF5NeverFailsOpen asserts the F5 invariant: GateDecide never panics
// on malformed input, and destructive content still blocks even when the input
// is degenerate. A nil map is the harshest degenerate input the public API can
// receive; it must not crash and an empty command correctly allows (nothing to
// evaluate). The deferred recover that converts any real panic into a degraded
// decision is exercised structurally + by the F1 denylist cases above.
func TestGateF5NeverFailsOpen(t *testing.T) {
	// Degenerate input must not panic and must return a coherent decision.
	d := GateDecide(GateInput{ToolName: "Bash", ToolInput: nil})
	if !d.Allow {
		t.Fatalf("empty command should allow, got %#v", d)
	}
	// Destructive content in a degraded (F1) context must still block — proving
	// the fail-closed path holds when full evaluation is unavailable.
	d = GateDegradedDecide(GateInput{ToolName: "Bash", ToolInput: map[string]any{"command": "rm -rf /tmp/x"}}, "test")
	if d.Allow {
		t.Fatalf("degraded rm -rf must block, got %#v", d)
	}
}

// TestHookJSONOnlyEmitsOnDeny is Finding #2: an explicit "allow" bypasses
// Claude Code's entire permission system for that call, so hookJSON (and thus
// EmitHookJSON's stdout) must stay silent on allow — only deny carries a
// hookSpecificOutput payload, matching harness_gate.py's _emit_block.
func TestHookJSONOnlyEmitsOnDeny(t *testing.T) {
	if b := hookJSON(GateDecision{Allow: true, Finding: "F3"}); b != nil {
		t.Fatalf("allow must emit nil, got %s", b)
	}
	if b := hookJSON(GateDecision{Allow: true, Degraded: true, Finding: "F1"}); b != nil {
		t.Fatalf("degraded allow must emit nil, got %s", b)
	}
	b := hookJSON(GateDecision{Allow: false, Reason: "nope", Finding: "F3"})
	if b == nil {
		t.Fatal("deny must emit JSON, got nil")
	}
	var payload map[string]any
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatalf("deny JSON invalid: %v", err)
	}
	spec, ok := payload["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("missing hookSpecificOutput: %s", b)
	}
	if spec["permissionDecision"] != "deny" {
		t.Fatalf(`want permissionDecision":"deny", got %v`, spec["permissionDecision"])
	}
}

// TestBashProtectedPathTildeExpansion is Finding #3: resolveArg must expand a
// leading ~ (mirroring Python's os.path.expanduser) before matching against
// the protected-paths manifest, or `rm ~/feed.xml` resolves relative to cwd
// and silently fails open.
func TestBashProtectedPathTildeExpansion(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	protectedFile := filepath.Join(tmpHome, "feed.xml")
	if err := os.WriteFile(protectedFile, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "protected_paths.txt")
	if err := os.WriteFile(manifest, []byte(protectedFile+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_PATHS", manifest)
	t.Setenv("HARNESS_UNLOCK", "")

	d := GateDecide(GateInput{ToolName: "Bash", ToolInput: map[string]any{"command": "rm ~/feed.xml"}})
	if d.Allow {
		t.Fatalf("expected rm ~/feed.xml to be blocked, got %#v", d)
	}
	if d.Finding != "F4" {
		t.Fatalf("expected F4 to decide, got %s (reason=%s)", d.Finding, d.Reason)
	}
}

// TestPreflightSnapshotIfDelete is Finding #4: a command the high-danger gate
// ALLOWS but full classification calls a delete must trigger a best-effort
// recovery snapshot; non-deletes and already-blocked high-danger deletes must
// not.
func TestPreflightSnapshotIfDelete(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	scriptDir := t.TempDir()
	markerDir := t.TempDir()
	marker := filepath.Join(markerDir, "marker")
	script := filepath.Join(scriptDir, "fake_recall.py")
	body := fmt.Sprintf("import pathlib\npathlib.Path(%q).touch()\n", marker)
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HARNESS_SNAPSHOT_DIR", t.TempDir())
	t.Setenv("GOV_RECALL_SCRIPT", script)

	PreflightSnapshotIfDelete("rm scratch.txt")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("expected snapshot marker after allowed delete: %v", err)
	}
	os.Remove(marker)

	PreflightSnapshotIfDelete("go test ./...")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("snapshot must not fire for a non-delete command")
	}

	PreflightSnapshotIfDelete("rm -rf x")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("snapshot must not fire for an already-blocked high-danger delete")
	}
}

func FuzzBashProtectedReason(f *testing.F) {
	root := f.TempDir()
	manifest := filepath.Join(f.TempDir(), "protected-paths.txt")
	if err := os.WriteFile(manifest, []byte(root+"/\n"), 0o600); err != nil {
		f.Fatal(err)
	}
	f.Setenv("GOV_PROTECTED_PATHS", manifest)
	f.Setenv("HARNESS_UNLOCK", "")
	for _, seed := range []string{
		"cat " + root + "/safe.txt",
		"rm -rf " + root,
		"echo changed > " + root + "/file",
		"go test ./...",
	} {
		f.Add(seed, root)
	}
	f.Fuzz(func(t *testing.T, command, cwd string) {
		if len(command) > 16*1024 || len(cwd) > 4*1024 {
			t.Skip()
		}
		_ = bashProtectedReason(command, cwd)
	})
}
