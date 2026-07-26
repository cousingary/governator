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

// TestV13Case37UnprovenClosureCannotApprove is Sol #32 / manifest 282. It
// runs the normal merge path with a Node backend whose node_modules link
// escapes the package. The backend itself produces otherwise-valid output;
// approval must be blocked specifically because its dependency closure cannot
// be frozen and identified.
func TestV13Case37UnprovenClosureCannotApprove(t *testing.T) {
	root, _ := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the Node closure approval fixture")
	}
	backendDir := t.TempDir()
	entry := filepath.Join(backendDir, "cli.js")
	body := "#!" + node + "\n" + `
const fs = require("fs");
fs.mkdirSync("output", {recursive: true});
fs.writeFileSync("output/result.txt", "ok\\n");
fs.writeFileSync("RESULT.json", '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\\n");
process.stdout.write('{"type":"result","total_cost_usd":0.01}\\n');
`
	if err := os.WriteFile(entry, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backendDir, "package.json"), []byte(`{"name":"unsafe-node-fixture"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(backendDir, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(t.TempDir(), "live-dep")
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "index.js"), []byte("module.exports = 'live';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(live, filepath.Join(backendDir, "node_modules", "dep")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CLAUDE_BIN", entry)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	c := contract(root)
	if closure, cerr := enforce.ExecutableReadClosure(node); cerr == nil {
		c.Local.ReadRoots = append(c.Local.ReadRoots, closure...)
	}
	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status == "APPROVED" {
		t.Fatalf("unproven Node dependency closure reached APPROVED: %s", rec.Message)
	}
	if !strings.Contains(rec.Message, "NODE_DEPENDENCY_CLOSURE_UNPROVEN") {
		t.Fatalf("expected closure violation, got status=%s message=%q", rec.Status, rec.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); err == nil {
		t.Fatal("unproven closure merged work into the live root before quarantine")
	}
}
