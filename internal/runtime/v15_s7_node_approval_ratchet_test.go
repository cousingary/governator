//go:build redteam

// v15_s7_node_approval_ratchet_test.go is rc8-upg15 Session 7's P2-1
// ratchet, case 390 (Sol15 P2-1 "Node tree can still be transiently mutated
// during local execution"). Sol15 classifies the same-UID mutation window as
// a residual containment limitation, not an rc8 blocker: the copied Node
// dependency tree is pre-hashed and post-hashed (persistent tampering is
// detected) but remains same-UID mutable between the two hashes, so a
// same-UID process could mutate a dependency mid-run and restore the
// approved bytes before the post-run hash. What bounds the impact is the
// policy boundary nodeBackendApprovalViolation (runtime.go): local Node
// execution may proceed for development but can NEVER produce a production
// approval -- digest-pinned Docker is required for approval.
//
// This case is the ratchet on that property. It fails if the mitigation is
// ever weakened: both at the policy-function level (every runner class) and
// end-to-end (a local Node run with a fully PROVEN dependency closure and
// otherwise-valid output must still not reach APPROVED). Session 7 discloses
// the residual window in docs/containment.md rather than rebuilding it;
// Sol15's six long-term options (immutable mount, read-only bind mount,
// sealed content-addressed filesystem, separate UID, stable descriptors,
// digest-pinned container for every security-sensitive Node backend) are
// recorded there as rc9+ candidates.
package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
)

func TestV15Case390LocalNodeBackendCannotProduceApprovingOutcome(t *testing.T) {
	const provenClosure = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	local := contracts.Contract{Local: &contracts.LocalRunnerConfig{}}
	if got := local.EffectiveRunner(); got != "local" {
		t.Fatalf("sanity: default contract runner = %q, want local", got)
	}
	reason := nodeBackendApprovalViolation(provenClosure, local)
	if reason == "" {
		t.Fatal("nodeBackendApprovalViolation(proven closure, local runner) = \"\"; a local Node backend must never be approving -- the same-UID mutation window is bounded ONLY by this policy boundary (Sol15 P2-1)")
	}
	if !strings.Contains(reason, "same-UID") {
		t.Fatalf("local-runner rejection reason %q must name the specific residual limitation (same-UID mutability), not a generic label", reason)
	}

	mutableTag := contracts.Contract{Runner: "docker", Docker: &contracts.DockerRunnerConfig{Image: "example/node-backend:latest"}}
	if reason := nodeBackendApprovalViolation(provenClosure, mutableTag); reason == "" {
		t.Fatal("nodeBackendApprovalViolation(proven closure, mutable-tag docker) = \"\"; approval requires a DIGEST-PINNED image, a mutable tag is not an immutable execution boundary")
	}
	shortDigest := contracts.Contract{Runner: "docker", Docker: &contracts.DockerRunnerConfig{Image: "example/node-backend@sha256:deadbeef"}}
	if reason := nodeBackendApprovalViolation(provenClosure, shortDigest); reason == "" {
		t.Fatal("nodeBackendApprovalViolation(proven closure, truncated digest) = \"\"; a truncated digest is not a valid content-addressed pin")
	}

	digestPinned := contracts.Contract{Runner: "docker", Docker: &contracts.DockerRunnerConfig{Image: "example/node-backend@sha256:" + strings.Repeat("ab", 32)}}
	if reason := nodeBackendApprovalViolation(provenClosure, digestPinned); reason != "" {
		t.Fatalf("nodeBackendApprovalViolation(proven closure, digest-pinned docker) = %q; digest-pinned Docker IS the approving boundary and must remain so -- the disclosure bounds the window, it does not ban Node work", reason)
	}

	if reason := nodeBackendApprovalViolation("", local); reason != "" {
		t.Fatalf("nodeBackendApprovalViolation(no closure, local runner) = %q; non-Node backends (empty dependency closure) are not subject to the Node policy boundary", reason)
	}

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the end-to-end local Node approval ratchet")
	}

	root, _ := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)

	backendDir := t.TempDir()
	entry := filepath.Join(backendDir, "cli.js")
	body := "#!" + node + "\n" + `
const fs = require("fs");
const dep = require("dep");
fs.mkdirSync("output", {recursive: true});
fs.writeFileSync("output/result.txt", dep + "\n");
fs.writeFileSync("RESULT.json", '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n');
process.stdout.write('{"type":"result","total_cost_usd":0.01}\n');
`
	if err := os.WriteFile(entry, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backendDir, "package.json"), []byte(`{"name":"ratchet-node-fixture"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	depDir := filepath.Join(backendDir, "node_modules", "dep")
	if err := os.MkdirAll(depDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(depDir, "package.json"), []byte(`{"name":"dep","main":"index.js"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(depDir, "index.js"), []byte("module.exports = 'approved-dependency-bytes';\n"), 0o644); err != nil {
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
	// Under the enforce wrap the frozen closure's private directory is
	// outside the Landlock plan's read closure (built from the backend's
	// CanonicalPath, not the frozen launchPath), so the backend's own exec
	// is denied on this host. That does not weaken this ratchet: the Node
	// approval boundary is evaluated at the approval decision regardless of
	// the backend's execution outcome, and the assertions below require the
	// exact LOCAL_NODE_BACKEND_NON_APPROVING violation with a proven
	// closure. (The denied dev-exec is a separate latent path, disclosed in
	// the Session 7 commit; closing it is rc9+ work, not this ratchet.)
	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status == "APPROVED" {
		t.Fatalf("local Node backend with a PROVEN dependency closure reached APPROVED (message %q) -- the same-UID mutation window is no longer bounded; local Node execution must never produce a production approval (Sol15 P2-1)", rec.Message)
	}
	if !strings.Contains(rec.Message, "LOCAL_NODE_BACKEND_NON_APPROVING") {
		t.Fatalf("local Node run blocked for %q instead of the Node policy boundary; the run must fail specifically because local Node closures are same-UID mutable (Sol15 P2-1), status=%s", rec.Message, rec.Status)
	}
	if strings.Contains(rec.Message, "NODE_DEPENDENCY_CLOSURE_UNPROVEN") {
		t.Fatalf("fixture's dependency closure was NOT proven (message %q) -- this case ratchets the approval boundary for PROVEN closures, re-check the fixture", rec.Message)
	}
}
