//go:build integration

package assay

// TestEvaluateAgainstRealCLIPassAndFail exercises the real Assayer `evaluate`
// subcommand end to end (as opposed to every other test in this package,
// which drives a stub subprocess). It is split into its own file behind the
// `integration` build tag so it is a separate, mandatory CI tier rather than
// part of the fast default `go test ./...` unit run (plan Session 2 item 2:
// "Keep the existing fast stub-subprocess unit tests as a separate, still-
// always-run tier").
//
// It runs only against ASSAYER_REPO, whose clean, tagged identity and package
// tree hash are verified by the package TestMain before any test can run.
import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/integrationharness"
)

func releasedAssayerRepo(t *testing.T) string {
	t.Helper()
	repo := os.Getenv("ASSAYER_REPO")
	if repo == "" {
		t.Fatal("ASSAYER_REPO is required: the integration tier must never fall back to a checked-in fixture")
	}
	return repo
}

func TestEvaluateAgainstRealCLIPassAndFail(t *testing.T) {
	requirePython3Mandatory(t)
	// Sol14 P0-2 (rc7 Session 5): the integration-tier TestMain
	// (assay_integration_testmain_test.go) already fail-closed the whole
	// package before any test ran if enforce.Supported() was false, so this
	// branch is structurally unreachable in the integration tier. It stays
	// as a hard Fatal -- never a t.Skip -- so the defect this case exists
	// to close (a skip hidden behind a package-level `ok` line) can never
	// recur at this name regardless of how a future edit reorders things.
	if !enforce.Supported() {
		t.Fatalf("integration tier reached a test with external enforcement unavailable -- the TestMain should have fail-closed the package first (Sol14 P0-2)")
	}
	repo := releasedAssayerRepo(t)

	dir := t.TempDir()
	content := `{"content":"def add(a, b):\n    return a + b\n","language":"python"}`
	path, sha := writeArtifact(t, dir, content)
	req := baseRequest(sha)
	req.CheckProfile = "coding-output-v2"
	req.ArtifactDeclaredPath = "result.py"
	req.Payload = json.RawMessage(content)

	snap := buildTestSnapshot(t, repo)
	identity, err := integrationharness.ResolveAssayerIdentity(repo, os.Getenv("GOV_INTEGRATION_ASSAYER_COMMIT"))
	if err != nil {
		t.Fatalf("resolve real Assayer identity: %v", err)
	}
	if snap.Identity.PackageTreeHash != identity.PackageTreeHash {
		t.Fatalf("Assayer identity package tree %s does not match sealed Snapshot tree %s", identity.PackageTreeHash, snap.Identity.PackageTreeHash)
	}
	v := Evaluate(context.Background(), Config{Repo: repo, Python: "python3"}, req, path, snap)
	if v.Verdict != VerdictPass {
		t.Fatalf("expected pass verdict against real assayer CLI, got %+v", v)
	}
	if v.ChecksResultHash == "" {
		t.Fatal("expected a non-empty checks_result_hash")
	}
	if v.ProfileDefinitionHash == "" {
		t.Fatal("expected a non-empty profile_definition_hash")
	}
	if v.ValidatorImplementationHash == "" {
		t.Fatal("expected a non-empty validator_implementation_hash")
	}
	if v.ValidatorConfigHash == "" {
		t.Fatal("expected a non-empty validator_config_hash")
	}

	// Now a payload missing the required field -> fail.
	badContent := `{}`
	badPath, badSHA := writeArtifact(t, dir, badContent)
	badReq := baseRequest(badSHA)
	badReq.CheckProfile = "coding-output-v2"
	badReq.Payload = json.RawMessage(`{}`)

	badV := Evaluate(context.Background(), Config{Repo: repo, Python: "python3"}, badReq, badPath, snap)
	if badV.Verdict != VerdictFail {
		t.Fatalf("expected fail verdict for missing required field, got %+v", badV)
	}
	if len(badV.FailedChecks) == 0 {
		t.Fatal("expected at least one failed check name")
	}
}

// requirePython3Mandatory differs from the fast tier's requirePython3
// (assay_test.go): that one t.Skips, appropriate for an environment gap
// unrelated to the Assayer boundary itself. Here, in the tier the plan
// declares mandatory, "python3 isn't on PATH" IS the blocking Assayer
// boundary failing to execute — so it must fail the job, not skip it.
func requirePython3Mandatory(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatalf("python3 not available: %v (mandatory integration tier: this must fail CI, not skip)", err)
	}
}
