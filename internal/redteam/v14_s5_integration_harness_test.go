//go:build redteam

package redteam

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

func v14S5RepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func v14S5CandidateAndTier(t *testing.T, pattern string, packages ...string) (string, string, string) {
	t.Helper()
	root := v14S5RepoRoot(t)
	work := t.TempDir()
	candidate := filepath.Join(work, "gov")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", candidate, "./cmd/gov")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build exact integration candidate: %v: %s", err, output)
	}
	evidenceDir := filepath.Join(work, "evidence")
	args := []string{"test", "-json", "-tags", "integration", "-p", "2", "-parallel", "2", "-count=1", "-run", pattern}
	args = append(args, packages...)
	tier := exec.Command("go", args...)
	tier.Dir = root
	// A release runs this corpus from an isolated Governator worktree, so
	// Assayer is not its sibling there. Honor the exact checkout the release
	// pinned; retain the sibling default only for a standalone local run.
	assayerRepo := os.Getenv("ASSAYER_REPO")
	if assayerRepo == "" {
		assayerRepo = filepath.Join(filepath.Dir(root), "assayer")
	}
	if info, statErr := os.Stat(assayerRepo); statErr != nil || !info.IsDir() {
		t.Fatalf("required ASSAYER_REPO %q is not a readable directory: %v", assayerRepo, statErr)
	}
	tier.Env = append(os.Environ(), "ASSAYER_REPO="+assayerRepo, "GOV_INTEGRATION_GOV_BIN="+candidate, "GOV_INTEGRATION_EVIDENCE_OUT="+evidenceDir)
	output, err := tier.CombinedOutput()
	if err != nil {
		t.Fatalf("mandatory integration tier: %v: %s", err, output)
	}
	return candidate, evidenceDir, string(output)
}

func v14S5SHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestV14Case319IntegrationTestMainDoesNotForceEnforcementUnsupported(t *testing.T) {
	root := v14S5RepoRoot(t)
	unit, err := os.ReadFile(filepath.Join(root, "internal", "assay", "assay_unit_testmain_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	integration, err := os.ReadFile(filepath.Join(root, "internal", "assay", "assay_integration_testmain_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "//go:build !integration") || !strings.Contains(string(unit), "enforce.ForceUnsupported = true") {
		t.Fatal("unit TestMain must be !integration-scoped and retain its unit-only ForceUnsupported fixture")
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "assay_integration_testmain_test.go", integration, 0)
	if err != nil {
		t.Fatal(err)
	}
	forced := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if selector, ok := lhs.(*ast.SelectorExpr); ok && selector.Sel.Name == "ForceUnsupported" {
				forced = true
			}
		}
		return true
	})
	if forced {
		t.Fatal("integration TestMain must never force external enforcement unsupported")
	}
	if !strings.Contains(string(integration), "integrationharness.Setup") {
		t.Fatal("integration TestMain must establish the real governed sandbox through integrationharness.Setup")
	}
}

func TestV14Case320IntegrationTierWithZeroTestsIsRejected(t *testing.T) {
	res := redteamgate.EvaluateIntegration("", []string{"TestRequiredIntegration"}, "")
	if res.OK || res.TestsRun != 0 || len(res.MissingTests) != 1 {
		t.Fatalf("zero-test integration tier was accepted: %+v", res)
	}
}

func TestV14Case321IntegrationTierWithAnySkipIsRejected(t *testing.T) {
	log := `{"Action":"run","Package":"example/integration","Test":"TestRequiredIntegration"}
{"Action":"skip","Package":"example/integration","Test":"TestRequiredIntegration"}`
	res := redteamgate.EvaluateIntegration(log, []string{"TestRequiredIntegration"}, "")
	if res.OK || len(res.SkippedTests) != 1 || res.SkippedTests[0] != "TestRequiredIntegration" {
		t.Fatalf("skipped integration test was accepted: %+v", res)
	}
}

func TestV14Case322RealGovernatorSandboxHelperExecutes(t *testing.T) {
	candidate, evidenceDir, log := v14S5CandidateAndTier(t, "^TestEvaluateAgainstRealCLIPassAndFail$", "./internal/assay")
	res := redteamgate.EvaluateIntegrationWithOptions(log, []string{"TestEvaluateAgainstRealCLIPassAndFail"}, redteamgate.IntegrationOptions{
		HarnessEvidencePath:          evidenceDir,
		ExpectedGovernorBinarySHA256: v14S5SHA256(t, candidate),
		ExpectedEvidencePackages:     []string{"assay"},
	})
	if !res.OK {
		t.Fatalf("real Assayer integration did not prove the candidate gov sandbox helper executed: %+v", res)
	}
}

func TestV14Case323ContextGraphInitSyncAndQueryThroughRealSandbox(t *testing.T) {
	candidate, evidenceDir, log := v14S5CandidateAndTier(t, "^TestPrepareBuildsFingerprintAndQueries$", "./internal/contextgraph")
	res := redteamgate.EvaluateIntegrationWithOptions(log, []string{"TestPrepareBuildsFingerprintAndQueries"}, redteamgate.IntegrationOptions{
		HarnessEvidencePath:          evidenceDir,
		ExpectedGovernorBinarySHA256: v14S5SHA256(t, candidate),
		ExpectedEvidencePackages:     []string{"contextgraph"},
	})
	if !res.OK {
		t.Fatalf("context-graph init/sync/query did not run through the real governed sandbox: %+v", res)
	}
}
