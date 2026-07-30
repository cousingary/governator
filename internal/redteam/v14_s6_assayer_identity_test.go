//go:build redteam

package redteam

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

func v14S6PassingLog(name string) string {
	return `{"Action":"run","Package":"example/assay","Test":"` + name + `"}` + "\n" +
		`{"Action":"pass","Package":"example/assay","Test":"` + name + `"}`
}

func v14S6Evidence(t *testing.T, commit string) string {
	t.Helper()
	dir := t.TempDir()
	write := `{"governor_binary_sha256":"gov","governor_binary_source":"env","enforce_supported":true,"sandbox_mechanism":"landlock+unshare (enforce.Supported)","self_exe_route":"fd-override","assayer_source":"ASSAYER_REPO","assayer_commit":"` + commit + `","assayer_version":"1.1.10","assayer_tag":"v1.1.10","assayer_package_tree_hash":"tree","assayer_schema_version":"0004","assayer_python_runtime":"Python 3.12","assayer_clean":true}`
	if err := os.WriteFile(filepath.Join(dir, "assay.json"), []byte(write), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestV14Case324RealAssayerPassVerdictIsHonored(t *testing.T) {
	candidate, evidence, log := v14S5CandidateAndTier(t, "^TestEvaluateAgainstRealCLIPassAndFail$", "./internal/assay")
	if res := redteamgate.EvaluateIntegrationWithOptions(log, []string{"TestEvaluateAgainstRealCLIPassAndFail"}, redteamgate.IntegrationOptions{HarnessEvidencePath: evidence, ExpectedGovernorBinarySHA256: v14S5SHA256(t, candidate), ExpectedEvidencePackages: []string{"assay"}, ExpectedAssayerCommit: "c509318637bbcc02c7802b7489f9c65bf8621e5d"}); !res.OK {
		t.Fatalf("real Assayer pass/fail bridge was not accepted: %+v", res)
	}
}

func TestV14Case325RealAssayerFailVerdictIsHonored(t *testing.T) {
	v14S6RequireBridge(t, "TestEvaluateAgainstRealCLIPassAndFail")
}
func TestV14Case326AssayerNonzeroExitIsError(t *testing.T) {
	v14S6RequireBridge(t, "TestEvaluateNonzeroExitIsError")
}
func TestV14Case327AssayerTimeoutIsError(t *testing.T) { v14S6RequireBridge(t, "TestEvaluateTimeout") }
func TestV14Case328MalformedAssayerOutputIsError(t *testing.T) {
	v14S6RequireBridge(t, "TestEvaluateUnparseableStdoutIsError")
}
func TestV14Case329PostEvaluationArtifactMutationIsDetected(t *testing.T) {
	v14S6RequireBridge(t, "TestEvaluateShaMismatchAfterEvaluationIsError")
}

func v14S6RequireBridge(t *testing.T, name string) {
	t.Helper()
	candidate, evidence, log := v14S5CandidateAndTier(t, "^"+name+"$", "./internal/assay")
	if res := redteamgate.EvaluateIntegrationWithOptions(log, []string{name}, redteamgate.IntegrationOptions{HarnessEvidencePath: evidence, ExpectedGovernorBinarySHA256: v14S5SHA256(t, candidate), ExpectedEvidencePackages: []string{"assay"}}); !res.OK {
		t.Fatalf("mandatory bridge test %s was not accepted: %+v", name, res)
	}
}

func TestV14Case330AssayerCheckoutCommitMustEqualReleaseCommit(t *testing.T) {
	commit := "c509318637bbcc02c7802b7489f9c65bf8621e5d"
	res := redteamgate.EvaluateIntegrationWithOptions(v14S6PassingLog("TestIdentity"), []string{"TestIdentity"}, redteamgate.IntegrationOptions{HarnessEvidencePath: v14S6Evidence(t, commit), ExpectedGovernorBinarySHA256: "gov", ExpectedEvidencePackages: []string{"assay"}, ExpectedAssayerCommit: "different"})
	if res.OK {
		t.Fatalf("integration gate accepted Assayer evidence for the wrong release commit: %+v", res)
	}
}
