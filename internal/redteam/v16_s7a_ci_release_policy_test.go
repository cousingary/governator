//go:build redteam

package redteam

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func s7aScript(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(repoRootForBundleTests(t), "scripts", name)
}

func s7aCIEnv() []string {
	return append(os.Environ(), "GITHUB_ACTIONS=true", "GITHUB_REPOSITORY=cousingary/governator",
		"GITHUB_WORKFLOW=Release",
		"GITHUB_WORKFLOW_REF=cousingary/governator/.github/workflows/release.yml@refs/tags/v1.0.2-rc10",
		"GITHUB_EVENT_NAME=push", "GITHUB_REF=refs/tags/v1.0.2-rc10", "GITHUB_REF_NAME=v1.0.2-rc10",
		"GITHUB_SHA=1111111111111111111111111111111111111111", "GITHUB_RUN_ID=123",
		"GITHUB_RUN_ATTEMPT=1", "RUNNER_OS=Linux", "RUNNER_ARCH=X64",
		"GOV_RELEASE_RUNNER_LABEL=ubuntu-24.04", "ImageOS=ubuntu24", "ImageVersion=20260727.1")
}

func s7aCIPolicy(t *testing.T, dir, tool string) string {
	t.Helper()
	path := filepath.Join(dir, "ci-policy.yaml")
	body := "schema_version: 2\nprofile: github-hosted-ephemeral\nrunner_label: ubuntu-24.04\nrunner_arch: X64\ntools:\n  " +
		tool + ":\n    command: " + tool + "\n    declared_source: runner-image\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestV16Case403ReviewedBytesProfileRemainsUnchanged(t *testing.T) {
	work := t.TempDir()
	tool := s4WriteTool(t, work, "#!/bin/sh\necho stable\n")
	policy := s4WritePolicy(t, work, tool)
	if out, err := s4Toolset(t, policy, filepath.Join(work, "toolset.json"), false); err != nil {
		t.Fatalf("reviewed-bytes regression: %v\n%s", err, out)
	}
}

func TestV16Case404ForgedGitHubEnvironmentNeverAuthenticatesMeasurements(t *testing.T) {
	work := t.TempDir()
	policy := s7aCIPolicy(t, work, "bash")
	outPath := filepath.Join(work, "toolset.json")
	toolbin := filepath.Join(work, "toolbin")
	t.Cleanup(func() { _ = os.Chmod(toolbin, 0o700) })
	cmd := exec.Command("python3", s7aScript(t, "release_toolset.py"), "--policy", policy,
		"--profile", "github-hosted-ephemeral", "--tools", "bash", "--out", outPath,
		"--toolbin", toolbin)
	cmd.Env = s7aCIEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CI measurement fixture: %v\n%s", err, out)
	}
	raw, _ := os.ReadFile(outPath)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	record := doc["tools"].([]any)[0].(map[string]any)
	if doc["authenticated"] != false || record["measured"] == nil || record["approved"] != nil {
		t.Fatal("runner-controlled input authenticated or mislabeled its own measurements")
	}
	if target, err := filepath.EvalSymlinks(filepath.Join(toolbin, "bash")); err != nil || target == "" {
		t.Fatalf("CI private toolbin was not built from the measured identity: %v", err)
	}
}

func TestV16Case405MutableActionOrRunnerReferenceIsRejected(t *testing.T) {
	workflow := filepath.Join(t.TempDir(), "release.yml")
	_ = os.WriteFile(workflow, []byte("jobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"), 0o644)
	out, err := exec.Command("python3", s7aScript(t, "builder_provenance.py"),
		"--workflow", workflow, "--check-workflow").CombinedOutput()
	if err == nil || (!strings.Contains(string(out), "MUTABLE_OR_UNLISTED_RUNNER") &&
		!strings.Contains(string(out), "MUTABLE_ACTION_REF")) {
		t.Fatalf("mutable workflow accepted: %v\n%s", err, out)
	}
}

func TestV16Case406MismatchedCIIdentityIsRejected(t *testing.T) {
	work := t.TempDir()
	policy := s7aCIPolicy(t, work, "bash")
	for name, override := range map[string]string{
		"repository":   "GITHUB_REPOSITORY=attacker/fork",
		"workflow-tag": "GITHUB_WORKFLOW_REF=cousingary/governator/.github/workflows/release.yml@refs/tags/v1.0.2-rc11",
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command("python3", s7aScript(t, "release_toolset.py"), "--policy", policy,
				"--profile", "github-hosted-ephemeral", "--tools", "bash",
				"--out", filepath.Join(work, name+".json"))
			cmd.Env = append(s7aCIEnv(), override)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "CI_IDENTITY_MISMATCH") {
				t.Fatalf("mismatched CI identity accepted: %v\n%s", err, out)
			}
		})
	}
}

func TestV16Case407CIToolChangedAfterMeasurementFailsVerification(t *testing.T) {
	work := t.TempDir()
	fakeBin := filepath.Join(work, "bin")
	_ = os.Mkdir(fakeBin, 0o755)
	tool := filepath.Join(fakeBin, "citool")
	_ = os.WriteFile(tool, []byte("#!/bin/sh\necho one\n"), 0o755)
	policy := s7aCIPolicy(t, work, "citool")
	outPath := filepath.Join(work, "toolset.json")
	env := append(s7aCIEnv(), "PATH="+fakeBin+":"+os.Getenv("PATH"))
	record := exec.Command("python3", s7aScript(t, "release_toolset.py"), "--policy", policy,
		"--profile", "github-hosted-ephemeral", "--tools", "citool", "--out", outPath)
	record.Env = env
	if out, err := record.CombinedOutput(); err != nil {
		t.Fatalf("record: %v\n%s", err, out)
	}
	_ = os.WriteFile(tool, []byte("#!/bin/sh\necho two\n"), 0o755)
	verify := exec.Command("python3", s7aScript(t, "release_toolset.py"), "--policy", policy,
		"--profile", "github-hosted-ephemeral", "--tools", "citool", "--verify", outPath)
	verify.Env = env
	out, err := verify.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "TOOLSET_VERIFICATION_FAILED") {
		t.Fatalf("changed CI tool accepted: %v\n%s", err, out)
	}
}

func TestV16Case408CIMeasurementCannotSerializeApprovedIdentity(t *testing.T) {
	content, _ := os.ReadFile(s7aScript(t, "release_toolset.py"))
	if !strings.Contains(string(content), "CI measurement is mislabeled approved/observed") {
		t.Fatal("CI verifier has no fail-closed approved-label rejection")
	}
}

func TestV16Case409BuilderProvenanceIsCoveredByChecksums(t *testing.T) {
	content, _ := os.ReadFile(s7aScript(t, "release.sh"))
	src := string(content)
	if generate, cover := strings.Index(src, `--out "$OUT_DIR/builder-provenance.json"`),
		strings.Index(src, `checksum_inputs+=(builder-provenance.json)`); generate < 0 || cover <= generate {
		t.Fatal("builder-provenance.json lacks post-generation checksum coverage")
	}
}

func TestV16Case410MissingOrMismatchedGitHubAttestationBlocksVerification(t *testing.T) {
	content, _ := os.ReadFile(s7aScript(t, "bundle_verify.py"))
	for _, required := range []string{"--signer-workflow", "--source-ref", "--source-digest",
		"--signer-digest", "--deny-self-hosted-runners", "GITHUB_PROVENANCE_INVALID"} {
		if !strings.Contains(string(content), required) {
			t.Fatalf("provenance verifier omits %q", required)
		}
	}
}

func TestV16Case411ReleaseWorkflowPassesStaticHostedPolicy(t *testing.T) {
	workflow := filepath.Join(repoRootForBundleTests(t), ".github", "workflows", "release.yml")
	if out, err := exec.Command("python3", s7aScript(t, "builder_provenance.py"),
		"--workflow", workflow, "--check-workflow").CombinedOutput(); err != nil {
		t.Fatalf("real release workflow violates hosted policy: %v\n%s", err, out)
	}
}

func TestV16Case412CILocalArchiveByteComparisonRemainsMandatory(t *testing.T) {
	work := t.TempDir()
	local, ci := filepath.Join(work, "local"), filepath.Join(work, "ci")
	_ = os.Mkdir(local, 0o755)
	_ = os.Mkdir(ci, 0o755)
	name := "gov_1.0.2-rc10_linux_amd64.tar.gz"
	_ = os.WriteFile(filepath.Join(local, name), []byte("local"), 0o644)
	_ = os.WriteFile(filepath.Join(ci, name), []byte("different"), 0o644)
	out, err := exec.Command("python3", s7aScript(t, "compare_release_builds.py"),
		"--local-dist", local, "--ci-dist", ci).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "CI_LOCAL_BYTE_IDENTITY_MISMATCH") {
		t.Fatalf("different local/CI archives accepted: %v\n%s", err, out)
	}
}

func TestV16Case413TierVerificationPropagatesExplicitCIProfile(t *testing.T) {
	tierContent, err := os.ReadFile(s7aScript(t, "release_tier_pipeline.sh"))
	if err != nil {
		t.Fatal(err)
	}
	tier := string(tierContent)
	if !strings.Contains(tier, `--toolset-profile) TOOLSET_PROFILE=$2`) {
		t.Fatal("tier runner does not accept an explicit toolset profile")
	}
	if strings.Count(tier, `--profile "$TOOLSET_PROFILE"`) != 2 {
		t.Fatal("tier runner must pass its explicit profile to both pre- and post-tier verification")
	}

	releaseContent, err := os.ReadFile(s7aScript(t, "release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(releaseContent), `--toolset-profile "$RELEASE_TOOL_PROFILE"`) {
		t.Fatal("release pipeline does not propagate its selected profile to the tier runner")
	}
}

func TestV16Case414ReleaseTiersUseAttemptScopedTrustedToolRegistry(t *testing.T) {
	content, err := os.ReadFile(s7aScript(t, "release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(content)
	for _, required := range []string{
		`TEST_TOOL_REGISTRY="$OUT_DIR/.test-tools.yaml"`,
		`GOV_TOOLREGISTRY_FILE="$TEST_TOOL_REGISTRY" "$INTEGRATION_GOV_BIN" tools enroll`,
		`"git:$GIT_TOOL" "bash:$BASH_TOOL" "python3:$PYTHON_TOOL"`,
	} {
		if !strings.Contains(src, required) {
			t.Fatalf("release pipeline omits attempt-scoped registry contract %q", required)
		}
	}
	if strings.Count(src, `GOV_TOOLREGISTRY_FILE=%q`) != 7 {
		t.Fatal("all six test tiers plus the integration gate must receive the attempt-scoped registry")
	}
}

func TestV16Case415GenericCIPythonUsesTrustedRunnerImage(t *testing.T) {
	policy := s7aScript(t, "release_tool_policy_ci.yaml")
	content, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	src := string(content)
	if !strings.Contains(src, "  python3:\n    command: /usr/bin/python3\n    declared_source: runner-image\n") {
		t.Fatal("generic CI python3 must use the root-owned runner-image interpreter")
	}
	for _, version := range []string{"3.10", "3.11", "3.12", "3.13"} {
		want := "  python" + version + ":\n    command: python" + version + "\n    declared_source: actions/setup-python\n"
		if !strings.Contains(src, want) {
			t.Fatalf("explicit Python %s matrix entry must remain supplied by setup-python", version)
		}
	}
	cmd := exec.Command("python3", s7aScript(t, "release_toolset.py"),
		"--policy", policy, "--profile", "github-hosted-ephemeral",
		"--tools", "python3", "--out", filepath.Join(t.TempDir(), "toolset.json"))
	cmd.Env = s7aCIEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("absolute root-owned runner-image python policy rejected: %v\n%s", err, out)
	}
}

func TestV16Case416HostedAssayerCheckoutRetainsPinnedReleaseTag(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repoRootForBundleTests(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(content)
	checkout := "repository: ${{ vars.ASSAYER_REPOSITORY || 'cousingary/assayer' }}\n" +
		"          ref: ${{ steps.assayer-ref.outputs.ref }}\n" +
		"          path: assayer\n" +
		"          fetch-depth: 0"
	if !strings.Contains(src, checkout) {
		t.Fatal("hosted Assayer checkout must retain tag history for exact pinned-release identity")
	}
}

func TestV16Case417HostedRunnerEnablesMandatoryLinuxContainment(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repoRootForBundleTests(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content),
		"sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0") {
		t.Fatal("Ubuntu 24.04 hosted release must enable the mandatory Landlock+unshare containment path")
	}
}
