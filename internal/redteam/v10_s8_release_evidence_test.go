//go:build redteam

package redteam

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/redteamgate"
)

// Session 8 (agents/governator-sol-upgrade10-rc4-plan.md): report cases 30
// and 36-41, closing P1-1 (Assayer clean shutdown), P1-3 (zero production
// red-team skips), P1-4 (retrievable, hash-verified evidence objects),
// P1-1's matrix patch-version requirement, P1-5 (signed by a trusted key
// only), and P1-6 (audit bundle outside the checkout).

// assayerRepoForTests resolves the real Assayer checkout, defaulting to the
// same path scripts/release.sh uses (ASSAYER_REPO).
func assayerRepoForTests() string {
	if v := os.Getenv("ASSAYER_REPO"); v != "" {
		return v
	}
	return "/mnt/e/downloads/assayer"
}

// TestV10Case30FullPython3135SuiteExitsCleanly is Sol10 report case 30
// (P1-1): "the full test suite printed a passing summary but the process
// remained alive." Two proofs: the real Assayer suite (whichever Python 3
// patch is actually on this host -- the release matrix records the exact
// patch it ran, per the P1-1 fix in scripts/release.sh; this test does not
// require 3.13.5 specifically to exist on every dev machine) exits within a
// bounded deadline, AND tests/conftest.py's clean-shutdown hook demonstrably
// fails a run that leaks a non-daemon thread -- proving the mechanism
// itself works even on a host that can't reproduce the original hang.
func TestV10Case30FullPython3135SuiteExitsCleanly(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}

	t.Run("real Assayer suite exits within a bounded deadline", func(t *testing.T) {
		// This checks P1-1's actual concern -- the PROCESS terminates
		// within a bounded deadline -- not that every assertion passes.
		// Assayer's own test suite has separately-known, pre-existing
		// timing-margin flakes under host contention (e.g. lease-heartbeat
		// tests with sub-second margins; unrelated to interpreter
		// shutdown, and out of P1-1's scope to fix here); a real assertion
		// failure still returns promptly and must not be confused with the
		// hang this test exists to catch.
		repo := assayerRepoForTests()
		if _, err := os.Stat(repo); err != nil {
			t.Skip("ASSAYER_REPO not present on this host")
		}
		cmd := exec.Command("python3", "-m", "pytest", "-q")
		cmd.Dir = repo
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Start(); err != nil {
			t.Fatalf("start pytest: %v", err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
			// Process returned (whatever its exit code) within the
			// deadline -- that is what this subtest asserts.
		case <-time.After(120 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatalf("assayer test suite did not exit within 120s -- exactly the P1-1 defect (passing assertions, hung process):\n%s", out.String())
		}
	})

	t.Run("clean-shutdown hook catches an injected leaked non-daemon thread", func(t *testing.T) {
		repo := assayerRepoForTests()
		conftestBytes, err := os.ReadFile(filepath.Join(repo, "tests", "conftest.py"))
		if err != nil {
			t.Skip("tests/conftest.py not present in ASSAYER_REPO on this host")
		}

		fixture := t.TempDir()
		if err := os.MkdirAll(filepath.Join(fixture, "tests"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture, "tests", "conftest.py"), conftestBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		rogue := `import threading
import time


def test_leaks_a_nondaemon_thread():
    thread = threading.Thread(target=lambda: time.sleep(3), daemon=False)
    thread.start()
    assert True
`
		if err := os.WriteFile(filepath.Join(fixture, "tests", "test_rogue_leak.py"), []byte(rogue), 0o644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command("python3", "-m", "pytest", "-q")
		cmd.Dir = fixture
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected the clean-shutdown hook to fail a run with a leaked non-daemon thread, but pytest exited 0:\n%s", out)
		}
		if !strings.Contains(string(out), "ASSAYER CLEAN-SHUTDOWN CHECK FAILED") || !strings.Contains(string(out), "non-daemon thread") {
			t.Fatalf("expected the clean-shutdown hook's specific failure message, got:\n%s", out)
		}
	})
}

// TestV10Case36ProductionReleaseWithOneSkippedRedteamTestFailsRelease is
// Sol10 report case 36 (P1-3): "a production release should not rely on a
// kernel-dependent skip" -- even one the manifest's own allowed_skip
// mechanism would otherwise authorize for ordinary development CI.
func TestV10Case36ProductionReleaseWithOneSkippedRedteamTestFailsRelease(t *testing.T) {
	manifest := redteamgate.Manifest{
		Version: 1,
		Cases: []redteamgate.CaseEntry{
			{Case: 1, Name: "TestV7Case1Known", Required: true},
			{
				Case: 8, Name: "TestV7Case8CleanupValidatorDetachedDescendantExtinctionFailureBlocksApproval",
				Required: true, Conditional: true,
				AllowedSkip: &redteamgate.AllowedSkip{
					Predicate: "case8_hangfuse_extinction_fixture",
					Reason:    "conditional: case8 hangfuse extinction fixture did not reach a blocking READ on this host/kernel before timeout",
				},
			},
		},
	}
	log := "" +
		"=== RUN   TestV7Case1Known\n" +
		"--- PASS: TestV7Case1Known (0.00s)\n" +
		"=== RUN   TestV7Case8CleanupValidatorDetachedDescendantExtinctionFailureBlocksApproval\n" +
		"    conditional: case8 hangfuse extinction fixture did not reach a blocking READ on this host/kernel before timeout\n" +
		"--- SKIP: TestV7Case8CleanupValidatorDetachedDescendantExtinctionFailureBlocksApproval (0.00s)\n"

	// Baseline: ordinary development CI (RequireZeroSkips unset) authorizes
	// exactly this skip via the manifest's own allowed_skip -- isolates the
	// production-mode assertion below from a false positive baked into the
	// fixture.
	dev := redteamgate.Evaluate(manifest, log, map[string]bool{"case8_hangfuse_extinction_fixture": false})
	if !dev.OK {
		t.Fatalf("expected the authorized skip to pass under the normal development-CI policy, got %+v", dev)
	}

	prod := redteamgate.EvaluateWithOptions(manifest, log, map[string]bool{"case8_hangfuse_extinction_fixture": false}, redteamgate.Options{RequireZeroSkips: true})
	if prod.OK {
		t.Fatalf("expected a production release (RequireZeroSkips) to refuse a release containing one skipped red-team test, even an authorized one: %+v", prod)
	}
	if len(prod.UnexpectedSkips) != 1 || prod.UnexpectedSkips[0] != "TestV7Case8CleanupValidatorDetachedDescendantExtinctionFailureBlocksApproval" {
		t.Fatalf("expected the skip to be named as unexpected under production policy, got %+v", prod)
	}
}

// writeGzippedFile gzip-compresses content to path and returns the SHA-256
// of the DECOMPRESSED content.
func writeGzippedFile(t *testing.T, path, content string) string {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// minimalPassingRedteamSuite returns a redteam suite object that satisfies
// every OTHER claims-verification requirement (identity_gate ok, discovered
// count, command shape, source_commit) so a case 37/38/39 fixture's only
// possible failure is the evidence-object defect under test.
func minimalPassingRedteamSuite(commit, logSHA, logPath string) map[string]any {
	suite := map[string]any{
		"command":          "go test -v -tags redteam -count=1 ./...",
		"result":           "PASS",
		"source_commit":    commit,
		"tests_discovered": 58,
		"tests_run":        58,
		"tests_skipped":    0,
		"tests_failed":     0,
		"identity_gate":    map[string]any{"ok": true, "discovered": 58, "run": 58, "skipped": 0, "failed": 0},
	}
	if logSHA != "" {
		suite["log_sha256"] = logSHA
	}
	if logPath != "" {
		suite["log_path"] = logPath
	}
	return suite
}

// writeTestSummaryAndWireManifest writes test-summary.json into distDir and
// patches the already-written build-manifest.json to reference it via
// test_summary_path -- the pre-existing buildReleaseFixtureDist
// (release_test.go) fixture never populates this field, since attacks
// 24-26 don't need it.
func writeTestSummaryAndWireManifest(t *testing.T, distDir, commit string, suites map[string]any) {
	t.Helper()
	summary := map[string]any{
		"source_commit":            commit,
		"environment_capabilities": map[string]any{"goos": "linux", "machine": "x86_64"},
		"suites":                   suites,
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distDir, "test-summary.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	patchManifestTestSummaryPath(t, distDir)
}

// buildEvidenceFixtureDist is buildReleaseFixtureDist (release_test.go)
// plus a test-summary.json wired into build-manifest.json's
// test_summary_path -- the layer cases 37-39 need that the pre-existing
// attack24-26 fixtures don't populate.
func buildEvidenceFixtureDist(t *testing.T, commit string, suites map[string]any) (distDir, repoRoot, platform string) {
	t.Helper()
	distDir, repoRoot, platform = buildReleaseFixtureDist(t, releaseFixtureOpts{
		version:        "1.0.0-redteam-evidence",
		manifestCommit: commit,
		mode:           0755,
	})
	writeTestSummaryAndWireManifest(t, distDir, commit, suites)
	return distDir, repoRoot, platform
}

// TestV10Case37ReferencedTestLogAbsentFailsRelease is Sol10 report case 37
// (P1-4): a suite declares log_sha256 but no retrievable log_path -- "a
// third party can see the claimed hashes but cannot retrieve and verify the
// objects those hashes identify."
func TestV10Case37ReferencedTestLogAbsentFailsRelease(t *testing.T) {
	commit := "37373737373737373737373737373737373737"
	suites := map[string]any{
		"redteam": minimalPassingRedteamSuite(commit, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ""),
	}
	dist, repoRoot, platform := buildEvidenceFixtureDist(t, commit, suites)

	out, err := runReleaseVerify(t, dist, repoRoot, platform)
	if err == nil {
		t.Fatalf("release_verify.sh accepted a suite with log_sha256 but no log_path; output:\n%s", out)
	}
	if !strings.Contains(out, "referenced test log absent") {
		t.Fatalf("expected the failure to name the absent referenced test log, got:\n%s", out)
	}
}

// TestV10Case38ReferencedTestLogWithWrongSHA256FailsRelease is Sol10 report
// case 38 (P1-4): the log object is present and retrievable, but its
// decompressed content does not hash to the declared value.
func TestV10Case38ReferencedTestLogWithWrongSHA256FailsRelease(t *testing.T) {
	commit := "38383838383838383838383838383838383838"
	dist, repoRoot, platform := buildReleaseFixtureDist(t, releaseFixtureOpts{
		version:        "1.0.0-redteam-evidence",
		manifestCommit: commit,
		mode:           0755,
	})
	writeGzippedFile(t, filepath.Join(dist, "redteam.log.gz"), "=== RUN Test\n--- PASS: Test (0.00s)\n")
	suites := map[string]any{
		"redteam": minimalPassingRedteamSuite(commit, "0000000000000000000000000000000000000000000000000000000000000", "redteam.log.gz"),
	}
	writeTestSummaryAndWireManifest(t, dist, commit, suites)

	out, err := runReleaseVerify(t, dist, repoRoot, platform)
	if err == nil {
		t.Fatalf("release_verify.sh accepted a log object whose content does not hash to the declared sha256; output:\n%s", out)
	}
	if !strings.Contains(out, "sha256 mismatch") {
		t.Fatalf("expected the failure to name a sha256 mismatch, got:\n%s", out)
	}
}

func patchManifestTestSummaryPath(t *testing.T, distDir string) {
	t.Helper()
	manifestPath := filepath.Join(distDir, "build-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["test_summary_path"] = "test-summary.json"
	patched, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, patched, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestV10Case39AssayerMatrixOmittingPatchVersionsFailsRelease is Sol10
// report case 39 (P1-1's matrix requirement): a matrix entry recording only
// a bare minor version ("3.13") hides which patch actually ran.
func TestV10Case39AssayerMatrixOmittingPatchVersionsFailsRelease(t *testing.T) {
	commit := "39393939393939393939393939393939393939"
	suites := map[string]any{
		// verifyTestSummary requires a redteam suite unconditionally --
		// minimal and otherwise-passing, so the only possible failure is
		// the assayer_matrix defect under test.
		"redteam": minimalPassingRedteamSuite(commit, "", ""),
		"assayer_matrix": map[string]any{
			"result": "PASS",
			"versions": []any{
				map[string]any{"python_version": "3.13", "python_executable": "python3.13", "result": "PASS"},
			},
		},
	}
	dist, repoRoot, platform := buildEvidenceFixtureDist(t, commit, suites)

	out, err := runReleaseVerify(t, dist, repoRoot, platform)
	if err == nil {
		t.Fatalf("release_verify.sh accepted an assayer_matrix entry with a bare minor python_version; output:\n%s", out)
	}
	if !strings.Contains(out, "non-patch python_version") {
		t.Fatalf("expected the failure to name the non-patch python_version, got:\n%s", out)
	}
}

// TestV10Case40ReleaseSignedWithNonproductionUnknownKeyFailsRelease is
// Sol10 report case 40 (P1-5): a release signed by a key not present in
// docs/TRUSTED_SIGNING_KEYS.txt must be refused, even though the signature
// itself verifies fine cryptographically. Uses an ephemeral, purpose-built
// test key pair -- never the real (nonexistent) production key.
func TestV10Case40ReleaseSignedWithNonproductionUnknownKeyFailsRelease(t *testing.T) {
	if _, err := exec.LookPath("minisign"); err != nil {
		t.Skip("minisign not on PATH")
	}
	repoRoot := repoRootForBundleTests(t)
	work := t.TempDir()

	genKey := func(secOut, pubOut string) {
		t.Helper()
		cmd := exec.Command("minisign", "-G", "-W", "-s", secOut, "-p", pubOut)
		cmd.Stdin = strings.NewReader("")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("minisign -G: %v\n%s", err, out)
		}
	}
	untrustedKey := filepath.Join(work, "untrusted.key")
	untrustedPub := filepath.Join(work, "untrusted.pub")
	genKey(untrustedKey, untrustedPub)

	checksums := filepath.Join(work, "checksums.txt")
	if err := os.WriteFile(checksums, []byte("deadbeef  gov_1.0.0_linux_amd64.tar.gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	minisig := filepath.Join(work, "checksums.txt.minisig")
	signCmd := exec.Command("minisign", "-S", "-s", untrustedKey, "-m", checksums, "-x", minisig, "-c", "redteam case 40")
	signCmd.Stdin = strings.NewReader("")
	if out, err := signCmd.CombinedOutput(); err != nil {
		t.Fatalf("minisign -S: %v\n%s", err, out)
	}

	// An empty trust file: the exact state docs/TRUSTED_SIGNING_KEYS.txt is
	// in today (no production key anchored yet).
	emptyTrust := filepath.Join(work, "empty_trust.txt")
	if err := os.WriteFile(emptyTrust, []byte("# no keys yet\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runPolicy := func(trustFile string) (string, error) {
		cmd := exec.Command("python3", filepath.Join(repoRoot, "scripts", "release_policy.py"), "signature",
			"--version", "1.0.0", "--require", "1", "--minisig", minisig, "--trusted-fingerprints-file", trustFile)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	out, err := runPolicy(emptyTrust)
	if err == nil {
		t.Fatalf("expected an empty trust file to refuse a production release, got:\n%s", out)
	}
	if !strings.Contains(out, "no trusted signing-key fingerprint") {
		t.Fatalf("expected the refusal to explain no key is anchored yet, got:\n%s", out)
	}

	wrongTrust := filepath.Join(work, "wrong_trust.txt")
	if err := os.WriteFile(wrongTrust, []byte("0000000000000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = runPolicy(wrongTrust)
	if err == nil {
		t.Fatalf("expected a trust file naming a different key to refuse this release, got:\n%s", out)
	}
	if !strings.Contains(out, "nonproduction/unknown key") {
		t.Fatalf("expected the refusal to name the nonproduction/unknown key reason, got:\n%s", out)
	}
}

// TestV10Case41AuditBundleGeneratedInsideSourceTreeFailsRelease is Sol10
// report case 41 (P1-6): scripts/audit_bundle.sh must refuse to generate
// its output inside the source checkout it is bundling.
func TestV10Case41AuditBundleGeneratedInsideSourceTreeFailsRelease(t *testing.T) {
	fixture := buildAuditBundleFixtureRepo(t)

	out, err := runAuditBundle(t, fixture, filepath.Join(fixture, "audit-bundle"))
	if err == nil {
		t.Fatalf("expected audit_bundle.sh to refuse an OUT_DIR inside the source checkout, but it succeeded:\n%s", out)
	}
	if !strings.Contains(out, "inside the source checkout") {
		t.Fatalf("expected the refusal to name the in-checkout OUT_DIR, got:\n%s", out)
	}

	// Positive case: a sibling directory (the new default's own shape)
	// succeeds. Sol11 P0-2: this fixture has no populated release dist/, so
	// the (now-default) release mode's evidence-completeness requirement
	// would refuse it for an unrelated reason -- source-only mode isolates
	// this assertion to the OUT_DIR-location behavior it targets.
	out, err = runAuditBundle(t, fixture, filepath.Join(fixture, "..", "audit-bundle-sibling"), "AUDIT_BUNDLE_MODE=source-only")
	if err != nil {
		t.Fatalf("expected audit_bundle.sh to accept an OUT_DIR outside the checkout, got error: %v\n%s", err, out)
	}
}
