//go:build redteam

// v15_s3_exact_artifact_test.go is rc8-upg15 Session 3's corpus, cases
// 362-368 (Sol15 P0-4 "Mandatory integration does not test the exact final
// executable" and P2-2's manifest-schema mismatch). Session 3 inverted the
// release order (build final -> archive -> extract -> integrate -> accept),
// deleted the separate dynamically-linked dist/integration-gov build, and
// wired the mandatory integration harness through enforce.SelfExeFDOverride
// so the fd-backed /proc/self/exe route -- not SelfExeOverride's
// sealed-copy pathname route -- is what the mandatory suite actually
// exercises. These seven cases prove each of Sol's seven named
// "Exact-artifact attacks" is caught: a tampered byte, a CGO/link-mode
// mismatch, an unpackaged/self-built candidate, a post-integration rebuild,
// a same-UID swap back to the pathname helper, the fd route's presence
// itself, and a manifest/archive binary mismatch.
package redteam

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/claims"
	"github.com/cousingary/governator/internal/redteamgate"
)

// v15S3BuildVariant builds ./cmd/gov at the real repo root with the given
// CGO_ENABLED setting, returning the built binary's path. Reused by cases
// 362/363 to obtain genuinely distinct, real executables rather than
// fabricated hashes -- Sol's own reproduction was the real fb70a417
// (dynamic) vs d3592a92 (static) SHA divergence, and these tests reproduce
// that divergence live rather than asserting against literal strings that
// could drift from the real toolchain's behavior.
func v15S3BuildVariant(t *testing.T, cgoEnabled string) string {
	t.Helper()
	root := v14S5RepoRoot(t)
	work := t.TempDir()
	out := filepath.Join(work, "gov")
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "./cmd/gov")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED="+cgoEnabled)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build CGO_ENABLED=%s candidate: %v: %s", cgoEnabled, err, output)
	}
	return out
}

// v15S3Evidence writes a harness evidence JSON that otherwise satisfies every
// EvaluateIntegrationWithOptions check (real fd-backed route, proven
// sandbox, recorded Assayer identity) except the ONE field each case
// overrides -- isolating each rejection to the single attack under test
// rather than an incidental fixture gap.
func v15S3Evidence(t *testing.T, dir, pkg string, override func(*redteamgate.HarnessEvidence)) {
	t.Helper()
	hev := redteamgate.HarnessEvidence{
		GovernorBinarySHA256: strings.Repeat("a", 64),
		GovernorBinarySource: "env",
		EnforceSupported:     true,
		SandboxMechanism:     "landlock+unshare (enforce.Supported)",
		AssayerSource:        "n/a (contextgraph)",
		AssayerClean:         true,
		SelfExeRoute:         "fd-override",
	}
	if override != nil {
		override(&hev)
	}
	b, err := json.Marshal(hev)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, pkg+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func v15S3PassingLog(name string) string {
	return `{"Action":"run","Package":"example/contextgraph","Test":"` + name + `"}` + "\n" +
		`{"Action":"pass","Package":"example/contextgraph","Test":"` + name + `"}`
}

const v15S3ExpectedTest = "TestPrepareBuildsFingerprintAndQueries"

func TestV15Case362IntegrationExecutableDifferingByOneByteFailsTheGate(t *testing.T) {
	genuine := v15S3BuildVariant(t, "0")
	genuineSHA := v14S5SHA256(t, genuine)

	data, err := os.ReadFile(genuine)
	if err != nil {
		t.Fatal(err)
	}
	tamperedData := append([]byte(nil), data...)
	tamperedData[len(tamperedData)-1] ^= 0xFF
	tampered := filepath.Join(t.TempDir(), "gov")
	if err := os.WriteFile(tampered, tamperedData, 0o755); err != nil {
		t.Fatal(err)
	}
	tamperedSHA := v14S5SHA256(t, tampered)
	if tamperedSHA == genuineSHA {
		t.Fatal("flipping the last byte did not change the sha256 -- fixture is broken")
	}

	dir := t.TempDir()
	v15S3Evidence(t, dir, "contextgraph", func(hev *redteamgate.HarnessEvidence) {
		hev.GovernorBinarySHA256 = tamperedSHA
	})
	res := redteamgate.EvaluateIntegrationWithOptions(v15S3PassingLog(v15S3ExpectedTest), []string{v15S3ExpectedTest}, redteamgate.IntegrationOptions{
		HarnessEvidencePath:          dir,
		ExpectedEvidencePackages:     []string{"contextgraph"},
		ExpectedGovernorBinarySHA256: genuineSHA,
	})
	if res.OK {
		t.Fatalf("gate accepted an integration executable differing by one tampered byte: %+v", res)
	}
}

func TestV15Case363IntegrationExecutableWithDifferentCGOSettingFailsTheGate(t *testing.T) {
	static := v15S3BuildVariant(t, "0")
	dynamic := v15S3BuildVariant(t, "1")
	staticSHA := v14S5SHA256(t, static)
	dynamicSHA := v14S5SHA256(t, dynamic)
	if staticSHA == dynamicSHA {
		t.Fatal("CGO_ENABLED=0 and CGO_ENABLED=1 builds unexpectedly hashed identically -- fixture cannot reproduce Sol's fb70a417/d3592a92 divergence on this host")
	}
	if staticOut, err := exec.Command("file", static).CombinedOutput(); err == nil {
		t.Logf("static build: %s", strings.TrimSpace(string(staticOut)))
	}
	if dynamicOut, err := exec.Command("file", dynamic).CombinedOutput(); err == nil {
		t.Logf("dynamic build: %s", strings.TrimSpace(string(dynamicOut)))
	}

	dir := t.TempDir()
	v15S3Evidence(t, dir, "contextgraph", func(hev *redteamgate.HarnessEvidence) {
		// The dynamically linked (default-CGO) build stands in for the
		// deleted dist/integration-gov -- the exact object Sol found the
		// mandatory suite was actually testing instead of the shipped,
		// statically linked release binary.
		hev.GovernorBinarySHA256 = dynamicSHA
	})
	res := redteamgate.EvaluateIntegrationWithOptions(v15S3PassingLog(v15S3ExpectedTest), []string{v15S3ExpectedTest}, redteamgate.IntegrationOptions{
		HarnessEvidencePath:          dir,
		ExpectedEvidencePackages:     []string{"contextgraph"},
		ExpectedGovernorBinarySHA256: staticSHA,
	})
	if res.OK {
		t.Fatalf("gate accepted a dynamically linked (default-CGO) integration executable in place of the static release build: %+v", res)
	}
}

func TestV15Case364IntegrationExecutableFromUnpackagedPathIsRejected(t *testing.T) {
	sha := strings.Repeat("c", 64)
	dir := t.TempDir()
	v15S3Evidence(t, dir, "contextgraph", func(hev *redteamgate.HarnessEvidence) {
		hev.GovernorBinarySHA256 = sha
		// "built" means the TestMain's ResolveGovBinary fell back to
		// compiling its own throwaway candidate (a standalone/unpackaged
		// dev run) rather than receiving GOV_INTEGRATION_GOV_BIN from the
		// release. Even a byte-for-byte matching hash must not satisfy a
		// release-bound (ExpectedGovernorBinarySHA256-supplied) gate here.
		hev.GovernorBinarySource = "built"
	})
	res := redteamgate.EvaluateIntegrationWithOptions(v15S3PassingLog(v15S3ExpectedTest), []string{v15S3ExpectedTest}, redteamgate.IntegrationOptions{
		HarnessEvidencePath:          dir,
		ExpectedEvidencePackages:     []string{"contextgraph"},
		ExpectedGovernorBinarySHA256: sha,
	})
	if res.OK {
		t.Fatalf("gate accepted a self-built/unpackaged integration binary for a release-bound run: %+v", res)
	}
}

func TestV15Case365RebuildAfterIntegrationFailsTheRelease(t *testing.T) {
	genuine := v15S3BuildVariant(t, "0")
	sha := v14S5SHA256(t, genuine)
	if err := redteamgate.VerifyArtifactUnchanged("host executable", sha, sha); err != nil {
		t.Fatalf("identical hashes were rejected as a rebuild: %v", err)
	}

	// Simulate a rebuild happening after the integration checkpoint changing
	// the artifact's bytes at the recorded path. This host's Go 1.26
	// toolchain happens to produce reproducible builds with -trimpath (a
	// second independent `go build` of identical source can hash
	// identically), so a real second `go build` cannot be trusted to
	// reliably differ -- flipping one byte deterministically reproduces
	// "the artifact at this path no longer matches what integration bound,"
	// which is the exact property this guard exists to catch, without
	// depending on the host toolchain's incidental (non-)reproducibility.
	data, err := os.ReadFile(genuine)
	if err != nil {
		t.Fatal(err)
	}
	rebuiltData := append([]byte(nil), data...)
	rebuiltData[0] ^= 0xFF
	rebuilt := filepath.Join(t.TempDir(), "gov")
	if err := os.WriteFile(rebuilt, rebuiltData, 0o755); err != nil {
		t.Fatal(err)
	}
	rebuiltSHA := v14S5SHA256(t, rebuilt)
	if rebuiltSHA == sha {
		t.Fatal("simulated rebuild did not change the sha256 -- fixture is broken")
	}
	if err := redteamgate.VerifyArtifactUnchanged("host executable", sha, rebuiltSHA); err == nil {
		t.Fatal("a rebuild that changed the artifact's sha256 after integration was not detected")
	}
}

func TestV15Case366PathnameHelperSwappedDuringTestIsDetected(t *testing.T) {
	dir := t.TempDir()
	v15S3Evidence(t, dir, "contextgraph", func(hev *redteamgate.HarnessEvidence) {
		// Simulates a same-UID swap back to the sealed-copy pathname route
		// (enforce.SelfExeOverride) mid-test, instead of the mandatory
		// tier's required fd-backed enforce.SelfExeFDOverride route.
		hev.SelfExeRoute = "pathname"
	})
	res := redteamgate.EvaluateIntegrationWithOptions(v15S3PassingLog(v15S3ExpectedTest), []string{v15S3ExpectedTest}, redteamgate.IntegrationOptions{
		HarnessEvidencePath:      dir,
		ExpectedEvidencePackages: []string{"contextgraph"},
	})
	if res.OK || res.HarnessOK {
		t.Fatalf("gate accepted evidence recording the pathname (sealed-copy) self-exec route: %+v", res)
	}
}

func TestV15Case367ProcSelfExeDescriptorRouteIsRequiredInMandatoryIntegration(t *testing.T) {
	requireLinuxSealedExecution(t, "/proc/self/exe descriptor-routed integration execution")
	_, evidenceDir, log := v14S5CandidateAndTier(t, "^"+v15S3ExpectedTest+"$", "./internal/contextgraph")
	res := redteamgate.EvaluateIntegrationWithOptions(log, []string{v15S3ExpectedTest}, redteamgate.IntegrationOptions{
		HarnessEvidencePath:      evidenceDir,
		ExpectedEvidencePackages: []string{"contextgraph"},
	})
	if !res.OK {
		t.Fatalf("real mandatory integration run was rejected: %+v", res)
	}
	data, err := os.ReadFile(filepath.Join(evidenceDir, "contextgraph.json"))
	if err != nil {
		t.Fatal(err)
	}
	var hev redteamgate.HarnessEvidence
	if err := json.Unmarshal(data, &hev); err != nil {
		t.Fatal(err)
	}
	if hev.SelfExeRoute != "fd-override" {
		t.Fatalf("real mandatory integration run recorded self_exe_route %q, want %q (the production fd-backed route)", hev.SelfExeRoute, "fd-override")
	}
}

func TestV15Case368ArchiveBinaryAndManifestBinaryMismatchFailsTheRelease(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	v15S3RunGit(t, root, "init")
	v15S3RunGit(t, root, "config", "user.email", "test@example.com")
	v15S3RunGit(t, root, "config", "user.name", "test")
	v15S3WriteFile(t, root, "go.mod", "module example.com/v15case368\n\ngo 1.22\n")
	v15S3WriteFile(t, root, "docs/claims.yaml", "version: 1\nclaims: []\n")
	v15S3WriteFile(t, root, "cmd/gov/main.go", `package main

import (
	"encoding/json"
	"fmt"
	"os"
)

var version = "dev"
var sourceCommit = "unknown"
var claimsHash = "unknown"

func main() {
	if len(os.Args) == 3 && os.Args[1] == "version" && os.Args[2] == "--json" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": version, "source_commit": sourceCommit, "claims_hash": claimsHash, "dirty": false})
		return
	}
	fmt.Println("gov", version)
}
`)
	v15S3RunGit(t, root, "add", ".")
	v15S3RunGit(t, root, "commit", "-m", "seed")
	commit := v15S3RunGitOutput(t, root, "rev-parse", "HEAD")
	claimsHash := v14S5SHA256(t, filepath.Join(root, "docs", "claims.yaml"))

	genuine := filepath.Join(root, "gov-genuine")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", genuine,
		"-ldflags", "-X main.version=v1.0.0 -X main.sourceCommit="+commit+" -X main.claimsHash="+claimsHash,
		"./cmd/gov")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build genuine artifact: %v: %s", err, out)
	}
	genuineSHA := v14S5SHA256(t, genuine)
	wrongSHA := strings.Repeat("d", 64)
	if wrongSHA == genuineSHA {
		t.Fatal("fixture collision")
	}

	redteamLogHash := v15S3GzipLog(t, filepath.Join(root, "evidence", "redteam.log.gz"), "=== RUN TestPlaceholder\n--- PASS: TestPlaceholder (0.00s)\nPASS\n")
	v15S3WriteFile(t, root, "evidence/test-summary.json", `{
  "source_commit": "`+commit+`",
  "environment_capabilities": {"goos": "test", "machine": "test"},
  "suites": {
    "redteam": {
      "command": "go test -v -tags redteam -count=1 ./...",
      "result": "PASS",
      "source_commit": "`+commit+`",
      "log_sha256": "`+redteamLogHash+`",
      "log_path": "redteam.log.gz",
      "tests_discovered": 58,
      "tests_run": 58,
      "tests_skipped": 0,
      "tests_failed": 0,
      "identity_gate": {"ok": true, "discovered": 58, "run": 58, "skipped": 0, "failed": 0}
    }
  }
}`)
	manifestPath := filepath.Join(root, "evidence", "release.json")
	// rc8-upg15 S3 (Sol15 P2-2) schema: archive_path/archive_sha256 name the
	// archive; executable_path/executable_sha256 name the contained binary.
	// executable_sha256 here is deliberately WRONG -- the manifest's claim
	// about the shipped executable's hash does not match the real artifact
	// this test points --artifact at, reproducing "archive binary and
	// manifest binary mismatch" directly against the production verifier
	// (internal/claims.verifyArtifactManifest), not a stand-in.
	v15S3WriteFile(t, root, "evidence/release.json", `{
  "version": "v1.0.0",
  "source_commit": "`+commit+`",
  "go_version": "",
  "build_flags": "test ldflags",
  "archive_path": "`+filepath.ToSlash(genuine)+`",
  "archive_sha256": "archive-sha-unused-in-this-test",
  "executable_path": "`+filepath.ToSlash(genuine)+`",
  "executable_sha256": "`+wrongSHA+`",
  "build_info": {},
  "claims_hash": "`+claimsHash+`",
  "test_run_id": "unit-test",
  "test_result": "PASS",
  "test_summary_path": "test-summary.json",
  "acceptance_run_id": "acceptance-test",
  "acceptance_result": "PASS"
}`)

	results, err := claims.VerifyWithOptions(root, claims.Document{}, claims.VerifyOptions{
		ArtifactPath: genuine,
		ManifestPath: manifestPath,
	})
	if err != nil {
		t.Fatalf("VerifyWithOptions: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].OK() {
		t.Fatalf("release-artifact verification accepted a manifest executable_sha256 that does not match the real archived binary: %+v", results[0])
	}
	var found bool
	for _, p := range results[0].Problems {
		if strings.Contains(p, "sha256 mismatch") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("verification was rejected, but not for the archive/manifest sha256 mismatch under test -- problems: %q", results[0].Problems)
	}
}

func v15S3WriteFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func v15S3RunGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func v15S3RunGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// v15S3GzipLog writes content gzip-compressed to path (mirroring
// release.sh's own per-tier log compression) and returns the DECOMPRESSED
// content's sha256 -- test-summary.json's log_sha256 fields always describe
// the decompressed bytes, matching verifyTestSummary's own expectation.
func v15S3GzipLog(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}
