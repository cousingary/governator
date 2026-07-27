//go:build redteam

package redteam

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// v11_s3_audit_bundle_evidence_test.go is the Sol v11 rc5 Session 3 corpus
// (agents/governator-sol-upgrade11-rc5-plan.md Session 3,
// agents/governator-sol-upgrade11.md P0-2): report corpus cases 11, 12, 17
// -- "An interrupted release is accepted as a valid audit bundle". Every
// test drives the REAL scripts/audit_bundle_validate.py (the release-mode
// evidence-completeness gate scripts/audit_bundle.sh now calls) as an
// actual OS subprocess against a synthetic dist/ fixture.

func s3AuditValidateScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(s3RepoRoot(t), "scripts", "audit_bundle_validate.py")
}

func s3GitCommit(t *testing.T, repo string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// s3InitRepo creates a minimal git repo with one commit, returning its
// path and HEAD commit.
func s3InitRepo(t *testing.T) (repo, commit string) {
	t.Helper()
	repo = t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=redteam", "GIT_AUTHOR_EMAIL=redteam@example.com", "GIT_COMMITTER_NAME=redteam", "GIT_COMMITTER_EMAIL=redteam@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "redteam@example.com")
	run("config", "user.name", "redteam")
	if err := os.WriteFile(filepath.Join(repo, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-q", "-m", "init")
	return repo, s3GitCommit(t, repo)
}

// s3RunAuditValidate runs the real scripts/audit_bundle_validate.py against
// distDir and returns its combined output + error.
func s3RunAuditValidate(t *testing.T, distDir, repo, releaseCommit string) (string, error) {
	t.Helper()
	cmd := exec.Command("python3", s3AuditValidateScript(t),
		"--dist-dir", distDir, "--repo", repo, "--release-commit", releaseCommit)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// s3WriteGzippedLog gzip-compresses content to path and returns the sha256
// of the DECOMPRESSED content.
// s3IdentityGate is the `gov redteam-gate verify` verdict a real release ships
// at test-summary.json suites.redteam.identity_gate. audit_bundle_validate
// validates production red-team skips through it BY IDENTITY -- gate ok,
// strict zero-skip mode, no failures, and no unauthorized skips -- rather than
// by a raw tests_skipped count, which could never reach 0 on any single host
// and could not tell a dropped claim from a coverage gap (rc6 Session 9).
// Every fixture claiming to be a complete dist must supply it.
func s3IdentityGate() map[string]any {
	return map[string]any{
		"ok":                 true,
		"require_zero_skips": true,
		"discovered":         58,
		"run":                58,
		"skipped":            0,
		"failed":             0,
		"inventory_supplied": true,
		"unexpected_skips":   []string{},
	}
}

func s3WriteGzippedLog(t *testing.T, path, content string) string {
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

// s3WriteDummyArchive writes a minimal, valid gzipped tar archive so the
// "at least one platform archive present" existence check is satisfied
// without needing a real gov binary.
func s3WriteDummyArchive(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	data := []byte("fake-binary-bytes")
	hdr := &tar.Header{Name: "gov", Mode: 0o755, Size: int64(len(data))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// s3TierNames is the six main go-test tiers audit_bundle_validate.py
// requires evidence for.
var s3TierNames = []string{"unit", "race", "integration", "corpus", "redteam", "redteam_race"}

// s3BuildCompleteDist assembles a synthetic dist/ directory that satisfies
// EVERY release-mode requirement audit_bundle_validate.py checks (short of
// cryptographic signature, which is only checked when
// --trusted-fingerprints-file/--trusted-public-keys-dir are passed -- these
// tests omit them, exactly like a local unsigned dry-run release). Returns
// the dist dir; callers corrupt/omit specific pieces per case.
func s3BuildCompleteDist(t *testing.T, commit string) string {
	t.Helper()
	dist := t.TempDir()
	s3WriteDummyArchive(t, filepath.Join(dist, "gov_1.0.0-test_linux_amd64.tar.gz"))
	for _, name := range []string{"checksums.txt", "checksums.txt.minisig", "architecture-build-metadata.json", "sbom.json", "claims.yaml", "claims-verify-report.txt", "preflight.json", "toolset.json"} {
		if err := os.WriteFile(filepath.Join(dist, name), []byte("placeholder\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := map[string]any{"source_commit": commit, "version": "1.0.0-test"}
	writeJSON(t, filepath.Join(dist, "build-manifest.json"), manifest)
	writeJSON(t, filepath.Join(dist, "acceptance-summary.json"), map[string]any{"overall_result": "PASS"})

	suites := map[string]any{}
	for _, tier := range s3TierNames {
		logName := strings.ReplaceAll(tier, "_", "-") + ".log.gz"
		sha := s3WriteGzippedLog(t, filepath.Join(dist, logName), tier+" ok\n")
		suites[tier] = map[string]any{
			"result":        "PASS",
			"log_path":      logName,
			"log_sha256":    sha,
			"tests_skipped": 0,
		}
		if tier == "redteam" {
			// A real release always carries the gate's structured verdict here,
			// and audit_bundle_validate validates production skips by identity
			// through it rather than by raw count (rc6 Session 9). A fixture
			// without it is not a complete dist.
			suites[tier].(map[string]any)["identity_gate"] = s3IdentityGate()
		}
	}
	writeJSON(t, filepath.Join(dist, "test-summary.json"), map[string]any{
		"overall_result": "PASS",
		"suites":         suites,
	})
	return dist
}

func writeJSON(t *testing.T, path string, data any) {
	t.Helper()
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestV11Case18TruncatedTestLogFailsReleaseEvidenceValidation is corpus
// case 11: "truncated test log". Every required file is present and
// test-summary.json is internally self-consistent EXCEPT the redteam
// tier's gzip'd log has been modified/truncated AFTER its sha256 was
// recorded -- the mere-existence check alone (P0-2's baseline) would miss
// this; the content-hash cross-check must catch it.
func TestV11Case18TruncatedTestLogFailsReleaseEvidenceValidation(t *testing.T) {
	repo, commit := s3InitRepo(t)
	dist := s3BuildCompleteDist(t, commit)

	// Truncate the redteam log AFTER test-summary.json already recorded its
	// original (longer) content's hash.
	if err := os.WriteFile(filepath.Join(dist, "redteam.log.gz"), []byte("not even gzip, and definitely not the original content"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := s3RunAuditValidate(t, dist, repo, commit)
	if err == nil {
		t.Fatalf("expected audit_bundle_validate.py to reject a truncated/modified test log, got success:\n%s", out)
	}
	if !strings.Contains(out, "TRUNCATED_OR_MODIFIED_TEST_LOG") && !strings.Contains(out, "could not be decompressed") {
		t.Fatalf("expected the failure to name the truncated/modified log, got:\n%s", out)
	}
}

// TestV11Case19NonemptyDistWithOnlyOneLogFailsReleaseEvidenceValidation is
// corpus case 12: "nonempty dist/ containing only one log" -- the exact
// rc4 state the P0-2 finding was found against (dist/ = a single
// test-unit.log, nothing else).
func TestV11Case19NonemptyDistWithOnlyOneLogFailsReleaseEvidenceValidation(t *testing.T) {
	repo, commit := s3InitRepo(t)
	dist := t.TempDir()
	if err := os.WriteFile(filepath.Join(dist, "test-unit.log"), []byte("=== RUN TestSomething\n--- PASS: TestSomething (0.00s)\nPASS\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := s3RunAuditValidate(t, dist, repo, commit)
	if err == nil {
		t.Fatalf("expected audit_bundle_validate.py to reject a dist/ containing only test-unit.log, got success:\n%s", out)
	}
	if !strings.Contains(out, "INCOMPLETE_RELEASE_EVIDENCE") {
		t.Fatalf("expected INCOMPLETE_RELEASE_EVIDENCE, got:\n%s", out)
	}
	// Every category of missing evidence should be named, not just the
	// first one found -- proves this isn't a fail-on-first-file check that
	// happens to catch this one case by luck.
	for _, want := range []string{"platform archive", "checksums.txt", "build-manifest.json"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected the failure to name missing %q, got:\n%s", want, out)
		}
	}
}

// TestV11Case24AuditBundleBeforeFinalManifestFails is corpus case 17:
// "audit bundle generated before final manifest". Every OTHER release
// artifact exists (archives, checksums, signature placeholder, SBOM,
// claims, summaries, evidence logs) but build-manifest.json itself -- the
// document release.sh writes LAST, only once test and acceptance evidence
// are both already finalized -- is absent, simulating exactly a bundle
// generated mid-pipeline, after most tiers completed but before the
// manifest step ran.
func TestV11Case24AuditBundleBeforeFinalManifestFails(t *testing.T) {
	repo, commit := s3InitRepo(t)
	dist := s3BuildCompleteDist(t, commit)
	if err := os.Remove(filepath.Join(dist, "build-manifest.json")); err != nil {
		t.Fatal(err)
	}

	out, err := s3RunAuditValidate(t, dist, repo, commit)
	if err == nil {
		t.Fatalf("expected audit_bundle_validate.py to reject a dist/ missing build-manifest.json, got success:\n%s", out)
	}
	if !strings.Contains(out, "INCOMPLETE_RELEASE_EVIDENCE") || !strings.Contains(out, "build-manifest.json") {
		t.Fatalf("expected INCOMPLETE_RELEASE_EVIDENCE naming build-manifest.json, got:\n%s", out)
	}
}

// TestV11Case18BPositiveCompleteDistPassesValidation is not a numbered
// corpus case -- it proves s3BuildCompleteDist itself represents a
// genuinely PASSING release (isolating the three failing cases above from
// a fixture-construction bug that would make every one of them trivially
// "pass" for the wrong reason).
func TestV11Case18BPositiveCompleteDistPassesValidation(t *testing.T) {
	repo, commit := s3InitRepo(t)
	dist := s3BuildCompleteDist(t, commit)
	out, err := s3RunAuditValidate(t, dist, repo, commit)
	if err != nil {
		t.Fatalf("expected a genuinely complete dist/ to pass validation, got error: %v\n%s", err, out)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("expected an OK verdict, got:\n%s", out)
	}
}
