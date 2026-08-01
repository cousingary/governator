//go:build redteam

package redteam

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/assay"
)

// Session 8 (agents/governator-sol-upgrade7-plan.md): Assayer fail-closed +
// close-out re-cut. Corpus cases 37, 38.

// assayerVerifyScript locates scripts/assayer_verify.sh the same way
// release_test.go's releaseVerifyScript locates release_verify.sh.
func assayerVerifyScript(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	return filepath.Join(repoRoot, "scripts", "assayer_verify.sh")
}

// buildAssayerRepoFixture creates a minimal git repo shaped like the real
// Assayer checkout: a pyproject.toml declaring [project] version, committed.
// If tag is non-empty, it is created pointing at the current HEAD before any
// caller-supplied post-tag commit runs.
func buildAssayerRepoFixture(t *testing.T, version string) (repoDir string) {
	t.Helper()
	repoDir = t.TempDir()
	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
	}
	run("git", "init", "-q")
	run("git", "config", "user.email", "redteam@example.test")
	run("git", "config", "user.name", "redteam")
	pyproject := "[project]\nname = \"assayer\"\nversion = \"" + version + "\"\n"
	if err := os.WriteFile(filepath.Join(repoDir, "pyproject.toml"), []byte(pyproject), 0644); err != nil {
		t.Fatal(err)
	}
	// rc8-upg15 S5/S7: assayer_verify.sh fails closed when the
	// release-pinned lockfile is absent; every fixture Assayer repo must
	// carry one so the gate under test is the tag/version behavior, not
	// the lockfile requirement.
	if err := os.WriteFile(filepath.Join(repoDir, "requirements-lock.txt"), []byte("# fixture release lockfile\nsupabase==2.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	run("git", "add", "pyproject.toml", "requirements-lock.txt")
	run("git", "commit", "-q", "-m", "init")
	return repoDir
}

func runAssayerVerify(t *testing.T, repoDir string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", assayerVerifyScript(t), "--assayer-repo", repoDir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestV7Case37AssayerVersionLacksTagBlocksRelease: Assayer's declared
// pyproject.toml version has no matching Git tag anywhere in its repo (the
// exact state Sol's audit found: declared 1.1.0, zero tags). release.sh's
// Assayer gate (scripts/assayer_verify.sh) must refuse before packaging --
// mirrors report RB1's "a security governor cannot release from clean
// source + unknown/older binary," applied to the Assayer side-channel the
// audit found ungated.
func TestV7Case37AssayerVersionLacksTagBlocksRelease(t *testing.T) {
	repo := buildAssayerRepoFixture(t, "1.1.0")

	out, err := runAssayerVerify(t, repo)
	if err == nil {
		t.Fatalf("assayer_verify.sh accepted a declared version with no matching Git tag; output:\n%s", out)
	}
	if !strings.Contains(out, "no matching Git tag") {
		t.Fatalf("expected assayer_verify.sh to name the missing-tag reason, got:\n%s", out)
	}
}

// TestV7AssayerVersionTagPointsAtWrongCommitBlocksRelease is the companion
// drift case to 37: a tag exists for the declared version, but a commit
// landed afterward (e.g. an unreviewed hotfix) without moving or re-cutting
// the tag, so "v1.1.0" no longer names the commit that would actually ship.
// Not a separately manifest-numbered corpus case -- it isolates the drift
// branch of the same fix from the missing-tag branch TestV7Case37 asserts,
// exactly as TestAttack24/25 isolate mode vs identity in release_test.go.
// Deliberately does NOT use the TestV7CaseN naming convention (unlike its
// name before this fix) -- internal/redteamgate/gate.go's name-drift check
// treats ANY TestV7Case-prefixed name found in the log as claiming corpus
// membership, manifest or not, so a name in that shape here would fail
// release.sh's redteam-gate verify step with "unmanifested TestV7Case
// test(s) found (name drift)" even though this test intentionally isn't a
// corpus case.
func TestV7AssayerVersionTagPointsAtWrongCommitBlocksRelease(t *testing.T) {
	repo := buildAssayerRepoFixture(t, "1.1.0")
	cmd := exec.Command("git", "tag", "v1.1.0")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git tag: %v: %s", err, out)
	}

	// A healthy run at this point (tag == HEAD) must pass -- isolates the
	// drift assertion below from a false positive baked into the fixture.
	if out, err := runAssayerVerify(t, repo); err != nil {
		t.Fatalf("assayer_verify.sh rejected the healthy tag==HEAD baseline it should accept: %v\n%s", err, out)
	}

	// Drift: a new commit lands without moving the tag.
	if err := os.WriteFile(filepath.Join(repo, "pyproject.toml"), []byte("[project]\nname = \"assayer\"\nversion = \"1.1.0\"\n# drift\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "pyproject.toml"}, {"commit", "-q", "-m", "drift"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	out, err := runAssayerVerify(t, repo)
	if err == nil {
		t.Fatalf("assayer_verify.sh accepted a version tag pointing at a commit other than HEAD; output:\n%s", out)
	}
	if !strings.Contains(out, "but HEAD is") {
		t.Fatalf("expected assayer_verify.sh to name the drift reason, got:\n%s", out)
	}
}

// TestV7Case38NoApplicableChecksBlocksApproval: a profile/registry/config
// error that resolves to zero checks must not silently read as PASS. Drives
// the REAL Assayer package's verify_scored() as a live Python subprocess
// (not a mocked return value) with an empty check list, exactly the
// "nothing was actually verified" state Sol's audit flagged, and asserts
// two things: (1) Assayer itself reports the distinct
// "no_applicable_checks" verdict for a blocking profile, never a bare
// "pass"; (2) Governator's own assay.Blocks() -- the function every real
// run's approval decision goes through -- treats that verdict as blocking.
// A genuinely check-less ADVISORY profile is proven NOT to over-block, so
// this isn't just "reject everything empty".
func TestV7Case38NoApplicableChecksBlocksApproval(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("python3 not available: %v", err)
	}

	const probe = `
import json
from assayer import verify_scored
blocking = verify_scored({"content": "x"}, [], enforcement="blocking")
advisory = verify_scored({"content": "x"}, [], enforcement="advisory")
print(json.dumps({
    "blocking_verdict": blocking.verdict,
    "blocking_had_error": blocking.had_error,
    "advisory_verdict": advisory.verdict,
}))
`
	cmd := exec.Command("python3", "-c", probe)
	cmd.Dir = assayerRepoRoot()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python3 -c verify_scored probe against the real Assayer package failed: %v\n%s", err, out)
	}

	var parsed struct {
		BlockingVerdict  string `json:"blocking_verdict"`
		BlockingHadError bool   `json:"blocking_had_error"`
		AdvisoryVerdict  string `json:"advisory_verdict"`
	}
	if jerr := json.Unmarshal(out, &parsed); jerr != nil {
		t.Fatalf("unparseable probe output: %v\n%s", jerr, out)
	}

	if parsed.BlockingVerdict != assay.VerdictNoApplicableChecks {
		t.Fatalf("real Assayer verify_scored({}, [], enforcement=blocking) returned verdict %q, want %q -- a zero-check blocking profile must not silently pass or masquerade as a crashed check",
			parsed.BlockingVerdict, assay.VerdictNoApplicableChecks)
	}
	if parsed.BlockingHadError {
		t.Fatalf("expected had_error=false for a zero-check profile (nothing crashed, nothing was applicable), got true")
	}
	if !assay.Blocks(parsed.BlockingVerdict, assay.EnforcementBlocking) {
		t.Fatalf("assay.Blocks(%q, %q) = false, want true -- Governator's own approval gate must refuse a run whose Assayer evaluation verified nothing",
			parsed.BlockingVerdict, assay.EnforcementBlocking)
	}

	if parsed.AdvisoryVerdict != assay.VerdictPass {
		t.Fatalf("real Assayer verify_scored({}, [], enforcement=advisory) returned verdict %q, want %q -- a genuinely check-less ADVISORY profile must not be over-blocked",
			parsed.AdvisoryVerdict, assay.VerdictPass)
	}
	if assay.Blocks(parsed.AdvisoryVerdict, assay.EnforcementAdvisory) {
		t.Fatalf("assay.Blocks(%q, %q) = true, want false -- advisory enforcement must never block", parsed.AdvisoryVerdict, assay.EnforcementAdvisory)
	}

	// Cross-repo traceability (matches assayer_test.go's established
	// pattern): prove the real Python-side regression test for this
	// property still exists, so a future edit can't silently delete it
	// while this Go probe keeps passing against stale expectations.
	assertAssayerTestFileContains(t, "tests/test_core.py",
		"class VerifyScoredEmptyChecksTests",
		"def test_no_checks_under_blocking_enforcement_is_no_applicable_checks",
		"def test_no_checks_under_advisory_enforcement_still_passes",
	)
}
