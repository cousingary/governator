//go:build redteam

package redteam

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v11_s8_release_workflow_test.go is the Sol v11 rc5 Session 8 corpus
// (agents/governator-sol-upgrade11-rc5-plan.md Session 8,
// agents/governator-sol-upgrade11.md P1-4, P1-6, P1-8): report corpus cases
// 45, 47, 48 -- "Release workflow, pinned tools, auto-detect release mode."
//
// Case 46 (corpus 45: "exact test log referenced but absent") drives the
// REAL scripts/audit_bundle_validate.py against a synthetic dist/ fixture
// that is complete except for one referenced evidence log being deleted --
// proving a release whose manifest references a log that does not exist on
// disk is rejected, not silently shipped.
//
// Cases 47 and 48 (corpus 47/48: "canonical GitHub workflow on a clean
// runner" / "release workflow without Assayer checkout") are structural
// assertions over .github/workflows/release.yml, assayer.lock, and
// scripts/release.sh -- proving the canonical workflow can reproduce the
// full local pipeline on a clean runner (every required tool and checkout
// is declared in the YAML itself) and that a release without Assayer
// checkout is structurally impossible (the workflow pins Assayer via
// assayer.lock and release.sh hard-fails on an absent ASSAYER_REPO).

// s8WorkflowYAML reads .github/workflows/release.yml from the repo root.
func s8WorkflowYAML(t *testing.T) string {
	t.Helper()
	repo := s3RepoRoot(t)
	path := filepath.Join(repo, ".github", "workflows", "release.yml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read %s: %v", path, err)
	}
	return string(b)
}

// s8ReleaseSH reads scripts/release.sh from the repo root.
func s8ReleaseSH(t *testing.T) string {
	t.Helper()
	repo := s3RepoRoot(t)
	path := filepath.Join(repo, "scripts", "release.sh")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read %s: %v", path, err)
	}
	return string(b)
}

// s8AssayerLock reads assayer.lock from the repo root.
func s8AssayerLock(t *testing.T) string {
	t.Helper()
	repo := s3RepoRoot(t)
	path := filepath.Join(repo, "assayer.lock")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read %s: %v", path, err)
	}
	return string(b)
}

// TestV11Case46ExactTestLogReferencedButAbsentFailsRelease is corpus case
// 45: "exact test log referenced but absent." A dist/ is otherwise a
// complete, valid release (every required file present, test-summary.json
// claiming PASS, acceptance PASS, zero skips, every other log present and
// hash-matching) EXCEPT one evidence log that test-summary.json references
// by name+hash has been deleted entirely. The mere-existence checks for
// the REQUIRED_TEST_EVIDENCE_LOGS set would catch a missing top-tier log,
// but a suite-level log_path reference that points at a file that is no
// longer on disk must also fail -- the release ships a manifest claiming
// evidence that cannot be retrieved or verified.
func TestV11Case46ExactTestLogReferencedButAbsentFailsRelease(t *testing.T) {
	repo, commit := s3InitRepo(t)
	dist := s3BuildCompleteDist(t, commit)

	// Delete the redteam tier's log AFTER test-summary.json already
	// references it by log_path + log_sha256. The file is now absent even
	// though the manifest claims it exists with a specific content hash.
	redteamLog := filepath.Join(dist, "redteam.log.gz")
	if err := os.Remove(redteamLog); err != nil {
		t.Fatal(err)
	}

	out, err := s3RunAuditValidate(t, dist, repo, commit)
	if err == nil {
		t.Fatalf("expected audit_bundle_validate.py to reject a dist/ whose test-summary.json references an absent log, got success:\n%s", out)
	}
	if !strings.Contains(out, "INCOMPLETE_RELEASE_EVIDENCE") {
		t.Fatalf("expected INCOMPLETE_RELEASE_EVIDENCE, got:\n%s", out)
	}
	if !strings.Contains(out, "redteam.log.gz") {
		t.Fatalf("expected the failure to name the absent redteam.log.gz, got:\n%s", out)
	}
}

// TestV11Case47CanonicalGitHubWorkflowReproducesOnCleanRunner is corpus
// case 47: "canonical GitHub workflow on a clean runner." A GitHub-hosted
// ubuntu-latest runner starts with none of: an Assayer checkout, Python
// 3.10/3.11/3.12/3.13, Minisign, or ASSAYER_REPO set. The workflow YAML
// itself must declare every one of these -- the report (P1-4) found the
// prior workflow checked out only Governator and configured Go, so the
// documented tag-push workflow could not reproduce the local release
// pipeline. This test proves the canonical workflow is structurally
// complete: removing any required piece would fail this assertion.
func TestV11Case47CanonicalGitHubWorkflowReproducesOnCleanRunner(t *testing.T) {
	yaml := s8WorkflowYAML(t)

	// Every required substring a clean runner needs the workflow to declare.
	required := []struct {
		needle string
		what   string
	}{
		// Assayer checkout at a pinned ref (P1-4: was entirely absent).
		{"assayer.lock", "Assayer ref pin source (assayer.lock)"},
		{"repository:", "Assayer checkout repository declaration"},
		{"path: assayer", "Assayer checkout path for ASSAYER_REPO"},
		// Python 3.10–3.13 matrix (P1-4: no interpreters were installed).
		{"'3.10'", "Python 3.10 setup"},
		{"'3.11'", "Python 3.11 setup"},
		{"'3.12'", "Python 3.12 setup"},
		{"'3.13'", "Python 3.13 setup"},
		// Minisign (P1-4/P1-6: was not installed or pinned).
		{"minisign", "Minisign install"},
		// ASSAYER_REPO explicitly set (P1-4: defaulted to a local-only path).
		{"ASSAYER_REPO:", "ASSAYER_REPO environment variable"},
		// Pinned Go toolchain (already present, but assert it stays).
		{"go-version-file: go.mod", "Go toolchain pinned to go.mod"},
		// The verification step that proves all four interpreters landed.
		{"Verify the full Python matrix", "Python matrix verification step"},
	}
	missing := []string{}
	for _, r := range required {
		if !strings.Contains(yaml, r.needle) {
			missing = append(missing, r.what)
		}
	}
	if len(missing) > 0 {
		t.Fatalf(".github/workflows/release.yml is missing required pieces for a clean-runner reproduction (Sol11 P1-4): %s", strings.Join(missing, "; "))
	}
}

// TestV11Case48ReleaseWorkflowWithoutAssayerCheckoutFails is corpus case
// 48: "release workflow without Assayer checkout." Three independent
// structural facts make a release without Assayer checkout impossible:
//
//  1. assayer.lock exists and declares a pinned ref (not a moving branch).
//  2. The workflow reads assayer.lock and checks out Assayer at that ref
//     (not a hardcoded "main" that could silently advance).
//  3. scripts/release.sh hard-fails when ASSAYER_REPO points at an absent
//     directory -- a workflow that forgot the Assayer checkout step cannot
//     produce a release, because the Assayer matrix gate refuses to
//     package (ASSAYER_RESULT=FAIL -> "refusing to package").
//
// Removing the Assayer checkout from the workflow (the exact regression
// this corpus case exists to catch) would break fact #2's assertion here
// and would also hit release.sh's hard-fail gate at runtime.
func TestV11Case48ReleaseWorkflowWithoutAssayerCheckoutFails(t *testing.T) {
	// Fact 1: assayer.lock exists and declares a pinned ref.
	lock := s8AssayerLock(t)
	if !strings.Contains(lock, "ref=v") {
		t.Fatalf("assayer.lock does not declare a ref=v... entry -- the Assayer pin is absent:\n%s", lock)
	}

	// Fact 2: the workflow reads assayer.lock and checks out Assayer at the
	// pinned ref (the step exists and references the lock, not a hardcoded
	// moving branch).
	yaml := s8WorkflowYAML(t)
	if !strings.Contains(yaml, "Read pinned Assayer ref from assayer.lock") {
		t.Fatalf("release.yml is missing the 'Read pinned Assayer ref from assayer.lock' step -- a workflow without an Assayer checkout at a pinned ref is the exact P1-4 regression")
	}
	if !strings.Contains(yaml, "Check out Assayer at its pinned ref") {
		t.Fatalf("release.yml is missing the 'Check out Assayer at its pinned ref' step")
	}

	// Fact 3: scripts/release.sh hard-fails when ASSAYER_REPO is absent.
	// This is the runtime gate that makes "workflow without Assayer
	// checkout" produce a failed release, not a release that silently
	// omits Assayer evidence. The refusal message is the exact string the
	// release operator sees.
	sh := s8ReleaseSH(t)
	if !strings.Contains(sh, "refusing to package") || !strings.Contains(sh, "Assayer matrix") {
		t.Fatalf("scripts/release.sh does not contain the hard-fail gate for an absent Assayer matrix -- a workflow without Assayer checkout could ship a release with no Assayer evidence (Sol11 P1-4 corpus 48)")
	}

	// Positive control: the absent-Assayer path is a FAIL, not a silent
	// skip. release.sh's own ASSAYER_RESULT for an absent repo is FAIL
	// (not SKIPPED), and that FAIL blocks packaging -- proving the gate
	// is a hard refusal, not a degradable one.
	if !strings.Contains(sh, `ASSAYER_RESULT=FAIL`) {
		t.Fatalf("scripts/release.sh does not set ASSAYER_RESULT=FAIL for an absent ASSAYER_REPO")
	}
}
