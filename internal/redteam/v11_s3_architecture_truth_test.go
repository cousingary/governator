//go:build redteam

package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// v11_s3_architecture_truth_test.go is the Sol v11 rc5 Session 3 corpus
// (agents/governator-sol-upgrade11-rc5-plan.md Session 3,
// agents/governator-sol-upgrade11.md P1-7): report corpus cases 41, 42, 43,
// 46 -- "Architecture and release truth are contradictory". Every test
// drives the REAL scripts/check_architecture_doc.py (extended this session
// to validate front-matter-style docs) as an actual OS subprocess against
// synthetic fixture docs/repos/dist directories.

func s3ArchDocScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(s3RepoRoot(t), "scripts", "check_architecture_doc.py")
}

func s3RunCheckArchitectureDoc(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("python3", append([]string{s3ArchDocScript(t)}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func s3WriteFrontMatterDoc(t *testing.T, path string, fields map[string]string, body string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("---\n")
	for _, k := range []string{"governator_commit", "governator_tag", "assayer_commit", "assayer_tag", "release_state", "artifact_manifest_sha256"} {
		if v, ok := fields[k]; ok {
			b.WriteString(k + ": " + v + "\n")
		}
	}
	b.WriteString("---\n")
	b.WriteString(body)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestV11Case27ArchitectureCompleteWithNoArtifactsRejected is corpus case
// 41: "architecture says complete with no artifacts". A front-matter doc
// declares release_state: complete with a real, git-resolvable
// governator_tag/governator_commit pair -- but no --dist-dir is even
// provided (equivalently: none exists), so the claimed release has zero
// verifiable artifacts behind it.
func TestV11Case27ArchitectureCompleteWithNoArtifactsRejected(t *testing.T) {
	repo, commit := s3InitRepo(t)
	tagCmd := exec.Command("git", "-C", repo, "tag", "v1.0.2-rc5-case41")
	if out, err := tagCmd.CombinedOutput(); err != nil {
		t.Fatalf("git tag: %v\n%s", err, out)
	}

	doc := filepath.Join(t.TempDir(), "architecture.md")
	s3WriteFrontMatterDoc(t, doc, map[string]string{
		"governator_commit":        commit,
		"governator_tag":           "v1.0.2-rc5-case41",
		"release_state":            "complete",
		"artifact_manifest_sha256": "null",
	}, "# Doc\n**Status:** current v1.0.2-rc5-case41\n")

	out, err := s3RunCheckArchitectureDoc(t, doc, "--repo", repo)
	if err == nil {
		t.Fatalf("expected check_architecture_doc.py to reject release_state: complete with no artifacts, got success:\n%s", out)
	}
	if !strings.Contains(out, "INCOMPLETE_RELEASE_EVIDENCE") {
		t.Fatalf("expected INCOMPLETE_RELEASE_EVIDENCE, got:\n%s", out)
	}

	// Positive control: the SAME doc with a real dist/ behind it (matching
	// manifest hash) is accepted -- proves the rejection above is really
	// about the missing artifacts, not an unrelated bug in the fixture.
	dist := s3BuildCompleteDist(t, commit)
	manifestSHA := fileSHA256Hex(t, filepath.Join(dist, "build-manifest.json"))
	doc2 := filepath.Join(t.TempDir(), "architecture-ok.md")
	s3WriteFrontMatterDoc(t, doc2, map[string]string{
		"governator_commit":        commit,
		"governator_tag":           "v1.0.2-rc5-case41",
		"release_state":            "complete",
		"artifact_manifest_sha256": manifestSHA,
	}, "# Doc\n**Status:** current v1.0.2-rc5-case41\n")
	out2, err2 := s3RunCheckArchitectureDoc(t, doc2, "--repo", repo, "--dist-dir", dist)
	if err2 != nil {
		t.Fatalf("expected the same claim backed by real, matching artifacts to pass, got error: %v\n%s", err2, out2)
	}
}

// TestV11Case28ArchitectureTagCommitDiffersFromGitTagRejected is corpus
// case 42: "architecture tag commit differs from Git tag". The doc's
// governator_tag is a REAL tag in the repo, but governator_commit names a
// different commit than the one that tag actually points at.
func TestV11Case28ArchitectureTagCommitDiffersFromGitTagRejected(t *testing.T) {
	repo, commit := s3InitRepo(t)
	tagCmd := exec.Command("git", "-C", repo, "tag", "v1.0.2-rc5-case42")
	if out, err := tagCmd.CombinedOutput(); err != nil {
		t.Fatalf("git tag: %v\n%s", err, out)
	}
	_ = commit // the tag's real commit; the doc below deliberately lies about it

	doc := filepath.Join(t.TempDir(), "architecture.md")
	s3WriteFrontMatterDoc(t, doc, map[string]string{
		"governator_commit":        "fedcba9876543210fedcba9876543210fedcba9",
		"governator_tag":           "v1.0.2-rc5-case42",
		"release_state":            "pending",
		"artifact_manifest_sha256": "null",
	}, "# Doc\n")

	out, err := s3RunCheckArchitectureDoc(t, doc, "--repo", repo)
	if err == nil {
		t.Fatalf("expected check_architecture_doc.py to reject a governator_tag/governator_commit mismatch, got success:\n%s", out)
	}
	if !strings.Contains(out, "TAG_COMMIT_MISMATCH") {
		t.Fatalf("expected TAG_COMMIT_MISMATCH, got:\n%s", out)
	}
}

// TestV11Case29ArchitectureCheckerSeesConflictingCurrentCommitsRejected is
// corpus case 43: "architecture checker sees conflicting current
// commits". The doc's own front matter (governator_commit) and its body's
// legacy "Source HEAD `<sha>`" declaration name TWO DIFFERENT commits --
// an internal self-contradiction about what "current" means, independent
// of whether either one matches git.
func TestV11Case29ArchitectureCheckerSeesConflictingCurrentCommitsRejected(t *testing.T) {
	doc := filepath.Join(t.TempDir(), "architecture.md")
	s3WriteFrontMatterDoc(t, doc, map[string]string{
		"governator_commit":        "1111111111111111111111111111111111111a",
		"governator_tag":           "v1.0.2-rc5-case43",
		"release_state":            "pending",
		"artifact_manifest_sha256": "null",
	}, "# Doc\nSource HEAD `2222222222222222222222222222222222222b`\n")

	out, err := s3RunCheckArchitectureDoc(t, doc)
	if err == nil {
		t.Fatalf("expected check_architecture_doc.py to reject conflicting current-commit declarations, got success:\n%s", out)
	}
	if !strings.Contains(out, "CONFLICTING_CURRENT_COMMITS") {
		t.Fatalf("expected CONFLICTING_CURRENT_COMMITS, got:\n%s", out)
	}

	// Positive control: the same two fields agreeing must pass this
	// specific check (other checks -- e.g. TAG_COMMIT_MISMATCH, since no
	// --repo is given here -- are simply inert without --repo).
	agreeingDoc := filepath.Join(t.TempDir(), "architecture-agree.md")
	s3WriteFrontMatterDoc(t, agreeingDoc, map[string]string{
		"governator_commit":        "1111111111111111111111111111111111111a",
		"governator_tag":           "v1.0.2-rc5-case43",
		"release_state":            "pending",
		"artifact_manifest_sha256": "null",
	}, "# Doc\nSource HEAD `1111111111111111111111111111111111111a`\n")
	out2, err2 := s3RunCheckArchitectureDoc(t, agreeingDoc)
	if err2 != nil {
		t.Fatalf("expected agreeing commit declarations to pass, got error: %v\n%s", err2, out2)
	}
}

// TestV11Case30TestSummaryPassWithIncompleteTierCheckpointRejected is
// corpus case 46: "test-summary PASS with incomplete tier checkpoint". A
// dist/ carries a test-summary.json claiming every suite PASSED, but its
// travelling release-attempt checkpoint state (scripts/
// release_checkpoint.py) is missing several required tiers -- proving
// audit_bundle_validate.py's evidence check does not simply trust
// test-summary.json's own say-so when contradicting checkpoint evidence
// travels alongside it.
func TestV11Case30TestSummaryPassWithIncompleteTierCheckpointRejected(t *testing.T) {
	repo, commit := s3InitRepo(t)
	dist := s3BuildCompleteDist(t, commit) // test-summary.json here already claims all-PASS

	// Attach a checkpoint state dir to this dist/ that is INCOMPLETE for
	// the same identity -- only "unit" has a checkpoint; the other five
	// required tiers have none.
	checkpointDir := filepath.Join(dist, ".checkpoints")
	if err := os.MkdirAll(checkpointDir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := s3DefaultIdentity()
	id.GovernatorCommit = commit
	identityFile := s3InitAttempt(t, checkpointDir, id, "attempt-case46")
	s3CheckpointWrite(t, filepath.Join(checkpointDir, "unit.json"), identityFile, "go test ./...", "PASS")

	out, err := s3RunAuditValidate(t, dist, repo, commit)
	if err == nil {
		t.Fatalf("expected audit_bundle_validate.py to reject test-summary.json's PASS claim when the travelling checkpoint evidence is incomplete, got success:\n%s", out)
	}
	if !strings.Contains(out, "tier-checkpoint aggregate rejected") {
		t.Fatalf("expected the failure to name the rejected tier-checkpoint aggregate, got:\n%s", out)
	}
}
