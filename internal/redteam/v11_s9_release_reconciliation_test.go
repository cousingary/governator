//go:build redteam

package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

// v11_s9_release_reconciliation_test.go is the Sol v11 rc5 Session 9 corpus
// (agents/governator-sol-upgrade11-rc5-plan.md Session 9,
// agents/governator-sol-upgrade11.md corpus cases 44 and 49): the two
// mandatory rc5 regression cases explicitly left for the terminal session
// rather than Sessions 1-8, because both require the release identity
// mechanics (Session 3) and the zero-skip gate (Session 1/8) to already
// exist before they can be exercised for real, and both are proved against
// the ACTUAL current toolchain (audit_bundle_validate.py, the real
// internal/redteam/manifest.yaml) rather than a synthetic stand-in --
// "verify this is actually true, don't just assert it" (the report's own
// wording for case 49).

// TestV11Case49TagRepointedAfterReleaseFailsAuditBundleValidation is corpus
// case 44: "current tag moved after a claimed release". scripts/
// audit_bundle.sh resolves RELEASE_COMMIT fresh via `git rev-parse "$REF"`
// every time it runs (REF defaults to a tag name) and hands that resolved
// commit to audit_bundle_validate.py, which rejects any disagreement with
// build-manifest.json's own source_commit. This test proves the exact
// consequence: build a real dist/ for commit A (tagged v-under-test at
// build time), then force-move that same tag to a different commit B --
// exactly what "the tag was moved after a claimed release" means in a real
// git repo -- and confirm a subsequent audit_bundle_validate.py invocation
// (which re-resolves the tag, as audit_bundle.sh always does) refuses the
// stale dist/ rather than silently accepting evidence for the wrong commit.
func TestV11Case49TagRepointedAfterReleaseFailsAuditBundleValidation(t *testing.T) {
	repo, commitA := s3InitRepo(t)

	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=redteam", "GIT_AUTHOR_EMAIL=redteam@example.com", "GIT_COMMITTER_NAME=redteam", "GIT_COMMITTER_EMAIL=redteam@example.com")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	// Tag commit A as the "claimed release" and build a complete, PASSING
	// dist/ for it -- exactly what a real scripts/release.sh run would have
	// produced and what a first, correct scripts/audit_bundle.sh run would
	// validate successfully.
	run("tag", "v1.0.2-rc5-test")
	dist := s3BuildCompleteDist(t, commitA)

	out, err := s3RunAuditValidate(t, dist, repo, commitA)
	if err != nil {
		t.Fatalf("expected the ORIGINAL claimed release (dist/ built for the tag's original commit) to validate cleanly, got error: %v\n%s", err, out)
	}

	// Now make a second commit and force-move the SAME tag onto it -- the
	// tag has been re-pointed after the release was claimed. Nothing in
	// dist/ changes: it still describes commit A.
	if err := os.WriteFile(filepath.Join(repo, "f2"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-q", "-m", "second commit")
	commitB := s3GitCommit(t, repo)
	if commitB == commitA {
		t.Fatal("test setup bug: second commit did not actually advance HEAD")
	}
	run("tag", "-f", "v1.0.2-rc5-test", commitB)

	// A real audit_bundle.sh invocation always re-resolves the tag fresh
	// (`git rev-parse "$REF"`) rather than trusting a cached value -- so a
	// verifier re-checking "the v1.0.2-rc5-test release" now resolves to
	// commitB, while the dist/ evidence on disk still names commitA.
	resolvedAfterRepoint := run("rev-parse", "v1.0.2-rc5-test")
	if resolvedAfterRepoint != commitB {
		t.Fatalf("test setup bug: tag did not actually move, resolves to %s want %s", resolvedAfterRepoint, commitB)
	}

	out, err = s3RunAuditValidate(t, dist, repo, resolvedAfterRepoint)
	if err == nil {
		t.Fatalf("expected audit_bundle_validate.py to refuse dist/ evidence for commitA once the release tag was re-pointed to commitB, got success:\n%s", out)
	}
	if !strings.Contains(out, "does not match the release commit") {
		t.Fatalf("expected a tag/commit mismatch naming the moved tag's new resolution, got:\n%s", out)
	}
}

// TestV11Case50ProductionManifestSkipOfAnyAttackFailsRelease is corpus case
// 49: "production release containing any skipped red-team attack must
// fail" -- proved against the REAL, current internal/redteam/manifest.yaml
// (not a synthetic mini-manifest), so this actually exercises the exact
// corpus a real scripts/release.sh invocation gates on. Case 8 is a real,
// currently-conditional entry in that manifest (case8_hangfuse_extinction_
// fixture) -- picked because it is one of the manifest's own sanctioned
// exceptions under ordinary development CI, which is exactly why proving a
// PRODUCTION run still refuses it matters: if even a manifest-authorized
// skip is rejected under RequireZeroSkips, an unauthorized one certainly is
// too.
func TestV11Case50ProductionManifestSkipOfAnyAttackFailsRelease(t *testing.T) {
	manifest, err := redteamgate.LoadManifest(filepath.Join("manifest.yaml"))
	if err != nil {
		t.Fatalf("LoadManifest(manifest.yaml): %v", err)
	}

	const skippedCase = "TestV7Case8CleanupValidatorDetachedDescendantExtinctionFailureBlocksApproval"
	const skipReason = "case8 hangfuse extinction fixture"

	var found bool
	for _, c := range manifest.Cases {
		if c.Name == skippedCase {
			found = true
			if !c.Conditional || c.AllowedSkip == nil || c.AllowedSkip.Reason != skipReason {
				t.Fatalf("test assumption stale: manifest entry for %s no longer matches the expected conditional/reason -- update this test's constants to match manifest.yaml", skippedCase)
			}
		}
	}
	if !found {
		t.Fatalf("test assumption stale: %s is no longer in manifest.yaml -- pick another real conditional case", skippedCase)
	}

	// Build a `go test -v` style log reporting every real manifest case as
	// PASS, except the one named case above, which is reported SKIP with
	// its own manifest-declared authorized reason -- the single skip a
	// development-mode run would legitimately wave through.
	var log strings.Builder
	for _, c := range manifest.Cases {
		log.WriteString("=== RUN   " + c.Name + "\n")
		if c.Name == skippedCase {
			log.WriteString("    " + skipReason + "\n")
			log.WriteString("--- SKIP: " + c.Name + " (0.00s)\n")
		} else {
			log.WriteString("--- PASS: " + c.Name + " (0.00s)\n")
		}
	}

	// Sol12 P0-3: capability evidence is tri-state, and the gate now requires
	// every predicate the manifest references to be proven present/absent in
	// the record (CAPABILITY_EVIDENCE_INCOMPLETE otherwise). Build a complete
	// record: every manifest predicate proven present, except the one the
	// skipped case authorizes on (case8_hangfuse_extinction_fixture → absent,
	// since case 8's skip is sanctioned by proven absence under dev CI).
	caps := map[string]redteamgate.CapabilityRecord{}
	for _, c := range manifest.Cases {
		if !c.Conditional || c.AllowedSkip == nil || c.AllowedSkip.Predicate == "" {
			continue
		}
		pred := c.AllowedSkip.Predicate
		state := redteamgate.CapabilityPresent
		if c.Name == skippedCase {
			state = redteamgate.CapabilityAbsent
		}
		caps[pred] = redteamgate.CapabilityRecord{State: state}
	}

	// Baseline: ordinary development CI authorizes exactly this skip via
	// the manifest's own allowed_skip mechanism -- isolates the production
	// assertion below from a false positive baked into the fixture.
	dev := redteamgate.Evaluate(manifest, log.String(), caps)
	if !dev.OK {
		t.Fatalf("expected the real manifest's authorized case-8 skip to pass under ordinary development-CI policy, got %+v", dev)
	}

	prod := redteamgate.EvaluateWithOptions(manifest, log.String(), caps, redteamgate.Options{RequireZeroSkips: true})
	if prod.OK {
		t.Fatalf("expected a production release (RequireZeroSkips) over the REAL current manifest to refuse a release containing one skipped red-team attack, even a manifest-authorized one: %+v", prod)
	}
	if len(prod.UnexpectedSkips) != 1 || prod.UnexpectedSkips[0] != skippedCase {
		t.Fatalf("expected exactly %s to be named as an unexpected skip under production policy, got %+v", skippedCase, prod)
	}
}
