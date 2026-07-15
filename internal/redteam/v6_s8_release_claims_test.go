//go:build redteam

// v6_s8_release_claims_test.go is the Sol redteam v6 Permanent Regression
// Corpus, cases 34-36, owned by Session 8 (Phase 8: release + claims
// gating). See agents/governator-sol-upgrade6-plan.md Session 8 and
// agents/governator-sol-upgrade6.md P0-18/P1-1/P1-2. These are meta-tests
// about the release pipeline and claims.yaml verification itself, not `gov`
// job attacks -- the task instructions explicitly permit deviating from the
// runGoverned/fixtureRepo pattern here. Session 0 already wired `-tags
// redteam`/`-race -tags redteam` into scripts/release.sh and CI (separate
// files, not touched by this package); what's still missing, and what these
// three cases scaffold, is claims.go actually REJECTING release evidence
// that was produced by a command excluding the required suite, below the
// expected test-count minimum, or carrying an ambiguous version/tag
// provenance -- none of which internal/claims/claims.go's verifyShipped/
// verifyTested check today (confirmed by reading claims.go in full: no
// field anywhere binds a claim to a recorded test *command*, a minimum test
// *count*, or a tag-vs-commit distance). Session 8 removes the expected-fail skips for cases 34-36 and asserts
// claims verification now rejects the malicious evidence shapes.
package redteam

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/claims"
)

// governatorRepoRoot resolves the real Governator repository root this test
// binary was built from (mirrors govBinary's own runtime.Caller(0)-based
// resolution in harness_test.go) -- claims.Verify operates against the real
// project source tree, not a disposable fixture repo.
func governatorRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

// repoHeadCommit returns the real repository's current HEAD commit SHA.
func repoHeadCommit(t *testing.T, repoRoot string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repoRoot, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// writeOutsideRepoJSON writes v as JSON to a file in t.TempDir() (never
// inside repoRoot -- these tests must not write into the real project tree)
// and returns a path relative to repoRoot that, when filepath.Join'd back
// with repoRoot the way claims.go's verifyShipped does, resolves to that
// temp file via a `..`-climbing relative path.
func writeOutsideRepoJSON(t *testing.T, repoRoot string, v any) string {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(abs, data, 0644); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(repoRoot, abs)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

// v6ClaimsAcceptanceArtifact writes a trivial acceptance artifact (no JSON
// pointer needed, so it only has to exist and be readable) outside repoRoot
// and returns its repoRoot-relative path, so a "shipped" maturity claim's
// acceptance tier is satisfiable without touching the real project tree.
func v6ClaimsAcceptanceArtifact(t *testing.T, repoRoot string) string {
	t.Helper()
	abs := filepath.Join(t.TempDir(), "acceptance.txt")
	if err := os.WriteFile(abs, []byte("accepted\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(repoRoot, abs)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

// v6BaseShippedClaim builds a Claim whose implemented/tested/accepted tiers
// are all genuinely satisfiable against the real repository (a real,
// exported symbol; this file's own real test function under the real
// "redteam" build tag; a trivial acceptance artifact) -- isolating each
// case's assertion to the ONE additional fact (redteam-tag command,
// minimum test count, or tag/commit provenance) that claims.go does not yet
// check at the "shipped" tier.
func v6BaseShippedClaim(t *testing.T, repoRoot, id string) claims.Claim {
	t.Helper()
	return claims.Claim{
		ID:              id,
		Title:           "v6 release-gate scaffold claim",
		ClaimedMaturity: claims.MaturityShipped,
		Implementation: []claims.FileSymbols{
			{File: "internal/contracts/schema.go", Symbols: []string{"Contract"}},
		},
		Tests: []claims.FileFuncs{
			{File: "internal/redteam/v6_s8_release_claims_test.go", Funcs: []string{"TestV6Case34ReleaseWithoutRedteamTagIsRejected"}, BuildTag: "redteam"},
		},
		AcceptanceArtifacts: []claims.ArtifactRef{
			{Path: v6ClaimsAcceptanceArtifact(t, repoRoot)},
		},
	}
}

// TestV6Case34ReleaseWithoutRedteamTagIsRejected is corpus case 34 (report
// P0-18, full completion): Session 0 wired `-tags redteam` into
// scripts/release.sh and CI, but claims verification has no mechanism to
// REJECT evidence that was produced by a command omitting that tag -- there
// is no field anywhere in claims.Claim/BinaryEvidence binding a claim to
// the recorded shell command that generated its test evidence. This test
// builds a claim whose binary_build_evidence points at a fake evidence.json
// recording a "redteam" suite entry whose command string omits `-tags
// redteam` (exactly the pre-S0 release.sh defect), and asserts claims
// verification rejects it.
func TestV6Case34ReleaseWithoutRedteamTagIsRejected(t *testing.T) {

	repoRoot := governatorRepoRoot(t)
	head := repoHeadCommit(t, repoRoot)

	evidence := map[string]any{
		"source_commit": head,
		"redteam": map[string]any{
			// The exact pre-S0 defect: compiles/runs the untagged package,
			// never the build-tagged corpus.
			"command":    "go test -count=1 ./...",
			"result":     "PASS",
			"test_count": 0,
		},
	}
	evidenceRel := writeOutsideRepoJSON(t, repoRoot, evidence)

	claim := v6BaseShippedClaim(t, repoRoot, "v6-case34-release-redteam-tag-required")
	claim.BinaryBuildEvidence = &claims.BinaryEvidence{EvidenceFile: evidenceRel, Commit: head}

	results, err := claims.Verify(repoRoot, claims.Document{Version: 1, Claims: []claims.Claim{claim}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].OK() {
		return // fixed: claims verification correctly rejected the evidence
	}
	t.Fatalf("claims verification accepted release evidence whose redteam-suite command excluded -tags redteam: %+v", results[0])
}

// TestV6Case35ReleaseTestCountBelowMinimumIsRejected is corpus case 35
// (report P1-2 / P0-18): same meta-test shape as case 34, but the recorded
// redteam-suite command DOES include -tags redteam, and reports PASS, yet
// the recorded test_count is far below any plausible minimum for the
// corpus (see this very package: 27 pre-existing TestAttackN + 36
// TestV6CaseN = 63 tests today). Claims verification must reject evidence
// claiming an implausibly low test count for a suite it asserts passed in
// full, rather than trusting a bare PASS/command-string match.
func TestV6Case35ReleaseTestCountBelowMinimumIsRejected(t *testing.T) {

	repoRoot := governatorRepoRoot(t)
	head := repoHeadCommit(t, repoRoot)

	evidence := map[string]any{
		"source_commit": head,
		"redteam": map[string]any{
			"command":    "go test -tags redteam -count=1 ./...",
			"result":     "PASS",
			"test_count": 2, // far below the real corpus size
		},
	}
	evidenceRel := writeOutsideRepoJSON(t, repoRoot, evidence)

	claim := v6BaseShippedClaim(t, repoRoot, "v6-case35-release-min-test-count")
	claim.BinaryBuildEvidence = &claims.BinaryEvidence{EvidenceFile: evidenceRel, Commit: head}

	results, err := claims.Verify(repoRoot, claims.Document{Version: 1, Claims: []claims.Claim{claim}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].OK() {
		return
	}
	t.Fatalf("claims verification accepted release evidence claiming an implausibly low redteam test_count: %+v", results[0])
}

// TestV6Case36UntaggedPostV1TagSourcePackagedAsV1IsRejected is corpus case
// 36 (report P1-1): this is the REAL current state of this repository, not
// a fabricated fixture -- `git describe --tags` reports HEAD several
// commits past the v1.0.0 tag (confirmed: v1.0.0-6-gfad1a95 at plan time),
// yet a binary_build_evidence.version of "1.0.0" would claim the exact tag
// version for source that is demonstrably not what was tagged.
// verifyShipped only checks that Commit is an ancestor of (or equal to)
// HEAD -- it never compares Commit against the nearest reachable tag, so
// this ambiguity verifies clean today. This test builds evidence for the
// real current HEAD labeled Version "1.0.0" and asserts claims verification
// rejects/flags the mismatch between the declared version and the tag the
// commit actually sits several commits past.
func TestV6Case36UntaggedPostV1TagSourcePackagedAsV1IsRejected(t *testing.T) {

	repoRoot := governatorRepoRoot(t)
	head := repoHeadCommit(t, repoRoot)

	describeOut, err := exec.Command("git", "-C", repoRoot, "describe", "--tags", "--long", head).Output()
	if err != nil {
		t.Skipf("no reachable tag to compare against in this checkout: %v", err)
	}
	describe := strings.TrimSpace(string(describeOut))
	// "<tag>-<N>-g<sha>": N==0 means HEAD IS the tag, nothing ambiguous to
	// prove here.
	parts := strings.Split(describe, "-")
	if len(parts) < 3 || parts[len(parts)-2] == "0" {
		t.Skipf("HEAD is exactly at its nearest tag (%s); this case needs a checkout several commits past a tag", describe)
	}
	tag := strings.Join(parts[:len(parts)-2], "-")

	evidence := map[string]any{
		"source_commit": head,
	}
	evidenceRel := writeOutsideRepoJSON(t, repoRoot, evidence)

	claim := v6BaseShippedClaim(t, repoRoot, "v6-case36-version-tag-provenance")
	// Version claims the ORIGINAL tag even though head sits several commits
	// past it -- exactly the report's "six post-tag security commits ship
	// under the original 1.0.0" scenario, reproduced against this
	// repository's real state.
	claim.BinaryBuildEvidence = &claims.BinaryEvidence{EvidenceFile: evidenceRel, Commit: head, Version: strings.TrimPrefix(tag, "v")}

	results, err := claims.Verify(repoRoot, claims.Document{Version: 1, Claims: []claims.Claim{claim}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].OK() {
		return
	}
	t.Fatalf("claims verification accepted binary_build_evidence.version=%q for a commit %s commits past that tag (%s) -- version/tag provenance ambiguity must be rejected or flagged: %+v", claim.BinaryBuildEvidence.Version, parts[len(parts)-2], describe, results[0])
}
