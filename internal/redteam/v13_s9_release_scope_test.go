//go:build redteam

// v13_s9_release_scope_test.go implements Sol13 rc6 corpus case 297.
//
// Session 9 found the rc6 cut unsatisfiable by construction, not by any
// missing machine. Two independently-reasonable gate rules combined into a
// deadlock:
//
//   - verifyCategoryCapabilityProof REQUIRES every darwin capability
//     attestation to be marked NonApproving ("darwin evidence must be
//     explicitly non-approving"), because no native Darwin acceptance
//     evidence exists for this codebase; and
//   - SkipCoveredByAttestations REJECTED every NonApproving category
//     outright, so a NonApproving attestation could never cover a skip.
//
// Together those mean corpus cases 34/35 (the Darwin-native containment and
// Assayer acceptance cases, both of which skip on every non-Darwin host)
// could not be cleared by ANY host -- including a genuine Mac producing a
// genuine signed passing run, since its attestation would be forced
// NonApproving and then rejected. The release could never be cut.
//
// The rc6 plan already states the correct rule for Session 9.2: "if a
// category has no available host, the release must either drop the claim for
// that platform (non-approving, as rc5 correctly did for Darwin) or block."
// Darwin IS dropped -- ClassifyPlatform reports it non-approving, every
// Darwin artifact ships labeled degraded, and ApprovedForProduction refuses
// it. A release that asserts no production property about a platform cannot
// coherently be blocked for lacking evidence of that property.
//
// This case pins the resulting rule from both sides: the exemption applies
// ONLY to a platform-bound category the release declares non-approving, it
// is recorded explicitly in the evidence rather than silently absorbed, and
// it is derived from ClassifyPlatform so that promoting Darwin to
// approvingPlatforms re-arms the coverage requirement automatically.
package redteam

import (
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

func TestV13Case297NonApprovingPlatformSkipIsOutOfReleaseScopeNotAGap(t *testing.T) {
	// Guard the premise: this case is only meaningful while Darwin is the
	// declared non-approving platform. If Darwin is ever promoted, this must
	// fail loudly rather than keep excusing skips.
	if status := redteamgate.ClassifyPlatform("darwin"); status != redteamgate.PlatformNonApproving {
		t.Fatalf(`ClassifyPlatform("darwin") = %q, want %q -- the out-of-release-scope exemption is derived from this classification and must vanish the moment Darwin becomes approving`, status, redteamgate.PlatformNonApproving)
	}

	darwinCase := redteamgate.CaseEntry{Case: 1, Name: "TestDarwinNativeOnly", Required: true, Conditional: true, AttestationCategory: redteamgate.AttestationCategoryDarwin}
	dockerCase := redteamgate.CaseEntry{Case: 2, Name: "TestDockerDaemonOnly", Required: true, Conditional: true, AttestationCategory: redteamgate.AttestationCategoryDockerEnabled}
	uncategorizedCase := redteamgate.CaseEntry{Case: 3, Name: "TestNoCategory", Required: true, Conditional: true}

	// 1. The deadlock is gone: a darwin-bound skip clears production mode
	//    with NO attestations at all, because the release makes no darwin
	//    claim to substantiate.
	manifest := redteamgate.Manifest{Cases: []redteamgate.CaseEntry{darwinCase}}
	log := "=== RUN   TestDarwinNativeOnly\n--- SKIP: TestDarwinNativeOnly (0.00s)\n"
	result := redteamgate.EvaluateWithOptions(manifest, log, nil, redteamgate.Options{RequireZeroSkips: true})
	if !result.OK {
		t.Fatalf("a skip on a platform the release declares non-approving still blocked the release: %+v", result)
	}

	// 2. It is DROPPED, not COVERED. An auditor reading the evidence must be
	//    able to see exactly which claims the release stopped asserting, so
	//    the skip is recorded in its own field and never counted as run.
	if len(result.OutOfScopeSkips) != 1 || result.OutOfScopeSkips[0] != "TestDarwinNativeOnly" {
		t.Fatalf("out-of-scope skip was not recorded as dropped evidence: %+v", result)
	}
	if result.Run != 0 || result.Skipped != 1 {
		t.Fatalf("an out-of-scope skip must still be tallied as a skip, never as a passing run: %+v", result)
	}

	// 3. The exemption does not leak to capability-shaped categories of the
	//    APPROVING platform. docker-enabled describes a capability of an
	//    approving Linux host, so its skip still demands a real signed
	//    category-matched host pass -- exactly the property case 226 (the
	//    real-Docker-daemon acceptance case) depends on.
	manifest = redteamgate.Manifest{Cases: []redteamgate.CaseEntry{dockerCase}}
	log = "=== RUN   TestDockerDaemonOnly\n--- SKIP: TestDockerDaemonOnly (0.00s)\n"
	result = redteamgate.EvaluateWithOptions(manifest, log, nil, redteamgate.Options{RequireZeroSkips: true})
	if result.OK || len(result.UnexpectedSkips) != 1 || len(result.OutOfScopeSkips) != 0 {
		t.Fatalf("a docker-enabled skip was excused as out of release scope: %+v", result)
	}

	// 4. Nor to a case with no attestation category at all -- "unclassified"
	//    must never become the cheapest way past a zero-skip release.
	manifest = redteamgate.Manifest{Cases: []redteamgate.CaseEntry{uncategorizedCase}}
	log = "=== RUN   TestNoCategory\n--- SKIP: TestNoCategory (0.00s)\n"
	result = redteamgate.EvaluateWithOptions(manifest, log, nil, redteamgate.Options{RequireZeroSkips: true})
	if result.OK || len(result.UnexpectedSkips) != 1 || len(result.OutOfScopeSkips) != 0 {
		t.Fatalf("an uncategorized skip was excused as out of release scope: %+v", result)
	}

	// 5. Development mode is untouched: outside RequireZeroSkips a darwin
	//    skip still has to be an authorized conditional skip with proven
	//    capability absence, so the exemption cannot be used to smuggle an
	//    unproven skip through ordinary CI either.
	if redteamgate.SkipOutOfReleaseScope(dockerCase) || redteamgate.SkipOutOfReleaseScope(uncategorizedCase) {
		t.Fatal("SkipOutOfReleaseScope must be true only for a platform-bound, non-approving category")
	}
	if !redteamgate.SkipOutOfReleaseScope(darwinCase) {
		t.Fatal("SkipOutOfReleaseScope must be true for the darwin category while darwin is non-approving")
	}
	if redteamgate.CategoryPlatform(redteamgate.AttestationCategoryCore) != "" {
		t.Fatal("core is a capability shape of the approving platform, not a platform of its own")
	}
}
