//go:build redteam

// v13_s9_release_scope_test.go implements Sol13 rc6 corpus case 297. S6b
// promotes Darwin after real native execution, so this case now pins the
// self-tightening half of the original rule: an approving Darwin platform
// gets no out-of-release-scope exemption, and a skipped native case requires
// exact signed Darwin coverage.
package redteam

import (
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

func TestV13Case297ApprovingPlatformSkipRequiresNativeEvidence(t *testing.T) {
	if status := redteamgate.ClassifyPlatform("darwin"); status != redteamgate.PlatformApproving {
		t.Fatalf(`ClassifyPlatform("darwin") = %q, want %q after native S6b acceptance`, status, redteamgate.PlatformApproving)
	}

	darwinCase := redteamgate.CaseEntry{Case: 1, Name: "TestDarwinNativeOnly", Required: true, Conditional: true, AttestationCategory: redteamgate.AttestationCategoryDarwin}
	dockerCase := redteamgate.CaseEntry{Case: 2, Name: "TestDockerDaemonOnly", Required: true, Conditional: true, AttestationCategory: redteamgate.AttestationCategoryDockerEnabled}
	uncategorizedCase := redteamgate.CaseEntry{Case: 3, Name: "TestNoCategory", Required: true, Conditional: true}

	// Darwin is now in release scope. With no attestation, its skip blocks.
	manifest := redteamgate.Manifest{Cases: []redteamgate.CaseEntry{darwinCase}}
	log := "=== RUN   TestDarwinNativeOnly\n--- SKIP: TestDarwinNativeOnly (0.00s)\n"
	result := redteamgate.EvaluateWithOptions(manifest, log, nil, redteamgate.Options{RequireZeroSkips: true})
	if result.OK || len(result.UnexpectedSkips) != 1 || len(result.OutOfScopeSkips) != 0 {
		t.Fatalf("an approving Darwin skip was still excused as out of release scope: %+v", result)
	}

	// The exemption does not leak to other capability-shaped categories.
	manifest = redteamgate.Manifest{Cases: []redteamgate.CaseEntry{dockerCase}}
	log = "=== RUN   TestDockerDaemonOnly\n--- SKIP: TestDockerDaemonOnly (0.00s)\n"
	result = redteamgate.EvaluateWithOptions(manifest, log, nil, redteamgate.Options{RequireZeroSkips: true})
	if result.OK || len(result.UnexpectedSkips) != 1 || len(result.OutOfScopeSkips) != 0 {
		t.Fatalf("a docker-enabled skip was excused as out of release scope: %+v", result)
	}

	// Nor to a case with no attestation category at all -- "unclassified"
	//    must never become the cheapest way past a zero-skip release.
	manifest = redteamgate.Manifest{Cases: []redteamgate.CaseEntry{uncategorizedCase}}
	log = "=== RUN   TestNoCategory\n--- SKIP: TestNoCategory (0.00s)\n"
	result = redteamgate.EvaluateWithOptions(manifest, log, nil, redteamgate.Options{RequireZeroSkips: true})
	if result.OK || len(result.UnexpectedSkips) != 1 || len(result.OutOfScopeSkips) != 0 {
		t.Fatalf("an uncategorized skip was excused as out of release scope: %+v", result)
	}

	if redteamgate.SkipOutOfReleaseScope(darwinCase) || redteamgate.SkipOutOfReleaseScope(dockerCase) || redteamgate.SkipOutOfReleaseScope(uncategorizedCase) {
		t.Fatal("no approving platform or capability category may be out of release scope")
	}
	if redteamgate.CategoryPlatform(redteamgate.AttestationCategoryCore) != "" {
		t.Fatal("core is a capability shape of the approving platform, not a platform of its own")
	}
}
