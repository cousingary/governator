//go:build redteam

package redteam

import (
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

// Session 7 (agents/governator-sol-upgrade7-plan.md): exact release tests
// (identity manifest) + release provenance. Corpus cases 31-36, report
// §"Mandatory final attack corpus" release tier: "A release with a missing
// current binary, a version that differs from the source tag, a missing
// manifest test, a substituted skip at constant count, a mode-stripped
// archive, or an installed binary whose hash ≠ release hash is impossible."
//
// 31/32/35/36 drive the real scripts/release_verify.sh end to end against a
// synthetic dist/ (buildReleaseFixtureDist, shared with the pre-existing
// TestAttack24/25 fixtures in release_test.go — same harness, new
// scenarios). 33/34 exercise internal/redteamgate directly: there is no
// "gov end to end" run for evaluating a already-captured test log against
// the manifest, so the black-box outcome asserted is the gate's own verdict
// (Result.OK / Result.Problems), never an unexported implementation detail.

// TestV7Case31MissingReleaseBinaryBlocksGate: build-manifest.json names an
// archive that was never actually written to the release directory. A
// security governor cannot release from "clean source + unknown/older
// binary" (report RB1) — release_verify.sh must refuse before it ever
// extracts or inspects anything.
func TestV7Case31MissingReleaseBinaryBlocksGate(t *testing.T) {
	commit := "31313131313131313131313131313131313131"
	dist, repoRoot, platform := buildReleaseFixtureDist(t, releaseFixtureOpts{
		version:        "1.0.2-rc1-redteam31",
		manifestCommit: commit,
		mode:           0755,
		omitArchive:    true,
	})

	out, err := runReleaseVerify(t, dist, repoRoot, platform)
	if err == nil {
		t.Fatalf("release_verify.sh accepted a release manifest whose archive does not exist; output:\n%s", out)
	}
	if !strings.Contains(out, "not found") {
		t.Fatalf("expected release_verify.sh to refuse a missing archive, got:\n%s", out)
	}
}

// TestV7Case32VersionMismatchBlocksGate: the archived binary's own
// `version --json` disagrees with build-manifest.json's declared version.
// claims.verifyArtifactManifest's version check (internal/claims/claims.go)
// must fail this before the release can package.
func TestV7Case32VersionMismatchBlocksGate(t *testing.T) {
	commit := "32323232323232323232323232323232323232"
	dist, repoRoot, platform := buildReleaseFixtureDist(t, releaseFixtureOpts{
		version:         "1.0.2-rc1-redteam32",
		manifestCommit:  commit,
		mode:            0755,
		artifactVersion: "1.0.2-rc1-redteam32-DRIFTED",
	})

	out, err := runReleaseVerify(t, dist, repoRoot, platform)
	if err == nil {
		t.Fatalf("release_verify.sh accepted an artifact whose self-reported version drifted from build-manifest.json; output:\n%s", out)
	}
	if !strings.Contains(out, "version") || !strings.Contains(out, "does not match") {
		t.Fatalf("expected release_verify.sh's claims-verify call to fail on a version mismatch, got:\n%s", out)
	}
}

// TestV7Case33MissingManifestTestBlocksGate: a required corpus case is
// entirely absent from the redteam suite's captured log (never ran, never
// even compiled in) — not a FAIL, not a SKIP, just missing. The old
// count-based gate (MIN_REDTEAM_TESTS) could not see this at all as long as
// some other test happened to make the total count. The identity-based
// gate must name the missing case and refuse.
func TestV7Case33MissingManifestTestBlocksGate(t *testing.T) {
	manifest := redteamgate.Manifest{
		Version: 1,
		Cases: []redteamgate.CaseEntry{
			{Case: 1, Name: "TestV7Case901FixturePresent", Required: true},
			{Case: 2, Name: "TestV7Case902FixtureNeverRan", Required: true},
		},
	}
	log := "" +
		"=== RUN   TestV7Case901FixturePresent\n" +
		"--- PASS: TestV7Case901FixturePresent (0.01s)\n"

	res := redteamgate.Evaluate(manifest, log, nil)
	if res.OK {
		t.Fatalf("gate accepted a suite silently missing a required corpus test; result: %+v", res)
	}
	found := false
	for _, name := range res.MissingTests {
		if name == "TestV7Case902FixtureNeverRan" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected MissingTests to name TestV7Case902FixtureNeverRan, got %+v", res)
	}
}

// TestV7Case34SubstitutedSkipAtConstantCountBlocksGate: report HS4's exact
// defect. A healthy run skips only the one case the manifest genuinely
// authorizes as conditional; the attack log instead skips a *different*,
// non-conditional required case and passes the conditional one — same
// tests-run count, same tests-skipped count, same tests-failed count (0) as
// the healthy baseline, so MIN_REDTEAM_TESTS/EXPECTED_REDTEAM_SKIPS-style
// counting alone cannot distinguish them. The identity-based gate must
// name the wrongly-skipped case as unexpected regardless of the totals
// matching.
func TestV7Case34SubstitutedSkipAtConstantCountBlocksGate(t *testing.T) {
	manifest := redteamgate.Manifest{
		Version: 1,
		Cases: []redteamgate.CaseEntry{
			{Case: 1, Name: "TestV7Case903FixtureAlwaysRequired", Required: true},
			{
				Case: 2, Name: "TestV7Case904FixtureConditional", Required: true, Conditional: true,
				AllowedSkip: &redteamgate.AllowedSkip{Predicate: "has_rare_capability", Reason: "environment lacks the rare capability"},
			},
		},
	}
	healthyLog := "" +
		"=== RUN   TestV7Case903FixtureAlwaysRequired\n" +
		"--- PASS: TestV7Case903FixtureAlwaysRequired (0.01s)\n" +
		"=== RUN   TestV7Case904FixtureConditional\n" +
		"    fixture_test.go:9: environment lacks the rare capability\n" +
		"--- SKIP: TestV7Case904FixtureConditional (0.00s)\n"
	if res := redteamgate.Evaluate(manifest, healthyLog, map[string]redteamgate.CapabilityRecord{"has_rare_capability": {State: redteamgate.CapabilityAbsent}}); !res.OK {
		t.Fatalf("gate rejected the healthy baseline it should accept: %+v", res)
	}

	attackLog := "" +
		"=== RUN   TestV7Case903FixtureAlwaysRequired\n" +
		"    fixture_test.go:9: unrelated, unauthorized reason\n" +
		"--- SKIP: TestV7Case903FixtureAlwaysRequired (0.00s)\n" +
		"=== RUN   TestV7Case904FixtureConditional\n" +
		"--- PASS: TestV7Case904FixtureConditional (0.01s)\n"
	res := redteamgate.Evaluate(manifest, attackLog, map[string]redteamgate.CapabilityRecord{"has_rare_capability": {State: redteamgate.CapabilityAbsent}})
	if res.OK {
		t.Fatalf("gate accepted a substituted skip at constant run/skip/fail counts; result: %+v", res)
	}
	found := false
	for _, name := range res.UnexpectedSkips {
		if name == "TestV7Case903FixtureAlwaysRequired" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected UnexpectedSkips to name TestV7Case903FixtureAlwaysRequired, got %+v", res)
	}
}

// TestV7Case35ArchiveModeStrippedBlocksGate: the archived gov binary ships
// at mode 0777. Same underlying assertion as the pre-existing
// TestAttack24ExtractedReleaseBinaryHasWrongMode (report P0-7 attack 24);
// reserved under its own TestV7CaseN name because the manifest and the
// identity-based gate key off this exact case's name, independent of the
// older v4 attack numbering.
func TestV7Case35ArchiveModeStrippedBlocksGate(t *testing.T) {
	commit := "35353535353535353535353535353535353535"
	dist, repoRoot, platform := buildReleaseFixtureDist(t, releaseFixtureOpts{
		version:        "1.0.2-rc1-redteam35",
		manifestCommit: commit,
		mode:           0777,
	})

	out, err := runReleaseVerify(t, dist, repoRoot, platform)
	if err == nil {
		t.Fatalf("release_verify.sh accepted an archived binary shipped at mode 0777; output:\n%s", out)
	}
	if !strings.Contains(out, "755") {
		t.Fatalf("expected release_verify.sh to fail on the mode-755 assertion, got:\n%s", out)
	}
}

// TestV7Case36InstalledHashMismatchBlocksGate: the release manifest's
// recorded artifact_sha256 does not match the archived binary's real hash
// (e.g. a locally-installed or re-packaged binary drifted from what the
// manifest says shipped). claims.verifyArtifactManifest's hash check must
// catch this independently of the commit-identity check TestAttack25
// already covers.
func TestV7Case36InstalledHashMismatchBlocksGate(t *testing.T) {
	commit := "36363636363636363636363636363636363636"
	dist, repoRoot, platform := buildReleaseFixtureDist(t, releaseFixtureOpts{
		version:                     "1.0.2-rc1-redteam36",
		manifestCommit:              commit,
		mode:                        0755,
		manifestArtifactSHAOverride: strings.Repeat("f", 64),
	})

	out, err := runReleaseVerify(t, dist, repoRoot, platform)
	if err == nil {
		t.Fatalf("release_verify.sh accepted a manifest whose artifact_sha256 does not match the real archived binary; output:\n%s", out)
	}
	if !strings.Contains(out, "sha256 mismatch") {
		t.Fatalf("expected release_verify.sh's claims-verify call to fail on an artifact sha256 mismatch, got:\n%s", out)
	}
}
