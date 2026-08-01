package redteamgate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadManifestRejectsDuplicateName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.yaml")
	data := "version: 1\ncases:\n  - case: 1\n    name: TestV7CaseX\n    required: true\n  - case: 2\n    name: TestV7CaseX\n    required: true\n"
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("expected LoadManifest to reject a duplicate case name")
	}
}

func TestLoadManifestRejectsBlankName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.yaml")
	data := "version: 1\ncases:\n  - case: 1\n    required: true\n"
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("expected LoadManifest to reject a case with a blank name")
	}
}

// TestLoadManifestAcceptsRealManifest is a regression check that
// internal/redteam/manifest.yaml (the actual release-gating manifest, not a
// fixture) parses cleanly under the Sol12 strict decoder: 342
// uniquely-numbered, uniquely-named required cases (the rc5 upgrade-12
// Session 1 corpus, cases 196-205, Session 2's cases 206-208, Session 3's
// cases 209-214, Session 4's cases 215-221, Session 5's cases 222-226, and
// Session 6's cases 227-231, and Sol13 S1-S2's cases 245-256, on top of
// upgrade-11's 195), plus Sol13 Session 3's cases 257-264, Sol13 Session 4's
// cases 266-272, Sol13 Session 5's cases 273-282, Sol13 Session 6's cases
// 283-285, plus case 296 (a
// rc6-upg13 S3 exclusion-audit gap closure enrolling a pre-existing
// internal/containment test that was never in the manifest -- deliberately
// numbered outside 265-295, which stays reserved for Sol13 Sessions 4-8) and
// case 297 (Sol13 Session 9's release-scope correction, numbered outside the
// same reserved range for the same reason), and case 298 (Sol13 Session 9's
// ledger-ordering correction: `ORDER BY created DESC` on an RFC3339Nano TEXT
// column selected the OLDER row, serving stale consumed artifacts, replayed
// approvals, and capability attestations -- numbered outside the same reserved
// range for the same reason),
// plus six Sol14 S1 cases (whose TestV14Case298-303 names are cycle-ordinal;
// their manifest ids are 299-304 because the prior Sol13 correction already
// owns id 298), plus six Sol14 S2 cases (TestV14Case304-309, manifest ids
// 305-310), plus seven Sol14 S3 cases (TestV14Case310-316, manifest ids
// 311-317), plus two Sol14 S4 cases (TestV14Case317-318, manifest ids
// 318-319), plus the documented non-production exclusions that let the authoritative
// inventory account for every //go:build redteam-tagged security test (P0-2),
// plus Sol14 S5's five cases (TestV14Case319-323, manifest ids 320-324) and
// S6's seven release-bound Assayer cases. S6 exhausted the drifted numbering:
// its seven tests (TestV14Case324-330) needed ids 325-331, but 331 was already
// S7's, so 1b28f42 duplicated id 330 and broke manifest load. The duplicate is
// resolved by reclaiming id 265 -- never allocated by the rc6-u13-s3 corpus,
// and the original source of the count/maximum skew that caused the drift --
// for TestV14Case329PostEvaluationArtifactMutationIsDetected. The corpus is
// now contiguous 1-342 with count == maximum, so Sol14 S7's six cases
// (TestV14Case331-336) and S8's six (TestV14Case337-342) are name-aligned and
// S9 appends 343-344 for a final total of 344. rc8-upg15 S1 (Sol15 P0-3)
// appends 345-353 (the quota-timestamp-panic corpus) for a final total of
// 353. rc8-upg15 S2b (Sol15 P0-1) appends 354-361 (the release
// tool-substitution corpus) for a final total of 361. rc8-upg15 S3 (Sol15
// P0-4/P2-2) appends 362-368 (the exact-artifact corpus) for a final total
// of 368. rc8-upg15 S4-S9 bring the corpus to 391. v16-release S1 appends
// 392-393 (document-truth corpus), S2 appends 394 (branch-topology corpus),
// S3 appends 395-397 (dist-dir-trap corpus), S4 appends 398-399
// (architecture-restructure corpus), S5 appends 400 (assayer-pin corpus) for
// a final total of 400, and S6 appends 401-402 (native-acceptance
// publication-gate corpus) for a final total of 402. v16-release S7a
// appends 403-418 (CI release-tool trust, provenance, and hosted-tier setup)
// for 418.
//
// This constant was not updated by S7 or S8; it read 330 (the post-S6 count)
// while the manifest held 342, so this package failed before the duplicate
// landed. Update it in every session that enrolls cases.
func TestLoadManifestAcceptsRealManifest(t *testing.T) {
	path := filepath.Join("..", "redteam", "manifest.yaml")
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest(%s): %v", path, err)
	}
	if len(m.Cases) != 418 {
		t.Fatalf("expected 418 cases in the mandatory final attack corpus, got %d", len(m.Cases))
	}
	seen := make(map[int]bool)
	for _, c := range m.Cases {
		if seen[c.Case] {
			t.Fatalf("duplicate case number %d", c.Case)
		}
		seen[c.Case] = true
		if !c.Required {
			t.Fatalf("case %d (%s): every corpus case must be required (conditional skips are the only sanctioned exception, and are still required=true)", c.Case, c.Name)
		}
	}
	for i := 1; i <= 264; i++ {
		if !seen[i] {
			t.Fatalf("manifest is missing case number %d", i)
		}
	}
	if len(m.Exclusions) == 0 {
		t.Fatalf("manifest carries no exclusions: the authoritative red-team inventory cannot account for non-manifest security tests (Sol12 P0-2)")
	}
	exclSeen := make(map[string]bool)
	for _, e := range m.Exclusions {
		if exclSeen[e.Name] {
			t.Fatalf("duplicate exclusion name %s", e.Name)
		}
		exclSeen[e.Name] = true
		if e.Reason == "" {
			t.Fatalf("exclusion %s has no documented reason", e.Name)
		}
	}
}

func TestParseVerboseLogCapturesSkipReason(t *testing.T) {
	log := "" +
		"=== RUN   TestFoo\n" +
		"    foo_test.go:12: expected-fail until S1: some reason\n" +
		"--- SKIP: TestFoo (0.00s)\n" +
		"=== RUN   TestBar\n" +
		"--- PASS: TestBar (0.01s)\n" +
		"=== RUN   TestBaz\n" +
		"--- FAIL: TestBaz (0.02s)\n"
	outcomes := ParseVerboseLog(log)
	if got := outcomes["TestFoo"]; got.Result != "SKIP" || !strings.Contains(got.Reason, "expected-fail until S1: some reason") {
		t.Fatalf("TestFoo: got %+v", got)
	}
	if got := outcomes["TestBar"]; got.Result != "PASS" {
		t.Fatalf("TestBar: got %+v", got)
	}
	if got := outcomes["TestBaz"]; got.Result != "FAIL" {
		t.Fatalf("TestBaz: got %+v", got)
	}
}

func TestEvaluateFlagsFailureRegardlessOfNamePrefix(t *testing.T) {
	// A manifest entry need not literally start with "TestV7Case" to be
	// checked for real — manifest membership, not string shape, decides
	// what's in scope. This guards the exact bug caught while building the
	// corpus (TestV7Case34's fixture): a naive "only process TestV7Case*
	// names" filter silently drops any manifest entry using a different
	// convention.
	manifest := Manifest{Cases: []CaseEntry{{Case: 1, Name: "SomeOtherConvention", Required: true}}}
	log := "=== RUN   SomeOtherConvention\n--- FAIL: SomeOtherConvention (0.00s)\n"
	res := Evaluate(manifest, log, nil)
	if res.OK {
		t.Fatalf("expected failure to be caught: %+v", res)
	}
	if len(res.FailedTests) != 1 || res.FailedTests[0] != "SomeOtherConvention" {
		t.Fatalf("expected FailedTests to name SomeOtherConvention, got %+v", res)
	}
}

func TestEvaluateFlagsUnmanifestedVersionedCaseAsDrift(t *testing.T) {
	// Sol12 P0-2: the stale TestV(7|8)Case regex is gone. Drift is now
	// detected from the AUTHORITATIVE INVENTORY supplied by the caller —
	// release.sh discovers it from //go:build redteam-tagged source. A test
	// in the inventory that is neither a manifest case nor a documented
	// exclusion is unmanifested drift and blocks the gate, regardless of
	// which version prefix its name happens to carry.
	manifest := Manifest{
		Cases:      []CaseEntry{{Case: 1, Name: "TestV7Case1Known", Required: true}},
		Exclusions: []ExclusionEntry{},
	}
	log := "" +
		"=== RUN   TestV7Case1Known\n" +
		"--- PASS: TestV7Case1Known (0.00s)\n" +
		"=== RUN   TestV8Case999Unmanifested\n" +
		"--- PASS: TestV8Case999Unmanifested (0.00s)\n"
	res := EvaluateWithOptions(manifest, log, nil, Options{
		DiscoveredTests: []string{"TestV7Case1Known", "TestV8Case999Unmanifested"},
	})
	if res.OK {
		t.Fatalf("expected an unmanifested inventory test to be flagged as drift: %+v", res)
	}
	if len(res.UnexpectedTests) != 1 || res.UnexpectedTests[0] != "TestV8Case999Unmanifested" {
		t.Fatalf("expected UnexpectedTests to name TestV8Case999Unmanifested, got %+v", res)
	}
}

func TestEvaluateIgnoresLegacyV6CaseNamesOutsideManifest(t *testing.T) {
	manifest := Manifest{Cases: []CaseEntry{{Case: 1, Name: "TestV7Case1Known", Required: true}}}
	log := "" +
		"=== RUN   TestV7Case1Known\n" +
		"--- PASS: TestV7Case1Known (0.00s)\n" +
		"=== RUN   TestV6Case999Legacy\n" +
		"--- PASS: TestV6Case999Legacy (0.00s)\n"
	res := Evaluate(manifest, log, nil)
	if !res.OK {
		t.Fatalf("legacy v6 cases should not be treated as manifest drift: %+v", res)
	}
	if len(res.UnexpectedTests) != 0 {
		t.Fatalf("unexpected tests = %+v, want none", res.UnexpectedTests)
	}
}

func TestEvaluateExactManifestSkipBlockedWhenCapabilityPresent(t *testing.T) {
	manifest := Manifest{Cases: []CaseEntry{{Case: 1, Name: "TestCorpusOne", Required: true}}}
	exact := []ExactManifest{{
		Name:                 "attacks",
		RequiredCapabilities: []string{"linux"},
		Tests:                []string{"TestExactAttack"},
	}}
	log := "" +
		"=== RUN   TestCorpusOne\n--- PASS: TestCorpusOne (0.00s)\n" +
		"=== RUN   TestExactAttack\n--- SKIP: TestExactAttack (0.00s)\n"
	caps := map[string]CapabilityRecord{
		"linux": {State: CapabilityPresent, Probe: "runtime.GOOS", Result: "linux"},
	}
	res := EvaluateWithOptions(manifest, log, caps, Options{
		RequireZeroSkips: true,
		DiscoveredTests:  []string{"TestCorpusOne", "TestExactAttack"},
		ExactManifests:   exact,
	})
	if res.OK {
		t.Fatalf("exact-manifest skip with capability present must block: %+v", res)
	}
	if len(res.UnexpectedSkips) != 1 || res.UnexpectedSkips[0] != "TestExactAttack" {
		t.Fatalf("expected TestExactAttack in UnexpectedSkips, got %+v", res)
	}
}

func TestEvaluateExactManifestSkipAuthorizedWhenCapabilityAbsent(t *testing.T) {
	manifest := Manifest{Cases: []CaseEntry{{Case: 1, Name: "TestCorpusOne", Required: true}}}
	exact := []ExactManifest{{
		Name:                 "docker-tests",
		RequiredCapabilities: []string{"has_docker_daemon"},
		Tests:                []string{"TestDockerAttack"},
	}}
	log := "" +
		"=== RUN   TestCorpusOne\n--- PASS: TestCorpusOne (0.00s)\n" +
		"=== RUN   TestDockerAttack\n--- SKIP: TestDockerAttack (0.00s)\n"
	caps := map[string]CapabilityRecord{
		"has_docker_daemon": {State: CapabilityAbsent, Probe: "docker info", Result: "cannot connect"},
	}
	res := EvaluateWithOptions(manifest, log, caps, Options{
		RequireZeroSkips: true,
		DiscoveredTests:  []string{"TestCorpusOne", "TestDockerAttack"},
		ExactManifests:   exact,
	})
	if !res.OK {
		t.Fatalf("exact-manifest skip with capability proven absent must be authorized: %+v", res)
	}
	if len(res.OutOfScopeSkips) != 1 || res.OutOfScopeSkips[0] != "TestDockerAttack" {
		t.Fatalf("expected TestDockerAttack in OutOfScopeSkips, got %+v", res)
	}
}

func TestEvaluateExactManifestIncompleteCapabilityBlocks(t *testing.T) {
	manifest := Manifest{Cases: []CaseEntry{{Case: 1, Name: "TestCorpusOne", Required: true}}}
	exact := []ExactManifest{{
		Name:                 "attacks",
		RequiredCapabilities: []string{"linux"},
		Tests:                []string{"TestExactAttack"},
	}}
	log := "" +
		"=== RUN   TestCorpusOne\n--- PASS: TestCorpusOne (0.00s)\n" +
		"=== RUN   TestExactAttack\n--- PASS: TestExactAttack (0.00s)\n"
	res := EvaluateWithOptions(manifest, log, nil, Options{
		DiscoveredTests: []string{"TestCorpusOne", "TestExactAttack"},
		ExactManifests:  exact,
	})
	if res.OK {
		t.Fatalf("incomplete capability evidence must block: %+v", res)
	}
	if len(res.IncompleteCapabilities) != 1 {
		t.Fatalf("expected one incomplete capability, got %+v", res.IncompleteCapabilities)
	}
}
