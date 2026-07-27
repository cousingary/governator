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
// fixture) parses cleanly under the Sol12 strict decoder: 285
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
// plus the documented non-production exclusions that let the authoritative
// inventory account for every //go:build redteam-tagged security test (P0-2).
func TestLoadManifestAcceptsRealManifest(t *testing.T) {
	path := filepath.Join("..", "redteam", "manifest.yaml")
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest(%s): %v", path, err)
	}
	if len(m.Cases) != 297 {
		t.Fatalf("expected 297 cases in the mandatory final attack corpus, got %d", len(m.Cases))
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
