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
// fixture) parses cleanly and reserves exactly 41 uniquely-named cases —
// the corpus size the current manifest mandates.
func TestLoadManifestAcceptsRealManifest(t *testing.T) {
	path := filepath.Join("..", "redteam", "manifest.yaml")
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest(%s): %v", path, err)
	}
	if len(m.Cases) != 41 {
		t.Fatalf("expected 41 cases in the mandatory final attack corpus, got %d", len(m.Cases))
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
	for i := 1; i <= 41; i++ {
		if !seen[i] {
			t.Fatalf("manifest is missing case number %d", i)
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

func TestEvaluateFlagsUnmanifestedV7CaseAsDrift(t *testing.T) {
	manifest := Manifest{Cases: []CaseEntry{{Case: 1, Name: "TestV7Case1Known", Required: true}}}
	log := "" +
		"=== RUN   TestV7Case1Known\n" +
		"--- PASS: TestV7Case1Known (0.00s)\n" +
		"=== RUN   TestV7Case999Unmanifested\n" +
		"--- PASS: TestV7Case999Unmanifested (0.00s)\n"
	res := Evaluate(manifest, log, nil)
	if res.OK {
		t.Fatalf("expected an unmanifested TestV7Case* test to be flagged as drift: %+v", res)
	}
	if len(res.UnexpectedTests) != 1 || res.UnexpectedTests[0] != "TestV7Case999Unmanifested" {
		t.Fatalf("expected UnexpectedTests to name TestV7Case999Unmanifested, got %+v", res)
	}
}
