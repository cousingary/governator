package redteamgate

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// writeExact writes an exact-manifest fixture to a temp file and returns its
// path. Used by every LoadExactManifest/LoadManifestSet test so each case is
// self-contained and the strict-decode behavior is exercised against real
// file I/O (matching how the release CLI loads them).
func writeExact(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadExactManifestAcceptsValid(t *testing.T) {
	dir := t.TempDir()
	path := writeExact(t, dir, "good.yaml",
		"name: red-team-attacks\nrequired_capabilities:\n  - linux\n  - has_systemd_user\ntests:\n  - TestExactAttackA\n  - TestExactAttackB\n")
	em, err := LoadExactManifest(path)
	if err != nil {
		t.Fatalf("LoadExactManifest: %v", err)
	}
	if em.Name != "red-team-attacks" {
		t.Fatalf("name = %q", em.Name)
	}
	if len(em.RequiredCapabilities) != 2 || em.RequiredCapabilities[0] != "linux" {
		t.Fatalf("required_capabilities = %+v", em.RequiredCapabilities)
	}
	if len(em.Tests) != 2 {
		t.Fatalf("tests = %+v", em.Tests)
	}
}

func TestLoadExactManifestRejectsUnknownField(t *testing.T) {
	// P1-8 strict decode: an unknown field is a contract violation, not a
	// permissive no-op. yaml.v3 KnownFields(true) catches it the same way
	// LoadManifest does for the numbered corpus.
	dir := t.TempDir()
	path := writeExact(t, dir, "bad.yaml", "name: bad\ntests: [TestX]\nbogus_field: 1\n")
	if _, err := LoadExactManifest(path); err == nil {
		t.Fatal("expected LoadExactManifest to reject an unknown field")
	}
}

func TestLoadExactManifestRejectsBlankName(t *testing.T) {
	dir := t.TempDir()
	path := writeExact(t, dir, "bad.yaml", "tests: [TestX]\n")
	if _, err := LoadExactManifest(path); err == nil {
		t.Fatal("expected LoadExactManifest to reject a blank manifest name")
	}
}

func TestLoadExactManifestRejectsUnknownPredicate(t *testing.T) {
	dir := t.TempDir()
	path := writeExact(t, dir, "bad.yaml", "name: bad\nrequired_capabilities: [not_a_real_predicate]\ntests: [TestX]\n")
	if _, err := LoadExactManifest(path); err == nil {
		t.Fatal("expected LoadExactManifest to reject an unknown capability predicate")
	}
}

func TestLoadExactManifestRejectsDuplicatePredicate(t *testing.T) {
	dir := t.TempDir()
	path := writeExact(t, dir, "bad.yaml", "name: bad\nrequired_capabilities:\n  - linux\n  - linux\ntests: [TestX]\n")
	if _, err := LoadExactManifest(path); err == nil {
		t.Fatal("expected LoadExactManifest to reject a duplicate required capability")
	}
}

func TestLoadExactManifestRejectsBlankPredicate(t *testing.T) {
	dir := t.TempDir()
	path := writeExact(t, dir, "bad.yaml", "name: bad\nrequired_capabilities:\n  - \"\"\ntests: [TestX]\n")
	if _, err := LoadExactManifest(path); err == nil {
		t.Fatal("expected LoadExactManifest to reject a blank required_capabilities entry")
	}
}

func TestLoadExactManifestRejectsEmptyTests(t *testing.T) {
	dir := t.TempDir()
	// An exact manifest with no tests asserts no coverage and only adds
	// noise to the set; require at least one. (A manifest that needs zero
	// tests should not exist.)
	path := writeExact(t, dir, "bad.yaml", "name: bad\ntests: []\n")
	if _, err := LoadExactManifest(path); err == nil {
		t.Fatal("expected LoadExactManifest to reject an empty tests list")
	}
}

func TestLoadExactManifestRejectsBlankTestName(t *testing.T) {
	dir := t.TempDir()
	path := writeExact(t, dir, "bad.yaml", "name: bad\ntests:\n  - \"\"\n  - TestReal\n")
	if _, err := LoadExactManifest(path); err == nil {
		t.Fatal("expected LoadExactManifest to reject a blank test name")
	}
}

func TestLoadExactManifestRejectsDuplicateTest(t *testing.T) {
	dir := t.TempDir()
	path := writeExact(t, dir, "bad.yaml", "name: bad\ntests:\n  - TestDup\n  - TestDup\n")
	if _, err := LoadExactManifest(path); err == nil {
		t.Fatal("expected LoadExactManifest to reject a duplicate test name")
	}
}

func TestLoadManifestSetZeroExactIsCorpusOnly(t *testing.T) {
	// S9b's wiring invariant: zero exact manifests loads the numbered corpus
	// alone. The real release manifest must load through LoadManifestSet
	// with no exact paths and yield exactly the corpus LoadManifest returns.
	path := filepath.Join("..", "redteam", "manifest.yaml")
	set, err := LoadManifestSet(path, nil)
	if err != nil {
		t.Fatalf("LoadManifestSet: %v", err)
	}
	if len(set.ExactManifests) != 0 {
		t.Fatalf("expected zero exact manifests, got %d", len(set.ExactManifests))
	}
	if len(set.Corpus.Cases) != 344 {
		t.Fatalf("expected the 344-case corpus, got %d", len(set.Corpus.Cases))
	}
	if set.ExactManifestTestNames() != nil {
		t.Fatalf("ExactManifestTestNames must be nil for an empty set")
	}
}

func TestLoadManifestSetRejectsDuplicateManifestName(t *testing.T) {
	dir := t.TempDir()
	corpus := writeExact(t, dir, "corpus.yaml", "version: 1\ncases:\n  - case: 1\n    name: TestCorpusOne\n    required: true\n")
	a := writeExact(t, dir, "a.yaml", "name: same\ntests: [TestA]\n")
	b := writeExact(t, dir, "b.yaml", "name: same\ntests: [TestB]\n")
	if _, err := LoadManifestSet(corpus, []string{a, b}); err == nil {
		t.Fatal("expected LoadManifestSet to reject a duplicate manifest name")
	}
}

func TestLoadManifestSetRejectsCrossManifestDuplicateTest(t *testing.T) {
	dir := t.TempDir()
	corpus := writeExact(t, dir, "corpus.yaml", "version: 1\ncases:\n  - case: 1\n    name: TestCorpusOne\n    required: true\n")
	a := writeExact(t, dir, "a.yaml", "name: first\ntests: [TestShared]\n")
	b := writeExact(t, dir, "b.yaml", "name: second\ntests: [TestShared]\n")
	if _, err := LoadManifestSet(corpus, []string{a, b}); err == nil {
		t.Fatal("expected LoadManifestSet to reject a test present in two manifests")
	}
}

func TestLoadManifestSetRejectsCorpusShadow(t *testing.T) {
	// A test must not be both a numbered corpus case and an exact-manifest
	// entry: that is the structural defense against silently re-classifying a
	// case out of the enforced corpus into a manifest S9b does not yet
	// enforce. Mirrors the exclusion-shadow rule in validateManifest.
	dir := t.TempDir()
	corpus := writeExact(t, dir, "corpus.yaml", "version: 1\ncases:\n  - case: 1\n    name: TestCorpusOne\n    required: true\n")
	em := writeExact(t, dir, "em.yaml", "name: extras\ntests: [TestCorpusOne]\n")
	if _, err := LoadManifestSet(corpus, []string{em}); err == nil {
		t.Fatal("expected LoadManifestSet to reject a test that is both a corpus case and an exact-manifest entry")
	}
}

func TestLoadManifestSetAcceptsValidCombination(t *testing.T) {
	dir := t.TempDir()
	corpus := writeExact(t, dir, "corpus.yaml", "version: 1\ncases:\n  - case: 1\n    name: TestCorpusOne\n    required: true\n")
	a := writeExact(t, dir, "a.yaml", "name: attacks\nrequired_capabilities: [linux]\ntests: [TestAttack1, TestAttack2]\n")
	b := writeExact(t, dir, "b.yaml", "name: integration\nrequired_capabilities: [has_docker_daemon]\ntests: [TestDockerBridge]\n")
	set, err := LoadManifestSet(corpus, []string{a, b})
	if err != nil {
		t.Fatalf("LoadManifestSet: %v", err)
	}
	if len(set.ExactManifests) != 2 {
		t.Fatalf("expected 2 exact manifests, got %d", len(set.ExactManifests))
	}
	got := set.ExactManifestTestNames()
	want := []string{"TestAttack1", "TestAttack2", "TestDockerBridge"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExactManifestTestNames = %+v, want %+v", got, want)
	}
}

// TestEvaluateWithOptionsIgnoresExactManifestsInS9b is the unit-level proof
// of S9b's "must not change a single verdict" boundary: the ExactManifests
// option is a populated-but-unconsumed wiring point in S9b, so a Result
// computed with exact manifests present must be byte-for-byte equal to one
// computed without them, for any corpus/log/capabilities. S9d is the session
// that begins reading ExactManifests; if it does so without also changing
// this property for the corpus-only case, this test stays green.
func TestEvaluateWithOptionsIgnoresExactManifestsInS9b(t *testing.T) {
	manifest := Manifest{Cases: []CaseEntry{{Case: 1, Name: "TestC1", Required: true}}}
	log := "=== RUN   TestC1\n--- PASS: TestC1 (0.00s)\n"
	caps := map[string]CapabilityRecord{}
	without := EvaluateWithOptions(manifest, log, caps, Options{})
	withExact := EvaluateWithOptions(manifest, log, caps, Options{
		ExactManifests: []ExactManifest{{
			Name:                 "irrelevant-in-s9b",
			RequiredCapabilities: []string{"linux"},
			Tests:                []string{"TestC1"}, // even a shadow-like name must not matter: not consumed
		}},
	})
	if !reflect.DeepEqual(without, withExact) {
		t.Fatalf("S9b must not let ExactManifests affect the verdict:\nwithout=%+v\nwithExact=%+v", without, withExact)
	}
}
