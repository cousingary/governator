//go:build redteam

package redteam

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

// v12_s1_gate_release_truth_test.go is the Sol v12 rc5 Session 1 corpus
// (agents/governator-sol-upgrade12-rc5-plan.md Session 1, report sections
// P0-2/P0-3/P1-8): the release-truth foundation. The zero-skip gate must
// compare the AUTHORITATIVE red-team inventory against the manifest rather
// than a stale TestV(7|8)Case regex, capability evidence must be tri-state,
// and the manifest must decode as strictly as a contract. Cases 1-7 prove
// gate-level refusals; cases 11-13 prove strict-loader refusals. Every case
// is enrolled by exact name in internal/redteam/manifest.yaml (cases
// 196-205) so the gate itself must see them pass to release.

// TestV12Case1UnmanifestedV9TestFailsGate: a V9-prefixed red-team test
// present in the discovered inventory but neither a manifest case nor a
// documented exclusion is unmanifested drift (P0-2). Under the old
// TestV(7|8)Case regex this V9 name was invisible to the gate.
func TestV12Case1UnmanifestedV9TestFailsGate(t *testing.T) {
	manifest := redteamgate.Manifest{
		Cases: []redteamgate.CaseEntry{
			{Case: 1, Name: "TestV9Case1KnownEnrolled", Required: true},
		},
	}
	log := "" +
		"=== RUN   TestV9Case1KnownEnrolled\n" +
		"--- PASS: TestV9Case1KnownEnrolled (0.00s)\n" +
		"=== RUN   TestV9Case777Unmanifested\n" +
		"--- PASS: TestV9Case777Unmanifested (0.00s)\n"
	res := redteamgate.EvaluateWithOptions(manifest, log, nil, redteamgate.Options{
		DiscoveredTests: []string{"TestV9Case1KnownEnrolled", "TestV9Case777Unmanifested"},
	})
	if res.OK {
		t.Fatalf("expected an unmanifested V9 inventory test to fail the gate: %+v", res)
	}
	if !contains(res.UnexpectedTests, "TestV9Case777Unmanifested") {
		t.Fatalf("expected UnexpectedTests to name TestV9Case777Unmanifested, got %+v", res)
	}
}

// TestV12Case2UnmanifestedV10TestFailsGate: same drift class as case 1, for
// the V10 namespace (also invisible under the V7/V8-only regex).
func TestV12Case2UnmanifestedV10TestFailsGate(t *testing.T) {
	manifest := redteamgate.Manifest{
		Cases: []redteamgate.CaseEntry{
			{Case: 1, Name: "TestV10Case1KnownEnrolled", Required: true},
		},
	}
	log := "" +
		"=== RUN   TestV10Case1KnownEnrolled\n" +
		"--- PASS: TestV10Case1KnownEnrolled (0.00s)\n" +
		"=== RUN   TestV10Case888Unmanifested\n" +
		"--- PASS: TestV10Case888Unmanifested (0.00s)\n"
	res := redteamgate.EvaluateWithOptions(manifest, log, nil, redteamgate.Options{
		DiscoveredTests: []string{"TestV10Case1KnownEnrolled", "TestV10Case888Unmanifested"},
	})
	if res.OK {
		t.Fatalf("expected an unmanifested V10 inventory test to fail the gate: %+v", res)
	}
	if !contains(res.UnexpectedTests, "TestV10Case888Unmanifested") {
		t.Fatalf("expected UnexpectedTests to name TestV10Case888Unmanifested, got %+v", res)
	}
}

// TestV12Case3UnmanifestedNonVersionedSecurityTestFailsGate: drift need not
// carry a versioned prefix. Any release-relevant security test the inventory
// discovers (here a non-versioned Assayer-integration test) that the
// manifest neither enrolls nor excludes must block the gate (P0-2).
func TestV12Case3UnmanifestedNonVersionedSecurityTestFailsGate(t *testing.T) {
	manifest := redteamgate.Manifest{
		Cases: []redteamgate.CaseEntry{
			{Case: 1, Name: "TestEnrolledSecurityCase", Required: true},
		},
	}
	log := "" +
		"=== RUN   TestEnrolledSecurityCase\n" +
		"--- PASS: TestEnrolledSecurityCase (0.00s)\n" +
		"=== RUN   TestEvaluateTimeout\n" +
		"--- SKIP: TestEvaluateTimeout (0.00s)\n"
	res := redteamgate.EvaluateWithOptions(manifest, log, nil, redteamgate.Options{
		DiscoveredTests: []string{"TestEnrolledSecurityCase", "TestEvaluateTimeout"},
	})
	if res.OK {
		t.Fatalf("expected an unmanifested non-versioned security test to fail the gate: %+v", res)
	}
	if !contains(res.UnexpectedTests, "TestEvaluateTimeout") {
		t.Fatalf("expected UnexpectedTests to name TestEvaluateTimeout, got %+v", res)
	}
}

// TestV12Case4SkippedDockerAttackOutsideManifestFailsGate: a Docker attack
// that skips and is not manifested cannot vanish from production evidence
// just because it lives outside the V7/V8 namespace (P0-2 root cause: the
// "Docker mutable-image attacks" / "in-container identity" skips the audit
// found among the ~22 skipped-but-ignored tests).
func TestV12Case4SkippedDockerAttackOutsideManifestFailsGate(t *testing.T) {
	manifest := redteamgate.Manifest{
		Cases: []redteamgate.CaseEntry{
			{Case: 1, Name: "TestEnrolledNonDockerCase", Required: true},
		},
	}
	log := "" +
		"=== RUN   TestEnrolledNonDockerCase\n" +
		"--- PASS: TestEnrolledNonDockerCase (0.00s)\n" +
		"=== RUN   TestAttack11MutableDockerTagChangesBeforeReplay\n" +
		"--- SKIP: TestAttack11MutableDockerTagChangesBeforeReplay (0.00s)\n"
	res := redteamgate.EvaluateWithOptions(manifest, log, nil, redteamgate.Options{
		DiscoveredTests: []string{"TestEnrolledNonDockerCase", "TestAttack11MutableDockerTagChangesBeforeReplay"},
	})
	if res.OK {
		t.Fatalf("expected a skipped unmanifested Docker attack to fail the gate: %+v", res)
	}
	if !contains(res.UnexpectedTests, "TestAttack11MutableDockerTagChangesBeforeReplay") {
		t.Fatalf("expected UnexpectedTests to name the Docker attack, got %+v", res)
	}
}

// TestV12Case5MissingCapabilityPredicateFailsGate: a manifest predicate the
// capability record does not prove is CAPABILITY_EVIDENCE_INCOMPLETE and
// blocks the release (P0-3) -- even when no case actually skipped. The old
// bool-map treated a missing key as "absent" and would have authorized a
// conditional skip on it.
func TestV12Case5MissingCapabilityPredicateFailsGate(t *testing.T) {
	manifest := redteamgate.Manifest{
		Cases: []redteamgate.CaseEntry{
			{
				Case: 1, Name: "TestConditionalCase", Required: true, Conditional: true,
				AllowedSkip: &redteamgate.AllowedSkip{Predicate: "has_second_uid", Reason: "no second uid"},
			},
		},
	}
	log := "=== RUN   TestConditionalCase\n--- PASS: TestConditionalCase (0.00s)\n"
	// capability record OMITS has_second_uid entirely
	res := redteamgate.EvaluateWithOptions(manifest, log, map[string]redteamgate.CapabilityRecord{}, redteamgate.Options{
		DiscoveredTests: []string{"TestConditionalCase"},
	})
	if res.OK {
		t.Fatalf("expected CAPABILITY_EVIDENCE_INCOMPLETE for an unproven predicate, got %+v", res)
	}
	if !incompleteFor(res.IncompleteCapabilities, "has_second_uid") {
		t.Fatalf("expected IncompleteCapabilities to name has_second_uid, got %+v", res)
	}
}

// TestV12Case6MisspelledCapabilityPredicateFailsGate: the capability record
// carries a typo'd predicate ("has_systemd_usr") while the manifest correctly
// references "has_systemd_user" -- the manifest predicate is therefore absent
// from the record and the gate refuses (P0-3). Isolates a producer-side typo
// from the manifest-side registry rejection.
func TestV12Case6MisspelledCapabilityPredicateFailsGate(t *testing.T) {
	manifest := redteamgate.Manifest{
		Cases: []redteamgate.CaseEntry{
			{
				Case: 1, Name: "TestSystemdCase", Required: true, Conditional: true,
				AllowedSkip: &redteamgate.AllowedSkip{Predicate: "has_systemd_user", Reason: "no systemd"},
			},
		},
	}
	log := "=== RUN   TestSystemdCase\n--- PASS: TestSystemdCase (0.00s)\n"
	// record has the MISSPELLED key; the manifest's correct predicate is absent
	caps := map[string]redteamgate.CapabilityRecord{
		"has_systemd_usr": {State: redteamgate.CapabilityAbsent},
	}
	res := redteamgate.EvaluateWithOptions(manifest, log, caps, redteamgate.Options{
		DiscoveredTests: []string{"TestSystemdCase"},
	})
	if res.OK {
		t.Fatalf("expected CAPABILITY_EVIDENCE_INCOMPLETE for a misspelled record predicate, got %+v", res)
	}
	if !incompleteFor(res.IncompleteCapabilities, "has_systemd_user") {
		t.Fatalf("expected IncompleteCapabilities to name has_systemd_user, got %+v", res)
	}
}

// TestV12Case7UnknownCapabilityValueFailsGate: the predicate is present in
// the record but its state is neither "present" nor "absent" -- an unproven
// value must not authorize a skip and must block the release (P0-3).
func TestV12Case7UnknownCapabilityValueFailsGate(t *testing.T) {
	manifest := redteamgate.Manifest{
		Cases: []redteamgate.CaseEntry{
			{
				Case: 1, Name: "TestGitCase", Required: true, Conditional: true,
				AllowedSkip: &redteamgate.AllowedSkip{Predicate: "git_trusted", Reason: "git not"},
			},
		},
	}
	log := "=== RUN   TestGitCase\n--- PASS: TestGitCase (0.00s)\n"
	// predicate present but state is an unproven sentinel (not present/absent)
	caps := map[string]redteamgate.CapabilityRecord{
		"git_trusted": {State: "unknown"},
	}
	res := redteamgate.EvaluateWithOptions(manifest, log, caps, redteamgate.Options{
		DiscoveredTests: []string{"TestGitCase"},
	})
	if res.OK {
		t.Fatalf("expected CAPABILITY_EVIDENCE_INCOMPLETE for an unproven capability value, got %+v", res)
	}
	if !incompleteFor(res.IncompleteCapabilities, "git_trusted") {
		t.Fatalf("expected IncompleteCapabilities to name git_trusted, got %+v", res)
	}
}

// TestV12Case11ManifestDuplicateYAMLKeyFailsLoad: the manifest is a release
// security policy and must parse as strictly as a contract (P1-8). A
// duplicated YAML mapping key silently last-wins under permissive decode;
// strict decoding rejects it at load time.
func TestV12Case11ManifestDuplicateYAMLKeyFailsLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.yaml")
	data := "version: 1\nversion: 2\ncases:\n  - case: 1\n    name: TestX\n    required: true\n    status: implemented\n"
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := redteamgate.LoadManifest(path); err == nil {
		t.Fatal("expected LoadManifest to reject a duplicate YAML mapping key")
	}
}

// TestV12Case12ManifestUnknownFieldFailsLoad: an unknown field in a manifest
// case is a typo or drift that permissive yaml.Unmarshal silently drops
// (P1-8). KnownFields rejects it.
func TestV12Case12ManifestUnknownFieldFailsLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.yaml")
	data := "version: 1\ncases:\n  - case: 1\n    name: TestX\n    required: true\n    status: implemented\n    bogus_field: oops\n"
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := redteamgate.LoadManifest(path); err == nil {
		t.Fatal("expected LoadManifest to reject an unknown manifest field")
	}
}

// TestV12Case13DuplicateCaseNumberFailsLoad: two manifest cases sharing a
// case number is a collision the manifest must reject (P1-8 uniqueness).
func TestV12Case13DuplicateCaseNumberFailsLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.yaml")
	data := "version: 1\ncases:\n  - case: 1\n    name: TestA\n    required: true\n    status: implemented\n  - case: 1\n    name: TestB\n    required: true\n    status: implemented\n"
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := redteamgate.LoadManifest(path); err == nil {
		t.Fatal("expected LoadManifest to reject a duplicate case number")
	}
}

// (contains is provided by internal/redteam/harness_test.go.)

// incompleteFor reports whether any IncompleteCapabilities entry names the
// given predicate (entries are formatted as "<predicate> (<detail>)").
func incompleteFor(entries []string, predicate string) bool {
	for _, e := range entries {
		if strings.HasPrefix(e, predicate+" ") || e == predicate {
			return true
		}
	}
	return false
}
