//go:build redteam

package redteam

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/redteamgate"
)

const v13S3CoveredTest = "TestV13S3SignedCoverage"

func v13S3Attestation(t *testing.T, category string) (redteamgate.CapabilityAttestation, ed25519.PrivateKey, redteamgate.AttestationVerificationOptions, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	platform := "linux/amd64"
	nonApproving := false
	if category == redteamgate.AttestationCategoryDarwin {
		platform = "darwin/amd64"
	}
	log := "=== RUN   " + v13S3CoveredTest + "\n--- PASS: " + v13S3CoveredTest + " (0.00s)\nPASS\n"
	record := func(state redteamgate.CapabilityState, probe, result string) redteamgate.CapabilityRecord {
		return redteamgate.CapabilityRecord{State: state, Probe: probe, Result: result, HostIdentity: "s3-capability-host", Platform: platform, Timestamp: now.Format(time.RFC3339)}
	}
	capabilities := map[string]redteamgate.CapabilityRecord{"linux": record(redteamgate.CapabilityPresent, "runtime.GOOS", "linux")}
	switch category {
	case redteamgate.AttestationCategoryDockerEnabled:
		capabilities["has_docker_daemon"] = record(redteamgate.CapabilityPresent, "docker info", "reachable")
	case redteamgate.AttestationCategorySystemdEnabled:
		capabilities["has_systemd_user"] = record(redteamgate.CapabilityPresent, "systemctl --user show-environment", "reachable")
	case redteamgate.AttestationCategoryFallbackHost:
		capabilities["has_systemd_user"] = record(redteamgate.CapabilityAbsent, "systemctl --user show-environment", "unreachable")
		capabilities["fallback_path_exercised"] = record(redteamgate.CapabilityPresent, "fallback fixture", "exercised")
	case redteamgate.AttestationCategoryDarwin:
		capabilities = map[string]redteamgate.CapabilityRecord{"has_darwin_native_host": record(redteamgate.CapabilityPresent, "runtime.GOOS", "darwin")}
	}
	keyID := redteamgate.SigningKeyID(publicKey)
	attestation := redteamgate.CapabilityAttestation{
		AttestationID: "s3-" + category, Category: category, HostIdentity: "s3-capability-host", Platform: platform, Kernel: "test-kernel",
		Capabilities: capabilities, ProbeImplementationVersion: "redteam-capabilities-v2", GovernatorCommit: "s3-governator", AssayerCommit: "s3-assayer",
		ReleaseVersion: "v1.0.2-rc6", TestSourceHash: "s3-source", TestBinarySHA256: "s3-binary", ToolchainHash: "s3-toolchain",
		TestCommand: []string{"go", "test", "-tags", "redteam", "./..."}, PassedTests: []string{v13S3CoveredTest}, RawLogSHA256: v13S2SHA256(log),
		StartedAt: now.Add(-time.Minute).Format(time.RFC3339), CompletedAt: now.Format(time.RFC3339), SigningKeyID: keyID, NonApproving: nonApproving,
	}
	options := redteamgate.AttestationVerificationOptions{TrustRegistry: redteamgate.TrustedSignerRegistry{Signers: []redteamgate.TrustedAttestationSigner{{KeyID: keyID, PublicKey: hex.EncodeToString(publicKey), Categories: redteamgate.RequiredAttestationCategories}}}, ExpectedBinding: &redteamgate.AttestationBinding{GovernatorCommit: attestation.GovernatorCommit, AssayerCommit: attestation.AssayerCommit, ReleaseVersion: attestation.ReleaseVersion, TestSourceHash: attestation.TestSourceHash, TestBinarySHA256: attestation.TestBinarySHA256, ToolchainHash: attestation.ToolchainHash}, ReleaseTime: now.Add(time.Minute), MaxAge: time.Hour}
	return attestation, privateKey, options, log
}

func v13S3Load(t *testing.T, attestations []redteamgate.CapabilityAttestation, privateKey ed25519.PrivateKey, options redteamgate.AttestationVerificationOptions, log string) []redteamgate.CapabilityAttestation {
	t.Helper()
	dir := t.TempDir()
	for index, attestation := range attestations {
		if err := redteamgate.SignCapabilityAttestation(&attestation, privateKey); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(attestation)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, string(rune('a'+index))+".json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".log", []byte(log), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := redteamgate.LoadAttestationsWithOptions(dir, options)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func TestV13Case13DockerCategoryFromHostWithoutDockerIsRejected(t *testing.T) {
	attestation, privateKey, options, log := v13S3Attestation(t, redteamgate.AttestationCategoryDockerEnabled)
	attestation.Capabilities["has_docker_daemon"] = redteamgate.CapabilityRecord{State: redteamgate.CapabilityAbsent, Probe: "docker info", Result: "unreachable", HostIdentity: attestation.HostIdentity, Platform: attestation.Platform, Timestamp: attestation.CompletedAt}
	result := redteamgate.AggregateAndVerify(v13S3Load(t, []redteamgate.CapabilityAttestation{attestation}, privateKey, options, log), nil)
	if result.OK || !strings.Contains(strings.Join(result.Problems, "\n"), "has_docker_daemon") {
		t.Fatalf("Docker-less host was accepted as Docker evidence: %+v", result)
	}
}

func TestV13Case14SystemdCategoryFromHostWithoutSystemdIsRejected(t *testing.T) {
	attestation, privateKey, options, log := v13S3Attestation(t, redteamgate.AttestationCategorySystemdEnabled)
	attestation.Capabilities["has_systemd_user"] = redteamgate.CapabilityRecord{State: redteamgate.CapabilityAbsent, Probe: "systemctl", Result: "unreachable", HostIdentity: attestation.HostIdentity, Platform: attestation.Platform, Timestamp: attestation.CompletedAt}
	result := redteamgate.AggregateAndVerify(v13S3Load(t, []redteamgate.CapabilityAttestation{attestation}, privateKey, options, log), nil)
	if result.OK || !strings.Contains(strings.Join(result.Problems, "\n"), "has_systemd_user") {
		t.Fatalf("systemd-less host was accepted as systemd evidence: %+v", result)
	}
}

func TestV13Case15FallbackCategoryFromSystemdEnabledExecutionIsRejected(t *testing.T) {
	attestation, privateKey, options, log := v13S3Attestation(t, redteamgate.AttestationCategoryFallbackHost)
	attestation.Capabilities["has_systemd_user"] = redteamgate.CapabilityRecord{State: redteamgate.CapabilityPresent, Probe: "systemctl", Result: "reachable", HostIdentity: attestation.HostIdentity, Platform: attestation.Platform, Timestamp: attestation.CompletedAt}
	result := redteamgate.AggregateAndVerify(v13S3Load(t, []redteamgate.CapabilityAttestation{attestation}, privateKey, options, log), nil)
	if result.OK || !strings.Contains(strings.Join(result.Problems, "\n"), "has_systemd_user") {
		t.Fatalf("systemd execution was accepted as fallback evidence: %+v", result)
	}
}

func TestV13Case16EmptyCapabilityMapIsRejected(t *testing.T) {
	attestation, privateKey, options, log := v13S3Attestation(t, redteamgate.AttestationCategoryCore)
	attestation.Capabilities = map[string]redteamgate.CapabilityRecord{}
	dir := t.TempDir()
	v13S2WriteAttestation(t, dir, attestation, log, privateKey, true)
	if _, err := redteamgate.LoadAttestationsWithOptions(dir, options); err == nil || !strings.Contains(err.Error(), "missing capabilities") {
		t.Fatalf("empty capability map was accepted: %v", err)
	}
}

func TestV13Case17MissingCapabilityProbeIsRejected(t *testing.T) {
	attestation, privateKey, options, log := v13S3Attestation(t, redteamgate.AttestationCategoryDockerEnabled)
	record := attestation.Capabilities["has_docker_daemon"]
	record.Probe = ""
	attestation.Capabilities["has_docker_daemon"] = record
	result := redteamgate.AggregateAndVerify(v13S3Load(t, []redteamgate.CapabilityAttestation{attestation}, privateKey, options, log), nil)
	if result.OK || !strings.Contains(strings.Join(result.Problems, "\n"), "no probe") {
		t.Fatalf("missing probe was accepted: %+v", result)
	}
}

func TestV13Case18SameEvidenceRelabeledUnderMultipleCategoriesIsRejected(t *testing.T) {
	core, privateKey, options, log := v13S3Attestation(t, redteamgate.AttestationCategoryCore)
	docker := core
	docker.AttestationID = "s3-docker-relabel"
	docker.Category = redteamgate.AttestationCategoryDockerEnabled
	docker.Capabilities["has_docker_daemon"] = redteamgate.CapabilityRecord{State: redteamgate.CapabilityPresent, Probe: "docker info", Result: "reachable", HostIdentity: docker.HostIdentity, Platform: docker.Platform, Timestamp: docker.CompletedAt}
	result := redteamgate.AggregateAndVerify(v13S3Load(t, []redteamgate.CapabilityAttestation{core, docker}, privateKey, options, log), nil)
	if result.OK || !strings.Contains(strings.Join(result.Problems, "\n"), "relabel") {
		t.Fatalf("same evidence was accepted under two categories: %+v", result)
	}
}

// Sol13 rc6 Session 9: this invariant remains independent of platform
// classification and is asserted on a non-platform-bound category.
func TestV13Case19NonApprovingCategoryCannotCoverProductionTest(t *testing.T) {
	manifest := redteamgate.Manifest{Cases: []redteamgate.CaseEntry{{Case: 1, Name: "TestDockerOnly", Required: true, AttestationCategory: redteamgate.AttestationCategoryDockerEnabled}}}
	log := "=== RUN   TestDockerOnly\n--- SKIP: TestDockerOnly (0.00s)\n"
	result := redteamgate.EvaluateWithOptions(manifest, log, nil, redteamgate.Options{RequireZeroSkips: true, Attestations: &redteamgate.AggregationResult{CoverageByCategory: map[string]map[string]bool{redteamgate.AttestationCategoryDockerEnabled: {"TestDockerOnly": true}}, NonApprovingCategories: map[string]bool{redteamgate.AttestationCategoryDockerEnabled: true}}})
	if result.OK || len(result.UnexpectedSkips) != 1 {
		t.Fatalf("non-approving category covered a production skip: %+v", result)
	}
	if len(result.OutOfScopeSkips) != 0 {
		t.Fatalf("a non-platform-bound category must never be excused as out of release scope: %+v", result)
	}
}

func TestV13Case20SupersededTestWithoutPassingReplacementIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	data := "version: 1\ncases:\n  - case: 1\n    name: TestReplacement\n    required: true\nexclusions:\n  - name: TestOldAttack\n    status: superseded\n    reason: replaced\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := redteamgate.LoadManifest(path); err == nil || !strings.Contains(err.Error(), "replacement_tests") {
		t.Fatalf("superseded test without a passing replacement was accepted: %v", err)
	}
}
