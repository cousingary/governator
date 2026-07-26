//go:build redteam

package redteam

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/redteamgate"
)

const v13S2Log = "=== RUN   TestV13S2SignedHostEvidence\n--- PASS: TestV13S2SignedHostEvidence (0.00s)\nPASS\n"

func v13S2Attestation(t *testing.T) (redteamgate.CapabilityAttestation, ed25519.PrivateKey, redteamgate.TrustedSignerRegistry, redteamgate.AttestationVerificationOptions) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := redteamgate.SigningKeyID(publicKey)
	registry := redteamgate.TrustedSignerRegistry{Signers: []redteamgate.TrustedAttestationSigner{{
		KeyID: keyID, PublicKey: hex.EncodeToString(publicKey), Categories: redteamgate.RequiredAttestationCategories,
	}}}
	now := time.Now().UTC().Truncate(time.Second)
	attestation := redteamgate.CapabilityAttestation{
		AttestationID:              "s2-attestation",
		Category:                   redteamgate.AttestationCategoryCore,
		HostIdentity:               "signed-capability-host",
		Platform:                   "linux/amd64",
		Kernel:                     "test-kernel",
		Capabilities:               map[string]redteamgate.CapabilityRecord{"has_docker_daemon": {State: redteamgate.CapabilityAbsent, Probe: "fixture", Result: "false", HostIdentity: "signed-capability-host", Platform: "linux/amd64", Timestamp: now.Format(time.RFC3339)}},
		ProbeImplementationVersion: "redteam-capabilities-v1",
		GovernatorCommit:           "governator-s2-commit",
		AssayerCommit:              "assayer-s2-commit",
		ReleaseVersion:             "v1.0.2-rc6",
		TestSourceHash:             "source-s2-hash",
		TestBinarySHA256:           "binary-s2-hash",
		ToolchainHash:              "toolchain-s2-hash",
		TestCommand:                []string{"go", "test", "-tags", "redteam", "./..."},
		PassedTests:                []string{"TestV13S2SignedHostEvidence"},
		RawLogSHA256:               v13S2SHA256(v13S2Log),
		StartedAt:                  now.Add(-time.Minute).Format(time.RFC3339),
		CompletedAt:                now.Format(time.RFC3339),
		SigningKeyID:               keyID,
	}
	options := redteamgate.AttestationVerificationOptions{
		TrustRegistry: registry,
		ExpectedBinding: &redteamgate.AttestationBinding{
			GovernatorCommit: attestation.GovernatorCommit,
			AssayerCommit:    attestation.AssayerCommit,
			ReleaseVersion:   attestation.ReleaseVersion,
			TestSourceHash:   attestation.TestSourceHash,
			TestBinarySHA256: attestation.TestBinarySHA256,
			ToolchainHash:    attestation.ToolchainHash,
		},
		ReleaseTime: now.Add(time.Minute),
		MaxAge:      time.Hour,
	}
	return attestation, privateKey, registry, options
}

func v13S2SHA256(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func v13S2WriteAttestation(t *testing.T, dir string, attestation redteamgate.CapabilityAttestation, log string, privateKey ed25519.PrivateKey, sign bool) {
	t.Helper()
	if sign {
		if err := redteamgate.SignCapabilityAttestation(&attestation, privateKey); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.Marshal(attestation)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "core.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".log", []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
}

func v13S2LoadError(t *testing.T, dir string, options redteamgate.AttestationVerificationOptions) string {
	t.Helper()
	_, err := redteamgate.LoadAttestationsWithOptions(dir, options)
	if err == nil {
		t.Fatal("forged capability attestation was accepted")
	}
	return err.Error()
}

func TestV13Case5UnsignedAttestationIsRejected(t *testing.T) {
	attestation, privateKey, _, options := v13S2Attestation(t)
	dir := t.TempDir()
	v13S2WriteAttestation(t, dir, attestation, v13S2Log, privateKey, false)
	if errorText := v13S2LoadError(t, dir, options); !strings.Contains(errorText, "missing signature") {
		t.Fatalf("unsigned attestation failed for the wrong reason: %s", errorText)
	}
}

func TestV13Case6InvalidAttestationSignatureIsRejected(t *testing.T) {
	attestation, privateKey, _, options := v13S2Attestation(t)
	attestation.HostIdentity = "modified-after-signing"
	dir := t.TempDir()
	// Sign the original record, then alter its signed host identity.
	attestation.HostIdentity = "signed-capability-host"
	if err := redteamgate.SignCapabilityAttestation(&attestation, privateKey); err != nil {
		t.Fatal(err)
	}
	attestation.HostIdentity = "modified-after-signing"
	v13S2WriteAttestation(t, dir, attestation, v13S2Log, privateKey, false)
	if errorText := v13S2LoadError(t, dir, options); !strings.Contains(errorText, "invalid attestation signature") {
		t.Fatalf("modified signed payload failed for the wrong reason: %s", errorText)
	}
}

func TestV13Case7UntrustedAttestationSignerIsRejected(t *testing.T) {
	attestation, privateKey, _, options := v13S2Attestation(t)
	options.TrustRegistry = redteamgate.TrustedSignerRegistry{Signers: []redteamgate.TrustedAttestationSigner{}}
	dir := t.TempDir()
	v13S2WriteAttestation(t, dir, attestation, v13S2Log, privateKey, true)
	if errorText := v13S2LoadError(t, dir, options); !strings.Contains(errorText, "untrusted attestation signer") {
		t.Fatalf("untrusted signer failed for the wrong reason: %s", errorText)
	}
}

func TestV13Case8AttestationForAnotherCommitIsRejected(t *testing.T) {
	attestation, privateKey, _, options := v13S2Attestation(t)
	attestation.GovernatorCommit = "another-commit"
	dir := t.TempDir()
	v13S2WriteAttestation(t, dir, attestation, v13S2Log, privateKey, true)
	if errorText := v13S2LoadError(t, dir, options); !strings.Contains(errorText, "binding does not match") {
		t.Fatalf("different commit failed for the wrong reason: %s", errorText)
	}
}

func TestV13Case9AttestationForAnotherRedteamBinaryIsRejected(t *testing.T) {
	attestation, privateKey, _, options := v13S2Attestation(t)
	attestation.TestBinarySHA256 = "another-binary"
	dir := t.TempDir()
	v13S2WriteAttestation(t, dir, attestation, v13S2Log, privateKey, true)
	if errorText := v13S2LoadError(t, dir, options); !strings.Contains(errorText, "binding does not match") {
		t.Fatalf("different redteam binary failed for the wrong reason: %s", errorText)
	}
}

func TestV13Case10FakeFiveCategorySameHostAttestationBundleIsRejected(t *testing.T) {
	attestation, _, _, options := v13S2Attestation(t)
	dir := t.TempDir()
	for _, category := range redteamgate.RequiredAttestationCategories {
		attestation.Category = category
		attestation.Signature = ""
		data, err := json.Marshal(attestation)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, category+".json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".log", []byte(v13S2Log), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if errorText := v13S2LoadError(t, dir, options); !strings.Contains(errorText, "missing signature") {
		t.Fatalf("forged five-category bundle failed for the wrong reason: %s", errorText)
	}
}

func TestV13Case11ModifiedLogAfterAttestationIsRejected(t *testing.T) {
	attestation, privateKey, _, options := v13S2Attestation(t)
	dir := t.TempDir()
	v13S2WriteAttestation(t, dir, attestation, v13S2Log+"modified after signing\n", privateKey, true)
	if errorText := v13S2LoadError(t, dir, options); !strings.Contains(errorText, "signed log hash differs") {
		t.Fatalf("modified log failed for the wrong reason: %s", errorText)
	}
}

func TestV13Case12TestListedAsCoveredWithoutAppearingInSignedLogIsRejected(t *testing.T) {
	attestation, privateKey, _, options := v13S2Attestation(t)
	attestation.PassedTests = []string{"TestInventedCoverage"}
	dir := t.TempDir()
	v13S2WriteAttestation(t, dir, attestation, v13S2Log, privateKey, true)
	if errorText := v13S2LoadError(t, dir, options); !strings.Contains(errorText, "signed test result lists") {
		t.Fatalf("invented coverage failed for the wrong reason: %s", errorText)
	}
}
