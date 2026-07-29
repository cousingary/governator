//go:build redteam

package redteam

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func s14WriteLiveArch(t *testing.T, dir, evidence, pub string, live bool, binaryHash, hookHash string) string {
	t.Helper()
	evidenceHash := "null"
	signer := "null"
	if evidence != "" {
		data, err := os.ReadFile(evidence)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		evidenceHash = hex.EncodeToString(sum[:])
		signer = "ed25519-public-key:" + pub
	}
	doc := fmt.Sprintf("---\nlive_install_claim: %t\ninstalled_binary_sha256: %s\nhook_configuration_sha256: %s\ninstall_evidence_sha256: %s\ninstall_evidence_signer: %s\n---\n# Architecture\n", live, binaryHash, hookHash, evidenceHash, signer)
	path := filepath.Join(dir, "arch.md")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func s14ValidateLiveInstall(t *testing.T, dist, commit, arch, evidence string) (string, error) {
	t.Helper()
	args := []string{s8Script(t, "audit_bundle_validate.py"), "--dist-dir", dist, "--repo", filepath.Dir(dist), "--release-commit", commit, "--architecture-doc", arch}
	if evidence != "" {
		args = append(args, "--install-evidence", evidence)
	}
	out, err := exec.Command("python3", args...).CombinedOutput()
	return string(out), err
}

func s14LiveEvidenceFixture(t *testing.T) (dir, dist, commit, arch, evidence, govBin, hookConfig, pub string) {
	t.Helper()
	dir = t.TempDir()
	commit = "abc123def456"
	dist = filepath.Join(dir, "dist")
	s8WriteCompleteDist(t, dist, commit)
	priv, key := s8GenerateKey(t)
	pub = key
	govBin = s8WriteFakeGov(t, dir, "1.0.2-rc6")
	hookConfig = s8WriteHookConfig(t, dir)
	manifest := s8WriteManifest(t, dir, "1.0.2-rc6", commit, govBin)
	if err := os.WriteFile(filepath.Join(dist, "build-manifest.json"), mustReadS14(t, manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	evidence = filepath.Join(dir, "install-evidence.json")
	out, err := s8GenerateEvidence(t, govBin, filepath.Join(dist, "build-manifest.json"), hookConfig, priv, evidence)
	if err != nil {
		t.Fatalf("generate evidence: %v\n%s", err, out)
	}
	binSum := sha256.Sum256(mustReadS14(t, govBin))
	hookSum := sha256.Sum256(mustReadS14(t, hookConfig))
	arch = s14WriteLiveArch(t, dir, evidence, pub, true, hex.EncodeToString(binSum[:]), hex.EncodeToString(hookSum[:]))
	return
}

func mustReadS14(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestV14Case337LiveInstallWordingReinstalledDoesNotAffectEnforcement(t *testing.T) {
	dir := t.TempDir()
	commit := "abc123def456"
	dist := filepath.Join(dir, "dist")
	s8WriteCompleteDist(t, dist, commit)
	arch := s14WriteLiveArch(t, dir, "", "", false, "null", "null")
	if err := os.WriteFile(arch, []byte("---\nlive_install_claim: false\ninstalled_binary_sha256: null\nhook_configuration_sha256: null\ninstall_evidence_sha256: null\ninstall_evidence_signer: null\n---\nThe live gate WAS reinstalled.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := s14ValidateLiveInstall(t, dist, commit, arch, "")
	if err != nil {
		t.Fatalf("prose wording changed enforcement: %v\n%s", err, out)
	}
}

func TestV14Case338LiveInstallWordingIsNowDoesNotAffectEnforcement(t *testing.T) {
	dir := t.TempDir()
	commit := "abc123def456"
	dist := filepath.Join(dir, "dist")
	s8WriteCompleteDist(t, dist, commit)
	arch := s14WriteLiveArch(t, dir, "", "", false, "null", "null")
	if err := os.WriteFile(arch, []byte("---\nlive_install_claim: false\ninstalled_binary_sha256: null\nhook_configuration_sha256: null\ninstall_evidence_sha256: null\ninstall_evidence_signer: null\n---\n~/.local/bin/gov is now rc6.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := s14ValidateLiveInstall(t, dist, commit, arch, "")
	if err != nil {
		t.Fatalf("prose wording changed enforcement: %v\n%s", err, out)
	}
}

func TestV14Case339LiveInstallClaimTrueWithoutEvidenceIsRejected(t *testing.T) {
	dir := t.TempDir()
	commit := "abc123def456"
	dist := filepath.Join(dir, "dist")
	s8WriteCompleteDist(t, dist, commit)
	arch := s14WriteLiveArch(t, dir, "", "", true, "a", "b")
	out, err := s14ValidateLiveInstall(t, dist, commit, arch, "")
	if err == nil || !strings.Contains(out, "LIVE_INSTALL_CLAIM_WITHOUT_EVIDENCE") {
		t.Fatalf("missing evidence accepted: %v\n%s", err, out)
	}
}

func TestV14Case340InvalidInstallationEvidenceSignatureIsRejected(t *testing.T) {
	_, dist, commit, arch, evidence, _, _, _ := s14LiveEvidenceFixture(t)
	var record map[string]any
	if err := json.Unmarshal(mustReadS14(t, evidence), &record); err != nil {
		t.Fatal(err)
	}
	record["signature"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	b, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidence, b, 0o644); err != nil {
		t.Fatal(err)
	}
	// Preserve the architecture document's evidence hash so this case reaches
	// cryptographic verification rather than failing only on a changed file.
	updatedHash := sha256.Sum256(b)
	lines := strings.Split(string(mustReadS14(t, arch)), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "install_evidence_sha256: ") {
			lines[i] = "install_evidence_sha256: " + hex.EncodeToString(updatedHash[:])
		}
	}
	if err := os.WriteFile(arch, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := s14ValidateLiveInstall(t, dist, commit, arch, evidence)
	if err == nil || !strings.Contains(out, "INSTALL_EVIDENCE_INVALID_SIGNATURE") {
		t.Fatalf("invalid signature accepted: %v\n%s", err, out)
	}
}

func TestV14Case341InstalledBinaryHashMismatchIsRejected(t *testing.T) {
	_, dist, commit, arch, evidence, _, _, _ := s14LiveEvidenceFixture(t)
	text := string(mustReadS14(t, arch))
	text = strings.Replace(text, "installed_binary_sha256: ", "installed_binary_sha256: 00", 1)
	if err := os.WriteFile(arch, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := s14ValidateLiveInstall(t, dist, commit, arch, evidence)
	if err == nil || !strings.Contains(out, "INSTALLED_BINARY_HASH_MISMATCH") {
		t.Fatalf("binary mismatch accepted: %v\n%s", err, out)
	}
}

func TestV14Case342HookConfigurationMismatchIsRejected(t *testing.T) {
	_, dist, commit, arch, evidence, _, _, _ := s14LiveEvidenceFixture(t)
	text := string(mustReadS14(t, arch))
	text = strings.Replace(text, "hook_configuration_sha256: ", "hook_configuration_sha256: 00", 1)
	if err := os.WriteFile(arch, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := s14ValidateLiveInstall(t, dist, commit, arch, evidence)
	if err == nil || !strings.Contains(out, "HOOK_CONFIGURATION_HASH_MISMATCH") {
		t.Fatalf("hook mismatch accepted: %v\n%s", err, out)
	}
}
