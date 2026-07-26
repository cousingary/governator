//go:build redteam

package redteam

import (
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func s8Script(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "scripts", name)
}

func s8GenerateKey(t *testing.T) (privHex, pubHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(priv), hex.EncodeToString(pub)
}

func s8WriteManifest(t *testing.T, dir, version, commit, govBinPath string) string {
	t.Helper()
	binSHA := ""
	if govBinPath != "" {
		data, err := os.ReadFile(govBinPath)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		binSHA = hex.EncodeToString(sum[:])
	}
	manifest := map[string]any{
		"version":       version,
		"source_commit": commit,
		"dirty":         false,
		"artifacts": []map[string]any{
			{"name": "gov", "sha256": binSHA},
		},
	}
	path := filepath.Join(dir, "build-manifest.json")
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func s8WriteFakeGov(t *testing.T, dir, version string) string {
	t.Helper()
	path := filepath.Join(dir, "gov")
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  hook)\n" +
		"    input=$(cat)\n" +
		"    tool=$(printf '%s' \"$input\" | python3 -c 'import sys,json; print(json.load(sys.stdin).get(\"tool_name\",\"\"))' 2>/dev/null)\n" +
		"    case \"$tool\" in\n" +
		"      Read) exit 0 ;;\n" +
		"      Write)\n" +
		"        fp=$(printf '%s' \"$input\" | python3 -c 'import sys,json; print(json.load(sys.stdin).get(\"tool_input\",{}).get(\"file_path\",\"\"))' 2>/dev/null)\n" +
		"        case \"$fp\" in /etc/*) exit 1 ;; *) exit 0 ;; esac ;;\n" +
		"      apply_patch) exit 1 ;;\n" +
		"      *) exit 0 ;;\n" +
		"    esac ;;\n" +
		"  version) echo 'gov " + version + "' ;;\n" +
		"  *) exit 0 ;;\n" +
		"esac\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func s8WriteHookConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "hook-config.json")
	if err := os.WriteFile(path, []byte(`{"hooks":[{"event":"PreToolUse","command":"gov hook pre-tool-use"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func s8GenerateEvidence(t *testing.T, govBin, manifest, hookConfig, privHex, out string) (string, error) {
	t.Helper()
	cmd := exec.Command("python3", s8Script(t, "install_evidence.py"), "generate",
		"--installed-path", govBin,
		"--release-manifest", manifest,
		"--hook-config", hookConfig,
		"--signing-key", privHex,
		"--out", out,
	)
	outBytes, err := cmd.CombinedOutput()
	return string(outBytes), err
}

func s8VerifyEvidence(t *testing.T, evidence, manifest, pubHex string) (string, error) {
	t.Helper()
	cmd := exec.Command("python3", s8Script(t, "install_evidence.py"), "verify",
		"--evidence", evidence,
		"--release-manifest", manifest,
		"--trusted-public-key", pubHex,
	)
	outBytes, err := cmd.CombinedOutput()
	return string(outBytes), err
}

func s8WriteGzLog(t *testing.T, dir, name string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte("ok\n")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

func s8WriteCompleteDist(t *testing.T, dir, commit string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("checksums.txt", "deadbeef  gov_1.0.2-rc6_linux_amd64.tar.gz\n")
	write("checksums.txt.minisig", "untrusted comment: test\nAAAA\n")
	manifest := map[string]any{"version": "1.0.2-rc6", "source_commit": commit, "dirty": false}
	mdata, _ := json.Marshal(manifest)
	write("build-manifest.json", string(mdata))
	write("architecture-build-metadata.json", "{}")
	write("sbom.json", "{}")
	write("claims.yaml", "version: 1\ncases: []\n")
	testSummary := map[string]any{
		"overall_result": "PASS",
		"suites": map[string]any{
			"redteam": map[string]any{"tests_skipped": 0},
		},
	}
	tsdata, _ := json.Marshal(testSummary)
	write("test-summary.json", string(tsdata))
	write("acceptance-summary.json", `{"overall_result":"PASS"}`)
	write("claims-verify-report.txt", "ok\n")
	write("preflight.json", "{}")
	write("toolset.json", "{}")
	for _, log := range []string{"unit.log.gz", "race.log.gz", "integration.log.gz", "corpus.log.gz", "redteam.log.gz", "redteam-race.log.gz"} {
		s8WriteGzLog(t, dir, log)
	}
	archive := filepath.Join(dir, "gov_1.0.2-rc6_linux_amd64.tar.gz")
	s8WriteGzLog(t, dir, "gov_1.0.2-rc6_linux_amd64.tar.gz")
	_ = archive
}

func TestV13Case289InstalledBinaryDifferingFromReleaseBinaryIsRejected(t *testing.T) {
	dir := t.TempDir()
	privHex, pubHex := s8GenerateKey(t)
	govBin := s8WriteFakeGov(t, dir, "1.0.2-rc6")
	manifest := s8WriteManifest(t, dir, "1.0.2-rc6", "abc123", govBin)
	hookConfig := s8WriteHookConfig(t, dir)
	evidencePath := filepath.Join(dir, "install-evidence.json")

	out, err := s8GenerateEvidence(t, govBin, manifest, hookConfig, privHex, evidencePath)
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, out)
	}

	if err := os.WriteFile(govBin, []byte("#!/bin/sh\necho substituted\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	out, err = s8VerifyEvidence(t, evidencePath, manifest, pubHex)
	if err == nil || !strings.Contains(out, "INSTALLED_BINARY_CHANGED") {
		t.Fatalf("installed binary differing from release binary was accepted: %v\n%s", err, out)
	}
}

func TestV13Case290InstalledBinaryWithWrongModeIsRejected(t *testing.T) {
	dir := t.TempDir()
	privHex, _ := s8GenerateKey(t)
	govBin := s8WriteFakeGov(t, dir, "1.0.2-rc6")
	manifest := s8WriteManifest(t, dir, "1.0.2-rc6", "abc123", govBin)
	hookConfig := s8WriteHookConfig(t, dir)
	evidencePath := filepath.Join(dir, "install-evidence.json")

	if err := os.Chmod(govBin, 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := s8GenerateEvidence(t, govBin, manifest, hookConfig, privHex, evidencePath)
	if err == nil || !strings.Contains(out, "WRONG_BINARY_MODE") {
		t.Fatalf("installed binary with wrong mode was accepted: %v\n%s", err, out)
	}
}

func TestV13Case291HookInvokingOlderBinaryIsDetected(t *testing.T) {
	dir := t.TempDir()
	privHex, pubHex := s8GenerateKey(t)
	govBin := s8WriteFakeGov(t, dir, "1.0.2-rc6")
	manifest := s8WriteManifest(t, dir, "1.0.2-rc6", "abc123", govBin)
	hookConfig := s8WriteHookConfig(t, dir)
	evidencePath := filepath.Join(dir, "install-evidence.json")

	out, err := s8GenerateEvidence(t, govBin, manifest, hookConfig, privHex, evidencePath)
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, out)
	}

	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	record["version"] = "1.0.2-rc3"
	record["source_commit"] = "oldcommit"
	delete(record, "signature")
	modified, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, modified, 0o644); err != nil {
		t.Fatal(err)
	}

	out, err = s8VerifyEvidence(t, evidencePath, manifest, pubHex)
	if err == nil || !strings.Contains(out, "INSTALL_EVIDENCE_UNSIGNED") {
		t.Fatalf("hook invoking older binary was not detected: %v\n%s", err, out)
	}
}

func TestV13Case292HookConfigurationChangedAfterInstallationIsDetected(t *testing.T) {
	dir := t.TempDir()
	privHex, pubHex := s8GenerateKey(t)
	govBin := s8WriteFakeGov(t, dir, "1.0.2-rc6")
	manifest := s8WriteManifest(t, dir, "1.0.2-rc6", "abc123", govBin)
	hookConfig := s8WriteHookConfig(t, dir)
	evidencePath := filepath.Join(dir, "install-evidence.json")

	out, err := s8GenerateEvidence(t, govBin, manifest, hookConfig, privHex, evidencePath)
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, out)
	}

	if err := os.WriteFile(hookConfig, []byte(`{"hooks":[{"event":"PreToolUse","command":"evil hook"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err = s8VerifyEvidence(t, evidencePath, manifest, pubHex)
	if err == nil || !strings.Contains(out, "HOOK_CONFIGURATION_CHANGED") {
		t.Fatalf("hook configuration change after installation was not detected: %v\n%s", err, out)
	}
}

func TestV13Case293MalformedApplyPatchLiveCanaryDenies(t *testing.T) {
	dir := t.TempDir()
	privHex, pubHex := s8GenerateKey(t)
	govBin := s8WriteFakeGov(t, dir, "1.0.2-rc6")
	manifest := s8WriteManifest(t, dir, "1.0.2-rc6", "abc123", govBin)
	hookConfig := s8WriteHookConfig(t, dir)
	evidencePath := filepath.Join(dir, "install-evidence.json")

	out, err := s8GenerateEvidence(t, govBin, manifest, hookConfig, privHex, evidencePath)
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, out)
	}

	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record["canary_malformed_patch_denies"] != true {
		t.Fatalf("canary_malformed_patch_denies is not true in evidence: %v", record["canary_malformed_patch_denies"])
	}

	out, err = s8VerifyEvidence(t, evidencePath, manifest, pubHex)
	if err != nil {
		t.Fatalf("verify of valid evidence failed: %v\n%s", err, out)
	}
}

func TestV13Case294ArchitectureClaimsLiveRc5WhileInstallEvidenceSaysRc3IsRejected(t *testing.T) {
	dir := t.TempDir()
	checkScript := s8Script(t, "check_architecture_doc.py")

	doc := `---
governator_commit: cfc6bb5734a732a97a20d3bf6fea0919fda97772
governator_tag: v1.0.2-rc5
release_state: complete
artifact_manifest_sha256: null
---

# Architecture

**Status:** ` + "`v1.0.2-rc5`" + `

## Remediation history

The live gate installed at ~/.local/bin/gov reports version 1.0.2-rc3.
No ` + "`v1.0.2-rc5`" + ` git tag currently exists (front matter ` + "`governator_tag: null`" + `).
`
	docPath := filepath.Join(dir, "arch.md")
	if err := os.WriteFile(docPath, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("python3", checkScript, docPath)
	outBytes, err := cmd.CombinedOutput()
	out := string(outBytes)
	if err == nil || !strings.Contains(out, "FRONT_MATTER_PROSE_CONTRADICTION") {
		t.Fatalf("architecture doc claiming live rc5 while prose says rc3/null was accepted: %v\n%s", err, out)
	}
}

func TestV13Case295LiveInstallClaimWithoutInstallationEvidenceIsRejected(t *testing.T) {
	dir := t.TempDir()
	validateScript := s8Script(t, "audit_bundle_validate.py")

	commit := "abc123def456"
	distDir := filepath.Join(dir, "dist")
	s8WriteCompleteDist(t, distDir, commit)

	archDoc := filepath.Join(dir, "arch.md")
	if err := os.WriteFile(archDoc, []byte("# Arch\n\nThe live gate installed at ~/.local/bin/gov is running.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	repoDir := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("python3", validateScript,
		"--dist-dir", distDir,
		"--repo", repoDir,
		"--release-commit", commit,
		"--architecture-doc", archDoc,
	)
	outBytes, err := cmd.CombinedOutput()
	out := string(outBytes)
	if err == nil || !strings.Contains(out, "LIVE_INSTALL_CLAIM_WITHOUT_EVIDENCE") {
		t.Fatalf("live-install claim without installation evidence was accepted: %v\n%s", err, out)
	}
}
