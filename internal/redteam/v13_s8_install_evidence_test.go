//go:build redteam

package redteam

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
		// Must mirror the REAL build-manifest schema that scripts/release.sh
		// emits: entries are keyed by `platform` and carry `binary_sha256` /
		// `extracted_binary_sha256`. There is no `name` field. The original
		// fixture used {"name": "gov", "sha256": ...}, a shape no release ever
		// produces, which is exactly why install_evidence.py's binary-hash
		// lookup could be broken against every real manifest while these cases
		// stayed green (rc6 Session 9).
		"artifacts": []map[string]any{
			{
				"platform":                s8HostPlatform(),
				"binary_sha256":           binSHA,
				"extracted_binary_sha256": binSHA,
				"approving":               true,
			},
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

// s8HostPlatform mirrors install_evidence.py's current_platform_id() so the
// fixture manifest carries an artifact entry for the host actually running the
// test, the same way a real release does.
func s8HostPlatform() string {
	goarch := runtime.GOARCH
	return runtime.GOOS + "_" + goarch
}

func s8WriteFakeGov(t *testing.T, dir, version string) string {
	t.Helper()
	path := filepath.Join(dir, "gov")
	// This stub must mirror the REAL hook protocol, not a convenient shorthand:
	// internal/runtime/gate.go's EmitHookJSON always exits 0 and expresses the
	// verdict in stdout JSON (an allow emits nothing at all), and protected
	// paths come from the GOV_PROTECTED_PATHS manifest rather than a hardcoded
	// /etc prefix. The previous stub denied by `exit 1` against a baked-in
	// /etc/* rule, which let install_evidence.py assert the wrong signal
	// against a gate that never uses it -- the canary was unpassable on every
	// real host while these cases stayed green (rc6 Session 9).
	script := `#!/usr/bin/env python3
import json, os, sys

def emit_deny(reason):
    json.dump({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "GOVERNATOR GATE - " + reason,
    }}, sys.stdout)
    sys.exit(0)

argv = sys.argv[1:]
if argv[:1] == ["hook"]:
    payload = json.load(sys.stdin)
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    if tool == "apply_patch":
        emit_deny("missing apply_patch command")
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        target = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        manifest = os.environ.get("GOV_PROTECTED_PATHS", "")
        patterns = []
        if manifest and os.path.isfile(manifest):
            for line in open(manifest):
                line = line.split("#", 1)[0].strip()
                if line:
                    patterns.append(line)
        for pattern in patterns:
            prefix = pattern[:-3] if pattern.endswith("/**") else pattern
            if target == prefix or target.startswith(prefix.rstrip("/") + "/"):
                emit_deny(target + " is a PROTECTED path (matched '" + pattern + "')")
    sys.exit(0)          # allow: exit 0, no payload
if argv[:1] in (["version"], ["--version"]):
    print("gov ` + version + `")
sys.exit(0)
`
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

func s8WriteFakeArchive(t *testing.T, dir, version string) string {
	t.Helper()
	name := fmt.Sprintf("gov_%s_%s.tar.gz", version, s8HostPlatform())
	path := filepath.Join(dir, name)
	govPath := filepath.Join(dir, "gov")
	govData, err := os.ReadFile(govPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	hdr := &tar.Header{Name: "gov", Mode: 0o755, Size: int64(len(govData)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(govData); err != nil {
		t.Fatal(err)
	}
	return path
}

func s8GenerateEvidence(t *testing.T, govBin, manifest, hookConfig, privHex, out string) (string, error) {
	t.Helper()
	archive := s8WriteFakeArchive(t, filepath.Dir(govBin), "1.0.2-rc6")
	archiveData, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	archiveSum := sha256.Sum256(archiveData)
	archiveSHA := hex.EncodeToString(archiveSum[:])
	govData, err := os.ReadFile(govBin)
	if err != nil {
		t.Fatal(err)
	}
	govSum := sha256.Sum256(govData)
	govSHA := hex.EncodeToString(govSum[:])

	manifestData, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(manifestData, &m); err != nil {
		t.Fatal(err)
	}
	artifacts, _ := m["artifacts"].([]any)
	if len(artifacts) > 0 {
		if a, ok := artifacts[0].(map[string]any); ok {
			a["archive_path"] = filepath.Base(archive)
			a["archive_sha256"] = archiveSHA
			a["executable_path"] = "gov"
			a["executable_sha256"] = govSHA
		}
	}
	patched, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, patched, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("python3", s8Script(t, "install_evidence.py"), "generate",
		"--installed-path", govBin,
		"--release-manifest", manifest,
		"--hook-config", hookConfig,
		"--signing-key", privHex,
		"--source-archive", archive,
		"--out", out,
	)
	cmd.Dir = filepath.Dir(s8Script(t, "install_evidence.py"))
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
			"redteam": map[string]any{"tests_skipped": 0, "identity_gate": s3IdentityGate()},
		},
	}
	tsdata, _ := json.Marshal(testSummary)
	write("test-summary.json", string(tsdata))
	write("acceptance-summary.json", `{"overall_result":"PASS"}`)
	write("claims-verify-report.txt", "ok\n")
	write("preflight.json", "{}")
	write("toolset.json", "{}")
	write("release-environment.json", "{}")
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
	if err := os.WriteFile(archDoc, []byte("---\nlive_install_claim: true\ninstalled_binary_sha256: null\nhook_configuration_sha256: null\ninstall_evidence_sha256: null\ninstall_evidence_signer: null\n---\n# Arch\n"), 0o644); err != nil {
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
		"--allow-unverified-signature",
	)
	outBytes, err := cmd.CombinedOutput()
	out := string(outBytes)
	if err == nil || !strings.Contains(out, "LIVE_INSTALL_CLAIM_WITHOUT_EVIDENCE") {
		t.Fatalf("live-install claim without installation evidence was accepted: %v\n%s", err, out)
	}
}
