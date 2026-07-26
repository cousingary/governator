//go:build redteam

package redteam

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func s4ToolsetScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRootForBundleTests(t), "scripts", "release_toolset.py")
}

func s4WriteTool(t *testing.T, directory, body string) string {
	t.Helper()
	path := filepath.Join(directory, "tool")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func s4WritePolicy(t *testing.T, directory, tool string) string {
	t.Helper()
	path := filepath.Join(directory, "release-tool-policy.yaml")
	content := "tools:\n  minisign:\n    path: " + tool + "\n    sha256: " + fileSHA256Hex(t, tool) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func s4Toolset(t *testing.T, policy, output string, verify bool) (string, error) {
	t.Helper()
	args := []string{s4ToolsetScript(t), "--policy", policy}
	if verify {
		args = append(args, "--tools", "minisign", "--verify", output)
	} else {
		args = append(args, "--out", output, "--tools", "minisign")
	}
	result := exec.Command("python3", args...)
	out, err := result.CombinedOutput()
	return string(out), err
}

func TestV13Case21FakeMinisignReturningSuccessIsRejected(t *testing.T) {
	work, dist, trustFile, keyDir, _, checksums, _, fingerprint := s1Stage(t)
	forged := filepath.Join(dist, "forged.minisig")
	s1ForgeMinisig(t, forged, fingerprint)
	marker := filepath.Join(work, "fake-minisign-ran")
	fake := s4WriteTool(t, work, "#!/bin/sh\ntouch '"+marker+"'\nexit 0\n")

	args := append(s1CommonArgs(trustFile, keyDir, checksums, forged), "--minisign-bin", fake, "--minisign-bin-hash", fileSHA256Hex(t, fake))
	out, err := s1Policy(t, args...)
	if err == nil || !strings.Contains(out, "cryptographic signature verification FAILED") {
		t.Fatalf("fake successful minisign affected verification: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("in-process verifier executed fake minisign: stat=%v", err)
	}
}

func TestV13Case22FakeMinisignBlessingItsOwnHashIsRejected(t *testing.T) {
	work, dist, trustFile, keyDir, _, checksums, _, fingerprint := s1Stage(t)
	forged := filepath.Join(dist, "forged.minisig")
	s1ForgeMinisig(t, forged, fingerprint)
	fake := s4WriteTool(t, work, "#!/bin/sh\nexit 0\n")

	args := append(s1CommonArgs(trustFile, keyDir, checksums, forged), "--minisign-bin", fake, "--minisign-bin-hash", fileSHA256Hex(t, fake))
	out, err := s1Policy(t, args...)
	if err == nil || !strings.Contains(out, "cryptographic signature verification FAILED") {
		t.Fatalf("self-hashed fake minisign blessed a forged packet: %v\n%s", err, out)
	}
}

func TestV13Case23ForgedSignatureWithTrustedKeyIDIsRejected(t *testing.T) {
	_, dist, trustFile, keyDir, _, checksums, _, fingerprint := s1Stage(t)
	forged := filepath.Join(dist, "forged.minisig")
	s1ForgeMinisig(t, forged, fingerprint)

	out, err := s1Policy(t, s1CommonArgs(trustFile, keyDir, checksums, forged)...)
	if err == nil || !strings.Contains(out, "cryptographic signature verification FAILED") {
		t.Fatalf("trusted key ID without a valid signature was accepted: %v\n%s", err, out)
	}
}

func TestV13Case24VerifierHashDifferingFromIndependentPolicyIsRejected(t *testing.T) {
	directory := t.TempDir()
	tool := s4WriteTool(t, directory, "#!/bin/sh\necho approved\n")
	policy := s4WritePolicy(t, directory, tool)
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho substituted\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := s4Toolset(t, policy, filepath.Join(directory, "toolset.json"), false)
	if err == nil || !strings.Contains(out, "differs from independently approved") {
		t.Fatalf("tool with a hash differing from policy was accepted: %v\n%s", err, out)
	}
}

func TestV13Case25ReleaseToolChangedAfterPreflightIsRejected(t *testing.T) {
	directory := t.TempDir()
	tool := s4WriteTool(t, directory, "#!/bin/sh\necho original\n")
	policy := s4WritePolicy(t, directory, tool)
	toolset := filepath.Join(directory, "toolset.json")
	if out, err := s4Toolset(t, policy, toolset, false); err != nil {
		t.Fatalf("preflight toolset: %v\n%s", err, out)
	}
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho changed\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := s4Toolset(t, policy, toolset, true)
	if err == nil || !strings.Contains(out, "TOOLSET_VERIFICATION_FAILED") {
		t.Fatalf("tool changed after preflight was accepted: %v\n%s", err, out)
	}

	release, err := os.ReadFile(s7ReleaseScript(t))
	if err != nil {
		t.Fatal(err)
	}
	postflight := strings.LastIndex(string(release), `release_toolset.py" --policy "$RELEASE_TOOL_POLICY" --verify "$OUT_DIR/toolset.json"`)
	signatureGate := strings.LastIndex(string(release), `release_policy.py" signature`)
	if postflight <= signatureGate {
		t.Fatal("release.sh does not re-verify the approved toolset after final signature verification")
	}
}

func TestV13Case26AbsentApprovedToolsetPolicyIsRejected(t *testing.T) {
	out, err := s4Toolset(t, filepath.Join(t.TempDir(), "missing-policy.yaml"), filepath.Join(t.TempDir(), "toolset.json"), false)
	if err == nil || !strings.Contains(out, "TOOLSET_POLICY_FAILED") {
		t.Fatalf("missing approved-tool policy was accepted: %v\n%s", err, out)
	}
}

func TestV13Case27ObservedAndApprovedToolHashesDifferIsRejected(t *testing.T) {
	directory := t.TempDir()
	tool := s4WriteTool(t, directory, "#!/bin/sh\necho original\n")
	policy := s4WritePolicy(t, directory, tool)
	toolset := filepath.Join(directory, "toolset.json")
	if out, err := s4Toolset(t, policy, toolset, false); err != nil {
		t.Fatalf("preflight toolset: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(toolset)
	if err != nil {
		t.Fatal(err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	record := evidence["tools"].([]any)[0].(map[string]any)
	record["observed"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
	modified, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toolset, modified, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := s4Toolset(t, policy, toolset, true)
	if err == nil || !strings.Contains(out, "TOOLSET_VERIFICATION_FAILED") {
		t.Fatalf("observed hash differing from approved hash was accepted: %v\n%s", err, out)
	}
}
