//go:build redteam

// v15_s4_install_provenance_test.go is rc8-upg15 Session 4's corpus, cases
// 369-377 (Sol15 P1-1 "Install evidence accepts an archive for the wrong
// platform"). Session 4 replaced the filename-regex archive validator with
// manifest-driven platform selection, added safe extraction with a member
// allow-list, and requires byte-for-byte equality between the installed
// binary and the archive's contained executable. These nine cases prove each
// of Sol's nine named "Install-evidence attacks" is caught.
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

func s4Script(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "scripts", name)
}

func s4HostPlatform() string {
	return runtime.GOOS + "_" + runtime.GOARCH
}

func s4GenerateKey(t *testing.T) (privHex, pubHex string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(priv), hex.EncodeToString(pub)
}

func s4SHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func s4WriteFakeGov(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "gov")
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
    sys.exit(0)
sys.exit(0)
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func s4WriteHookConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "hook-config.json")
	if err := os.WriteFile(path, []byte(`{"hooks":[{"event":"PreToolUse","command":"gov hook pre-tool-use"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func s4WriteManifest(t *testing.T, dir, archiveName, archiveSHA, execSHA string) string {
	t.Helper()
	manifest := map[string]any{
		"version":       "1.0.2-rc8",
		"source_commit": "abc1234",
		"dirty":         false,
		"artifacts": []map[string]any{
			{
				"platform":          s4HostPlatform(),
				"archive_path":      archiveName,
				"archive_sha256":    archiveSHA,
				"executable_path":   "gov",
				"executable_sha256": execSHA,
				"approving":         true,
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

type s4TarMember struct {
	Name     string
	Body     []byte
	Mode     int64
	Typeflag byte
	Linkname string
}

func s4WriteTarGz(t *testing.T, path string, members []s4TarMember) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	for _, m := range members {
		hdr := &tar.Header{
			Name:     m.Name,
			Mode:     m.Mode,
			Size:     int64(len(m.Body)),
			Typeflag: m.Typeflag,
			Linkname: m.Linkname,
		}
		if m.Typeflag == tar.TypeSymlink || m.Typeflag == tar.TypeLink {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if m.Typeflag == tar.TypeReg && len(m.Body) > 0 {
			if _, err := tw.Write(m.Body); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func s4RunGenerate(t *testing.T, govBin, manifestPath, hookConfig, privHex, archive, out string) (string, error) {
	t.Helper()
	cmd := exec.Command("python3", s4Script(t, "install_evidence.py"), "generate",
		"--installed-path", govBin,
		"--release-manifest", manifestPath,
		"--hook-config", hookConfig,
		"--signing-key", privHex,
		"--source-archive", archive,
		"--out", out,
	)
	cmd.Dir = filepath.Dir(s4Script(t, "install_evidence.py"))
	outBytes, err := cmd.CombinedOutput()
	return string(outBytes), err
}

func TestV15Case369DarwinArchiveOnLinuxHostIsRejected(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("case 369 targets a Linux host receiving a Darwin archive")
	}
	dir := t.TempDir()
	govBin := s4WriteFakeGov(t, dir)
	hookConfig := s4WriteHookConfig(t, dir)
	privHex, _ := s4GenerateKey(t)

	govData, _ := os.ReadFile(govBin)
	govSHA := s4SHA256(t, govBin)

	correctArchiveName := fmt.Sprintf("gov_1.0.2-rc8_%s.tar.gz", s4HostPlatform())
	correctArchive := filepath.Join(dir, correctArchiveName)
	s4WriteTarGz(t, correctArchive, []s4TarMember{
		{Name: "gov", Body: govData, Mode: 0o755, Typeflag: tar.TypeReg},
	})
	correctSHA := s4SHA256(t, correctArchive)

	darwinArchive := filepath.Join(dir, "gov_1.0.2-rc8_darwin_arm64.tar.gz")
	s4WriteTarGz(t, darwinArchive, []s4TarMember{
		{Name: "gov", Body: govData, Mode: 0o755, Typeflag: tar.TypeReg},
	})

	manifestPath := s4WriteManifest(t, dir, correctArchiveName, correctSHA, govSHA)
	out := filepath.Join(dir, "evidence.json")
	output, err := s4RunGenerate(t, govBin, manifestPath, hookConfig, privHex, darwinArchive, out)
	if err == nil {
		t.Fatalf("install_evidence accepted a Darwin archive on a Linux host: %s", output)
	}
	if !strings.Contains(output, "WRONG_PLATFORM_ARCHIVE") {
		t.Fatalf("expected WRONG_PLATFORM_ARCHIVE rejection, got: %s", output)
	}
}

func TestV15Case370Arm64ArchiveOnAmd64HostIsRejected(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("case 370 targets an AMD64 host receiving an ARM64 archive")
	}
	dir := t.TempDir()
	govBin := s4WriteFakeGov(t, dir)
	hookConfig := s4WriteHookConfig(t, dir)
	privHex, _ := s4GenerateKey(t)

	govData, _ := os.ReadFile(govBin)
	govSHA := s4SHA256(t, govBin)

	correctArchiveName := fmt.Sprintf("gov_1.0.2-rc8_%s.tar.gz", s4HostPlatform())
	correctArchive := filepath.Join(dir, correctArchiveName)
	s4WriteTarGz(t, correctArchive, []s4TarMember{
		{Name: "gov", Body: govData, Mode: 0o755, Typeflag: tar.TypeReg},
	})
	correctSHA := s4SHA256(t, correctArchive)

	arm64Archive := filepath.Join(dir, "gov_1.0.2-rc8_linux_arm64.tar.gz")
	s4WriteTarGz(t, arm64Archive, []s4TarMember{
		{Name: "gov", Body: govData, Mode: 0o755, Typeflag: tar.TypeReg},
	})

	manifestPath := s4WriteManifest(t, dir, correctArchiveName, correctSHA, govSHA)
	out := filepath.Join(dir, "evidence.json")
	output, err := s4RunGenerate(t, govBin, manifestPath, hookConfig, privHex, arm64Archive, out)
	if err == nil {
		t.Fatalf("install_evidence accepted an ARM64 archive on an AMD64 host: %s", output)
	}
	if !strings.Contains(output, "WRONG_PLATFORM_ARCHIVE") {
		t.Fatalf("expected WRONG_PLATFORM_ARCHIVE rejection, got: %s", output)
	}
}

func TestV15Case371CorrectlyNamedArchiveWithWrongContentsIsRejected(t *testing.T) {
	dir := t.TempDir()
	govBin := s4WriteFakeGov(t, dir)
	hookConfig := s4WriteHookConfig(t, dir)
	privHex, _ := s4GenerateKey(t)

	archiveName := fmt.Sprintf("gov_1.0.2-rc8_%s.tar.gz", s4HostPlatform())
	wrongContent := []byte("this is not the real gov binary")
	archivePath := filepath.Join(dir, archiveName)
	s4WriteTarGz(t, archivePath, []s4TarMember{
		{Name: "gov", Body: wrongContent, Mode: 0o755, Typeflag: tar.TypeReg},
	})
	archiveSHA := s4SHA256(t, archivePath)
	govSHA := s4SHA256(t, govBin)

	manifestPath := s4WriteManifest(t, dir, archiveName, archiveSHA, govSHA)
	out := filepath.Join(dir, "evidence.json")
	output, err := s4RunGenerate(t, govBin, manifestPath, hookConfig, privHex, archivePath, out)
	if err == nil {
		t.Fatalf("install_evidence accepted an archive whose contained binary differs from the installed binary: %s", output)
	}
	if !strings.Contains(output, "CONTAINED_BINARY_HASH_MISMATCH") && !strings.Contains(output, "INSTALLED_BINARY_NOT_FROM_ARCHIVE") {
		t.Fatalf("expected CONTAINED_BINARY_HASH_MISMATCH or INSTALLED_BINARY_NOT_FROM_ARCHIVE, got: %s", output)
	}
}

func TestV15Case372ArchiveContainingSymlinkedGovIsRejected(t *testing.T) {
	dir := t.TempDir()
	govBin := s4WriteFakeGov(t, dir)
	hookConfig := s4WriteHookConfig(t, dir)
	privHex, _ := s4GenerateKey(t)

	archiveName := fmt.Sprintf("gov_1.0.2-rc8_%s.tar.gz", s4HostPlatform())
	archivePath := filepath.Join(dir, archiveName)
	s4WriteTarGz(t, archivePath, []s4TarMember{
		{Name: "gov", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777},
	})
	archiveSHA := s4SHA256(t, archivePath)
	govSHA := s4SHA256(t, govBin)

	manifestPath := s4WriteManifest(t, dir, archiveName, archiveSHA, govSHA)
	out := filepath.Join(dir, "evidence.json")
	output, err := s4RunGenerate(t, govBin, manifestPath, hookConfig, privHex, archivePath, out)
	if err == nil {
		t.Fatalf("install_evidence accepted an archive containing a symlinked gov: %s", output)
	}
	if !strings.Contains(output, "UNSAFE_ARCHIVE") {
		t.Fatalf("expected UNSAFE_ARCHIVE rejection, got: %s", output)
	}
}

func TestV15Case373DuplicateGovMembersAreRejected(t *testing.T) {
	dir := t.TempDir()
	govBin := s4WriteFakeGov(t, dir)
	hookConfig := s4WriteHookConfig(t, dir)
	privHex, _ := s4GenerateKey(t)

	govData, _ := os.ReadFile(govBin)
	archiveName := fmt.Sprintf("gov_1.0.2-rc8_%s.tar.gz", s4HostPlatform())
	archivePath := filepath.Join(dir, archiveName)
	s4WriteTarGz(t, archivePath, []s4TarMember{
		{Name: "gov", Body: govData, Mode: 0o755, Typeflag: tar.TypeReg},
		{Name: "gov", Body: []byte("second copy"), Mode: 0o755, Typeflag: tar.TypeReg},
	})
	archiveSHA := s4SHA256(t, archivePath)
	govSHA := s4SHA256(t, govBin)

	manifestPath := s4WriteManifest(t, dir, archiveName, archiveSHA, govSHA)
	out := filepath.Join(dir, "evidence.json")
	output, err := s4RunGenerate(t, govBin, manifestPath, hookConfig, privHex, archivePath, out)
	if err == nil {
		t.Fatalf("install_evidence accepted an archive with duplicate gov members: %s", output)
	}
	if !strings.Contains(output, "UNSAFE_ARCHIVE") {
		t.Fatalf("expected UNSAFE_ARCHIVE rejection, got: %s", output)
	}
}

func TestV15Case374PathTraversalMemberIsRejected(t *testing.T) {
	dir := t.TempDir()
	govBin := s4WriteFakeGov(t, dir)
	hookConfig := s4WriteHookConfig(t, dir)
	privHex, _ := s4GenerateKey(t)

	govData, _ := os.ReadFile(govBin)
	archiveName := fmt.Sprintf("gov_1.0.2-rc8_%s.tar.gz", s4HostPlatform())
	archivePath := filepath.Join(dir, archiveName)
	s4WriteTarGz(t, archivePath, []s4TarMember{
		{Name: "../evil", Body: []byte("pwned"), Mode: 0o644, Typeflag: tar.TypeReg},
		{Name: "gov", Body: govData, Mode: 0o755, Typeflag: tar.TypeReg},
	})
	archiveSHA := s4SHA256(t, archivePath)
	govSHA := s4SHA256(t, govBin)

	manifestPath := s4WriteManifest(t, dir, archiveName, archiveSHA, govSHA)
	out := filepath.Join(dir, "evidence.json")
	output, err := s4RunGenerate(t, govBin, manifestPath, hookConfig, privHex, archivePath, out)
	if err == nil {
		t.Fatalf("install_evidence accepted an archive with a path-traversal member: %s", output)
	}
	if !strings.Contains(output, "UNSAFE_ARCHIVE") {
		t.Fatalf("expected UNSAFE_ARCHIVE rejection, got: %s", output)
	}
}

func TestV15Case375CorrectExecutablePlusHiddenExtraPayloadIsRejected(t *testing.T) {
	dir := t.TempDir()
	govBin := s4WriteFakeGov(t, dir)
	hookConfig := s4WriteHookConfig(t, dir)
	privHex, _ := s4GenerateKey(t)

	govData, _ := os.ReadFile(govBin)
	govSHA := s4SHA256(t, govBin)
	archiveName := fmt.Sprintf("gov_1.0.2-rc8_%s.tar.gz", s4HostPlatform())
	archivePath := filepath.Join(dir, archiveName)
	s4WriteTarGz(t, archivePath, []s4TarMember{
		{Name: "gov", Body: govData, Mode: 0o755, Typeflag: tar.TypeReg},
		{Name: ".hidden_payload", Body: []byte("backdoor"), Mode: 0o644, Typeflag: tar.TypeReg},
	})
	archiveSHA := s4SHA256(t, archivePath)

	manifestPath := s4WriteManifest(t, dir, archiveName, archiveSHA, govSHA)
	out := filepath.Join(dir, "evidence.json")
	output, err := s4RunGenerate(t, govBin, manifestPath, hookConfig, privHex, archivePath, out)
	if err == nil {
		t.Fatalf("install_evidence accepted an archive with a hidden extra payload member: %s", output)
	}
	if !strings.Contains(output, "UNSAFE_ARCHIVE") {
		t.Fatalf("expected UNSAFE_ARCHIVE rejection, got: %s", output)
	}
}

func TestV15Case376InstalledFileModifiedAfterExtractionIsDetected(t *testing.T) {
	dir := t.TempDir()
	govBin := s4WriteFakeGov(t, dir)
	hookConfig := s4WriteHookConfig(t, dir)
	privHex, _ := s4GenerateKey(t)

	govData, _ := os.ReadFile(govBin)
	govSHA := s4SHA256(t, govBin)
	archiveName := fmt.Sprintf("gov_1.0.2-rc8_%s.tar.gz", s4HostPlatform())
	archivePath := filepath.Join(dir, archiveName)
	s4WriteTarGz(t, archivePath, []s4TarMember{
		{Name: "gov", Body: govData, Mode: 0o755, Typeflag: tar.TypeReg},
	})
	archiveSHA := s4SHA256(t, archivePath)

	tampered := append([]byte(nil), govData...)
	tampered[len(tampered)-1] ^= 0xFF
	tamperedBin := filepath.Join(dir, "gov-tampered")
	if err := os.WriteFile(tamperedBin, tampered, 0o755); err != nil {
		t.Fatal(err)
	}

	manifestPath := s4WriteManifest(t, dir, archiveName, archiveSHA, govSHA)
	out := filepath.Join(dir, "evidence.json")
	output, err := s4RunGenerate(t, tamperedBin, manifestPath, hookConfig, privHex, archivePath, out)
	if err == nil {
		t.Fatalf("install_evidence accepted an installed binary that differs from the archive's contained binary: %s", output)
	}
	if !strings.Contains(output, "INSTALLED_BINARY_NOT_FROM_ARCHIVE") && !strings.Contains(output, "CONTAINED_BINARY_HASH_MISMATCH") {
		t.Fatalf("expected INSTALLED_BINARY_NOT_FROM_ARCHIVE or CONTAINED_BINARY_HASH_MISMATCH, got: %s", output)
	}
}

func TestV15Case377CorrectArchiveHashWithWrongContainedModeIsRejected(t *testing.T) {
	dir := t.TempDir()
	govBin := s4WriteFakeGov(t, dir)
	hookConfig := s4WriteHookConfig(t, dir)
	privHex, _ := s4GenerateKey(t)

	govData, _ := os.ReadFile(govBin)
	govSHA := s4SHA256(t, govBin)
	archiveName := fmt.Sprintf("gov_1.0.2-rc8_%s.tar.gz", s4HostPlatform())
	archivePath := filepath.Join(dir, archiveName)
	s4WriteTarGz(t, archivePath, []s4TarMember{
		{Name: "gov", Body: govData, Mode: 0o644, Typeflag: tar.TypeReg},
	})
	archiveSHA := s4SHA256(t, archivePath)

	manifestPath := s4WriteManifest(t, dir, archiveName, archiveSHA, govSHA)
	out := filepath.Join(dir, "evidence.json")
	output, err := s4RunGenerate(t, govBin, manifestPath, hookConfig, privHex, archivePath, out)
	if err == nil {
		t.Fatalf("install_evidence accepted an archive whose contained binary has mode 0644 instead of 0755: %s", output)
	}
	if !strings.Contains(output, "WRONG_CONTAINED_MODE") && !strings.Contains(output, "WRONG_BINARY_MODE") {
		t.Fatalf("expected WRONG_CONTAINED_MODE or WRONG_BINARY_MODE rejection, got: %s", output)
	}
}
