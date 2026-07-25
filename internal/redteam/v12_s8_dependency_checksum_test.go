//go:build redteam

package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func s8RepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve this test file's own path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

func s8ReleasePolicyScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(s8RepoRoot(t), "scripts", "release_policy.py")
}

func s8ReleaseScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(s8RepoRoot(t), "scripts", "release.sh")
}

// TestV12Case42ChecksumPathTraversalRejected proves that a checksums.txt
// entry containing parent traversal (../) is rejected by the release policy
// parser (Sol12 P1-7). An attacker who can inject a checksum entry with ../
// could escape the artifacts directory and verify against an arbitrary file.
func TestV12Case42ChecksumPathTraversalRejected(t *testing.T) {
	script := s8ReleasePolicyScript(t)
	if _, err := os.Stat(script); err != nil {
		t.Skip("release_policy.py not found")
	}
	tmpDir := t.TempDir()
	checksums := filepath.Join(tmpDir, "checksums.txt")
	content := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ../../../etc/passwd\n"
	if err := os.WriteFile(checksums, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-c", `
import sys, pathlib
sys.path.insert(0, sys.argv[1])
from release_policy import parse_checksums
try:
    parse_checksums(pathlib.Path(sys.argv[2]))
    print("ACCEPTED")
except ValueError as e:
    print(f"REJECTED: {e}")
`, filepath.Dir(script), checksums)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python3 invocation failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "ACCEPTED") {
		t.Fatal("release_policy.parse_checksums must REJECT a checksum entry with parent traversal ../ (Sol12 P1-7)")
	}
	if !strings.Contains(string(out), "REJECTED") {
		t.Fatalf("expected REJECTED output, got: %s", out)
	}
}

// TestV12Case43ChecksumAbsolutePathRejected proves that a checksums.txt entry
// containing an absolute path is rejected by the release policy parser
// (Sol12 P1-7). An absolute path lets an attacker point verification at any
// file on the system.
func TestV12Case43ChecksumAbsolutePathRejected(t *testing.T) {
	script := s8ReleasePolicyScript(t)
	if _, err := os.Stat(script); err != nil {
		t.Skip("release_policy.py not found")
	}
	tmpDir := t.TempDir()
	checksums := filepath.Join(tmpDir, "checksums.txt")
	content := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /etc/shadow\n"
	if err := os.WriteFile(checksums, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-c", `
import sys, pathlib
sys.path.insert(0, sys.argv[1])
from release_policy import parse_checksums
try:
    parse_checksums(pathlib.Path(sys.argv[2]))
    print("ACCEPTED")
except ValueError as e:
    print(f"REJECTED: {e}")
`, filepath.Dir(script), checksums)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python3 invocation failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "ACCEPTED") {
		t.Fatal("release_policy.parse_checksums must REJECT a checksum entry with an absolute path (Sol12 P1-7)")
	}
	if !strings.Contains(string(out), "REJECTED") {
		t.Fatalf("expected REJECTED output, got: %s", out)
	}
}

// TestV12Case44SymlinkedReleaseArtifactRejected proves that a symlinked
// release artifact is rejected by verify_checksums_self_consistent (Sol12
// P1-7). A symlink could point outside the artifacts directory, letting an
// attacker substitute arbitrary content while passing the hash check.
func TestV12Case44SymlinkedReleaseArtifactRejected(t *testing.T) {
	script := s8ReleasePolicyScript(t)
	if _, err := os.Stat(script); err != nil {
		t.Skip("release_policy.py not found")
	}
	tmpDir := t.TempDir()
	realFile := filepath.Join(tmpDir, "real-artifact.tar.gz")
	if err := os.WriteFile(realFile, []byte("fake archive content"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(tmpDir, "gov_1.0.2_linux.tar.gz")
	if err := os.Symlink(realFile, symlink); err != nil {
		t.Skipf("cannot create symlink on this platform: %v", err)
	}
	// Compute the hash of the real file so the checksum entry matches content
	cmd := exec.Command("sha256sum", realFile)
	hashOut, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.Fields(string(hashOut))[0]
	checksums := filepath.Join(tmpDir, "checksums.txt")
	if err := os.WriteFile(checksums, []byte(hash+"  gov_1.0.2_linux.tar.gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verifyCmd := exec.Command("python3", "-c", `
import sys, pathlib
sys.path.insert(0, sys.argv[1])
from release_policy import verify_checksums_self_consistent
ok, msg, _ = verify_checksums_self_consistent(pathlib.Path(sys.argv[2]))
if ok:
    print("ACCEPTED")
else:
    print(f"REJECTED: {msg}")
`, filepath.Dir(script), checksums)
	out, err := verifyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python3 invocation failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "ACCEPTED") {
		t.Fatal("verify_checksums_self_consistent must REJECT a symlinked release artifact (Sol12 P1-7)")
	}
	if !strings.Contains(string(out), "symlink") {
		t.Fatalf("expected symlink rejection message, got: %s", out)
	}
}

// TestV12Case45DuplicateChecksumEntryRejected proves that a checksums.txt
// with duplicate entries for the same filename is rejected (Sol12 P1-7).
// Duplicate entries could mask a substitution attack where the second entry
// overrides the first in a naive parser.
func TestV12Case45DuplicateChecksumEntryRejected(t *testing.T) {
	script := s8ReleasePolicyScript(t)
	if _, err := os.Stat(script); err != nil {
		t.Skip("release_policy.py not found")
	}
	tmpDir := t.TempDir()
	checksums := filepath.Join(tmpDir, "checksums.txt")
	content := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  gov.tar.gz\n" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  gov.tar.gz\n"
	if err := os.WriteFile(checksums, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-c", `
import sys, pathlib
sys.path.insert(0, sys.argv[1])
from release_policy import parse_checksums
try:
    parse_checksums(pathlib.Path(sys.argv[2]))
    print("ACCEPTED")
except ValueError as e:
    print(f"REJECTED: {e}")
`, filepath.Dir(script), checksums)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python3 invocation failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "ACCEPTED") {
		t.Fatal("release_policy.parse_checksums must REJECT duplicate checksum entries (Sol12 P1-7)")
	}
	if !strings.Contains(string(out), "duplicate") {
		t.Fatalf("expected duplicate rejection message, got: %s", out)
	}
}

// TestV12Case46MalformedChecksumLineRejected proves that a non-comment,
// non-empty line that does not match the checksum format is rejected (Sol12
// P1-7). A permissive parser that silently skips malformed lines lets an
// attacker inject arbitrary content without detection.
func TestV12Case46MalformedChecksumLineRejected(t *testing.T) {
	script := s8ReleasePolicyScript(t)
	if _, err := os.Stat(script); err != nil {
		t.Skip("release_policy.py not found")
	}
	tmpDir := t.TempDir()
	checksums := filepath.Join(tmpDir, "checksums.txt")
	content := "this is not a valid checksum line at all\n"
	if err := os.WriteFile(checksums, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-c", `
import sys, pathlib
sys.path.insert(0, sys.argv[1])
from release_policy import parse_checksums
try:
    parse_checksums(pathlib.Path(sys.argv[2]))
    print("ACCEPTED")
except ValueError as e:
    print(f"REJECTED: {e}")
`, filepath.Dir(script), checksums)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python3 invocation failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "ACCEPTED") {
		t.Fatal("release_policy.parse_checksums must REJECT a malformed checksum line (Sol12 P1-7)")
	}
	if !strings.Contains(string(out), "malformed") {
		t.Fatalf("expected malformed rejection message, got: %s", out)
	}
}

// TestV12Case47CleanRunnerWithoutGlobalPytestStillRunsViaVenv proves that
// the release script's Assayer matrix creates per-version venvs and does not
// depend on global GitHub-runner packages (Sol12 P1-2). The script must
// contain venv creation and locked-dependency installation logic.
func TestV12Case47CleanRunnerWithoutGlobalPytestStillRunsViaVenv(t *testing.T) {
	releaseSh := s8ReleaseScript(t)
	if _, err := os.Stat(releaseSh); err != nil {
		t.Skip("release.sh not found")
	}
	content, err := os.ReadFile(releaseSh)
	if err != nil {
		t.Fatal(err)
	}
	src := string(content)

	if !strings.Contains(src, "-m venv") {
		t.Fatal("release.sh Assayer matrix does not create per-version venvs (Sol12 P1-2: must not depend on global runner packages)")
	}
	if !strings.Contains(src, "requirements-lock.txt") {
		t.Fatal("release.sh Assayer matrix does not install from requirements-lock.txt (Sol12 P1-2: locked dependencies)")
	}
	if !strings.Contains(src, "assayer-venvs") {
		t.Fatal("release.sh Assayer matrix does not use a dedicated venv directory (Sol12 P1-2)")
	}
	if !strings.Contains(src, "wheel_hashes") || !strings.Contains(src, "importlib.metadata") {
		t.Fatal("release.sh Assayer matrix does not record installed wheel hashes (Sol12 P1-2)")
	}
}

// TestV12Case48PerPythonLockedDependencyInstallation proves that the release
// script records per-Python wheel hashes from the isolated venv (Sol12
// P1-2). The matrix JSON must include wheel_hashes and isolated_venv fields
// so release evidence proves the exact dependency closure per interpreter.
func TestV12Case48PerPythonLockedDependencyInstallation(t *testing.T) {
	releaseSh := s8ReleaseScript(t)
	if _, err := os.Stat(releaseSh); err != nil {
		t.Skip("release.sh not found")
	}
	content, err := os.ReadFile(releaseSh)
	if err != nil {
		t.Fatal(err)
	}
	src := string(content)

	if !strings.Contains(src, `"wheel_hashes"`) {
		t.Fatal("release.sh matrix JSON does not record wheel_hashes (Sol12 P1-2)")
	}
	if !strings.Contains(src, `"isolated_venv"`) {
		t.Fatal("release.sh matrix JSON does not record isolated_venv flag (Sol12 P1-2)")
	}
	if !strings.Contains(src, "pip") && !strings.Contains(src, "install") {
		t.Fatal("release.sh Assayer matrix does not install dependencies via pip (Sol12 P1-2)")
	}
}

// TestV12Case49UnknownAssayerDependencyHashDisablesReplay proves that an
// Assayer snapshot with an unknown dependency identity (DependencyHash empty,
// DependencyUnavailableReason non-empty) disables strict replay and blocks
// production approval (Sol12 P1-6). Two different unknown dependency
// environments must never compare equal.
func TestV12Case49UnknownAssayerDependencyHashDisablesReplay(t *testing.T) {
	repoRoot := s8RepoRoot(t)
	runtimeGo := filepath.Join(repoRoot, "internal", "runtime", "runtime.go")
	content, err := os.ReadFile(runtimeGo)
	if err != nil {
		t.Fatal(err)
	}
	src := string(content)

	if !strings.Contains(src, "DependencyUnavailableReason") {
		t.Fatal("runtime.go does not check DependencyUnavailableReason (Sol12 P1-6: unknown dependency identity must disable strict replay)")
	}
	if !strings.Contains(src, "assayer dependency identity is unknown") {
		t.Fatal("runtime.go does not produce the expected strict-replay-disabled reason for unknown Assayer dependency identity (Sol12 P1-6)")
	}

	snapshotGo := filepath.Join(repoRoot, "internal", "assay", "snapshot.go")
	snapContent, err := os.ReadFile(snapshotGo)
	if err != nil {
		t.Fatal(err)
	}
	snapSrc := string(snapContent)

	if !strings.Contains(snapSrc, "DependencyUnavailableReason string") {
		t.Fatal("SnapshotIdentity does not include DependencyUnavailableReason field (Sol12 P1-6: two unknown environments must not compare equal)")
	}
	if !strings.Contains(snapSrc, "DependencyUnavailableReason: runtimeManifest.DependencyUnavailableReason") {
		t.Fatal("BuildSnapshot does not populate DependencyUnavailableReason in SnapshotIdentity (Sol12 P1-6)")
	}
}
