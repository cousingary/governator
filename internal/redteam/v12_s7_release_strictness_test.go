//go:build redteam

package redteam

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func s7RepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve this test file's own path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

func s7CheckpointScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(s7RepoRoot(t), "scripts", "release_checkpoint.py")
}

func s7ToolsetScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(s7RepoRoot(t), "scripts", "release_toolset.py")
}

func s7ReleaseScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(s7RepoRoot(t), "scripts", "release.sh")
}

func s7WriteIdentity(t *testing.T, path string, fields map[string]string) {
	t.Helper()
	args := []string{s7CheckpointScript(t), "identity"}
	for _, k := range []string{
		"governator_commit", "governator_tag", "assayer_commit",
		"go_sum_hash", "toolchain_hash", "environment_hash",
		"go_test_parallelism", "requested_version", "expected_exact_tag",
		"release_mode", "distribution_allowed",
	} {
		args = append(args, "--"+strings.ReplaceAll(k, "_", "-"), fields[k])
	}
	cmd := exec.Command("python3", args...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("release_checkpoint.py identity: %v", err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func s7DefaultFields() map[string]string {
	return map[string]string{
		"governator_commit":    "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee0",
		"governator_tag":       "v1.0.2-rc5",
		"assayer_commit":       "a55a11a55a11a55a11a55a11a55a11a55a11a55",
		"go_sum_hash":          "gosum-hash-1",
		"toolchain_hash":       "toolchain-hash-1",
		"environment_hash":     "environment-hash-1",
		"go_test_parallelism":  "2",
		"requested_version":    "1.0.2-rc5",
		"expected_exact_tag":   "v1.0.2-rc5",
		"release_mode":         "production",
		"distribution_allowed": "true",
	}
}

// TestV12Case37RCVersionRequireTagZeroStillStrict proves that a production
// version (vX.Y.Z-rcN) cannot have its tag requirement weakened by
// REQUIRE_TAG=0. The release script derives strictness from the version
// string itself (Sol12 P1-3): for any version matching the production
// pattern, REQUIRE_TAG is forced to 1 regardless of the caller's environment.
func TestV12Case37RCVersionRequireTagZeroStillStrict(t *testing.T) {
	releaseSh := s7ReleaseScript(t)
	if _, err := os.Stat(releaseSh); err != nil {
		t.Skip("release.sh not found")
	}
	content, err := os.ReadFile(releaseSh)
	if err != nil {
		t.Fatal(err)
	}
	src := string(content)

	if !strings.Contains(src, `RELEASE_MODE="production"`) {
		t.Fatal("release.sh does not derive RELEASE_MODE from version (Sol12 P1-3 fix missing)")
	}
	if !strings.Contains(src, "REQUIRE_TAG=1") {
		t.Fatal("release.sh does not force REQUIRE_TAG=1 for production versions")
	}

	idx := strings.Index(src, `RELEASE_MODE="production"`)
	after := src[idx:]
	prodBlock := after[:min(len(after), 600)]
	if strings.Contains(prodBlock, "REQUIRE_TAG=${REQUIRE_TAG") {
		t.Fatal("production release mode still allows caller to override REQUIRE_TAG via env (Sol12 P1-3 defect not closed)")
	}
	if !strings.Contains(prodBlock, "REQUIRE_TAG=1") {
		t.Fatal("production release mode block does not unconditionally set REQUIRE_TAG=1")
	}
}

// TestV12Case38RCVersionRequireZeroSkipsZeroStillStrict proves that a
// production version cannot have its zero-skips requirement weakened by
// GOV_RELEASE_REQUIRE_ZERO_SKIPS=0. The release script forces
// REQUIRE_ZERO_SKIPS=1 for production versions (Sol12 P1-3).
func TestV12Case38RCVersionRequireZeroSkipsZeroStillStrict(t *testing.T) {
	releaseSh := s7ReleaseScript(t)
	content, err := os.ReadFile(releaseSh)
	if err != nil {
		t.Fatal(err)
	}
	src := string(content)

	idx := strings.Index(src, `RELEASE_MODE="production"`)
	if idx < 0 {
		t.Fatal("release.sh missing production release mode derivation")
	}
	after := src[idx:]
	prodBlock := after[:min(len(after), 600)]
	if !strings.Contains(prodBlock, "REQUIRE_ZERO_SKIPS=1") {
		t.Fatal("production release mode block does not unconditionally set REQUIRE_ZERO_SKIPS=1 (Sol12 P1-3)")
	}

	if strings.Contains(src, "REQUIRE_ZERO_SKIPS=${GOV_RELEASE_REQUIRE_ZERO_SKIPS:-$REQUIRE_TAG}") {
		t.Fatal("release.sh still re-derives REQUIRE_ZERO_SKIPS from env in the redteam-gate section (Sol12 P1-3 defect: caller can weaken)")
	}
}

// TestV12Case39ReleaseToolReplacedAfterPreflightFails proves that
// release_toolset.py --verify detects a tool binary substitution after
// preflight recording (Sol12 P1-4). A same-UID process swapping a tool
// between preflight and tier execution must be caught.
func TestV12Case39ReleaseToolReplacedAfterPreflightFails(t *testing.T) {
	toolsetPy := s7ToolsetScript(t)
	if _, err := os.Stat(toolsetPy); err != nil {
		t.Skip("release_toolset.py not found")
	}

	tmpDir := t.TempDir()
	fakeToolDir := filepath.Join(tmpDir, "tools")
	if err := os.MkdirAll(fakeToolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeTool := filepath.Join(fakeToolDir, "faketool")
	if err := os.WriteFile(fakeTool, []byte("#!/bin/sh\necho v1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	toolsetJSON := filepath.Join(tmpDir, "toolset.json")
	cmd := exec.Command("python3", toolsetPy, "--out", toolsetJSON, "--tools", "faketool")
	cmd.Env = append(os.Environ(), "PATH="+fakeToolDir+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("release_toolset.py --out: %v\n%s", err, out)
	}

	verifyCmd := exec.Command("python3", toolsetPy, "--verify", toolsetJSON)
	verifyCmd.Env = append(os.Environ(), "PATH="+fakeToolDir+":"+os.Getenv("PATH"))
	if out, err := verifyCmd.CombinedOutput(); err != nil {
		t.Fatalf("verify of unmodified toolset should pass: %v\n%s", err, out)
	}

	if err := os.WriteFile(fakeTool, []byte("#!/bin/sh\necho v2-SUBSTITUTED\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	verifyCmd2 := exec.Command("python3", toolsetPy, "--verify", toolsetJSON)
	verifyCmd2.Env = append(os.Environ(), "PATH="+fakeToolDir+":"+os.Getenv("PATH"))
	out2, err2 := verifyCmd2.CombinedOutput()
	if err2 == nil {
		t.Fatal("release_toolset.py --verify must FAIL when a tool binary is substituted after preflight (Sol12 P1-4)")
	}
	if !strings.Contains(string(out2), "TOOLSET_VERIFICATION_FAILED") {
		t.Fatalf("expected TOOLSET_VERIFICATION_FAILED in output, got: %s", out2)
	}
}

// TestV12Case40CheckpointReusedUnderAnotherVersionRejected proves that a
// checkpoint created under one VERSION is rejected when a different VERSION
// attempts to reuse it (Sol12 P1-5). The checkpoint identity now binds
// requested_version + expected_exact_tag + release_mode +
// distribution_allowed, so cross-version reuse is impossible.
func TestV12Case40CheckpointReusedUnderAnotherVersionRejected(t *testing.T) {
	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fieldsA := s7DefaultFields()
	fieldsA["requested_version"] = "1.0.2-rc5"
	fieldsA["expected_exact_tag"] = "v1.0.2-rc5"

	idFileA := filepath.Join(tmpDir, "identity-a.json")
	s7WriteIdentity(t, idFileA, fieldsA)

	initCmd := exec.Command("python3", s7CheckpointScript(t), "init",
		"--state-dir", stateDir, "--identity-file", idFileA, "--attempt-id", "attempt-aaa")
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}

	identityFile := filepath.Join(stateDir, "identity.json")
	writeCmd := exec.Command("python3", s7CheckpointScript(t), "write",
		"--checkpoint", filepath.Join(stateDir, "unit.json"),
		"--identity-file", identityFile,
		"--command", "go test ./...",
		"--started", "2026-01-01T00:00:00Z", "--completed", "2026-01-01T00:01:00Z",
		"--exit-code", "0", "--log-sha256", "abc123", "--result", "PASS",
		"--duration-seconds", "60")
	if out, err := writeCmd.CombinedOutput(); err != nil {
		t.Fatalf("write: %v\n%s", err, out)
	}

	fieldsB := s7DefaultFields()
	fieldsB["requested_version"] = "1.0.3-rc1"
	fieldsB["expected_exact_tag"] = "v1.0.3-rc1"

	idFileB := filepath.Join(tmpDir, "identity-b.json")
	s7WriteIdentity(t, idFileB, fieldsB)

	aggCmd := exec.Command("python3", s7CheckpointScript(t), "aggregate",
		"--state-dir", stateDir, "--identity-file", idFileB,
		"--required", "unit")
	out, err := aggCmd.CombinedOutput()
	if err == nil {
		t.Fatal("aggregate must REJECT a checkpoint whose requested_version differs from the current attempt (Sol12 P1-5: cross-version checkpoint reuse)")
	}
	if !strings.Contains(string(out), "MIXED_RELEASE_EVIDENCE") && !strings.Contains(string(out), "does not match") {
		t.Fatalf("expected MIXED_RELEASE_EVIDENCE rejection, got: %s", out)
	}
}

// TestV12Case41MultipleTagsOnOneCommitBindToExpectedExactTag proves that
// when multiple tags point at the same commit, the checkpoint identity uses
// the expected v${VERSION} tag (not the first sorted tag) and a checkpoint
// created under a different tag is rejected (Sol12 P1-5).
func TestV12Case41MultipleTagsOnOneCommitBindToExpectedExactTag(t *testing.T) {
	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fieldsA := s7DefaultFields()
	fieldsA["governator_tag"] = "v1.0.2-rc5"
	fieldsA["expected_exact_tag"] = "v1.0.2-rc5"

	idFileA := filepath.Join(tmpDir, "identity-a.json")
	s7WriteIdentity(t, idFileA, fieldsA)

	initCmd := exec.Command("python3", s7CheckpointScript(t), "init",
		"--state-dir", stateDir, "--identity-file", idFileA, "--attempt-id", "attempt-multi-tag")
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}

	identityFile := filepath.Join(stateDir, "identity.json")
	writeCmd := exec.Command("python3", s7CheckpointScript(t), "write",
		"--checkpoint", filepath.Join(stateDir, "unit.json"),
		"--identity-file", identityFile,
		"--command", "go test ./...",
		"--started", "2026-01-01T00:00:00Z", "--completed", "2026-01-01T00:01:00Z",
		"--exit-code", "0", "--log-sha256", "abc123", "--result", "PASS",
		"--duration-seconds", "60")
	if out, err := writeCmd.CombinedOutput(); err != nil {
		t.Fatalf("write: %v\n%s", err, out)
	}

	fieldsB := s7DefaultFields()
	fieldsB["governator_tag"] = "v1.0.2-rc4"
	fieldsB["expected_exact_tag"] = "v1.0.2-rc4"

	idFileB := filepath.Join(tmpDir, "identity-b.json")
	s7WriteIdentity(t, idFileB, fieldsB)

	aggCmd := exec.Command("python3", s7CheckpointScript(t), "aggregate",
		"--state-dir", stateDir, "--identity-file", idFileB,
		"--required", "unit")
	out, err := aggCmd.CombinedOutput()
	if err == nil {
		t.Fatal("aggregate must REJECT a checkpoint whose expected_exact_tag differs (Sol12 P1-5: multiple tags on one commit must bind to the expected tag)")
	}
	if !strings.Contains(string(out), "MIXED_RELEASE_EVIDENCE") && !strings.Contains(string(out), "does not match") {
		t.Fatalf("expected MIXED_RELEASE_EVIDENCE rejection for tag mismatch, got: %s", out)
	}

	checkCmd := exec.Command("python3", s7CheckpointScript(t), "check",
		"--checkpoint", filepath.Join(stateDir, "unit.json"),
		"--identity-file", idFileB,
		"--command", "go test ./...")
	checkOut, checkErr := checkCmd.CombinedOutput()
	if checkErr == nil {
		t.Fatal("check must report STALE when expected_exact_tag differs (Sol12 P1-5)")
	}
	if !strings.Contains(string(checkOut), "STALE") {
		t.Fatalf("expected STALE for tag mismatch, got: %s", checkOut)
	}

	var identityData map[string]interface{}
	idBytes, _ := os.ReadFile(identityFile)
	if err := json.Unmarshal(idBytes, &identityData); err != nil {
		t.Fatal(err)
	}
	if identityData["expected_exact_tag"] != "v1.0.2-rc5" {
		t.Fatalf("identity.json expected_exact_tag = %v, want v1.0.2-rc5 (must bind to the exact expected tag, not first-sorted)", identityData["expected_exact_tag"])
	}
}
