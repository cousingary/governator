package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureValidate runs `gov validate <path>` and returns the exit code plus
// combined stdout+stderr, since the cleanup-doctrine finding (Session 5, gap
// #5) is written to stderr while the base VALID line goes to stdout.
func captureValidate(t *testing.T, path string) (int, string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	os.Stdout, os.Stderr = outW, errW
	code := run([]string{"validate", path})
	_ = outW.Close()
	_ = errW.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	out, _ := io.ReadAll(outR)
	errOut, _ := io.ReadAll(errR)
	return code, string(out) + string(errOut)
}

// surgeonJobWithoutCleanup writes a valid mode:surgeon job YAML with a
// success validator that gives it no lint/format coverage — the doctrine
// gap #5 finding should fire against it.
func surgeonJobWithoutCleanup(t *testing.T, dir string) string {
	t.Helper()
	root := t.TempDir()
	body := `job_id: doctrine-surgeon
job_type: code_change
agent: claude-code
mode: surgeon
workspace:
  root: ` + root + `
  worktree: auto
allowed:
  read: ["**"]
  write: ["output/**"]
  execute: ["go test ./..."]
forbidden:
  paths: [".git/**"]
  commands: ["rm -rf"]
  behaviors: ["network"]
budget: {max_minutes: 5, max_commands: 10, max_files_changed: 5, max_lines_changed: 100, max_new_files: 2, max_deleted: 0}
preflight:
  intended_writes: ["output/**"]
success:
  required_files: ["output/result.txt"]
  validators: ["go test ./..."]
on_violation: quarantine
`
	path := filepath.Join(dir, "doctrine-surgeon.yaml")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGovValidateWarnsOnMissingCleanupCoverageByDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	path := surgeonJobWithoutCleanup(t, dir)

	code, output := captureValidate(t, path)
	if code != 0 {
		t.Fatalf("expected warn-only exit 0, got %d: %s", code, output)
	}
	if !strings.Contains(output, "DOCTRINE WARNING") || !strings.Contains(output, "doctrine-surgeon") {
		t.Fatalf("expected a doctrine warning naming the job, got: %s", output)
	}
}

func TestGovValidateEnforcesCleanupWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("doctrine:\n  require_cleanup: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", configPath)
	path := surgeonJobWithoutCleanup(t, dir)

	code, output := captureValidate(t, path)
	if code != 1 {
		t.Fatalf("expected enforced doctrine to fail validate, got exit %d: %s", code, output)
	}
	if !strings.Contains(output, "DOCTRINE ERROR") {
		t.Fatalf("expected a doctrine error, got: %s", output)
	}
}

func TestGovValidateSilentWhenCleanupBlockPresent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("doctrine:\n  require_cleanup: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", configPath)
	path := surgeonJobWithoutCleanup(t, dir)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	withCleanup := strings.Replace(string(body), "on_violation: quarantine",
		"cleanup:\n  required: false\n  validators: [\"gofmt -l .\"]\non_violation: quarantine", 1)
	if err := os.WriteFile(path, []byte(withCleanup), 0644); err != nil {
		t.Fatal(err)
	}

	code, output := captureValidate(t, path)
	if code != 0 {
		t.Fatalf("expected a satisfied cleanup doctrine to validate cleanly, got exit %d: %s", code, output)
	}
	if strings.Contains(output, "DOCTRINE") {
		t.Fatalf("expected no doctrine finding once a cleanup block is present, got: %s", output)
	}
}
