package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cleanEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"GOV_CONFIG", "GOV_PROTECTED_PATHS", "GOV_PROTECTED_MANIFEST",
		"CLAUDE_HARNESS_STATE", "GOV_SNAPSHOT_DIR", "HARNESS_SNAPSHOT_DIR",
		"GOV_SNAPSHOT_ROOTS", "GOV_LEDGER_DIR", "GOV_HOME", "GOVERNATOR_HOME",
		"GOV_CODEX_BIN", "GOV_DEFAULT_AGENT", "GOV_DEFAULT_MAX_MINUTES",
	} {
		t.Setenv(name, "")
	}
}

func TestLoadPrecedence(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "custom.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte(`protected_manifest: /from/file
snapshot_dir: /snap/file
snapshot_roots: [/root/file]
ledger_dir: /ledger/file
backends:
  codex: {bin: codex-file}
defaults: {agent: codex, max_minutes: 12}
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_PATHS", "/from/env")
	t.Setenv("GOV_CODEX_BIN", "codex-env")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProtectedManifest != "/from/env" || cfg.SnapshotDir != "/snap/file" {
		t.Fatalf("paths=%+v", cfg)
	}
	if cfg.Backends["codex"].Bin != "codex-env" || cfg.Defaults.Agent != "codex" || cfg.Defaults.MaxMinutes != 12 {
		t.Fatalf("config=%+v", cfg)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("mystery: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "field mystery") {
		t.Fatalf("error=%v", err)
	}
}

func TestScaffoldIsIdempotent(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	results, err := Scaffold(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("results=%+v", results)
	}
	for _, result := range results {
		if result.Skipped {
			t.Fatalf("first run skipped %s", result.Path)
		}
		if _, err := os.Stat(result.Path); err != nil {
			t.Fatal(err)
		}
	}
	results, err = Scaffold(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if !result.Skipped {
			t.Fatalf("second run overwrote %s", result.Path)
		}
	}
}
