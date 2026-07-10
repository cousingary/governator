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
		"GOV_CODEX_BIN", "GOV_RTK_MODE", "GOV_RTK_BIN",
		"GOV_GRAPH_MODE", "GOV_GRAPH_PROVIDER", "GOV_GRAPH_BIN",
		"GOV_MINIMALISM_MODE",
		"GOV_SPEND_DAILY_CAP_USD", "GOV_SPEND_HALT_FILE",
		"GOV_DEFAULT_AGENT", "GOV_DEFAULT_MAX_MINUTES",
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
rtk: {mode: off, bin: rtk-file}
graph: {mode: auto, provider: codegraph, bin: codegraph-file}
minimalism: {mode: lite}
spend: {daily_cap_usd: 2.5, halt_file: /halt/file}
defaults: {agent: codex, max_minutes: 12}
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_PATHS", "/from/env")
	t.Setenv("GOV_CODEX_BIN", "codex-env")
	t.Setenv("GOV_RTK_MODE", "required")
	t.Setenv("GOV_RTK_BIN", "rtk-env")
	t.Setenv("GOV_GRAPH_MODE", "required")
	t.Setenv("GOV_GRAPH_BIN", "codegraph-env")
	t.Setenv("GOV_MINIMALISM_MODE", "ultra")
	t.Setenv("GOV_SPEND_DAILY_CAP_USD", "9.5")
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
	if cfg.RTK.Mode != "required" || cfg.RTK.Bin != "rtk-env" {
		t.Fatalf("rtk config=%+v", cfg.RTK)
	}
	if cfg.Graph.Mode != "required" || cfg.Graph.Provider != "codegraph" || cfg.Graph.Bin != "codegraph-env" {
		t.Fatalf("graph config=%+v", cfg.Graph)
	}
	if cfg.Minimalism.Mode != "ultra" {
		t.Fatalf("minimalism config=%+v", cfg.Minimalism)
	}
	if cfg.Spend.DailyCapUSD != 9.5 || cfg.Spend.HaltFile != "/halt/file" {
		t.Fatalf("spend config=%+v", cfg.Spend)
	}
}

func TestLoadSpendHaltFileEnvOverride(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GOV_SPEND_HALT_FILE", "/env/halt")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Spend.HaltFile != "/env/halt" {
		t.Fatalf("halt file=%s", cfg.Spend.HaltFile)
	}
}

func TestLoadDefaultSpendIsUnlimitedWithHaltFileUnderHome(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Spend.DailyCapUSD != 0 {
		t.Fatalf("expected default daily_cap_usd=0 (unlimited), got %v", cfg.Spend.DailyCapUSD)
	}
	want := filepath.Join(home, ".governator", "HALT")
	if cfg.Spend.HaltFile != want {
		t.Fatalf("halt file=%s want=%s", cfg.Spend.HaltFile, want)
	}
}

func TestLoadRejectsNegativeSpendCap(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("spend: {daily_cap_usd: -1}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "invalid spend.daily_cap_usd") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadRejectsInvalidRTKMode(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("rtk: {mode: always}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "invalid rtk.mode") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadRejectsInvalidGraphMode(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("graph: {mode: always}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "invalid graph.mode") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadRejectsInvalidMinimalismMode(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("minimalism: {mode: extreme}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "invalid minimalism.mode") {
		t.Fatalf("error=%v", err)
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
	example, err := os.ReadFile(filepath.Join(home, ".governator", "jobs", "example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"worktree: auto", "on_violation: quarantine"} {
		if !strings.Contains(string(example), want) {
			t.Fatalf("example contract missing %q", want)
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
