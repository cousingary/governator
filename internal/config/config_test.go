package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
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
		"GOV_DOCTRINE_REQUIRE_CLEANUP",
		"GOV_DEFAULT_AGENT", "GOV_DEFAULT_MAX_MINUTES",
		"GOV_ASSAY_REPO", "GOV_ASSAY_PYTHON", "GOV_ASSAY_TIMEOUT_SECONDS",
		"GOV_CONTAINMENT_OVERRIDE_PUBLIC_KEY", "GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING",
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

func TestLoadBackendModelCapabilitiesMergeFieldByField(t *testing.T) {
	// A file declaring only model facts (no bin override) must not lose those
	// facts just because Bin is blank -- merge is field-by-field, not a
	// wholesale Backend replace keyed on Bin being set.
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "custom.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte(`backends:
  claude-code:
    vision: true
    tool_calling: true
    local_only: true
    context_tokens: 200000
    output_tokens: 8192
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Backends["claude-code"]
	if got.Bin != "claude" {
		t.Fatalf("bin override absent from file must keep the built-in default, got %q", got.Bin)
	}
	if !got.Vision || !got.ToolCalling || !got.LocalOnly || got.ContextTokens != 200000 || got.OutputTokens != 8192 {
		t.Fatalf("model capability fields not merged: %+v", got)
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

func TestLoadDoctrineRequireCleanupDefaultsFalse(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Doctrine.RequireCleanup {
		t.Fatalf("expected doctrine.require_cleanup to default false, got true")
	}
}

func TestLoadDoctrineRequireCleanupFromFileAndEnv(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("doctrine: {require_cleanup: true}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Doctrine.RequireCleanup {
		t.Fatalf("expected file to enable doctrine.require_cleanup")
	}

	t.Setenv("GOV_DOCTRINE_REQUIRE_CLEANUP", "false")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Doctrine.RequireCleanup {
		t.Fatalf("expected env override to disable doctrine.require_cleanup")
	}
}

// TestLoadAssayDefaultsToUnconfigured is the Phase 3A skip-by-default
// regression test: with no assay.repo set anywhere (no config file, no
// env), Assay.Repo must stay empty so internal/assay.Config.Configured()
// reports false and every existing run/test that never heard of assay
// keeps behaving exactly as before this field existed.
func TestLoadAssayDefaultsToUnconfigured(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Assay.Repo != "" {
		t.Fatalf("expected assay.repo to default empty (unconfigured), got %q", cfg.Assay.Repo)
	}
	if cfg.Assay.Python != "python3" {
		t.Fatalf("expected assay.python to default to python3, got %q", cfg.Assay.Python)
	}
	if cfg.Assay.TimeoutSeconds != 60 {
		t.Fatalf("expected assay.timeout_seconds to default to 60, got %d", cfg.Assay.TimeoutSeconds)
	}
}

func TestLoadAssayFromFileAndEnv(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("assay: {repo: /opt/assayer, python: python3.11, timeout_seconds: 30}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Assay.Repo != "/opt/assayer" || cfg.Assay.Python != "python3.11" || cfg.Assay.TimeoutSeconds != 30 {
		t.Fatalf("assay config=%+v", cfg.Assay)
	}

	t.Setenv("GOV_ASSAY_REPO", "/env/assayer")
	t.Setenv("GOV_ASSAY_PYTHON", "python3.12")
	t.Setenv("GOV_ASSAY_TIMEOUT_SECONDS", "45")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Assay.Repo != "/env/assayer" || cfg.Assay.Python != "python3.12" || cfg.Assay.TimeoutSeconds != 45 {
		t.Fatalf("assay env-overridden config=%+v", cfg.Assay)
	}
}

func TestLoadQuotasFromFile(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte(`quotas:
  - backend: Codex
    account: Default
    window_type: daily
    estimated_limit: 1000
    confidence: 0.75
`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Quotas) != 1 || cfg.Quotas[0].Backend != "codex" || cfg.Quotas[0].Account != "default" || cfg.Quotas[0].WindowType != "daily" || cfg.Quotas[0].EstimatedLimit != 1000 || cfg.Quotas[0].Confidence != 0.75 {
		t.Fatalf("quotas=%+v", cfg.Quotas)
	}
}

func TestLoadRejectsInvalidQuota(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("quotas: [{backend: codex, window_type: yearly, estimated_limit: 1}]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "invalid quota window_type") {
		t.Fatalf("error=%v", err)
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
	if _, err := contracts.Parse(example); err != nil {
		t.Fatalf("scaffolded example contract (with commented cleanup block) does not parse: %v", err)
	}
	t.Setenv("GOV_CONFIG", Path())
	if cfg, err := Load(); err != nil {
		t.Fatalf("scaffolded config.yaml (with doctrine block) does not load: %v", err)
	} else if cfg.Doctrine.RequireCleanup {
		t.Fatalf("scaffolded config should default doctrine.require_cleanup to false")
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

func TestLoadGovHomeMovesDefaultHaltFileNextToLedger(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	govHome := t.TempDir()
	t.Setenv("GOV_HOME", govHome)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LedgerDir != govHome {
		t.Fatalf("ledger_dir=%s want=%s", cfg.LedgerDir, govHome)
	}
	// The spend cap reads the ledger under GOV_HOME; the still-default halt
	// file must follow it, or a real operator halt in ~/.governator/HALT
	// would bleed into every GOV_HOME-isolated run (tests especially).
	want := filepath.Join(govHome, "HALT")
	if cfg.Spend.HaltFile != want {
		t.Fatalf("halt file=%s want=%s", cfg.Spend.HaltFile, want)
	}
}

func TestLoadGovHomeDoesNotOverrideExplicitHaltFile(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GOV_HOME", t.TempDir())
	path := filepath.Join(home, "custom.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("spend: {halt_file: /halt/explicit}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Spend.HaltFile != "/halt/explicit" {
		t.Fatalf("explicit halt_file must win over the GOV_HOME redirect, got %s", cfg.Spend.HaltFile)
	}
}

// TestLoadContainmentOverridePublicKey is the Session 3 (Phase 2) config
// regression: the operator ed25519 override key loads from file and env, and
// defaults empty (fail-closed — no key means no high-risk override accepted).
func TestLoadContainmentOverridePublicKey(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Containment.OverridePublicKey != "" {
		t.Fatalf("expected containment.override_public_key to default empty (fail-closed), got %q", cfg.Containment.OverridePublicKey)
	}
	if cfg.Containment.LocalEffectfulTiering != "enforce" {
		t.Fatalf("expected containment.local_effectful_tiering to default enforce, got %q", cfg.Containment.LocalEffectfulTiering)
	}

	path := filepath.Join(home, "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("containment: {override_public_key: deadbeef}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Containment.OverridePublicKey != "deadbeef" {
		t.Fatalf("file override key = %q", cfg.Containment.OverridePublicKey)
	}

	t.Setenv("GOV_CONTAINMENT_OVERRIDE_PUBLIC_KEY", "cafef00d")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Containment.OverridePublicKey != "cafef00d" {
		t.Fatalf("env override key = %q", cfg.Containment.OverridePublicKey)
	}
}

func TestLoadContainmentLocalEffectfulTieringFromFileAndEnv(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("containment: {local_effectful_tiering: off}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Containment.LocalEffectfulTiering != "off" {
		t.Fatalf("file local_effectful_tiering = %q", cfg.Containment.LocalEffectfulTiering)
	}

	t.Setenv("GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING", "enforce")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Containment.LocalEffectfulTiering != "enforce" {
		t.Fatalf("env local_effectful_tiering = %q", cfg.Containment.LocalEffectfulTiering)
	}
}

func TestLoadRejectsInvalidContainmentLocalEffectfulTiering(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("containment: {local_effectful_tiering: permissive}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "invalid containment.local_effectful_tiering") {
		t.Fatalf("error=%v", err)
	}
}

// TestLoadStrictMissingFileReturnsDefaults proves the absent-config branch of
// Sol Critical 2: a missing configuration file is NOT an error — built-in
// defaults apply. This is the one case where falling back to defaults is
// correct; every other present-but-invalid case must fail (see below).
func TestLoadStrictMissingFileReturnsDefaults(t *testing.T) {
	cleanEnv(t)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	cfg, err := LoadStrict()
	if err != nil {
		t.Fatalf("missing config file should not error, got: %v", err)
	}
	builtIn := BuiltIn()
	if cfg.Defaults.Agent != builtIn.Defaults.Agent || cfg.Defaults.MaxMinutes != builtIn.Defaults.MaxMinutes {
		t.Fatalf("missing config did not return built-in defaults: %+v", cfg.Defaults)
	}
}

// TestLoadStrictRejectsMalformedYAML proves the malformed-YAML branch of Sol
// Critical 2: present-but-unparseable configuration is fatal with a specific
// message, never silently replaced by defaults.
func TestLoadStrictRejectsMalformedYAML(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	// Unclosed flow mapping — a YAML syntax error, not just an unknown field.
	if err := os.WriteFile(path, []byte("spend: {daily_cap_usd: [unterminated\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStrict()
	if err == nil {
		t.Fatal("malformed YAML should produce an error, got nil")
	}
}

// TestLoadStrictRejectsUnknownField proves the strict-decoding branch via the
// canonical LoadStrict API (an unknown field is fatal). Mirrors the existing
// TestLoadRejectsUnknownKeys but pins the canonical entry point.
func TestLoadStrictRejectsUnknownField(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("totally_made_up_field: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStrict()
	if err == nil || !strings.Contains(err.Error(), "totally_made_up_field") {
		t.Fatalf("expected an error naming the unknown field, got: %v", err)
	}
}

// TestLoadStrictRejectsInvalidPolicyValue proves the invalid-policy branch via
// the canonical LoadStrict API: a structurally-valid but semantically-invalid
// policy rule (bad verdict) is fatal at load time, never silently disarmed.
func TestLoadStrictRejectsInvalidPolicyValue(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("policy_rules:\n  - id: bad\n    when: [{field: backend, op: eq, value: glm}]\n    verdict: ALLOW\n    reason: r\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStrict()
	if err == nil {
		t.Fatal("invalid policy verdict should produce an error, got nil")
	}
}
