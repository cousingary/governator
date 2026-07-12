package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cousingary/governator/internal/policy"
	"gopkg.in/yaml.v3"
)

// Backend configures one routing candidate. Bin overrides the binary path.
// The remaining fields are operator-declared facts about whichever model the
// operator has pointed this backend at (vision, tool calling, locality,
// context/output limits) — Governator never infers them from the backend
// name, since the same CLI wrapper can run different models over time. They
// back the router's optional RoutingRequirements hard filters (see
// internal/contracts.RoutingRequirements and docs/routing.md) and default to
// unsupported/zero (fail closed) until declared here.
type Backend struct {
	Bin           string `yaml:"bin"`
	Vision        bool   `yaml:"vision,omitempty"`
	ToolCalling   bool   `yaml:"tool_calling,omitempty"`
	LocalOnly     bool   `yaml:"local_only,omitempty"`
	ContextTokens int    `yaml:"context_tokens,omitempty"`
	OutputTokens  int    `yaml:"output_tokens,omitempty"`
}

type RTK struct {
	Mode string `yaml:"mode"`
	Bin  string `yaml:"bin"`
}

type Graph struct {
	Mode     string `yaml:"mode"`
	Provider string `yaml:"provider"`
	Bin      string `yaml:"bin"`
}

type Minimalism struct {
	Mode string `yaml:"mode"`
}

type Spend struct {
	DailyCapUSD float64 `yaml:"daily_cap_usd"`
	HaltFile    string  `yaml:"halt_file"`
}

// QuotaWindow seeds a subscription/reset window for a backend. Usage units are
// tokens by convention; runtime reservations use budget.max_tokens and
// completion replaces the reservation with measured total_tokens when the
// backend reports them.
type QuotaWindow struct {
	Backend         string  `yaml:"backend"`
	Account         string  `yaml:"account"`
	WindowType      string  `yaml:"window_type"` // 5h, daily, weekly, monthly
	WindowStartedAt string  `yaml:"window_started_at"`
	ResetAt         string  `yaml:"reset_at"`
	EstimatedLimit  float64 `yaml:"estimated_limit"`
	Confidence      float64 `yaml:"confidence"`
}

// Doctrine holds config-gated policy toggles enforced by `gov validate`
// rather than the always-on schema checks in internal/contracts. Default
// false on every field so every existing config file and job YAML keeps
// validating unchanged.
type Doctrine struct {
	// RequireCleanup upgrades the cleanup-doctrine check (a write-capable
	// contract with neither a cleanup block nor a lint/format validator in
	// success.validators) from a warning to a validation error.
	RequireCleanup bool `yaml:"require_cleanup"`
}

// Containment configures the Session 3 (Phase 2) risk-class containment
// policy. OverridePublicKey is the ed25519 public key (hex) an operator uses
// to sign high-risk containment overrides. Empty (the default) means overrides
// are refused — a high-risk job without qualifying containment simply fails
// before launch. Configure it only when you genuinely need the escape hatch.
type Containment struct {
	OverridePublicKey string `yaml:"override_public_key"`
}

type Defaults struct {
	Agent      string `yaml:"agent"`
	MaxMinutes int    `yaml:"max_minutes"`
}

// Assay configures the Governator<->Assayer synchronous bridge (Phase 3A):
// Repo is the assayer checkout containing cli.py, Python is the interpreter
// to invoke it with, TimeoutSeconds bounds the subprocess call. Repo empty
// (the default — BuiltIn leaves it unset) means assay steps are SKIPPED and
// RECORDED AS SKIPPED by internal/assay: every existing config and every
// existing run that doesn't set this keeps behaving exactly as it did
// before this field existed.
type Assay struct {
	Repo           string `yaml:"repo"`
	Python         string `yaml:"python"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

type Config struct {
	ProtectedManifest string             `yaml:"protected_manifest"`
	SnapshotDir       string             `yaml:"snapshot_dir"`
	SnapshotRoots     []string           `yaml:"snapshot_roots"`
	LedgerDir         string             `yaml:"ledger_dir"`
	Backends          map[string]Backend `yaml:"backends"`
	RTK               RTK                `yaml:"rtk"`
	Graph             Graph              `yaml:"graph"`
	Minimalism        Minimalism         `yaml:"minimalism"`
	Spend             Spend              `yaml:"spend"`
	Quotas            []QuotaWindow      `yaml:"quotas"`
	Doctrine          Doctrine           `yaml:"doctrine"`
	Defaults          Defaults           `yaml:"defaults"`
	Assay             Assay              `yaml:"assay"`
	Containment       Containment        `yaml:"containment"`
	// PolicyRules is the Session 5 (Sol Phase 4) organization layer of the
	// layered policy engine: declarative rules evaluated first and with the
	// most authority — no lower layer (project doctrine, job contract,
	// session override) can loosen a DENY an org rule produces. Empty by
	// default (BuiltIn leaves it nil) so every existing config.yaml keeps
	// behaving exactly as it did before this field existed; see
	// docs/contracts.md for the condition language and example rules.
	PolicyRules []policy.ConditionRule `yaml:"policy_rules"`
}

// Env is the single environment lookup seam used by Governator packages.
func Env(name string) string { return strings.TrimSpace(os.Getenv(name)) }

func HomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "."
	}
	return home
}

func Path() string {
	if path := Env("GOV_CONFIG"); path != "" {
		return filepath.Clean(path)
	}
	return filepath.Join(HomeDir(), ".governator", "config.yaml")
}

func BuiltIn() Config {
	base := filepath.Join(HomeDir(), ".governator")
	return Config{
		ProtectedManifest: filepath.Join(base, "protected-paths.txt"),
		SnapshotDir:       filepath.Join(base, "snapshots"),
		LedgerDir:         base,
		Backends: map[string]Backend{
			"claude": {Bin: "claude"}, "claude-code": {Bin: "claude"},
			"codex": {Bin: "codex"}, "glm": {Bin: "glm"},
			"opencode": {Bin: "opencode"}, "pi": {Bin: "pi"},
		},
		RTK:        RTK{Mode: "auto", Bin: "rtk"},
		Graph:      Graph{Mode: "auto", Provider: "codegraph", Bin: "codegraph"},
		Minimalism: Minimalism{Mode: "full"},
		Spend:      Spend{DailyCapUSD: 0, HaltFile: filepath.Join(base, "HALT")},
		Quotas:     nil,
		Doctrine:   Doctrine{RequireCleanup: false},
		Defaults:   Defaults{Agent: "claude-code", MaxMinutes: 30},
		// Repo intentionally left unset: assay steps are skipped by default
		// (see Assay's doc comment). Python/TimeoutSeconds default sensibly
		// so a config that only sets `assay.repo` gets a working invocation.
		Assay: Assay{Python: "python3", TimeoutSeconds: 60},
		// Containment intentionally left unset: no override key means high-risk
		// jobs must qualify for containment on their own (fail-closed).
		Containment: Containment{},
	}
}

func Load() (Config, error) {
	cfg := BuiltIn()
	path := Path()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	if err == nil {
		var file Config
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&file); err != nil {
			return Config{}, fmt.Errorf("decode config %s: %w", path, err)
		}
		merge(&cfg, file)
	}
	applyEnv(&cfg)
	clean(&cfg)
	if cfg.RTK.Mode != "auto" && cfg.RTK.Mode != "off" && cfg.RTK.Mode != "required" {
		return Config{}, fmt.Errorf("invalid rtk.mode %q (want auto, off, or required)", cfg.RTK.Mode)
	}
	if cfg.Graph.Mode != "auto" && cfg.Graph.Mode != "off" && cfg.Graph.Mode != "required" {
		return Config{}, fmt.Errorf("invalid graph.mode %q (want auto, off, or required)", cfg.Graph.Mode)
	}
	if cfg.Graph.Provider != "codegraph" {
		return Config{}, fmt.Errorf("invalid graph.provider %q (want codegraph)", cfg.Graph.Provider)
	}
	if cfg.Minimalism.Mode != "off" && cfg.Minimalism.Mode != "lite" && cfg.Minimalism.Mode != "full" && cfg.Minimalism.Mode != "ultra" {
		return Config{}, fmt.Errorf("invalid minimalism.mode %q (want off, lite, full, or ultra)", cfg.Minimalism.Mode)
	}
	if cfg.Spend.DailyCapUSD < 0 {
		return Config{}, fmt.Errorf("invalid spend.daily_cap_usd %v (want >= 0, 0 = unlimited)", cfg.Spend.DailyCapUSD)
	}
	for _, q := range cfg.Quotas {
		if q.EstimatedLimit < 0 {
			return Config{}, fmt.Errorf("invalid quota estimated_limit %v for backend %q (want >= 0)", q.EstimatedLimit, q.Backend)
		}
		if q.Confidence < 0 || q.Confidence > 1 {
			return Config{}, fmt.Errorf("invalid quota confidence %v for backend %q (want 0..1)", q.Confidence, q.Backend)
		}
		if q.WindowType != "" && q.WindowType != "5h" && q.WindowType != "daily" && q.WindowType != "weekly" && q.WindowType != "monthly" {
			return Config{}, fmt.Errorf("invalid quota window_type %q (want 5h, daily, weekly, or monthly)", q.WindowType)
		}
	}
	for _, rule := range cfg.PolicyRules {
		if err := rule.Validate(); err != nil {
			return Config{}, fmt.Errorf("invalid policy_rules: %w", err)
		}
	}
	return cfg, nil
}

func Current() Config {
	cfg, err := Load()
	if err != nil {
		cfg = BuiltIn()
		applyEnv(&cfg)
		clean(&cfg)
	}
	return cfg
}

func merge(dst *Config, src Config) {
	if src.ProtectedManifest != "" {
		dst.ProtectedManifest = src.ProtectedManifest
	}
	if src.SnapshotDir != "" {
		dst.SnapshotDir = src.SnapshotDir
	}
	if src.SnapshotRoots != nil {
		dst.SnapshotRoots = append([]string(nil), src.SnapshotRoots...)
	}
	if src.LedgerDir != "" {
		dst.LedgerDir = src.LedgerDir
	}
	for name, backend := range src.Backends {
		// Field-by-field, not a wholesale replace: an operator declaring only
		// `backends.codex.vision: true` (no bin override) must not silently
		// lose that declaration just because Bin is blank.
		existing := dst.Backends[name]
		if backend.Bin != "" {
			existing.Bin = backend.Bin
		}
		if backend.Vision {
			existing.Vision = backend.Vision
		}
		if backend.ToolCalling {
			existing.ToolCalling = backend.ToolCalling
		}
		if backend.LocalOnly {
			existing.LocalOnly = backend.LocalOnly
		}
		if backend.ContextTokens > 0 {
			existing.ContextTokens = backend.ContextTokens
		}
		if backend.OutputTokens > 0 {
			existing.OutputTokens = backend.OutputTokens
		}
		dst.Backends[name] = existing
	}
	if src.RTK.Mode != "" {
		dst.RTK.Mode = src.RTK.Mode
	}
	if src.RTK.Bin != "" {
		dst.RTK.Bin = src.RTK.Bin
	}
	if src.Graph.Mode != "" {
		dst.Graph.Mode = src.Graph.Mode
	}
	if src.Graph.Provider != "" {
		dst.Graph.Provider = src.Graph.Provider
	}
	if src.Graph.Bin != "" {
		dst.Graph.Bin = src.Graph.Bin
	}
	if src.Minimalism.Mode != "" {
		dst.Minimalism.Mode = src.Minimalism.Mode
	}
	if src.Spend.DailyCapUSD != 0 {
		dst.Spend.DailyCapUSD = src.Spend.DailyCapUSD
	}
	if src.Spend.HaltFile != "" {
		dst.Spend.HaltFile = src.Spend.HaltFile
	}
	if src.Quotas != nil {
		dst.Quotas = append([]QuotaWindow(nil), src.Quotas...)
	}
	if src.PolicyRules != nil {
		dst.PolicyRules = append([]policy.ConditionRule(nil), src.PolicyRules...)
	}
	if src.Doctrine.RequireCleanup {
		dst.Doctrine.RequireCleanup = true
	}
	if src.Defaults.Agent != "" {
		dst.Defaults.Agent = src.Defaults.Agent
	}
	if src.Defaults.MaxMinutes > 0 {
		dst.Defaults.MaxMinutes = src.Defaults.MaxMinutes
	}
	if src.Assay.Repo != "" {
		dst.Assay.Repo = src.Assay.Repo
	}
	if src.Assay.Python != "" {
		dst.Assay.Python = src.Assay.Python
	}
	if src.Assay.TimeoutSeconds > 0 {
		dst.Assay.TimeoutSeconds = src.Assay.TimeoutSeconds
	}
	if src.Containment.OverridePublicKey != "" {
		dst.Containment.OverridePublicKey = src.Containment.OverridePublicKey
	}
}

func applyEnv(cfg *Config) {
	if value := firstEnv("GOV_PROTECTED_PATHS", "GOV_PROTECTED_MANIFEST"); value != "" {
		cfg.ProtectedManifest = value
	} else if state := Env("CLAUDE_HARNESS_STATE"); state != "" {
		cfg.ProtectedManifest = filepath.Join(state, "protected_paths.txt")
	}
	if value := firstEnv("GOV_SNAPSHOT_DIR", "HARNESS_SNAPSHOT_DIR"); value != "" {
		cfg.SnapshotDir = value
	}
	if value := Env("GOV_SNAPSHOT_ROOTS"); value != "" {
		cfg.SnapshotRoots = splitPathList(value)
	}
	if value := firstEnv("GOV_LEDGER_DIR", "GOV_HOME", "GOVERNATOR_HOME"); value != "" {
		cfg.LedgerDir = value
		// Keep the still-default halt file next to the ledger it guards when
		// the home is overridden: the spend cap reads the ledger under this
		// home, so consulting ~/.governator/HALT from a GOV_HOME-isolated run
		// (tests especially) would let a real operator halt bleed into every
		// isolated environment. An explicit spend.halt_file in the config
		// file, or GOV_SPEND_HALT_FILE (applied below), still wins.
		if cfg.Spend.HaltFile == filepath.Join(HomeDir(), ".governator", "HALT") {
			cfg.Spend.HaltFile = filepath.Join(value, "HALT")
		}
	}
	for name, backend := range cfg.Backends {
		envName := "GOV_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_BIN"
		if name == "claude-code" {
			envName = "GOV_CLAUDE_BIN"
		}
		if value := Env(envName); value != "" {
			backend.Bin = value
			cfg.Backends[name] = backend
		}
	}
	if value := Env("GOV_RTK_MODE"); value != "" {
		cfg.RTK.Mode = value
	}
	if value := Env("GOV_RTK_BIN"); value != "" {
		cfg.RTK.Bin = value
	}
	if value := Env("GOV_GRAPH_MODE"); value != "" {
		cfg.Graph.Mode = value
	}
	if value := Env("GOV_GRAPH_PROVIDER"); value != "" {
		cfg.Graph.Provider = value
	}
	if value := Env("GOV_GRAPH_BIN"); value != "" {
		cfg.Graph.Bin = value
	}
	if value := Env("GOV_MINIMALISM_MODE"); value != "" {
		cfg.Minimalism.Mode = value
	}
	if value := Env("GOV_SPEND_DAILY_CAP_USD"); value != "" {
		if cap, err := strconv.ParseFloat(value, 64); err == nil && cap >= 0 {
			cfg.Spend.DailyCapUSD = cap
		}
	}
	if value := Env("GOV_SPEND_HALT_FILE"); value != "" {
		cfg.Spend.HaltFile = value
	}
	if value := Env("GOV_DOCTRINE_REQUIRE_CLEANUP"); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			cfg.Doctrine.RequireCleanup = b
		}
	}
	if value := Env("GOV_DEFAULT_AGENT"); value != "" {
		cfg.Defaults.Agent = value
	}
	if value := Env("GOV_DEFAULT_MAX_MINUTES"); value != "" {
		if minutes, err := strconv.Atoi(value); err == nil && minutes > 0 {
			cfg.Defaults.MaxMinutes = minutes
		}
	}
	if value := Env("GOV_ASSAY_REPO"); value != "" {
		cfg.Assay.Repo = value
	}
	if value := Env("GOV_ASSAY_PYTHON"); value != "" {
		cfg.Assay.Python = value
	}
	if value := Env("GOV_ASSAY_TIMEOUT_SECONDS"); value != "" {
		if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
			cfg.Assay.TimeoutSeconds = seconds
		}
	}
	if value := Env("GOV_CONTAINMENT_OVERRIDE_PUBLIC_KEY"); value != "" {
		cfg.Containment.OverridePublicKey = value
	}
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := Env(name); value != "" {
			return value
		}
	}
	return ""
}

func splitPathList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, string(os.PathListSeparator)) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func clean(cfg *Config) {
	cfg.RTK.Mode = strings.ToLower(strings.TrimSpace(cfg.RTK.Mode))
	cfg.RTK.Bin = strings.TrimSpace(cfg.RTK.Bin)
	cfg.Graph.Mode = strings.ToLower(strings.TrimSpace(cfg.Graph.Mode))
	cfg.Graph.Provider = strings.ToLower(strings.TrimSpace(cfg.Graph.Provider))
	cfg.Graph.Bin = strings.TrimSpace(cfg.Graph.Bin)
	cfg.Minimalism.Mode = strings.ToLower(strings.TrimSpace(cfg.Minimalism.Mode))
	cfg.Spend.HaltFile = expand(cfg.Spend.HaltFile)
	for i := range cfg.Quotas {
		cfg.Quotas[i].Backend = strings.ToLower(strings.TrimSpace(cfg.Quotas[i].Backend))
		cfg.Quotas[i].Account = strings.ToLower(strings.TrimSpace(cfg.Quotas[i].Account))
		cfg.Quotas[i].WindowType = strings.ToLower(strings.TrimSpace(cfg.Quotas[i].WindowType))
	}
	cfg.ProtectedManifest = expand(cfg.ProtectedManifest)
	cfg.SnapshotDir = expand(cfg.SnapshotDir)
	cfg.LedgerDir = expand(cfg.LedgerDir)
	cfg.Assay.Python = strings.TrimSpace(cfg.Assay.Python)
	if strings.TrimSpace(cfg.Assay.Repo) != "" {
		cfg.Assay.Repo = expand(cfg.Assay.Repo)
	}
	for i := range cfg.SnapshotRoots {
		cfg.SnapshotRoots[i] = expand(cfg.SnapshotRoots[i])
	}
}

func expand(path string) string {
	if path == "~" {
		return HomeDir()
	}
	if strings.HasPrefix(path, "~/") {
		path = filepath.Join(HomeDir(), path[2:])
	}
	return filepath.Clean(os.ExpandEnv(path))
}

func BackendBin(name string) string {
	cfg := Current()
	if backend, ok := cfg.Backends[name]; ok && backend.Bin != "" {
		return backend.Bin
	}
	return name
}
