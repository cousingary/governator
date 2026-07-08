package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Backend struct {
	Bin string `yaml:"bin"`
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

type Defaults struct {
	Agent      string `yaml:"agent"`
	MaxMinutes int    `yaml:"max_minutes"`
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
	Defaults          Defaults           `yaml:"defaults"`
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
		Defaults:   Defaults{Agent: "claude-code", MaxMinutes: 30},
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
		if backend.Bin != "" {
			dst.Backends[name] = backend
		}
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
	if src.Defaults.Agent != "" {
		dst.Defaults.Agent = src.Defaults.Agent
	}
	if src.Defaults.MaxMinutes > 0 {
		dst.Defaults.MaxMinutes = src.Defaults.MaxMinutes
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
	if value := Env("GOV_DEFAULT_AGENT"); value != "" {
		cfg.Defaults.Agent = value
	}
	if value := Env("GOV_DEFAULT_MAX_MINUTES"); value != "" {
		if minutes, err := strconv.Atoi(value); err == nil && minutes > 0 {
			cfg.Defaults.MaxMinutes = minutes
		}
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
	cfg.ProtectedManifest = expand(cfg.ProtectedManifest)
	cfg.SnapshotDir = expand(cfg.SnapshotDir)
	cfg.LedgerDir = expand(cfg.LedgerDir)
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
