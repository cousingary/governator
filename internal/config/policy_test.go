package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/policy"
)

func TestLoadPolicyRulesFromConfigFile(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "custom.yaml")
	if err := os.WriteFile(path, []byte(`policy_rules:
  - id: network-enablement
    when:
      - field: network_enabled
        op: eq
        value: "true"
    verdict: ASK
    reason: network access needs operator review
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", path)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PolicyRules) != 1 || cfg.PolicyRules[0].ID != "network-enablement" {
		t.Fatalf("expected 1 policy rule loaded from config, got %+v", cfg.PolicyRules)
	}
	if cfg.PolicyRules[0].Verdict != policy.VerdictAsk {
		t.Fatalf("expected verdict ASK, got %s", cfg.PolicyRules[0].Verdict)
	}
}

func TestLoadPolicyRulesEmptyByDefault(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(home, "missing.yaml"))

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PolicyRules != nil {
		t.Fatalf("expected no policy rules with no config file, got %+v", cfg.PolicyRules)
	}
}

func TestLoadRejectsInvalidPolicyRule(t *testing.T) {
	cleanEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, "custom.yaml")
	if err := os.WriteFile(path, []byte(`policy_rules:
  - id: bad-rule
    when: []
    verdict: ASK
    reason: x
`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_CONFIG", path)

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "invalid policy_rules") {
		t.Fatalf("expected Load to reject an invalid policy rule, got %v", err)
	}
}
