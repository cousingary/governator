package containment

import (
	"testing"

	"github.com/cousingary/governator/internal/contracts"
)

func authorityContract() contracts.Contract {
	return contracts.Contract{
		JobID: "auth-1", JobType: "batch_worker", Agent: "codex",
		Mode: contracts.ModeBatchWorker, Runner: "local", OnViolation: "quarantine",
		Budget: contracts.Budget{MaxMinutes: 5, MaxTokens: 1000},
	}
}

// TestRequiresHostContainmentIsAuthorityDerived covers the seven permanent
// RB2 authority shapes. The selection decision is tested independently of
// host kernel availability; black-box corpus cases cover fail-before-launch.
func TestRequiresHostContainmentIsAuthorityDerived(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*contracts.Contract)
	}{
		{"empty risk + explicit network prohibition", func(c *contracts.Contract) {
			c.Forbidden.Behaviors = []string{"network"}
		}},
		{"low risk + external-write authority", func(c *contracts.Contract) {
			c.RiskClass = "low"
			c.Allowed.Write = []string{"output/**"}
		}},
		{"low risk + interpreter/host-secret-read authority", func(c *contracts.Contract) {
			c.RiskClass = "low"
			c.Allowed.Execute = []string{"python3 validator.py"}
		}},
		{"low risk + Unix-socket-capable helper authority", func(c *contracts.Contract) {
			c.RiskClass = "low"
			c.Success.Validators = []string{"socket-helper"}
		}},
		{"low risk + loopback-capable helper authority", func(c *contracts.Contract) {
			c.RiskClass = "low"
			c.Cleanup = &contracts.Cleanup{Validators: []string{"loopback-helper"}}
		}},
		{"legacy no-risk + mergeable output", func(c *contracts.Contract) {
			c.Produces = []contracts.ArtifactSpec{{Name: "report", Path: ".governator/artifacts/report", MaxBytes: 1}}
		}},
		{"risk high-to-low, authority unchanged", func(c *contracts.Contract) {
			c.RiskClass = "low"
			c.Allowed.Write = []string{"output/**"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := authorityContract()
			tc.mutate(&c)
			if !RequiresHostContainment(c, true) {
				t.Fatal("authority-bearing local contract did not require host containment")
			}
		})
	}
}

func TestNetworkForbiddenRequiresContainmentAtEveryRiskTier(t *testing.T) {
	for _, risk := range []string{"high", "medium", "low", ""} {
		c := authorityContract()
		c.RiskClass = risk
		c.Forbidden.Behaviors = []string{"network"}
		if !RequiresHostContainment(c, true) {
			t.Fatalf("risk_class %q + network forbidden did not require containment", risk)
		}
	}
}

func TestRiskLabelCannotRemoveBaselineContainment(t *testing.T) {
	base := authorityContract()
	base.Allowed.Write = []string{"output/**"}
	for _, risk := range []string{"high", "medium", "low", ""} {
		c := base
		c.RiskClass = risk
		if !RequiresHostContainment(c, true) {
			t.Fatalf("risk_class %q removed authority-required containment", risk)
		}
	}
}

func TestPolicyOffCannotDisableExplicitNetworkBoundary(t *testing.T) {
	c := authorityContract()
	c.Forbidden.Behaviors = []string{"network"}
	if !RequiresHostContainment(c, false) {
		t.Fatal("explicit no-network must remain externally enforced when effectful tiering is off")
	}
}

func TestDockerDoesNotInheritLocalAuthorityBaseline(t *testing.T) {
	c := authorityContract()
	c.Runner = "docker"
	c.Docker = &contracts.DockerRunnerConfig{Image: "agent:latest"}
	c.Allowed.Write = []string{"output/**"}
	if RequiresHostContainment(c, true) {
		t.Fatal("low/unlabelled Docker job must use its container boundary, not the local-run baseline")
	}
	c.RiskClass = "high"
	if !RequiresHostContainment(c, true) {
		t.Fatal("high risk must strengthen containment for Docker too")
	}
}
