package panel

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
)

func TestGeneratePanelPlanIsValid(t *testing.T) {
	plan, err := GeneratePlan(Options{Root: "/repo", OutDir: "jobs/panel", Envelope: []string{"internal/**"}, Count: 3, Agent: "claude-code", MaxTotalTokens: 90000, Intent: "review architecture"})
	if err != nil {
		t.Fatal(err)
	}
	levels, err := contracts.ValidatePlanManifest(&plan, "/repo", []string{"internal/**"}, 90000)
	if err != nil {
		t.Fatalf("generated panel plan should validate: %v", err)
	}
	if len(levels) != 3 {
		t.Fatalf("expected members, comparison, judge levels; got %d", len(levels))
	}
	if len(levels[0]) != 3 || levels[1][0].JobID != "panel-compare" || levels[2][0].JobID != "panel-judge" {
		t.Fatalf("unexpected levels: %+v", levels)
	}
}

func TestGeneratePanelPlanDefaultsQuorumAndDiversity(t *testing.T) {
	plan, err := GeneratePlan(Options{Root: "/repo", OutDir: "jobs/panel", Envelope: []string{"internal/**"}, Count: 3, Agent: "claude-code", MaxTotalTokens: 90000, Intent: "review architecture"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Panel.EffectiveMinSuccess() != 3 {
		t.Fatalf("expected default min_success == member count, got %d", plan.Panel.EffectiveMinSuccess())
	}
	d := plan.Panel.EffectiveDiversity()
	if d.GroupBy != "backend" || d.MinUnique != 3 {
		t.Fatalf("expected default diversity backend/3, got %+v", d)
	}
	// 120s default member timeout rounds up to 2 minutes on the member job's
	// own budget; comparison/judge keep the pre-Phase-2 10-minute default.
	for _, job := range plan.Jobs {
		switch job.JobID {
		case "panel-member-1", "panel-member-2", "panel-member-3":
			if job.Budget.MaxMinutes != 2 {
				t.Fatalf("member %s: expected max_minutes=2, got %d", job.JobID, job.Budget.MaxMinutes)
			}
		case "panel-compare", "panel-judge":
			if job.Budget.MaxMinutes != 10 {
				t.Fatalf("%s: expected max_minutes=10, got %d", job.JobID, job.Budget.MaxMinutes)
			}
		}
	}
}

func TestGeneratePanelPlanHonorsExplicitQuorumAndDiversity(t *testing.T) {
	plan, err := GeneratePlan(Options{
		Root: "/repo", OutDir: "jobs/panel", Envelope: []string{"internal/**"}, Count: 3, Agent: "claude-code", MaxTotalTokens: 90000, Intent: "review architecture",
		MinSuccess: 2, MemberTimeoutSeconds: 90, HardTimeoutSeconds: 200, DiversityKey: "model_family", DiversityMinUnique: 2, DiversityFallbackKey: "backend",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Panel.EffectiveMinSuccess() != 2 {
		t.Fatalf("expected min_success=2, got %d", plan.Panel.EffectiveMinSuccess())
	}
	if plan.Panel.EffectiveHardTimeoutSeconds() != 200 {
		t.Fatalf("expected hard_timeout_seconds=200, got %d", plan.Panel.EffectiveHardTimeoutSeconds())
	}
	d := plan.Panel.EffectiveDiversity()
	if d.GroupBy != "model_family" || d.MinUnique != 2 || d.FallbackGroupBy != "backend" {
		t.Fatalf("expected model_family/2/backend, got %+v", d)
	}
	for _, job := range plan.Jobs {
		if strings.HasPrefix(job.JobID, "panel-member-") && job.Budget.MaxMinutes != 2 {
			t.Fatalf("%s: expected 90s to round up to 2 minutes, got %d", job.JobID, job.Budget.MaxMinutes)
		}
	}
	if _, err := contracts.ValidatePlanManifest(&plan, "/repo", []string{"internal/**"}, 90000); err != nil {
		t.Fatalf("generated panel plan with explicit quorum/diversity should validate: %v", err)
	}
}

func TestCompareArtifactsAnonymizesIdentity(t *testing.T) {
	comparison, err := CompareArtifacts([]ArtifactInput{
		{Name: "b", Data: []byte(`{"agent":"codex","model":"x","summary":"same","finding":"beta"}`)},
		{Name: "a", Data: []byte(`{"agent":"claude-code","provider":"anthropic","summary":"same","finding":"alpha"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(comparison)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, forbidden := range []string{"claude-code", "codex", "anthropic", "\"model\"", "\"agent\"", "\"provider\""} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("comparison leaked identity %q: %s", forbidden, text)
		}
	}
	if comparison.Participants[0].Label != "panelist_1" || comparison.Participants[0].SourceName != "a" {
		t.Fatalf("expected deterministic anonymous label order, got %+v", comparison.Participants)
	}
	if len(comparison.DifferingPaths) == 0 {
		t.Fatal("expected differing paths to be reported")
	}
}
