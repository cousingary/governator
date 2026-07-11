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
