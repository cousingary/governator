package contracts

import (
	"strings"
	"testing"
)

func panelArtifact(name string) ArtifactSpec {
	return ArtifactSpec{Name: name, Path: ".governator/artifacts/" + name + ".json", Schema: "schemas/panel.schema.json", MaxBytes: 1024}
}

func validPanelPlan(root string) Plan {
	a := planJob(root, "panel-member-a")
	a.Mode = ModeArchitect
	a.Allowed.Write = nil
	a.Preflight.IntendedWrites = nil
	a.Success.RequiredFiles = nil
	a.Produces = []ArtifactSpec{panelArtifact("panel_a")}
	b := planJob(root, "panel-member-b")
	b.Mode = ModeVerifier
	b.Allowed.Write = nil
	b.Preflight.IntendedWrites = nil
	b.Success.RequiredFiles = nil
	b.Produces = []ArtifactSpec{panelArtifact("panel_b")}
	cmp := planJob(root, "panel-compare")
	cmp.Mode = ModeVerifier
	cmp.Allowed.Write = nil
	cmp.Preflight.IntendedWrites = nil
	cmp.Success.RequiredFiles = nil
	cmp.DependsOn = []string{"panel-member-a", "panel-member-b"}
	cmp.Consumes = []string{"panel_a", "panel_b"}
	cmp.Produces = []ArtifactSpec{panelArtifact("panel_comparison")}
	judge := planJob(root, "panel-judge")
	judge.Mode = ModeArchitect
	judge.Allowed.Write = nil
	judge.Preflight.IntendedWrites = nil
	judge.Success.RequiredFiles = nil
	judge.DependsOn = []string{"panel-member-a", "panel-member-b", "panel-compare"}
	judge.Consumes = []string{"panel_comparison"}
	judge.Produces = []ArtifactSpec{panelArtifact("panel_judgment")}
	return Plan{Panel: &PanelSpec{ID: "panel", Members: []string{"panel-member-a", "panel-member-b"}, ComparisonJob: "panel-compare", Judge: "panel-judge"}, Jobs: []Contract{a, b, cmp, judge}}
}

func TestValidatePanelRejectsWriteModeMember(t *testing.T) {
	root := "/repo"
	plan := validPanelPlan(root)
	plan.Jobs[0].Mode = ModeSurgeon
	plan.Jobs[0].Allowed.Write = []string{"internal/**"}
	plan.Jobs[0].Preflight.IntendedWrites = []string{"internal/**"}
	plan.Jobs[0].Success.RequiredFiles = []string{"internal/x.go"}

	_, err := ValidatePlanManifest(&plan, root, []string{"internal/**"}, 50000)
	if err == nil {
		t.Fatal("expected panel validation to reject write-capable member mode")
	}
	if !strings.Contains(err.Error(), "panel members must use read-only modes") {
		t.Fatalf("expected mode-specific panel error, got %v", err)
	}
}

func TestValidatePanelRejectsJudgeThatCanAutoMerge(t *testing.T) {
	root := "/repo"
	plan := validPanelPlan(root)
	plan.Jobs[3].Mode = ModeSurgeon
	plan.Jobs[3].Allowed.Write = []string{"internal/**"}
	plan.Jobs[3].Preflight.IntendedWrites = []string{"internal/**"}
	plan.Jobs[3].Success.RequiredFiles = []string{"internal/x.go"}

	_, err := ValidatePlanManifest(&plan, root, []string{"internal/**"}, 50000)
	if err == nil {
		t.Fatal("expected panel validation to reject write-capable judge")
	}
	if !strings.Contains(err.Error(), "advisory and cannot auto-merge") {
		t.Fatalf("expected advisory judge error, got %v", err)
	}
}

func TestValidatePanelRejectsJudgeConsumingRawMemberArtifact(t *testing.T) {
	root := "/repo"
	plan := validPanelPlan(root)
	plan.Jobs[3].Consumes = []string{"panel_a", "panel_comparison"}

	_, err := ValidatePlanManifest(&plan, root, []string{"internal/**"}, 50000)
	if err == nil {
		t.Fatal("expected panel validation to reject raw member artifact consumption by judge")
	}
	if !strings.Contains(err.Error(), "must not consume raw member artifact") {
		t.Fatalf("expected raw-member anonymization error, got %v", err)
	}
}
