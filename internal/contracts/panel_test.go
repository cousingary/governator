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

func TestValidatePanelRejectsMinSuccessBelowTwo(t *testing.T) {
	root := "/repo"
	plan := validPanelPlan(root)
	plan.Panel.MinSuccess = 1

	_, err := ValidatePlanManifest(&plan, root, []string{"internal/**"}, 50000)
	if err == nil {
		t.Fatal("expected panel validation to reject min_success below 2")
	}
	if !strings.Contains(err.Error(), "panel.min_success") {
		t.Fatalf("expected panel.min_success error, got %v", err)
	}
}

func TestValidatePanelRejectsMinSuccessAboveMemberCount(t *testing.T) {
	root := "/repo"
	plan := validPanelPlan(root)
	plan.Panel.MinSuccess = 3 // only 2 members declared

	_, err := ValidatePlanManifest(&plan, root, []string{"internal/**"}, 50000)
	if err == nil {
		t.Fatal("expected panel validation to reject min_success above member count")
	}
	if !strings.Contains(err.Error(), "panel.min_success") {
		t.Fatalf("expected panel.min_success error, got %v", err)
	}
}

func TestValidatePanelRejectsHardTimeoutBelowMemberTimeout(t *testing.T) {
	root := "/repo"
	plan := validPanelPlan(root)
	plan.Panel.MemberTimeoutSeconds = 200
	plan.Panel.HardTimeoutSeconds = 100

	_, err := ValidatePlanManifest(&plan, root, []string{"internal/**"}, 50000)
	if err == nil {
		t.Fatal("expected panel validation to reject hard_timeout_seconds below member_timeout_seconds")
	}
	if !strings.Contains(err.Error(), "panel.hard_timeout_seconds") {
		t.Fatalf("expected panel.hard_timeout_seconds error, got %v", err)
	}
}

func TestValidatePanelRejectsUnknownDiversityKey(t *testing.T) {
	root := "/repo"
	plan := validPanelPlan(root)
	plan.Panel.Diversity = &PanelDiversity{GroupBy: "vendor"}

	_, err := ValidatePlanManifest(&plan, root, []string{"internal/**"}, 50000)
	if err == nil {
		t.Fatal("expected panel validation to reject an unknown diversity key")
	}
	if !strings.Contains(err.Error(), "panel.diversity.group_by") {
		t.Fatalf("expected panel.diversity.group_by error, got %v", err)
	}
}

func TestValidatePanelRejectsFallbackKeyEqualToKey(t *testing.T) {
	root := "/repo"
	plan := validPanelPlan(root)
	plan.Panel.Diversity = &PanelDiversity{GroupBy: "backend", FallbackGroupBy: "backend"}

	_, err := ValidatePlanManifest(&plan, root, []string{"internal/**"}, 50000)
	if err == nil {
		t.Fatal("expected panel validation to reject fallback_key equal to key")
	}
	if !strings.Contains(err.Error(), "panel.diversity.fallback_group_by") {
		t.Fatalf("expected panel.diversity.fallback_group_by error, got %v", err)
	}
}

func TestPanelSpecEffectiveDefaults(t *testing.T) {
	spec := PanelSpec{Members: []string{"a", "b", "c"}}
	if got := spec.EffectiveMinSuccess(); got != 3 {
		t.Fatalf("EffectiveMinSuccess: want 3, got %d", got)
	}
	if got := spec.EffectiveMemberTimeoutSeconds(); got != 120 {
		t.Fatalf("EffectiveMemberTimeoutSeconds: want 120, got %d", got)
	}
	if got := spec.EffectiveHardTimeoutSeconds(); got != 180 {
		t.Fatalf("EffectiveHardTimeoutSeconds: want 180, got %d", got)
	}
	d := spec.EffectiveDiversity()
	if d.GroupBy != "backend" || d.MinUnique != 3 || d.FallbackGroupBy != "" {
		t.Fatalf("EffectiveDiversity: want backend/3/'', got %+v", d)
	}

	spec.MinSuccess = 2
	spec.Diversity = &PanelDiversity{GroupBy: "model_family"}
	if got := spec.EffectiveMinSuccess(); got != 2 {
		t.Fatalf("EffectiveMinSuccess override: want 2, got %d", got)
	}
	d = spec.EffectiveDiversity()
	if d.GroupBy != "model_family" || d.MinUnique != 3 {
		t.Fatalf("EffectiveDiversity override: want model_family/3, got %+v", d)
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
