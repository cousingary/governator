package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/router"
)

func panelMember(id string) contracts.Contract {
	return contracts.Contract{JobID: id, JobType: "panel_analysis", Agent: contracts.AgentAuto, Mode: contracts.ModeArchitect}
}

func allPresentBinary(string) bool { return true }

func TestResolvePanelBackendsAssignsDistinctBackends(t *testing.T) {
	db, err := observability.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	jobs := []contracts.Contract{panelMember("m1"), panelMember("m2"), panelMember("m3")}
	spec := contracts.PanelSpec{ID: "panel", Members: []string{"m1", "m2", "m3"}, ComparisonJob: "cmp", Judge: "judge"}

	out, report, err := resolvePanelBackends(db, router.Router{Binary: allPresentBinary}, jobs, spec)
	if err != nil {
		t.Fatalf("resolvePanelBackends: %v", err)
	}
	if report.Degraded {
		t.Fatalf("expected no degradation with 5 registered backends for 3 members, got reasons %v", report.DegradedReasons)
	}
	seen := map[string]bool{}
	for _, job := range out {
		if job.Agent == contracts.AgentAuto {
			t.Fatalf("member %s: expected a concrete agent, still auto", job.JobID)
		}
		seen[job.Agent] = true
	}
	if len(seen) != 3 {
		t.Fatalf("expected 3 distinct backends, got %d: %v", len(seen), seen)
	}
	if report.DiversityUnique != 3 {
		t.Fatalf("expected report.DiversityUnique=3, got %d", report.DiversityUnique)
	}
	if len(report.Diversity) != 3 {
		t.Fatalf("expected 3 recorded routing decisions, got %d", len(report.Diversity))
	}
}

func TestResolvePanelBackendsDegradesWhenPoolTooSmall(t *testing.T) {
	db, err := observability.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Only two backends "installed": claude-code and codex. Three members
	// still need routing, so the third can't get a fresh backend.
	only2 := func(name string) bool { return name == "claude-code" || name == "codex" }
	jobs := []contracts.Contract{panelMember("m1"), panelMember("m2"), panelMember("m3")}
	spec := contracts.PanelSpec{ID: "panel", Members: []string{"m1", "m2", "m3"}, ComparisonJob: "cmp", Judge: "judge"}

	out, report, err := resolvePanelBackends(db, router.Router{Binary: only2}, jobs, spec)
	if err != nil {
		t.Fatalf("resolvePanelBackends: %v", err)
	}
	if !report.Degraded {
		t.Fatal("expected degraded status when only 2 backends are available for 3 members")
	}
	foundInsufficientDiversity := false
	for _, reason := range report.DegradedReasons {
		if strings.Contains(reason, "insufficient_diversity") {
			foundInsufficientDiversity = true
		}
	}
	if !foundInsufficientDiversity {
		t.Fatalf("expected an insufficient_diversity reason, got %v", report.DegradedReasons)
	}
	if report.DiversityUnique != 2 {
		t.Fatalf("expected report.DiversityUnique=2, got %d", report.DiversityUnique)
	}
	// Every member must still have been assigned a real backend — diversity
	// degrades a panel, it never fails one closed.
	for _, job := range out {
		if job.Agent == contracts.AgentAuto || (job.Agent != "claude-code" && job.Agent != "codex") {
			t.Fatalf("member %s: expected a reused backend from {claude-code,codex}, got %q", job.JobID, job.Agent)
		}
	}
}

func TestResolvePanelBackendsExplicitAgentCountsTowardDiversity(t *testing.T) {
	db, err := observability.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m1 := panelMember("m1")
	m1.Agent = "claude-code" // operator override: never re-routed
	jobs := []contracts.Contract{m1, panelMember("m2")}
	spec := contracts.PanelSpec{ID: "panel", Members: []string{"m1", "m2"}, ComparisonJob: "cmp", Judge: "judge"}

	out, report, err := resolvePanelBackends(db, router.Router{Binary: allPresentBinary}, jobs, spec)
	if err != nil {
		t.Fatalf("resolvePanelBackends: %v", err)
	}
	if out[0].Agent != "claude-code" {
		t.Fatalf("expected explicit agent left untouched, got %q", out[0].Agent)
	}
	if out[1].Agent == "claude-code" {
		t.Fatalf("expected m2 excluded from m1's explicit backend, got %q", out[1].Agent)
	}
	if len(report.Diversity) != 1 {
		t.Fatalf("expected exactly one routed decision (m2 only), got %d", len(report.Diversity))
	}
	if report.Degraded {
		t.Fatalf("expected no degradation, got %v", report.DegradedReasons)
	}
}

func TestAdjustComparisonConsumesDropsStragglerArtifact(t *testing.T) {
	spec := contracts.PanelSpec{ID: "panel", Members: []string{"m1", "m2", "m3"}, ComparisonJob: "cmp", Judge: "judge"}
	cmp := contracts.Contract{
		JobID: "cmp", Consumes: []string{"art1", "art2", "art3"},
		ArtifactSources: map[string]string{"art1": "m1", "art2": "m2", "art3": "m3"},
	}
	judge := contracts.Contract{JobID: "judge", Consumes: []string{"panel_comparison"}, ArtifactSources: map[string]string{"panel_comparison": "cmp"}}
	tail := [][]contracts.Contract{{cmp}, {judge}}

	out, err := adjustComparisonConsumes(tail, spec, []string{"m1", "m2"})
	if err != nil {
		t.Fatal(err)
	}
	gotCmp := out[0][0]
	if len(gotCmp.Consumes) != 2 || !containsString(gotCmp.Consumes, "art1") || !containsString(gotCmp.Consumes, "art2") {
		t.Fatalf("expected comparison to consume only art1,art2 got %v", gotCmp.Consumes)
	}
	if _, ok := gotCmp.ArtifactSources["art3"]; ok {
		t.Fatalf("expected art3 dropped from ArtifactSources, got %v", gotCmp.ArtifactSources)
	}
	gotJudge := out[1][0]
	if len(gotJudge.Consumes) != 1 || gotJudge.Consumes[0] != "panel_comparison" {
		t.Fatalf("expected judge's consumes untouched, got %v", gotJudge.Consumes)
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// panelExecContract builds a minimal, Contract.Validate-passing read-only
// (or verifier) job for real end-to-end RunPanel execution — the same
// shape internal/panel.readOnlyJob produces, hand-built here so the test can
// wire ArtifactSources directly instead of round-tripping through
// contracts.ValidatePlan (RunPanel's real caller, gov batch run, does that
// step before calling RunPanel; this test starts from its output).
func panelExecContract(root, id, jobType, agent string, produces []contracts.ArtifactSpec, consumes []string, dependsOn []string, artifactSources map[string]string) contracts.Contract {
	validators := []string{"test -f " + produces[0].Path}
	return contracts.Contract{
		JobID: id, JobType: jobType, Agent: agent, Mode: contracts.ModeArchitect,
		Workspace:     contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:       contracts.Permissions{Read: []string{"**"}, Write: []string{}, Execute: []string{"test -f *"}},
		Forbidden:     contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}, Behaviors: []string{"network"}},
		Budget:        contracts.Budget{MaxMinutes: 5, MaxCommands: 5, MaxFilesChanged: 1, MaxLinesChanged: 1, MaxNewFiles: 1, MaxTokens: 1000},
		TelemetryMode: "estimated",
		Preflight:     contracts.Preflight{IntendedWrites: []string{}},
		Success:       contracts.Success{RequiredFiles: []string{}, Validators: validators},
		Produces:      produces, Consumes: consumes, DependsOn: dependsOn, ArtifactSources: artifactSources,
		RiskClass: "low", OnViolation: "quarantine",
	}
}

func panelFakeBackend(t *testing.T, body string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fake-panel-backend")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nset -eu\n"+body), 0755); err != nil {
		t.Fatal(err)
	}
	return bin
}

const panelFakeResult = `printf '{"status":"complete","files_changed":[],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.01}\n'
`

// panelExecFixture wires the prompt/env plumbing five panel-exec tests
// share: one prompt file per (agent, mode) pair actually used, and a
// per-backend fake binary via GOV_<BACKEND>_BIN.
func panelExecFixture(t *testing.T, bins map[string]string, modes map[string]string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	promptRoot := t.TempDir()
	for agent, mode := range modes {
		writePrompt(t, promptRoot, agent, mode)
	}
	t.Setenv("GOV_PROMPTS", promptRoot)
	for agent, bin := range bins {
		envName := "GOV_" + strings.ToUpper(strings.ReplaceAll(agent, "-", "_")) + "_BIN"
		if agent == "claude-code" {
			envName = "GOV_CLAUDE_BIN"
		}
		t.Setenv(envName, bin)
	}
	return home
}

// TestRunPanelQuorumProceedsWithoutStraggler is the Phase 2 quorum
// acceptance test: min_success=2 on a 3-member panel with a 1s hard
// timeout. m1 (claude-code) succeeds immediately; m2 (codex) takes 2 real
// seconds but still succeeds, reaching quorum (2/2); by the time m3's
// (glm) turn comes the level's cumulative wall-clock already exceeds the
// 1s hard timeout, so RunPanel never launches it — m3 is recorded TIMEOUT.
// The panel still completes: comparison and judge run against only m1 and
// m2's artifacts and reach APPROVED.
func TestRunPanelQuorumProceedsWithoutStraggler(t *testing.T) {
	root, _ := fixture(t)
	panelExecFixture(t,
		map[string]string{
			"claude-code": panelFakeBackend(t, `mkdir -p .governator/artifacts
printf '{"summary":"m1","findings":[]}' > .governator/artifacts/art1.json
`+panelFakeResult),
			"codex": panelFakeBackend(t, `sleep 2
mkdir -p .governator/artifacts
printf '{"summary":"m2","findings":[]}' > .governator/artifacts/art2.json
`+panelFakeResult),
			"glm": panelFakeBackend(t, `mkdir -p .governator/artifacts
printf '{"summary":"m3","findings":[]}' > .governator/artifacts/art3.json
`+panelFakeResult),
			"opencode": panelFakeBackend(t, `mkdir -p .governator/artifacts
printf '{"version":1,"participants":[],"differing_paths":[]}' > .governator/artifacts/panel-comparison.json
`+panelFakeResult),
			"pi": panelFakeBackend(t, `mkdir -p .governator/artifacts
printf '{"summary":"judged","recommendation":"n/a"}' > .governator/artifacts/panel-judgment.json
`+panelFakeResult),
		},
		map[string]string{"claude-code": "architect", "codex": "architect", "glm": "architect", "opencode": "verifier", "pi": "architect"},
	)

	m1 := panelExecContract(root, "m1", "panel_analysis", "claude-code",
		[]contracts.ArtifactSpec{{Name: "art1", Path: ".governator/artifacts/art1.json", MaxBytes: 4096}}, nil, nil, nil)
	m2 := panelExecContract(root, "m2", "panel_analysis", "codex",
		[]contracts.ArtifactSpec{{Name: "art2", Path: ".governator/artifacts/art2.json", MaxBytes: 4096}}, nil, nil, nil)
	m3 := panelExecContract(root, "m3", "panel_analysis", "glm",
		[]contracts.ArtifactSpec{{Name: "art3", Path: ".governator/artifacts/art3.json", MaxBytes: 4096}}, nil, nil, nil)
	cmp := panelExecContract(root, "cmp", "panel_comparison", "opencode",
		[]contracts.ArtifactSpec{{Name: "panel_comparison", Path: ".governator/artifacts/panel-comparison.json", MaxBytes: 4096}},
		[]string{"art1", "art2", "art3"}, []string{"m1", "m2", "m3"},
		map[string]string{"art1": "m1", "art2": "m2", "art3": "m3"})
	judge := panelExecContract(root, "judge", "panel_judgment", "pi",
		[]contracts.ArtifactSpec{{Name: "panel_judgment", Path: ".governator/artifacts/panel-judgment.json", MaxBytes: 4096}},
		[]string{"panel_comparison"}, []string{"m1", "m2", "m3", "cmp"},
		map[string]string{"panel_comparison": "cmp"})

	spec := contracts.PanelSpec{
		ID: "panel", Members: []string{"m1", "m2", "m3"}, ComparisonJob: "cmp", Judge: "judge",
		MinSuccess: 2, HardTimeoutSeconds: 1,
	}
	levels := [][]contracts.Contract{{m1, m2, m3}, {cmp}, {judge}}

	summary, report, err := New().RunPanel(context.Background(), spec, levels, BatchOptions{})
	if err != nil {
		t.Fatalf("RunPanel: %v", err)
	}

	statusByID := map[string]string{}
	for _, j := range summary.Jobs {
		statusByID[j.JobID] = j.Status
	}
	if statusByID["m1"] != "APPROVED" || statusByID["m2"] != "APPROVED" {
		t.Fatalf("expected m1,m2 APPROVED, got %+v", statusByID)
	}
	if statusByID["m3"] != "TIMEOUT" {
		t.Fatalf("expected m3 TIMEOUT (hard timeout elapsed before its turn), got %q", statusByID["m3"])
	}
	if statusByID["cmp"] != "APPROVED" || statusByID["judge"] != "APPROVED" {
		t.Fatalf("expected comparison and judge to complete APPROVED despite the timed-out member, got %+v", statusByID)
	}
	if !report.Degraded {
		t.Fatal("expected the panel to report degraded (hard timeout hit)")
	}
	found := false
	for _, reason := range report.DegradedReasons {
		if strings.Contains(reason, "hard_timeout_elapsed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a hard_timeout_elapsed degraded reason, got %v", report.DegradedReasons)
	}
	if len(report.SucceededMembers) != 2 {
		t.Fatalf("expected 2 succeeded members recorded, got %v", report.SucceededMembers)
	}

	// Membership must land in panel_members so the Phase 7 disagreement
	// metric has data (recordPanelMembership) — one row per member, in
	// spec.Members order, including the timed-out straggler.
	db, err := observability.Open(Home())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT member_label, job_id, agent FROM panel_members WHERE panel_id='panel' ORDER BY member_label ASC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type memberRow struct{ label, jobID, agent string }
	var got []memberRow
	for rows.Next() {
		var m memberRow
		if err := rows.Scan(&m.label, &m.jobID, &m.agent); err != nil {
			t.Fatal(err)
		}
		got = append(got, m)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []memberRow{
		{"member-1", "m1", "claude-code"},
		{"member-2", "m2", "codex"},
		{"member-3", "m3", "glm"},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d panel_members rows, got %+v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("panel_members[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestRunPanelQuorumSkipsMemberOnceSatisfied is the companion fast path:
// with min_success=2 and two immediately-successful members, RunPanel must
// never even launch a third — proven by a marker file the third member's
// script would create if it ran.
func TestRunPanelQuorumSkipsMemberOnceSatisfied(t *testing.T) {
	root, _ := fixture(t)
	marker := filepath.Join(t.TempDir(), "m3-ran.marker")
	panelExecFixture(t,
		map[string]string{
			"claude-code": panelFakeBackend(t, `mkdir -p .governator/artifacts
printf '{"summary":"m1","findings":[]}' > .governator/artifacts/art1.json
`+panelFakeResult),
			"codex": panelFakeBackend(t, `mkdir -p .governator/artifacts
printf '{"summary":"m2","findings":[]}' > .governator/artifacts/art2.json
`+panelFakeResult),
			"glm": panelFakeBackend(t, `touch `+marker+`
mkdir -p .governator/artifacts
printf '{"summary":"m3","findings":[]}' > .governator/artifacts/art3.json
`+panelFakeResult),
			"opencode": panelFakeBackend(t, `mkdir -p .governator/artifacts
printf '{"version":1,"participants":[],"differing_paths":[]}' > .governator/artifacts/panel-comparison.json
`+panelFakeResult),
			"pi": panelFakeBackend(t, `mkdir -p .governator/artifacts
printf '{"summary":"judged","recommendation":"n/a"}' > .governator/artifacts/panel-judgment.json
`+panelFakeResult),
		},
		map[string]string{"claude-code": "architect", "codex": "architect", "glm": "architect", "opencode": "verifier", "pi": "architect"},
	)

	m1 := panelExecContract(root, "m1", "panel_analysis", "claude-code",
		[]contracts.ArtifactSpec{{Name: "art1", Path: ".governator/artifacts/art1.json", MaxBytes: 4096}}, nil, nil, nil)
	m2 := panelExecContract(root, "m2", "panel_analysis", "codex",
		[]contracts.ArtifactSpec{{Name: "art2", Path: ".governator/artifacts/art2.json", MaxBytes: 4096}}, nil, nil, nil)
	m3 := panelExecContract(root, "m3", "panel_analysis", "glm",
		[]contracts.ArtifactSpec{{Name: "art3", Path: ".governator/artifacts/art3.json", MaxBytes: 4096}}, nil, nil, nil)
	cmp := panelExecContract(root, "cmp", "panel_comparison", "opencode",
		[]contracts.ArtifactSpec{{Name: "panel_comparison", Path: ".governator/artifacts/panel-comparison.json", MaxBytes: 4096}},
		[]string{"art1", "art2", "art3"}, []string{"m1", "m2", "m3"},
		map[string]string{"art1": "m1", "art2": "m2", "art3": "m3"})
	judge := panelExecContract(root, "judge", "panel_judgment", "pi",
		[]contracts.ArtifactSpec{{Name: "panel_judgment", Path: ".governator/artifacts/panel-judgment.json", MaxBytes: 4096}},
		[]string{"panel_comparison"}, []string{"m1", "m2", "m3", "cmp"},
		map[string]string{"panel_comparison": "cmp"})

	spec := contracts.PanelSpec{
		ID: "panel", Members: []string{"m1", "m2", "m3"}, ComparisonJob: "cmp", Judge: "judge",
		MinSuccess: 2, HardTimeoutSeconds: 60,
	}
	levels := [][]contracts.Contract{{m1, m2, m3}, {cmp}, {judge}}

	summary, report, err := New().RunPanel(context.Background(), spec, levels, BatchOptions{})
	if err != nil {
		t.Fatalf("RunPanel: %v", err)
	}
	statusByID := map[string]string{}
	for _, j := range summary.Jobs {
		statusByID[j.JobID] = j.Status
	}
	if statusByID["m3"] != "SKIPPED" {
		t.Fatalf("expected m3 SKIPPED once quorum was met, got %q", statusByID["m3"])
	}
	if report.Degraded {
		t.Fatalf("skipping a member once quorum is met is the intended fast path, not degradation: %v", report.DegradedReasons)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("m3's backend must never have been invoked once quorum was already satisfied")
	}
}
