package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

// planProjectRoot creates a disposable git repo suitable as a `gov plan`
// workspace.root: it needs real content under internal/ so a compiled
// sub-contract's required_files check (internal/x.go) has something to
// point at once merged.
func planProjectRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	batchGit(t, root, "init", "-b", "main")
	batchGit(t, root, "config", "user.email", "test@example.invalid")
	batchGit(t, root, "config", "user.name", "Governator Test")
	if err := os.MkdirAll(filepath.Join(root, "internal"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "internal", "x.go"), []byte("package internal\n"), 0644); err != nil {
		t.Fatal(err)
	}
	batchGit(t, root, "add", ".")
	batchGit(t, root, "commit", "-m", "seed")
	return root
}

// planFakeBin is the planner-mode stand-in for batchFakeBin: instead of
// writing output/result.txt, it writes a canned jobs/testplan/PLAN.yaml
// (the fixed --out this file's tests always pass) so each test can drive
// gov plan's downstream validation/explode logic with a controlled manifest.
func planFakeBin(t *testing.T, planYAML string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fake-claude-plan")
	script := "#!/bin/sh\n" +
		"mkdir -p jobs/testplan\n" +
		"cat > jobs/testplan/PLAN.yaml <<'PLANEOF'\n" + planYAML + "\nPLANEOF\n" +
		`printf '{"status":"complete","files_changed":["jobs/testplan/PLAN.yaml"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json` + "\n" +
		`printf '{"type":"result","total_cost_usd":0.10}\n'` + "\n"
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func planJobYAML(jobID, root string, dependsOn []string) string {
	deps := "[]"
	if len(dependsOn) > 0 {
		deps = "[" + strings.Join(dependsOn, ", ") + "]"
	}
	return fmt.Sprintf(`  - task: "do %s"
    job_id: %s
    job_type: code_change
    agent: claude-code
    mode: surgeon
    workspace: {root: %s, worktree: auto}
    allowed: {read: ["**"], write: ["internal/**"], execute: []}
    forbidden: {paths: [".git/**"], commands: ["rm -rf"], behaviors: [network]}
    budget: {max_minutes: 10, max_commands: 10, max_files_changed: 3, max_lines_changed: 100, max_new_files: 1, max_deleted: 0, max_tokens: 10000}
    preflight: {intended_writes: ["internal/**"]}
    success: {required_files: ["internal/x.go"], validators: ["true"]}
    on_violation: quarantine
    risk_class: low
    depends_on: %s
`, jobID, jobID, root, deps)
}

func TestPlanCommandEndToEndWritesValidatedJobFilesAndShow(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	root := planProjectRoot(t)
	t.Chdir(root)

	planYAML := "jobs:\n" + planJobYAML("plan-job-a", root, nil) + planJobYAML("plan-job-b", root, []string{"plan-job-a"})
	t.Setenv("GOV_CLAUDE_BIN", planFakeBin(t, planYAML))

	intentPath := filepath.Join(t.TempDir(), "intent.md")
	if err := os.WriteFile(intentPath, []byte("# Intent\nDo the two-job thing.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	code, output := captureRunInput(t, []string{
		"plan", intentPath, "--out", "jobs/testplan",
		"--envelope", "internal/**", "--max-total-tokens", "50000",
		"--backend", "claude-code",
	}, "")
	if code != 0 {
		t.Fatalf("exit=%d output=%s", code, output)
	}
	if !strings.Contains(output, "jobs=2 levels=2 written=2") {
		t.Fatalf("expected the summary line, got %s", output)
	}
	for _, id := range []string{"plan-job-a", "plan-job-b"} {
		if _, err := os.Stat(filepath.Join(root, "jobs", "testplan", id+".yaml")); err != nil {
			t.Fatalf("expected %s.yaml on disk: %v", id, err)
		}
	}

	showCode, showOutput := captureRunInput(t, []string{"plan", "--show", filepath.Join(root, "jobs", "testplan")}, "")
	if showCode != 0 {
		t.Fatalf("show exit=%d output=%s", showCode, showOutput)
	}
	if !strings.Contains(showOutput, "plan-job-a") || !strings.Contains(showOutput, "plan-job-b") {
		t.Fatalf("expected both job ids in --show output, got %s", showOutput)
	}
	if !strings.Contains(showOutput, "jobs=2 levels=2") {
		t.Fatalf("expected the aggregate line in --show output, got %s", showOutput)
	}
}

func TestPlanPanelCommandWritesValidatedPanelTemplate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	root := planProjectRoot(t)
	t.Chdir(root)
	intentPath := filepath.Join(t.TempDir(), "intent.md")
	if err := os.WriteFile(intentPath, []byte("# Intent\nReview the architecture.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	code, output := captureRunInput(t, []string{
		"plan", "--panel", "3", intentPath, "--out", "jobs/panel",
		"--envelope", "internal/**", "--max-total-tokens", "90000", "--backend", "claude-code",
	}, "")
	if code != 0 {
		t.Fatalf("exit=%d output=%s", code, output)
	}
	if !strings.Contains(output, "panel: 3 members") || !strings.Contains(output, "jobs=5 levels=3 written=5 schemas=3") {
		t.Fatalf("expected panel summary, got %s", output)
	}
	for _, rel := range []string{
		"jobs/panel/PLAN.yaml",
		"jobs/panel/panel-member-1.yaml",
		"jobs/panel/panel-member-2.yaml",
		"jobs/panel/panel-member-3.yaml",
		"jobs/panel/panel-compare.yaml",
		"jobs/panel/panel-judge.yaml",
		"jobs/panel/schemas/panel-member.schema.json",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("expected %s on disk: %v", rel, err)
		}
	}
	showCode, showOutput := captureRunInput(t, []string{"plan", "--show", filepath.Join(root, "jobs", "panel")}, "")
	if showCode != 0 {
		t.Fatalf("show exit=%d output=%s", showCode, showOutput)
	}
	if !strings.Contains(showOutput, "panel-judge") || !strings.Contains(showOutput, "jobs=5 levels=3") {
		t.Fatalf("expected panel jobs in --show, got %s", showOutput)
	}
}

func TestPlanPanelCommandHonorsQuorumAndDiversityFlags(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	root := planProjectRoot(t)
	t.Chdir(root)
	intentPath := filepath.Join(t.TempDir(), "intent.md")
	if err := os.WriteFile(intentPath, []byte("# Intent\nReview the architecture.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	code, output := captureRunInput(t, []string{
		"plan", "--panel", "3", intentPath, "--out", "jobs/panel2",
		"--envelope", "internal/**", "--max-total-tokens", "90000", "--backend", "claude-code",
		"--min-success", "2", "--member-timeout-seconds", "90", "--hard-timeout-seconds", "200",
		"--diversity-key", "model_family", "--diversity-min-unique", "2", "--diversity-fallback-key", "backend",
	}, "")
	if code != 0 {
		t.Fatalf("exit=%d output=%s", code, output)
	}
	plan, err := contracts.ParsePlanFile(filepath.Join(root, "jobs", "panel2", "PLAN.yaml"))
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
}

func TestDetectPanelSpecFindsPanelPlanAlongsideJobFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	root := planProjectRoot(t)
	t.Chdir(root)
	intentPath := filepath.Join(t.TempDir(), "intent.md")
	if err := os.WriteFile(intentPath, []byte("# Intent\nReview.\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if code, output := captureRunInput(t, []string{
		"plan", "--panel", "2", intentPath, "--out", "jobs/panel3",
		"--envelope", "internal/**", "--max-total-tokens", "90000", "--backend", "claude-code",
	}, ""); code != 0 {
		t.Fatalf("exit=%d output=%s", code, output)
	}

	spec, err := detectPanelSpec([]string{filepath.Join(root, "jobs", "panel3")})
	if err != nil {
		t.Fatal(err)
	}
	if spec == nil || spec.ID != "panel" || len(spec.Members) != 2 {
		t.Fatalf("expected the panel spec to be found, got %+v", spec)
	}

	// An ordinary batch directory (no PLAN.yaml) must not be mistaken for a
	// panel plan.
	ordinary := t.TempDir()
	spec, err = detectPanelSpec([]string{ordinary})
	if err != nil {
		t.Fatal(err)
	}
	if spec != nil {
		t.Fatalf("expected no panel spec for a plain directory, got %+v", spec)
	}
}

func TestPlanCommandQuarantinesOnCyclicPlanAndWritesNoJobFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	root := planProjectRoot(t)
	t.Chdir(root)

	planYAML := "jobs:\n" + planJobYAML("cyc-job-a", root, []string{"cyc-job-b"}) + planJobYAML("cyc-job-b", root, []string{"cyc-job-a"})
	t.Setenv("GOV_CLAUDE_BIN", planFakeBin(t, planYAML))

	intentPath := filepath.Join(t.TempDir(), "intent.md")
	if err := os.WriteFile(intentPath, []byte("# Intent\nCyclic.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	code, _ := captureRunInput(t, []string{
		"plan", intentPath, "--out", "jobs/testplan",
		"--envelope", "internal/**", "--max-total-tokens", "50000",
		"--backend", "claude-code",
	}, "")
	if code == 0 {
		t.Fatal("expected a non-zero exit for a cyclic plan")
	}
	if _, err := os.Stat(filepath.Join(root, "jobs", "testplan")); !os.IsNotExist(err) {
		t.Fatalf("expected no merge into the live root for a quarantined plan, stat err=%v", err)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var status, message string
	if err := db.QueryRow(`SELECT status, message FROM runs WHERE job_id='plan-testplan'`).Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status != "QUARANTINED" || !strings.Contains(message, "cycle") {
		t.Fatalf("status=%s message=%s", status, message)
	}
}

// orderedBatchJobFixture is batchJobFixture plus a depends_on field, for
// exercising `gov batch run <dir> --ordered` at the CLI layer.
func orderedBatchJobFixture(t *testing.T, jobsDir, jobID string, dependsOn []string) string {
	t.Helper()
	root := t.TempDir()
	batchGit(t, root, "init", "-b", "main")
	batchGit(t, root, "config", "user.email", "test@example.invalid")
	batchGit(t, root, "config", "user.name", "Governator Test")
	if err := os.WriteFile(filepath.Join(root, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	batchGit(t, root, "add", ".")
	batchGit(t, root, "commit", "-m", "seed")

	deps := "[]"
	if len(dependsOn) > 0 {
		deps = "[" + strings.Join(dependsOn, ", ") + "]"
	}
	yaml := fmt.Sprintf(`task: write deterministic test output
job_id: %s
job_type: test
agent: claude-code
mode: surgeon
workspace:
  root: %s
  worktree: auto
allowed:
  read: ["**"]
  write: ["output/**"]
  execute: ["test"]
forbidden:
  paths: [".git/**"]
  commands: ["rm -rf"]
  behaviors: [network]
budget: {max_minutes: 1, max_commands: 5, max_files_changed: 5, max_lines_changed: 20, max_new_files: 2, max_deleted: 0}
preflight:
  intended_writes: ["output/**"]
success:
  required_files: ["output/result.txt"]
  validators: ["test -f output/result.txt"]
on_violation: quarantine
risk_class: low
depends_on: %s
`, jobID, root, deps)
	path := filepath.Join(jobsDir, jobID+".yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBatchRunOrderedCLIRunsDependentJobAfterDependency(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	t.Setenv("GOV_CLAUDE_BIN", batchFakeBin(t))

	jobsDir := t.TempDir()
	orderedBatchJobFixture(t, jobsDir, "ordered-cli-a", nil)
	orderedBatchJobFixture(t, jobsDir, "ordered-cli-b", []string{"ordered-cli-a"})

	code, output := captureRunInput(t, []string{"batch", "run", jobsDir, "--ordered"}, "")
	if code != 0 {
		t.Fatalf("exit=%d output=%s", code, output)
	}
	if !strings.Contains(output, "jobs=2 quarantined=0") {
		t.Fatalf("expected aggregate summary line, got %s", output)
	}

	idxA := strings.Index(output, "ordered-cli-a\t")
	idxB := strings.Index(output, "ordered-cli-b\t")
	if idxA < 0 || idxB < 0 {
		t.Fatalf("expected both ordered jobs in output, got %s", output)
	}
	if idxB < idxA {
		t.Fatalf("expected the dependent job to be printed after its dependency, got %s", output)
	}
}

func TestBatchRunRefusesDependsOnWithoutOrdered(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	jobsDir := t.TempDir()
	orderedBatchJobFixture(t, jobsDir, "unordered-dep-a", nil)
	orderedBatchJobFixture(t, jobsDir, "unordered-dep-b", []string{"unordered-dep-a"})

	// Without --ordered, depends_on would be silently ignored and both jobs
	// would run in parallel — the CLI must refuse instead.
	code, _ := captureRunInput(t, []string{"batch", "run", jobsDir}, "")
	if code != 2 {
		t.Fatalf("expected exit 2 refusing depends_on without --ordered, got %d", code)
	}
}

func TestBatchRunOrderedRefusesDanglingDependsOn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	jobsDir := t.TempDir()
	orderedBatchJobFixture(t, jobsDir, "dangling-dep-b", []string{"dangling-dep-a"})

	// TopologicalLevels silently drops references it can't resolve, so a
	// subset batch would run the job WITHOUT its declared prerequisite — the
	// CLI must fail closed before launching anything.
	code, _ := captureRunInput(t, []string{"batch", "run", jobsDir, "--ordered"}, "")
	if code != 2 {
		t.Fatalf("expected exit 2 refusing a dangling depends_on, got %d", code)
	}
}
