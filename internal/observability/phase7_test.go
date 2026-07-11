package observability

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBackendValidOutputRatesSumsAcrossJobTypes(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO agent_profiles(agent,job_type,runs,valid_outputs,failures,total_cost_usd) VALUES
('claude','fix',10,9,1,1),('claude','feature',10,7,3,1),('codex','fix',4,1,3,1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	rates, err := BackendValidOutputRates(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(rates) != 2 {
		t.Fatalf("expected 2 backends, got %#v", rates)
	}
	if rates[0].Backend != "claude" || rates[0].Runs != 20 || rates[0].ValidOutputs != 16 || rates[0].ValidRate != 0.8 {
		t.Fatalf("unexpected claude row: %#v", rates[0])
	}
	if rates[1].Backend != "codex" || rates[1].Runs != 4 || rates[1].ValidRate != 0.25 {
		t.Fatalf("unexpected codex row: %#v", rates[1])
	}
}

func TestFailureTypesByBackend(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(id,job_id,agent,status,created,failure_taxonomy) VALUES
('r1','j1','claude','QUARANTINED','t0','SCOPE_DRIFT'),
('r2','j2','claude','QUARANTINED','t1','SCOPE_DRIFT'),
('r3','j3','claude','APPROVED','t2',''),
('r4','j4','codex','QUARANTINED','t3','VALIDATION_FAILED')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	counts, err := FailureTypesByBackend(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 2 {
		t.Fatalf("expected 2 rows (empty taxonomy excluded), got %#v", counts)
	}
	if counts[0].Backend != "claude" || counts[0].Taxonomy != "SCOPE_DRIFT" || counts[0].Count != 2 {
		t.Fatalf("unexpected first row: %#v", counts[0])
	}
}

func TestFallbackFrequencies(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO fallback_attempts(root_run_id,run_id,attempt,backend,fallback_reason,created) VALUES
('root','r2',2,'codex','breaker open','t1'),
('root','r3',3,'codex','breaker open','t2'),
('root','r4',2,'gemini','breaker open','t3')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	freqs, err := FallbackFrequencies(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(freqs) != 2 || freqs[0].Backend != "codex" || freqs[0].Count != 2 || freqs[1].Backend != "gemini" || freqs[1].Count != 1 {
		t.Fatalf("unexpected fallback frequencies: %#v", freqs)
	}
}

func TestQuotaUtilizationsHonestZeroWithoutLimit(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO quota_windows(backend,account,window_type,estimated_limit,measured_usage,confidence,updated_at) VALUES
('claude','default','daily',100,40,0.8,'t0'),
('codex','default','daily',0,15,0,'t1')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	utils, err := QuotaUtilizations(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(utils) != 2 {
		t.Fatalf("expected 2 rows, got %#v", utils)
	}
	if utils[0].Backend != "claude" || utils[0].Utilization != 0.4 {
		t.Fatalf("unexpected claude utilization: %#v", utils[0])
	}
	if utils[1].Backend != "codex" || utils[1].Utilization != 0 {
		t.Fatalf("expected 0 utilization with no known limit, got %#v", utils[1])
	}
}

func TestRepairDepthDistribution(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(id,job_id,status,created,repair_of) VALUES
('root-1','j1','QUARANTINED','t0',''),
('repair-1','j1','QUARANTINED','t1','root-1'),
('repair-2','j1','APPROVED','t2','root-1'),
('root-2','j2','QUARANTINED','t3',''),
('repair-3','j2','APPROVED','t4','root-2')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	summary, err := RepairDepthDistribution(home)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Lineages != 2 || summary.TotalRepairs != 3 || summary.MaxDepth != 2 || summary.AvgDepth != 1.5 {
		t.Fatalf("unexpected repair depth summary: %#v", summary)
	}
}

func TestValidatorFailureClusters(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO validators(run_id,command,exit_code,output) VALUES
('r1','go test ./...',1,'fail'),
('r2','go test ./...',1,'fail'),
('r3','go vet ./...',0,'ok'),
('r4','go build ./...',2,'fail')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	clusters, err := ValidatorFailureClusters(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 2 || clusters[0].Command != "go test ./..." || clusters[0].Count != 2 {
		t.Fatalf("unexpected validator clusters: %#v", clusters)
	}
}

func TestAssayFailureClustersBucketsBareErrors(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := RecordAssayEvaluation(db, AssayEvaluationRecord{RunID: "r1", Profile: "coding-output-v1", Verdict: "fail", FailedChecks: []string{"no_boilerplate", "no_placeholders"}, Created: "t0"}); err != nil {
		t.Fatal(err)
	}
	if err := RecordAssayEvaluation(db, AssayEvaluationRecord{RunID: "r2", Profile: "coding-output-v1", Verdict: "fail", FailedChecks: []string{"no_boilerplate"}, Created: "t1"}); err != nil {
		t.Fatal(err)
	}
	if err := RecordAssayEvaluation(db, AssayEvaluationRecord{RunID: "r3", Profile: "coding-output-v1", Verdict: "error", FailedChecks: nil, Created: "t2"}); err != nil {
		t.Fatal(err)
	}
	if err := RecordAssayEvaluation(db, AssayEvaluationRecord{RunID: "r4", Profile: "coding-output-v1", Verdict: "pass", FailedChecks: nil, Created: "t3"}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	clusters, err := AssayFailureClusters(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 3 {
		t.Fatalf("expected 3 clusters (pass verdict excluded), got %#v", clusters)
	}
	if clusters[0].FailedCheck != "no_boilerplate" || clusters[0].Count != 2 {
		t.Fatalf("expected no_boilerplate to lead with count 2, got %#v", clusters[0])
	}
	foundError := false
	for _, c := range clusters {
		if c.FailedCheck == "(error)" {
			foundError = true
		}
	}
	if !foundError {
		t.Fatalf("expected bare ERROR verdict bucketed under (error): %#v", clusters)
	}
}

func TestPanelDisagreementRate(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(id,job_id,status,created) VALUES
('run-a1','job-a1','APPROVED','t0'),
('run-a2','job-a2','APPROVED','t1'),
('run-a3','job-a3','QUARANTINED','t2'),
('run-b1','job-b1','APPROVED','t3'),
('run-b2','job-b2','APPROVED','t4')`); err != nil {
		t.Fatal(err)
	}
	if err := RecordPanelMembers(db, []PanelMemberRecord{
		{PanelID: "panel-a", MemberLabel: "1", JobID: "job-a1", Agent: "claude"},
		{PanelID: "panel-a", MemberLabel: "2", JobID: "job-a2", Agent: "codex"},
		{PanelID: "panel-a", MemberLabel: "3", JobID: "job-a3", Agent: "gemini"},
		{PanelID: "panel-b", MemberLabel: "1", JobID: "job-b1", Agent: "claude"},
		{PanelID: "panel-b", MemberLabel: "2", JobID: "job-b2", Agent: "codex"},
	}, "t5"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	report, err := PanelDisagreementRate(home)
	if err != nil {
		t.Fatal(err)
	}
	if report.Panels != 2 || report.Disagreements != 1 || report.Rate != 0.5 {
		t.Fatalf("unexpected panel disagreement report: %#v", report)
	}
}

func TestPanelDisagreementRateEmptyIsHonestZero(t *testing.T) {
	home := t.TempDir()
	report, err := PanelDisagreementRate(home)
	if err != nil {
		t.Fatal(err)
	}
	if report.Panels != 0 || report.Disagreements != 0 || report.Rate != 0 {
		t.Fatalf("expected zero-evidence report, got %#v", report)
	}
}

func TestCostByOutcome(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(id,job_id,status,created,cost_usd) VALUES
('r1','j1','APPROVED','t0',1.0),
('r2','j2','APPROVED','t1',3.0),
('r3','j3','QUARANTINED','t2',2.0),
('r4','j4','ROLLED_BACK','t3',4.0)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	outcome, err := CostByOutcome(home)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.ApprovedCount != 2 || outcome.ApprovedCostUSD != 4.0 || outcome.CostPerApproved != 2.0 {
		t.Fatalf("unexpected approved side: %#v", outcome)
	}
	if outcome.RejectedCount != 2 || outcome.RejectedCostUSD != 6.0 || outcome.CostPerRejected != 3.0 {
		t.Fatalf("unexpected rejected side: %#v", outcome)
	}
}

func TestExportJSONLWritesOneLinePerMetricRow(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO agent_profiles(agent,job_type,runs,valid_outputs,failures,total_cost_usd) VALUES('claude','fix',5,4,1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(id,job_id,status,created,cost_usd) VALUES('r1','j1','APPROVED','t0',1.5)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	var buf bytes.Buffer
	if err := ExportJSONL(home, &buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected multiple JSONL rows, got %d: %s", len(lines), buf.String())
	}
	sawBackendRow := false
	for _, line := range lines {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("line not valid JSON: %s (%v)", line, err)
		}
		metric, _ := decoded["metric"].(string)
		if metric == "" {
			t.Fatalf("row missing metric tag: %s", line)
		}
		if metric == "backend_valid_rate" && decoded["backend"] == "claude" {
			sawBackendRow = true
		}
	}
	if !sawBackendRow {
		t.Fatalf("expected a backend_valid_rate row for claude in export:\n%s", buf.String())
	}
}
