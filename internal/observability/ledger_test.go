package observability

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenMigratesLegacyLedger(t *testing.T) {
	home := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(home, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := "CREATE TABLE runs(id TEXT PRIMARY KEY, job_id TEXT, status TEXT, root TEXT, worktree TEXT, branch TEXT, contract_hash TEXT, base_head TEXT, approved_head TEXT, diff TEXT, transcript TEXT, message TEXT, commit_hash TEXT, created TEXT)"
	if _, err := db.Exec(legacy); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	migrated, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()

	rows, err := migrated.Query("PRAGMA table_info(runs)")
	if err != nil {
		t.Fatal(err)
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"job_type", "agent", "mode", "cost_usd", "valid_output", "failure_taxonomy", "result_json", "prompt_version", "envelope_json", "notes", "input_tokens", "output_tokens", "cached_input_tokens", "cache_creation_tokens", "reasoning_tokens", "total_tokens", "usage_available", "tool_calls", "transcript_bytes", "graph_provider", "graph_version", "graph_fingerprint", "graph_files", "graph_nodes", "graph_edges", "graph_db_bytes"} {
		if !columns[name] {
			t.Errorf("missing migrated column %s", name)
		}
	}
	for _, table := range []string{"runs", "jobs", "agents", "agent_profiles", "files_touched", "commands_run", "validators", "violations", "repair_packets", "eval_runs", "hook_events", "parity_events", "batches", "route_decisions", "artifacts", "assay_evaluations"} {
		var count int
		if err := migrated.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("missing table %s", table)
		}
	}
}

func TestUsageSummaryFor(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO runs(id,status,input_tokens,output_tokens,cached_input_tokens,cache_creation_tokens,reasoning_tokens,total_tokens,usage_available,tool_calls,transcript_bytes) VALUES('run-1','APPROVED',100,20,70,5,4,129,1,3,2048)`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := UsageSummaryFor(home, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if report.Runs != 1 || report.MeasuredRuns != 1 || report.TotalTokens != 129 || report.CachedTokens != 75 || report.ToolCalls != 3 || report.TranscriptBytes != 2048 {
		t.Fatalf("unexpected usage report: %+v", report)
	}
}

func TestRecordCompletionSpendCapRefusalDoesNotTouchAgentProfiles(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// A SPEND_CAP refusal never launched the backend: it must still record
	// its violation row, but must not book a run/failure against the agent —
	// that would corrupt the evidence gov score/route rank agents by.
	if err := RecordCompletion(db, Completion{
		RunID: "refused-1", Agent: "claude-code", JobType: "code_change",
		Status: "QUARANTINED", FailureTaxonomy: "SPEND_CAP",
		Violations: []string{"spend_cap: daily spend over cap"},
	}); err != nil {
		t.Fatal(err)
	}
	var profiles int
	if err := db.QueryRow("SELECT COUNT(*) FROM agent_profiles").Scan(&profiles); err != nil {
		t.Fatal(err)
	}
	if profiles != 0 {
		t.Fatalf("SPEND_CAP refusal must not create an agent_profiles row, got %d", profiles)
	}
	var violations int
	if err := db.QueryRow("SELECT COUNT(*) FROM violations WHERE run_id='refused-1'").Scan(&violations); err != nil {
		t.Fatal(err)
	}
	if violations != 1 {
		t.Fatalf("SPEND_CAP refusal must still record its violation row, got %d", violations)
	}

	// A genuine quarantine still books against the agent as before.
	if err := RecordCompletion(db, Completion{
		RunID: "failed-1", Agent: "claude-code", JobType: "code_change",
		Status: "QUARANTINED", FailureTaxonomy: "VALIDATOR_FAILED",
	}); err != nil {
		t.Fatal(err)
	}
	var runs, failures int
	if err := db.QueryRow("SELECT runs, failures FROM agent_profiles WHERE agent='claude-code' AND job_type='code_change'").Scan(&runs, &failures); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || failures != 1 {
		t.Fatalf("real quarantine must book exactly one run+failure, got runs=%d failures=%d", runs, failures)
	}
}

func TestRecordRouteDecisionPersistsOneRowPerCandidate(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := RecordRouteDecision(db, RouteDecisionRecord{
		RunID: "run-1", JobID: "j", JobType: "code", Objective: "balanced",
		Preview: false, Created: "2026-07-10T00:00:00Z",
		Rows: []RouteDecisionRow{
			{Candidate: "claude-code", Total: 0.85, Selected: true},
			{Candidate: "glm", Excluded: true, ExclusionReason: "binary_missing"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM route_decisions WHERE run_id='run-1'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected one row per candidate (2), got %d", n)
	}
	var selected, excluded, preview int
	if err := db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(excluded),0),COALESCE(SUM(preview),0) FROM route_decisions WHERE run_id='run-1'`).Scan(&selected, &excluded, &preview); err != nil {
		t.Fatal(err)
	}
	if selected != 2 { // total rows
		t.Fatalf("expected 2 rows, got %d", selected)
	}
	if excluded != 1 {
		t.Fatalf("expected 1 excluded row, got %d", excluded)
	}
	if preview != 0 {
		t.Fatalf("preview flag not persisted, got %d", preview)
	}
	var selCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM route_decisions WHERE run_id='run-1' AND selected=1`).Scan(&selCount); err != nil {
		t.Fatal(err)
	}
	if selCount != 1 {
		t.Fatalf("expected exactly one selected row, got %d", selCount)
	}
}

func TestRecordRouteDecisionPersistsPolicyHash(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := RecordRouteDecision(db, RouteDecisionRecord{
		RunID: "run-2", JobID: "j", JobType: "code", Objective: "balanced",
		PolicyHash: "deadbeef01234567", Preview: false, Created: "2026-07-11T00:00:00Z",
		Rows: []RouteDecisionRow{{Candidate: "claude-code", Total: 0.9, Selected: true}},
	}); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := db.QueryRow(`SELECT policy_hash FROM route_decisions WHERE run_id='run-2'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "deadbeef01234567" {
		t.Fatalf("policy_hash not persisted, got %q", got)
	}
}

func TestRecordAssayEvaluationAppendsRows(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := RecordAssayEvaluation(db, AssayEvaluationRecord{
		RunID: "run-1", AttemptID: "run-1", JobID: "job-1", Profile: "coding-output-v1",
		PolicyVersion: "v1", Verdict: "fail", FailedChecks: []string{"required_fields", "no_boilerplate:content"},
		ChecksHash: "abc123", DurationMS: 42, Created: "2026-07-11T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	// Append-only, like repair_packets: a second evaluation for the same run
	// gets its own row rather than overwriting the first.
	if err := RecordAssayEvaluation(db, AssayEvaluationRecord{
		RunID: "run-1", AttemptID: "run-1", JobID: "job-1", Profile: "coding-output-v1",
		Verdict: "skipped", Created: "2026-07-11T00:00:01Z",
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := AssayEvaluationsForRun(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 append-only rows, got %d: %+v", len(rows), rows)
	}
	if rows[0].Verdict != "fail" || rows[1].Verdict != "skipped" {
		t.Fatalf("unexpected verdict order: %+v", rows)
	}
	if rows[0].ChecksHash != "abc123" || rows[0].DurationMS != 42 || rows[0].PolicyVersion != "v1" {
		t.Fatalf("fields not persisted: %+v", rows[0])
	}
	if len(rows[0].FailedChecks) != 2 || rows[0].FailedChecks[0] != "required_fields" {
		t.Fatalf("failed_checks not round-tripped: %+v", rows[0].FailedChecks)
	}
	// A verdict with no failed checks must round-trip as an empty slice,
	// not nil, so callers can range over it unconditionally.
	if rows[1].FailedChecks == nil || len(rows[1].FailedChecks) != 0 {
		t.Fatalf("expected empty (non-nil) failed_checks for skipped row, got %#v", rows[1].FailedChecks)
	}
}

// TestRecordPolicyRuleEventsAppendsRows is the Phase 6 ledger acceptance
// check: a run's temporal-rule violations (deny AND advisory flag alike)
// round-trip through policy_rule_events, append-only per run like
// assay_evaluations.
func TestRecordPolicyRuleEventsAppendsRows(t *testing.T) {
	home := t.TempDir()
	db, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := RecordPolicyRuleEvents(db, []PolicyRuleEventRecord{
		{RunID: "run-1", Rule: "secret-read-precedes-network", Verdict: "deny", Detail: "read then fetch", CauseSeq: 0, TriggerSeq: 2, Created: "2026-07-11T00:00:00Z"},
		{RunID: "run-1", Rule: "suspected-injection-precedes-exec", Verdict: "flag", Detail: "output then exec", CauseSeq: 3, TriggerSeq: 4, Created: "2026-07-11T00:00:01Z"},
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := PolicyRuleEventsForRun(db, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %+v", len(rows), rows)
	}
	if rows[0].Verdict != "deny" || rows[0].CauseSeq != 0 || rows[0].TriggerSeq != 2 {
		t.Fatalf("deny row not persisted correctly: %+v", rows[0])
	}
	if rows[1].Verdict != "flag" || rows[1].Rule != "suspected-injection-precedes-exec" {
		t.Fatalf("flag row not persisted correctly: %+v", rows[1])
	}
}
