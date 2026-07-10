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
	for _, table := range []string{"runs", "jobs", "agents", "agent_profiles", "files_touched", "commands_run", "validators", "violations", "repair_packets", "eval_runs", "hook_events", "parity_events"} {
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
