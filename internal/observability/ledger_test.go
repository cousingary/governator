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
	for _, name := range []string{"job_type", "agent", "mode", "cost_usd", "valid_output", "failure_taxonomy", "result_json", "prompt_version"} {
		if !columns[name] {
			t.Errorf("missing migrated column %s", name)
		}
	}
	for _, table := range []string{"runs", "jobs", "agents", "agent_profiles", "files_touched", "commands_run", "validators", "violations", "repair_packets", "eval_runs"} {
		var count int
		if err := migrated.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("missing table %s", table)
		}
	}
}
