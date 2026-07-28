//go:build redteam

package redteam

import (
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/runtime"
	_ "modernc.org/sqlite"
)

func TestV14Case317StaleCreatedTimeRoutingRowDoesNotFeedQualityScoring(t *testing.T) {
	const olderCreated = "2026-07-28T00:00:00Z"
	const newerCreated = "2026-07-28T00:00:00.5Z"

	if !(olderCreated > newerCreated) {
		t.Fatalf("premise broken: lexicographic trap not armed -- %q must sort above %q", olderCreated, newerCreated)
	}

	home := t.TempDir()
	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`INSERT INTO runs(id,job_id,job_type,agent,mode,status,created) VALUES('run-stale','job-a','test','agent-a','surgeon','FAILED',?)`, olderCreated); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(id,job_id,job_type,agent,mode,status,created) VALUES('run-fresh','job-a','test','agent-a','surgeon','APPROVED',?)`, newerCreated); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(id,job_id,job_type,agent,mode,status,created) VALUES('run-other','job-b','test','agent-b','surgeon','APPROVED',?)`, newerCreated); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO panel_members(panel_id,member_label,job_id,agent,created) VALUES('panel-1','m1','job-a','agent-a',?)`, olderCreated); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO panel_members(panel_id,member_label,job_id,agent,created) VALUES('panel-1','m2','job-b','agent-b',?)`, olderCreated); err != nil {
		t.Fatal(err)
	}
	db.Close()

	result, err := observability.PanelDisagreementRate(home)
	if err != nil {
		t.Fatal(err)
	}
	if result.Panels != 1 {
		t.Fatalf("expected 1 panel, got %+v", result)
	}
	if result.Disagreements != 0 {
		t.Fatalf("stale FAILED row (created=%s, lexicographically higher) was selected over the actual newest APPROVED run (created=%s): "+
			"panel disagreement = %d, want 0. ORDER BY r.created DESC inverts insertion order on RFC3339Nano TEXT.",
			olderCreated, newerCreated, result.Disagreements)
	}
}

func TestV14Case318GovDiffLastSelectsTheActualLatestRun(t *testing.T) {
	const olderCreated = "2026-07-28T00:00:00Z"
	const newerCreated = "2026-07-28T00:00:00.5Z"

	if !(olderCreated > newerCreated) {
		t.Fatalf("premise broken: lexicographic trap not armed -- %q must sort above %q", olderCreated, newerCreated)
	}

	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(id,job_id,job_type,agent,mode,status,root,worktree,branch,diff,transcript,message,created) VALUES('run-older','job-x','test','claude-code','surgeon','APPROVED','','','','','','',?)`, olderCreated); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(id,job_id,job_type,agent,mode,status,root,worktree,branch,diff,transcript,message,created) VALUES('run-newer','job-x','test','claude-code','surgeon','FAILED','','','','','','',?)`, newerCreated); err != nil {
		t.Fatal(err)
	}
	db.Close()

	rec, err := runtime.Last("last")
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID != "run-newer" {
		t.Fatalf("Last(\"last\") returned %q (created=%s); the actual latest run by insertion order is \"run-newer\" (created=%s). "+
			"ORDER BY created DESC on RFC3339Nano TEXT inverts chronology when the earlier timestamp's fraction is trimmed.",
			rec.ID, olderCreated, newerCreated)
	}
	if rec.Status != "FAILED" {
		t.Fatalf("Last(\"last\") status = %q, want FAILED (the newer run's status)", rec.Status)
	}
}
