package runtime

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/dbtime"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/quota"
)

// recoveryFixture opens a fresh ledger under a temp GOV_HOME and returns it
// alongside a throwaway repo root, matching how runOnce would have left
// things for a run that got interrupted partway through.
func recoveryFixture(t *testing.T) (db *sql.DB, home, root string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("GOV_HOME", home)
	root = t.TempDir()
	db, err := dbOpen(home)
	if err != nil {
		t.Fatalf("dbOpen: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, home, root
}

// seedQuotaWindow gives backend enough estimated headroom for quota.Reserve
// to actually create a reservation row (an empty windows table makes Reserve
// a silent no-op), so tests can verify the reservation is released. The
// numeric _unix_nano columns must be set alongside their legacy text mirrors
// -- Sol15 P0-3's dbtime.VerifyLegacyRoundTrip (wired into quota.scanWindow)
// treats a row whose numeric column is left at its zero-value default while
// its text column holds a real timestamp as ledger corruption, which is
// exactly what omitting them here used to produce silently.
func seedQuotaWindow(t *testing.T, db *sql.DB, backend string, now time.Time) {
	t.Helper()
	reset := now.Add(24 * time.Hour)
	nowNanos, err := dbtime.ToUnixNano(now)
	if err != nil {
		t.Fatal(err)
	}
	resetNanos, err := dbtime.ToUnixNano(reset)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO quota_windows(backend,account,window_type,window_started_at,reset_at,estimated_limit,measured_usage,reserved_usage,confidence,source,updated_at,window_started_unix_nano,reset_unix_nano,updated_unix_nano)
VALUES(?,?,?,?,?,?,0,0,0.9,'test',?,?,?,?) ON CONFLICT(backend,account,window_type) DO NOTHING`,
		backend, quota.DefaultAccount, "daily", now.Format(time.RFC3339Nano), reset.Format(time.RFC3339Nano), 1000000.0, now.Format(time.RFC3339Nano), nowNanos, resetNanos, nowNanos)
	if err != nil {
		t.Fatalf("seed quota window: %v", err)
	}
}

// seedInterruptedRun writes a runs row exactly as runOnce leaves one behind
// when the process dies before reaching a terminal status: status=RUNNING,
// a workspace on disk, and an open quota reservation. It returns the
// reservation id so tests can assert it gets released.
func seedInterruptedRun(t *testing.T, db *sql.DB, id, root, worktree, branch string) int64 {
	t.Helper()
	now := time.Now().UTC()
	rec := RunRecord{
		ID: id, JobID: "job-" + id, JobType: "test", Agent: "claude-code", Mode: "surgeon",
		Status: "RUNNING", Root: root, Worktree: worktree, Branch: branch,
		Created: now.Format(time.RFC3339Nano),
	}
	if err := insertRun(db, rec, "hash-"+id, "non-git"); err != nil {
		t.Fatalf("insertRun: %v", err)
	}
	seedQuotaWindow(t, db, rec.Agent, now)
	res, err := quota.Reserve(db, rec.Agent, quota.DefaultAccount, id, 100, time.Hour, now)
	if err != nil {
		t.Fatalf("quota.Reserve: %v", err)
	}
	if res.ID == 0 {
		t.Fatalf("expected a real reservation, got none")
	}
	return res.ID
}

func stage(t *testing.T, db *sql.DB, runID, name, detail string) {
	t.Helper()
	if err := observability.RecordStage(db, runID, name, detail, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("RecordStage(%s): %v", name, err)
	}
}

func runStatus(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var status string
	if err := db.QueryRow(`SELECT status FROM runs WHERE id=?`, id).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	return status
}

func reservationSettled(t *testing.T, db *sql.DB, id int64) bool {
	t.Helper()
	var settled string
	if err := db.QueryRow(`SELECT COALESCE(settled_at,'') FROM quota_reservations WHERE id=?`, id).Scan(&settled); err != nil {
		t.Fatalf("query reservation: %v", err)
	}
	return settled != ""
}

func TestRecoverInterruptedRun_PreAgentRunningIsSafe(t *testing.T) {
	db, _, root := recoveryFixture(t)
	work := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}
	resID := seedInterruptedRun(t, db, "run-preagent", root, work, "")
	stage(t, db, "run-preagent", "WORKSPACE_READY", "")

	v, err := recoverInterruptedRun(context.Background(), db, RunRecord{ID: "run-preagent", Root: root, Worktree: work, Status: "RUNNING"}, false)
	if err != nil {
		t.Fatalf("recoverInterruptedRun: %v", err)
	}
	if v.Action != "safe_resume" {
		t.Fatalf("action = %q, want safe_resume (detail=%s)", v.Action, v.Detail)
	}
	if got := runStatus(t, db, "run-preagent"); got != "ABANDONED" {
		t.Fatalf("run status = %q, want ABANDONED", got)
	}
	if !reservationSettled(t, db, resID) {
		t.Fatal("quota reservation was not released")
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatal("worktree was not destroyed")
	}
}

func TestRecoverInterruptedRun_AgentRunningUnchangedIsSafe(t *testing.T) {
	db, _, root := recoveryFixture(t)
	work := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	resID := seedInterruptedRun(t, db, "run-unchanged", root, work, "")
	before, err := fingerprint(work)
	if err != nil {
		t.Fatal(err)
	}
	detail, _ := json.Marshal(map[string]string{"worktree_digest": snapshotDigest(before)})
	stage(t, db, "run-unchanged", "AGENT_RUNNING", string(detail))

	v, err := recoverInterruptedRun(context.Background(), db, RunRecord{ID: "run-unchanged", Root: root, Worktree: work, Status: "RUNNING"}, false)
	if err != nil {
		t.Fatalf("recoverInterruptedRun: %v", err)
	}
	if v.Action != "safe_resume" {
		t.Fatalf("action = %q, want safe_resume (detail=%s)", v.Action, v.Detail)
	}
	if got := runStatus(t, db, "run-unchanged"); got != "ABANDONED" {
		t.Fatalf("run status = %q, want ABANDONED", got)
	}
	if !reservationSettled(t, db, resID) {
		t.Fatal("quota reservation was not released")
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatal("worktree was not destroyed")
	}
}

func TestRecoverInterruptedRun_AgentRunningChangedIsQuarantined(t *testing.T) {
	db, _, root := recoveryFixture(t)
	work := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	resID := seedInterruptedRun(t, db, "run-changed", root, work, "")
	before, err := fingerprint(work)
	if err != nil {
		t.Fatal(err)
	}
	detail, _ := json.Marshal(map[string]string{"worktree_digest": snapshotDigest(before)})
	stage(t, db, "run-changed", "AGENT_RUNNING", string(detail))
	// Simulate the agent having started editing before the process died.
	if err := os.WriteFile(filepath.Join(work, "mid-edit.txt"), []byte("uncommitted\n"), 0644); err != nil {
		t.Fatal(err)
	}

	v, err := recoverInterruptedRun(context.Background(), db, RunRecord{ID: "run-changed", Root: root, Worktree: work, Status: "RUNNING"}, false)
	if err != nil {
		t.Fatalf("recoverInterruptedRun: %v", err)
	}
	if v.Action != "quarantined" {
		t.Fatalf("action = %q, want quarantined (detail=%s)", v.Action, v.Detail)
	}
	if got := runStatus(t, db, "run-changed"); got != "QUARANTINED" {
		t.Fatalf("run status = %q, want QUARANTINED", got)
	}
	// A quarantined run must still release its reservation and destroy the
	// worktree — quarantine means "don't reuse this as a fresh attempt
	// silently," not "leak the resources."
	if !reservationSettled(t, db, resID) {
		t.Fatal("quota reservation was not released")
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatal("worktree was not destroyed")
	}
}

func TestAbandonRun_ForcesCleanupEvenWhenChanged(t *testing.T) {
	db, _, root := recoveryFixture(t)
	work := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}
	seedInterruptedRun(t, db, "run-forced", root, work, "")
	stage(t, db, "run-forced", "AGENT_RUNNING", `{"worktree_digest":"deadbeef"}`)
	if err := os.WriteFile(filepath.Join(work, "mid-edit.txt"), []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}

	v, err := recoverInterruptedRun(context.Background(), db, RunRecord{ID: "run-forced", Root: root, Worktree: work, Status: "RUNNING"}, true)
	if err != nil {
		t.Fatalf("recoverInterruptedRun(forced): %v", err)
	}
	if v.Action != "safe_resume" {
		t.Fatalf("action = %q, want safe_resume (forced abandon always wins)", v.Action)
	}
	if got := runStatus(t, db, "run-forced"); got != "ABANDONED" {
		t.Fatalf("run status = %q, want ABANDONED", got)
	}
}

func TestResumeRun_RefusesWhileLockIsLive(t *testing.T) {
	db, home, root := recoveryFixture(t)
	work := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}
	resID := seedInterruptedRun(t, db, "run-live", root, work, "")

	release, err := lock(root, home)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	defer release()

	v, err := ResumeRun(context.Background(), "run-live")
	if err != nil {
		t.Fatalf("ResumeRun: %v", err)
	}
	if v.Action != "still_running" {
		t.Fatalf("action = %q, want still_running", v.Action)
	}
	if got := runStatus(t, db, "run-live"); got != "RUNNING" {
		t.Fatalf("run status = %q, want unchanged RUNNING", got)
	}
	if reservationSettled(t, db, resID) {
		t.Fatal("quota reservation must not be released while the lock is live")
	}
}

func TestResumeRun_AlreadyTerminalIsNoop(t *testing.T) {
	db, _, root := recoveryFixture(t)
	rec := RunRecord{ID: "run-done", JobID: "job-done", Status: "APPROVED", Root: root, Created: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := insertRun(db, rec, "hash", "non-git"); err != nil {
		t.Fatal(err)
	}

	v, err := ResumeRun(context.Background(), "run-done")
	if err != nil {
		t.Fatalf("ResumeRun: %v", err)
	}
	if v.Action != "already_terminal" {
		t.Fatalf("action = %q, want already_terminal", v.Action)
	}
	if got := runStatus(t, db, "run-done"); got != "APPROVED" {
		t.Fatalf("run status = %q, want unchanged APPROVED", got)
	}
}

func TestRecoverStaleRuns_ReportsEachInterruptedRunAndIsIdempotent(t *testing.T) {
	db, home, root := recoveryFixture(t)
	workA := filepath.Join(t.TempDir(), "work-a")
	workB := filepath.Join(t.TempDir(), "work-b")
	for _, w := range []string{workA, workB} {
		if err := os.MkdirAll(w, 0700); err != nil {
			t.Fatal(err)
		}
	}
	seedInterruptedRun(t, db, "run-a", root, workA, "")
	stage(t, db, "run-a", "PARSED", "")
	liveRoot := t.TempDir()
	seedInterruptedRun(t, db, "run-b", liveRoot, workB, "")
	stage(t, db, "run-b", "PARSED", "")

	release, err := lock(liveRoot, home)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	defer release()

	verdicts, err := RecoverStaleRuns(context.Background())
	if err != nil {
		t.Fatalf("RecoverStaleRuns: %v", err)
	}
	byID := map[string]RecoveryVerdict{}
	for _, v := range verdicts {
		byID[v.RunID] = v
	}
	if byID["run-a"].Action != "safe_resume" {
		t.Fatalf("run-a action = %q, want safe_resume", byID["run-a"].Action)
	}
	if byID["run-b"].Action != "still_running" {
		t.Fatalf("run-b action = %q, want still_running (its lock is held)", byID["run-b"].Action)
	}
	if got := runStatus(t, db, "run-b"); got != "RUNNING" {
		t.Fatalf("run-b status = %q, want unchanged RUNNING", got)
	}

	// A second pass must not error and must not re-touch run-a (already
	// terminal) or fabricate a new verdict for it.
	verdicts2, err := RecoverStaleRuns(context.Background())
	if err != nil {
		t.Fatalf("RecoverStaleRuns (second pass): %v", err)
	}
	for _, v := range verdicts2 {
		if v.RunID == "run-a" {
			t.Fatalf("run-a reappeared in a second recover --stale pass: %+v", v)
		}
	}
}
