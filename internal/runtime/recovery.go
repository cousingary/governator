package runtime

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/lifecycle"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/quota"
	"github.com/cousingary/governator/internal/runner"
	"github.com/cousingary/governator/internal/spend"
)

// stageOrder is the durable run state machine (Phase 4 plan). A run's
// progress is measured by the highest index reached in run_stages, not by
// runs.status alone, so a crash mid-runOnce is diagnosable from the ledger.
// QUARANTINED/ROLLED_BACK/ABANDONED are alternate terminal outcomes reachable
// from several points (not only after APPROVED) and are intentionally absent
// from this list — they are read from runs.status, never compared by index.
var stageOrder = []string{
	"PARSED", "PREFLIGHTED", "ROUTED", "QUOTA_RESERVED", "WORKSPACE_READY",
	"AGENT_RUNNING", "AUDITED", "VALIDATING", "ASSAYING", "MERGED", "APPROVED",
}

func stageIndex(stage string) int {
	for i, s := range stageOrder {
		if s == stage {
			return i
		}
	}
	return -1
}

// RecoveryVerdict is the outcome of one gov run resume/abandon/recover
// decision.
type RecoveryVerdict struct {
	RunID  string `json:"run_id"`
	Action string `json:"action"` // safe_resume | quarantined | already_terminal | still_running
	Detail string `json:"detail"`
}

// InspectRun returns a run record plus its full stage checkpoint history, for
// `gov run inspect`.
func InspectRun(runID string) (RunRecord, []observability.StageRecord, error) {
	r, err := Last(runID)
	if err != nil {
		return r, nil, err
	}
	db, err := dbOpen(Home())
	if err != nil {
		return r, nil, err
	}
	defer db.Close()
	stages, err := observability.StageHistory(db, r.ID)
	return r, stages, err
}

// ResumeRun evaluates one interrupted run (status still RUNNING because the
// process died before runOnce reached a terminal update) and applies the
// Phase 4 recovery rule: safe to discard as a fresh attempt, or quarantined
// because the agent may have left the worktree mid-edit. It always releases
// any open quota reservation and destroys any leftover worktree, whichever
// way the verdict falls — an interrupted run must never hold either resource
// hostage.
func ResumeRun(ctx context.Context, runID string) (RecoveryVerdict, error) {
	r, err := Last(runID)
	if err != nil {
		return RecoveryVerdict{RunID: runID}, err
	}
	if r.Status != "RUNNING" {
		return RecoveryVerdict{RunID: r.ID, Action: "already_terminal", Detail: "status=" + r.Status}, nil
	}
	if r.Root != "" && lockIsLive(r.Root, Home()) {
		return RecoveryVerdict{RunID: r.ID, Action: "still_running", Detail: "workspace lock is held by a live process"}, nil
	}
	db, err := dbOpen(Home())
	if err != nil {
		return RecoveryVerdict{RunID: r.ID}, err
	}
	defer db.Close()
	return recoverInterruptedRun(ctx, db, r, false)
}

// AbandonRun forces cleanup of an interrupted run regardless of how far it
// got, for an operator who has already decided the run cannot be trusted (or
// wants to reclaim resources without waiting on the fingerprint check).
func AbandonRun(runID string) (RecoveryVerdict, error) {
	r, err := Last(runID)
	if err != nil {
		return RecoveryVerdict{RunID: runID}, err
	}
	if r.Status != "RUNNING" {
		return RecoveryVerdict{RunID: r.ID, Action: "already_terminal", Detail: "status=" + r.Status}, nil
	}
	if r.Root != "" && lockIsLive(r.Root, Home()) {
		return RecoveryVerdict{RunID: r.ID, Action: "still_running", Detail: "workspace lock is held by a live process; refusing to abandon"}, nil
	}
	db, err := dbOpen(Home())
	if err != nil {
		return RecoveryVerdict{RunID: r.ID}, err
	}
	defer db.Close()
	return recoverInterruptedRun(context.Background(), db, r, true)
}

// RecoverStaleRuns scans every run still marked RUNNING and applies the same
// rule ResumeRun applies to one run, skipping any whose workspace lock is
// still held by a live process. It never touches an already-terminal run.
func RecoverStaleRuns(ctx context.Context) ([]RecoveryVerdict, error) {
	db, err := dbOpen(Home())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	// ORDER BY rowid, not created -- insertion order; created is TEXT RFC3339Nano (Sol14 P1-3).
	rows, err := db.Query(`SELECT id FROM runs WHERE status='RUNNING' ORDER BY rowid ASC`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	out := make([]RecoveryVerdict, 0, len(ids))
	for _, id := range ids {
		r, err := Last(id)
		if err != nil {
			return out, err
		}
		if r.Root != "" && lockIsLive(r.Root, Home()) {
			out = append(out, RecoveryVerdict{RunID: id, Action: "still_running", Detail: "workspace lock is held by a live process"})
			continue
		}
		v, err := recoverInterruptedRun(ctx, db, r, false)
		if err != nil {
			return out, err
		}
		out = append(out, v)
	}
	return out, nil
}

// recoverInterruptedRun classifies then cleans up one run whose lock is
// already known not to be live. forced=true (gov run abandon) always treats
// the run as safe to discard without consulting the fingerprint.
func recoverInterruptedRun(ctx context.Context, db *sql.DB, r RunRecord, forced bool) (RecoveryVerdict, error) {
	now := time.Now().UTC()
	stages, err := observability.StageHistory(db, r.ID)
	if err != nil {
		return RecoveryVerdict{RunID: r.ID}, err
	}
	var latestStage, latestDetail string
	if n := len(stages); n > 0 {
		latestStage, latestDetail = stages[n-1].Stage, stages[n-1].Detail
	}

	safe := true
	reason := "no agent work recorded before interruption"
	if idx := stageIndex(latestStage); idx >= stageIndex("AGENT_RUNNING") {
		// The agent may have started editing the worktree; only a
		// byte-identical worktree is safe to discard as a fresh attempt. A
		// missing worktree, a changed one, or a missing baseline digest are
		// all treated as unsafe (fail-closed) rather than guessed.
		safe = false
		switch {
		case r.Worktree == "":
			reason = "no worktree recorded"
		default:
			if baseline := stageWorktreeDigest(latestDetail); baseline == "" {
				reason = "no worktree baseline recorded"
			} else if cur, ferr := fingerprint(r.Worktree); ferr != nil {
				reason = "worktree unreadable: " + ferr.Error()
			} else if snapshotDigest(cur) == baseline {
				safe, reason = true, "worktree unchanged since agent launch"
			} else {
				reason = "worktree changed since agent launch"
			}
		}
	}
	if forced {
		safe, reason = true, "operator-forced abandon"
	}

	if err := quota.ReleaseForRun(db, r.ID, now); err != nil {
		return RecoveryVerdict{RunID: r.ID}, err
	}
	if err := spend.ReleaseForRun(db, r.ID, now); err != nil {
		return RecoveryVerdict{RunID: r.ID}, err
	}
	// Sol P1.6 (finding #13): a failed workspace/container teardown must
	// never be papered over by marking the run recovered/abandoned anyway —
	// that is exactly how a crashed Docker run left its container running
	// forever while the ledger called the run cleanly closed. A cleanup
	// failure is durably enqueued (destroyLeftoverWorkspace already did that)
	// and the run is left RUNNING so the next recovery pass (or `gov
	// reconcile` draining the enqueued opWorkspaceDestroy row) retries it;
	// only a successful teardown reaches the ABANDONED/QUARANTINED update
	// below.
	if ok := destroyLeftoverWorkspace(ctx, db, r, stages); !ok {
		detail := "workspace/container cleanup failed; retry enqueued to maintenance_outbox, run left RUNNING pending cleanup"
		if err := lifecycle.Record(db, r.ID, lifecycle.CleanupPending, detail, now.Format(time.RFC3339Nano)); err != nil {
			return RecoveryVerdict{RunID: r.ID}, err
		}
		return RecoveryVerdict{RunID: r.ID, Action: "cleanup_pending", Detail: detail}, nil
	}

	status := "ABANDONED"
	action := "safe_resume"
	if !safe {
		status, action = "QUARANTINED", "quarantined"
	}
	if _, err := db.Exec(`UPDATE runs SET status=?, message=? WHERE id=?`, status, reason, r.ID); err != nil {
		return RecoveryVerdict{RunID: r.ID}, err
	}
	if err := lifecycle.Record(db, r.ID, lifecycle.Stage(status), reason, now.Format(time.RFC3339Nano)); err != nil {
		return RecoveryVerdict{RunID: r.ID}, err
	}
	return RecoveryVerdict{RunID: r.ID, Action: action, Detail: reason}, nil
}

// workspaceDescriptorFromStages finds the WORKSPACE_READY stage row (it may
// not be the latest — a crash can happen many stages later) and decodes its
// workspaceDescriptor detail. Pre-S10 runs, and any run whose crash predates
// even WORKSPACE_READY, have no such row (or an empty/legacy detail); ok is
// false in both cases so the caller falls back to RunRecord's bare fields.
func workspaceDescriptorFromStages(stages []observability.StageRecord) (workspaceDescriptor, bool) {
	for _, s := range stages {
		if s.Stage != "WORKSPACE_READY" || s.Detail == "" {
			continue
		}
		var d workspaceDescriptor
		if err := json.Unmarshal([]byte(s.Detail), &d); err != nil {
			return workspaceDescriptor{}, false
		}
		if d.Path == "" {
			return workspaceDescriptor{}, false
		}
		return d, true
	}
	return workspaceDescriptor{}, false
}

// destroyLeftoverWorkspace tears down an interrupted run's workspace through
// the same runner.Destroy path the normal completion flow uses (Sol P1.6,
// finding #13) — never a bespoke, container-blind worktree-only cleanup.
// The WORKSPACE_READY descriptor (see newWorkspaceDescriptor) tells it which
// Runner kind and Container name were actually in play; a run recorded
// before that descriptor existed falls back to RunRecord's worktree/branch
// fields, exactly as before this session (local worktrees only — no run that
// predates the descriptor could have used the Docker runner).
//
// A no-op (returns true) when there is nothing left to tear down. Any
// Destroy failure is durably enqueued via the same maintenance_outbox
// opWorkspaceDestroy path `gov reconcile` already knows how to retry, and
// this function reports failure so the caller does not mark the run
// recovered/abandoned while a container may still be alive.
func destroyLeftoverWorkspace(ctx context.Context, db *sql.DB, r RunRecord, stages []observability.StageRecord) bool {
	kind := "local"
	ws := runner.Workspace{Path: r.Worktree, Root: r.Root, Branch: r.Branch, Git: r.Branch != ""}
	if d, ok := workspaceDescriptorFromStages(stages); ok {
		kind = d.Runner
		ws = runner.Workspace{Path: d.Path, Root: d.Root, Branch: d.Branch, Git: d.Git, Container: d.Container}
	}
	if ws.Path == "" && ws.Container == "" {
		return true
	}
	if ws.Path != "" && ws.Container == "" {
		if _, err := os.Stat(ws.Path); os.IsNotExist(err) {
			return true
		}
	}
	var rn runner.Runner = &runner.LocalWorktreeRunner{}
	if kind == "docker" {
		rn = &runner.DockerRunner{ControllerEnvironment: controllerenv.Freeze()}
	}
	destroyCtx, cancel := context.WithTimeout(ctx, workspaceCleanupTimeout)
	defer cancel()
	if err := rn.Destroy(destroyCtx, ws, true); err != nil {
		payload, _ := json.Marshal(workspaceDestroyPayload{
			Path: ws.Path, Root: ws.Root, Branch: ws.Branch, Git: ws.Git, Container: ws.Container, Approved: true,
		})
		noteOperationalFailure(db, r.ID, opWorkspaceDestroy, err, string(payload))
		return false
	}
	return true
}

// lockIsLive reports whether root's workspace lock currently points at a
// live process, without acquiring the lock itself.
func lockIsLive(root, home string) bool {
	return isLiveLock(lockPath(root, home))
}

// snapshotDigest collapses a worktree fingerprint into one deterministic
// digest so it can be stored as run_stages detail and compared across a
// process restart, without persisting the (potentially large) per-file map.
func snapshotDigest(s snapshot) string {
	names := make([]string, 0, len(s))
	for name := range s {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		st := s[name]
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write([]byte(st.Hash))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// stageWorktreeDigest extracts the worktree_digest field recorded in an
// AGENT_RUNNING stage's detail JSON, or "" if absent/unparseable.
func stageWorktreeDigest(detail string) string {
	if detail == "" {
		return ""
	}
	var v map[string]string
	if json.Unmarshal([]byte(detail), &v) != nil {
		return ""
	}
	return v["worktree_digest"]
}
