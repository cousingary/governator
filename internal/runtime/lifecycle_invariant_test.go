package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/lifecycle"
)

// This file property-tests the five S9 lifecycle invariants
// (agents/governator-sol-upgrade4-plan.md, Session 9) against the real
// recovery code path, not just the graph in internal/lifecycle:
//
//   - "no approval before final state" and "no merge without an approved
//     tree hash" are graph-shape properties, tested exhaustively/randomly
//     in internal/lifecycle/lifecycle_test.go
//     (TestProperty_NoApprovalBeforeFinalState,
//     TestProperty_NoMergeWithoutPriorApprovalIntent) against the same
//     transitions table internal/runtime now records through
//     (lifecycle.Record, wired into every RecordStage call site this
//     session).
//   - "no reservation without settlement or recovery" and "no workspace
//     left unowned" are swept below across every stage a run could be
//     interrupted at, generalizing the three specific scenarios
//     recovery_test.go already covered (PreAgentRunning,
//     AgentRunningUnchanged, AgentRunningChanged) into full stage coverage.
//   - "no one-shot approval consumed without action" is
//     internal/observability.ConsumePolicyOverrideReservations' verify-all
//     -> consume-all -> commit transaction (Sol P1-5), already
//     property-tested by internal/observability/policy_checkpoints_test.go
//     and exercised black-box by internal/redteam/policy_race_test.go
//     (report §9 attack 18/20) — not duplicated here.

// TestLifecycleInvariant_RecoveryNeverLeaksReservationOrWorkspace sweeps
// every stage a run's process could plausibly die at (everything before the
// point runOnce commits to a terminal outcome) and asserts
// recoverInterruptedRun always ends with the run's quota reservation
// settled/released and its workspace destroyed — regardless of which stage
// the interruption happened at, and regardless of whether that leaves the
// run ABANDONED (safe to retry) or QUARANTINED (worktree may have been
// mid-edit). A resource leak at any one of these stages is exactly the
// failure mode Sol redteam v4 report finding "a detached child wrote into
// the live repo seconds after APPROVED" and its siblings describe.
func TestLifecycleInvariant_RecoveryNeverLeaksReservationOrWorkspace(t *testing.T) {
	interruptible := []lifecycle.Stage{
		lifecycle.Parsed, lifecycle.Preflighted, lifecycle.Routed,
		lifecycle.QuotaReserved, lifecycle.WorkspaceReady, lifecycle.AgentRunning,
		lifecycle.OutputTruncated, lifecycle.DescendantsTerminated, lifecycle.Audited,
		lifecycle.Validating, lifecycle.Assaying, lifecycle.FinalValidationBarrier,
	}
	for _, st := range interruptible {
		st := st
		t.Run(string(st), func(t *testing.T) {
			db, _, root := recoveryFixture(t)
			id := "run-" + string(st)
			work := filepath.Join(t.TempDir(), "work")
			if err := os.MkdirAll(work, 0700); err != nil {
				t.Fatal(err)
			}
			resID := seedInterruptedRun(t, db, id, root, work, "")
			stage(t, db, id, string(st), "")

			v, err := recoverInterruptedRun(context.Background(), db, RunRecord{ID: id, Root: root, Worktree: work, Status: "RUNNING"}, false)
			if err != nil {
				t.Fatalf("recoverInterruptedRun at %s: %v", st, err)
			}
			if v.Action != "safe_resume" && v.Action != "quarantined" {
				t.Fatalf("recoverInterruptedRun at %s: action=%q, want a terminal recovery outcome (safe_resume or quarantined)", st, v.Action)
			}
			if !reservationSettled(t, db, resID) {
				t.Fatalf("interrupted at %s: quota reservation %d was neither settled nor released", st, resID)
			}
			if _, err := os.Stat(work); !os.IsNotExist(err) {
				t.Fatalf("interrupted at %s: workspace %s was not destroyed", st, work)
			}
		})
	}
}

// TestLifecycleInvariant_RollbackReachesTerminalFromCompleteNotJustApproved
// is a regression test for a real bug this session's own migration to
// lifecycle.Record surfaced: Rollback (runtime.go) gates on
// r.Status=="APPROVED", but runs.status is never rewritten to "COMPLETE" —
// COMPLETE is only ever a run_stages checkpoint (recorded after the
// APPROVED stage checkpoint, runtime.go:3226-3348) — so by the time an
// operator runs `gov run rollback` against a finished git run, the run's
// *latest recorded stage* is COMPLETE, not APPROVED. Without the
// lifecycle.transitions[Complete] = {RolledBack} edge added alongside this
// test, every rollback of a completed run would fail closed with a
// lifecycle validation error despite runs.status correctly reading
// APPROVED.
func TestLifecycleInvariant_RollbackReachesTerminalFromCompleteNotJustApproved(t *testing.T) {
	history := []lifecycle.Stage{lifecycle.Approved, lifecycle.Complete}
	if err := lifecycle.Validate(history, lifecycle.RolledBack); err != nil {
		t.Fatalf("Validate(latest=COMPLETE, next=ROLLED_BACK) = %v, want nil (this is the real shape Rollback records against)", err)
	}
}
