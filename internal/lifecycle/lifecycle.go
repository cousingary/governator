// Package lifecycle formalizes the run state machine that
// internal/runtime/recovery.go's stageOrder and internal/observability's
// run_stages ledger have modeled informally since Phase 4. Sol redteam v4
// S9 (agents/governator-sol-upgrade4-plan.md) asks for this as "an explicit
// type with tested transitions" — every RecordStage call site in the
// runtime package now goes through Record, which validates the edge from
// the run's last recorded stage before delegating to
// observability.RecordStage, instead of trusting each call site to only
// ever be reached in the right order.
//
// The plan's own narrative sketch of the lifecycle —
// CREATED -> ENVIRONMENT_FROZEN -> RESOURCES_RESERVED -> WORKSPACE_READY ->
// BACKEND_RUNNING -> DESCENDANTS_TERMINATED -> FINAL_STATE_CAPTURED ->
// TREE_APPROVED -> MERGE_INTENT -> TREE_COMMITTED -> LEDGER_FINALIZED ->
// COMPLETE — is a simplified macro view. The stages actually recorded by
// runtime.go are finer-grained (see Macro below for the mapping) and branch
// (a QUARANTINED run never reaches TREE_APPROVED; a non-git root never
// reaches MERGE_INTENT at all). This package models the real graph, not the
// narrative one, because only the real graph is enforceable.
package lifecycle

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/cousingary/governator/internal/observability"
)

// Stage is one checkpoint in a run's durable state machine. The string
// values are wire-compatible with the run_stages table and every existing
// caller of observability.RecordStage/StageHistory — this package adds
// validation on top of that ledger, it does not change its shape.
type Stage string

const (
	Parsed                 Stage = "PARSED"
	Preflighted            Stage = "PREFLIGHTED"
	Routed                 Stage = "ROUTED"
	QuotaReserved          Stage = "QUOTA_RESERVED"
	WorkspaceReady         Stage = "WORKSPACE_READY"
	AgentRunning           Stage = "AGENT_RUNNING"
	OutputTruncated        Stage = "OUTPUT_TRUNCATED"
	DescendantsTerminated  Stage = "DESCENDANTS_TERMINATED"
	Audited                Stage = "AUDITED"
	Validating             Stage = "VALIDATING"
	Assaying               Stage = "ASSAYING"
	FinalValidationBarrier Stage = "FINAL_VALIDATION_BARRIER"
	MergeIntent            Stage = "MERGE_INTENT"
	MergeApplied           Stage = "MERGE_APPLIED"
	RootCommitted          Stage = "ROOT_COMMITTED"
	Merged                 Stage = "MERGED"
	MergedLedgerPending    Stage = "MERGED_LEDGER_PENDING"
	LedgerFinalizing       Stage = "LEDGER_FINALIZING"
	Approved               Stage = "APPROVED"
	Quarantined            Stage = "QUARANTINED"
	Complete               Stage = "COMPLETE"
	RolledBack             Stage = "ROLLED_BACK"
	CleanupPending         Stage = "CLEANUP_PENDING"
	Abandoned              Stage = "ABANDONED"
)

// Macro names the plan's narrative macro-state a real Stage corresponds to,
// purely for documentation/reporting (e.g. `gov run inspect`) — it is never
// consulted by Validate.
func Macro(s Stage) string {
	switch s {
	case Parsed, Preflighted, Routed:
		return "ENVIRONMENT_FROZEN"
	case QuotaReserved:
		return "RESOURCES_RESERVED"
	case WorkspaceReady:
		return "WORKSPACE_READY"
	case AgentRunning, OutputTruncated:
		return "BACKEND_RUNNING"
	case DescendantsTerminated:
		return "DESCENDANTS_TERMINATED"
	case Audited, Validating, Assaying, FinalValidationBarrier:
		return "FINAL_STATE_CAPTURED"
	case MergeIntent:
		return "MERGE_INTENT"
	case MergeApplied, RootCommitted, Merged:
		return "TREE_COMMITTED"
	case Approved:
		return "TREE_APPROVED"
	case LedgerFinalizing, MergedLedgerPending:
		return "LEDGER_FINALIZED"
	case Complete:
		return "COMPLETE"
	default:
		return string(s)
	}
}

// terminal stages never have a validated forward transition. MergedLedgerPending
// is terminal from this package's point of view even though `gov reconcile`
// may later retry the specific write that failed (internal/runtime/reconcile.go
// opStageEvent) — that retry re-records the very stage that was already
// underway (LEDGER_FINALIZING, APPROVED, or QUARANTINED), it does not advance
// the graph, so it needs no edge here.
var terminalStages = map[Stage]bool{
	Complete:            true,
	RolledBack:          true,
	Abandoned:           true,
	MergedLedgerPending: true,
}

// transitions is the validated edge set for the primary run path, built
// directly from every observability.RecordStage call site in
// internal/runtime (runtime.go, policy_gate.go) as of Sol redteam v4 S9.
// Keep this in sync with those call sites: it is exercised as live
// enforcement by Record, not just by tests.
var transitions = map[Stage][]Stage{
	Parsed:                {Preflighted},
	Preflighted:           {Quarantined, Routed},
	Routed:                {Quarantined, QuotaReserved},
	QuotaReserved:         {WorkspaceReady, Quarantined},
	WorkspaceReady:        {AgentRunning},
	AgentRunning:          {OutputTruncated, DescendantsTerminated},
	OutputTruncated:       {DescendantsTerminated},
	DescendantsTerminated: {Audited},
	Audited:               {Validating},
	// Assaying is conditional on the contract declaring c.Assay != nil
	// (runtime.go:3046) — most runs skip it, going straight from Validating
	// to FinalValidationBarrier once every shell/PostRunValidate check has
	// passed.
	//
	// Quarantined is reachable directly from Validating/Assaying/MergeIntent
	// too: rec.Status (runtime.go:3192-3227) is written unconditionally at
	// the end of runOnce regardless of *when* violations first appeared.
	// FinalValidationBarrier/MergeApplied/RootCommitted are each recorded
	// only `if len(violations) == 0` at that specific point in the pipeline,
	// so a validator/assay/merge failure leaves whichever of those stages
	// was last successfully recorded, and the run proceeds straight to the
	// QUARANTINED write from there without ever reaching the next stage of
	// the happy path. (Found by running scripts/redteam.sh against this
	// table before trusting it — TestAttack1/2/3/4/19's hostile-hook/
	// pathspec fixtures all quarantine from exactly this shape of early
	// failure.)
	Validating: {Assaying, FinalValidationBarrier, Quarantined},
	Assaying:   {FinalValidationBarrier, Quarantined},
	// FinalValidationBarrier only ever reaches Quarantined directly (an
	// early merge-precondition failure, e.g. requireCleanLiveRoot); a
	// violations==0 run always attempts the Merged checkpoint next
	// (runtime.go:3163, unconditional on git vs non-git, outside the
	// `if git {}` branch below) — it is never a direct predecessor of
	// Approved. For a git root that attempt goes through MergeIntent ->
	// MergeApplied -> RootCommitted -> Merged; a non-git root skips straight
	// to Merged via captureRecall/mergeCopyChanged (runtime.go:3130-3162),
	// never recording MergeIntent at all.
	FinalValidationBarrier: {MergeIntent, Merged, Quarantined},
	MergeIntent:            {MergeApplied, Quarantined},
	MergeApplied:           {RootCommitted},
	RootCommitted:          {Merged, LedgerFinalizing, MergedLedgerPending},
	// Merged reaches Approved/Quarantined directly only for a non-git root:
	// rootCommitted (and therefore the LedgerFinalizing checkpoint,
	// runtime.go:3221) is exclusively a git-path concept. That non-git path
	// also never reaches Complete — runtime.go only records COMPLETE when
	// rootCommitted is true (line 3347) — a real gap flagged in the S9
	// findings log, not fixed here: S9's mandate is formalizing the graph
	// that exists, not changing which stages runOnce records.
	Merged:           {LedgerFinalizing, Approved, Quarantined, MergedLedgerPending},
	LedgerFinalizing: {Approved, Quarantined, MergedLedgerPending},
	Approved:         {Complete, RolledBack, MergedLedgerPending},
	Quarantined:      {Complete, MergedLedgerPending},
	// Complete's own runs.status column stays "APPROVED" — COMPLETE is only
	// ever a run_stages checkpoint, never written back to runs.status (see
	// runtime.go:3226-3348) — so `gov run rollback` (Rollback, called well
	// after the original run finished) checks r.Status=="APPROVED" but by
	// then the run's *latest recorded stage* is almost always COMPLETE, not
	// APPROVED itself. Discovered by this session's own migration of
	// Rollback's RecordStage call to lifecycle.Record: without this edge,
	// every rollback of a completed git run would fail closed.
	Complete: {RolledBack},
}

// recoveryTargets are reachable from any non-terminal stage: a crash can
// interrupt a run at any point, and internal/runtime/recovery.go's
// recoverInterruptedRun classifies whatever stage it finds into exactly one
// of these three outcomes (see recoverInterruptedRun's safe/forced logic).
// CleanupPending is not itself terminal — the next recovery pass retries
// from it — but its only validated successors are the other two recovery
// targets, so it is listed as its own source below rather than folded into
// terminalStages.
var recoveryTargets = map[Stage]bool{
	CleanupPending: true,
	Abandoned:      true,
	Quarantined:    true,
}

func init() {
	transitions[CleanupPending] = []Stage{CleanupPending, Abandoned, Quarantined}
}

// Validate reports whether next is a legal successor to the last stage in
// history (oldest-first, as returned by observability.StageHistory). An
// empty history requires next == Parsed. Re-recording the current latest
// stage is always legal (idempotent replay: this mirrors run_stages'
// ON CONFLICT(run_id,stage) DO NOTHING, which the same retry paths this
// package validates — e.g. reconcile.go's opStageEvent replay — rely on).
func Validate(history []Stage, next Stage) error {
	if len(history) == 0 {
		if next != Parsed {
			return fmt.Errorf("lifecycle: run has no recorded stage; only %s may be first, got %s", Parsed, next)
		}
		return nil
	}
	latest := history[len(history)-1]
	if next == latest {
		return nil
	}
	if !terminalStages[latest] {
		if recoveryTargets[next] {
			return nil
		}
	}
	for _, allowed := range transitions[latest] {
		if allowed == next {
			return nil
		}
	}
	if terminalStages[latest] {
		return fmt.Errorf("lifecycle: invalid transition %s -> %s: %s is terminal", latest, next, latest)
	}
	return fmt.Errorf("lifecycle: invalid transition %s -> %s", latest, next)
}

// Record validates that stage is a legal successor to runID's current
// latest recorded stage (via observability.StageHistory), then delegates to
// observability.RecordStage. It is the single choke point every
// RecordStage call site in internal/runtime now goes through — an
// out-of-order write (the exact shape of a crash-recovery or reconcile bug
// reordering the ledger) is rejected here instead of silently landing in
// run_stages.
func Record(db *sql.DB, runID string, stage Stage, detail, created string) error {
	rows, err := observability.StageHistory(db, runID)
	if err != nil {
		return err
	}
	history := make([]Stage, len(rows))
	for i, r := range rows {
		history[i] = Stage(r.Stage)
	}
	if err := Validate(history, stage); err != nil {
		return err
	}
	return observability.RecordStage(db, runID, string(stage), detail, created)
}

// Now formats the current instant the same way every call site already did
// inline (time.Now().UTC().Format(time.RFC3339Nano)) — pulled out here so
// migrated call sites are one line shorter, not to change the format.
func Now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
