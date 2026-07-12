package runtime

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cousingary/governator/internal/breaker"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/quota"
	"github.com/cousingary/governator/internal/runner"
	"github.com/cousingary/governator/internal/spend"
)

// Session 4 (Sol Phase 3): the runtime used to swallow every error from a
// handful of post-run secondary operations — breaker feedback, quota reset
// hints, spend-halt recalculation, workspace/container destruction, and a few
// best-effort audit-row writes that shared the same "must never block an
// already-decided run" philosophy. An approved or quarantined result must
// stay exactly as decided, but the failure itself must never simply vanish.
// These op_kind constants name every operation `gov reconcile` knows how to
// retry from a durable maintenance_outbox row.
const (
	opBreakerFailure   = "breaker_record_failure"
	opBreakerSuccess   = "breaker_record_success"
	opQuotaResetHint   = "quota_reset_hint"
	opQuotaRelease     = "quota_release"
	opSpendHaltCheck   = "spend_halt_check"
	opWorkspaceDestroy = "workspace_destroy"
	opPolicyRuleEvents = "policy_rule_events"
	opStageEvent       = "stage_event"
	opPanelMembers     = "panel_members"
	opAssayEvaluation  = "assay_evaluation"
	opRunUpdate        = "run_update"
	opRunCompletion    = "run_completion"
	opRunArtifacts     = "run_artifacts"
	opQuotaSettle      = "quota_settle"
)

type breakerFeedbackPayload struct {
	Agent       string `json:"agent"`
	FailureKind string `json:"failure_kind,omitempty"`
}

type quotaResetHintPayload struct {
	Agent   string    `json:"agent"`
	Account string    `json:"account"`
	ResetAt time.Time `json:"reset_at"`
}

type quotaReleasePayload struct {
	ReservationID int64 `json:"reservation_id"`
}

type quotaSettlePayload struct {
	ReservationID int64   `json:"reservation_id"`
	Measured      float64 `json:"measured"`
}

type workspaceDestroyPayload struct {
	Path      string `json:"path"`
	Root      string `json:"root"`
	Branch    string `json:"branch"`
	Git       bool   `json:"git"`
	Container string `json:"container,omitempty"`
	Approved  bool   `json:"approved"`
}

type stageEventPayload struct {
	RunID  string `json:"run_id"`
	Stage  string `json:"stage"`
	Detail string `json:"detail"`
}

type policyRuleEventsPayload struct {
	Rows []observability.PolicyRuleEventRecord `json:"rows"`
}

type panelMembersPayload struct {
	Records []observability.PanelMemberRecord `json:"records"`
	Created string                            `json:"created"`
}

type assayEvaluationPayload struct {
	Record observability.AssayEvaluationRecord `json:"record"`
}

type runUpdatePayload struct {
	Record   RunRecord `json:"record"`
	Approved string    `json:"approved"`
}

type completionPayload struct {
	Record observability.Completion `json:"record"`
}

type artifactsPayload struct {
	Records []observability.ArtifactRecord `json:"records"`
	Created string                         `json:"created"`
}

// noteOperationalFailure ensures a best-effort operation's error is never
// simply dropped: an operational_errors row captures it for the audit trail,
// and a maintenance_outbox row lets `gov reconcile` finish the work later.
// Both writes go to the same ledger db as the failed operation itself, so a
// truly dead database can still lose the record — at that point the failure
// is surfaced on stderr as the absolute last resort rather than silently
// discarded.
func noteOperationalFailure(db *sql.DB, runID, opKind string, opErr error, payload string) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := observability.RecordOperationalError(db, observability.OperationalError{
		RunID: runID, OpKind: opKind, Detail: opErr.Error(), Created: now,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "governator: operational_errors write failed (op=%s run=%s cause=%v): %v\n", opKind, runID, opErr, err)
	}
	if err := observability.EnqueueOutbox(db, runID, opKind, payload, now); err != nil {
		fmt.Fprintf(os.Stderr, "governator: maintenance_outbox enqueue failed (op=%s run=%s cause=%v): %v\n", opKind, runID, opErr, err)
	}
}

// ReconcileOutcome is one outbox row's fate during a single `gov reconcile`
// pass.
type ReconcileOutcome struct {
	ID     int64  `json:"id"`
	RunID  string `json:"run_id"`
	OpKind string `json:"op_kind"`
	Status string `json:"status"` // done | retry
	Error  string `json:"error,omitempty"`
}

// ReconcileReport summarizes one `gov reconcile` pass.
type ReconcileReport struct {
	Processed int                `json:"processed"`
	Done      int                `json:"done"`
	Retried   int                `json:"retried"`
	Outcomes  []ReconcileOutcome `json:"outcomes"`
}

// Reconcile drains every pending maintenance_outbox row: each is retried
// against the same operation the original best-effort call attempted. A row
// that succeeds is marked done; a row that fails again stays pending with its
// attempts counter incremented, ready for the next reconcile pass (or for
// `gov cleanup --stale` to give up on, once attempts crosses the caller's
// threshold).
func Reconcile(ctx context.Context) (ReconcileReport, error) {
	db, err := dbOpen(Home())
	if err != nil {
		return ReconcileReport{}, err
	}
	defer db.Close()
	cfg := config.Current()
	items, err := observability.PendingOutbox(db)
	if err != nil {
		return ReconcileReport{}, err
	}
	report := ReconcileReport{}
	for _, item := range items {
		report.Processed++
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if opErr := dispatchReconcile(ctx, db, cfg, item); opErr != nil {
			if err := observability.MarkOutboxRetry(db, item.ID, opErr.Error(), now); err != nil {
				return report, err
			}
			report.Retried++
			report.Outcomes = append(report.Outcomes, ReconcileOutcome{ID: item.ID, RunID: item.RunID, OpKind: item.OpKind, Status: "retry", Error: opErr.Error()})
			continue
		}
		if err := observability.MarkOutboxDone(db, item.ID, now); err != nil {
			return report, err
		}
		report.Done++
		report.Outcomes = append(report.Outcomes, ReconcileOutcome{ID: item.ID, RunID: item.RunID, OpKind: item.OpKind, Status: "done"})
	}
	return report, nil
}

// dispatchReconcile re-attempts one outbox row's operation from its payload
// alone — no in-memory state from the original run survives a process
// restart, so every op_kind must be fully reconstructable from JSON.
func dispatchReconcile(ctx context.Context, db *sql.DB, cfg config.Config, item observability.OutboxItem) error {
	switch item.OpKind {
	case opBreakerFailure:
		var p breakerFeedbackPayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return breaker.RecordFailure(db, p.Agent, p.FailureKind, time.Now().UTC())
	case opBreakerSuccess:
		var p breakerFeedbackPayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return breaker.RecordSuccess(db, p.Agent, time.Now().UTC())
	case opQuotaResetHint:
		var p quotaResetHintPayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return quota.ApplyResetHint(db, p.Agent, p.Account, p.ResetAt, time.Now().UTC())
	case opQuotaRelease:
		var p quotaReleasePayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return quota.Release(db, p.ReservationID, time.Now().UTC())
	case opQuotaSettle:
		var p quotaSettlePayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return quota.Settle(db, p.ReservationID, p.Measured, time.Now().UTC())
	case opSpendHaltCheck:
		return spend.MaybeHalt(cfg, db)
	case opWorkspaceDestroy:
		var p workspaceDestroyPayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return reconcileWorkspaceDestroy(ctx, p)
	case opPolicyRuleEvents:
		var p policyRuleEventsPayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return observability.RecordPolicyRuleEvents(db, p.Rows)
	case opStageEvent:
		var p stageEventPayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return observability.RecordStage(db, p.RunID, p.Stage, p.Detail, time.Now().UTC().Format(time.RFC3339Nano))
	case opPanelMembers:
		var p panelMembersPayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return observability.RecordPanelMembers(db, p.Records, p.Created)
	case opAssayEvaluation:
		var p assayEvaluationPayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return observability.RecordAssayEvaluation(db, p.Record)
	case opRunUpdate:
		var p runUpdatePayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return updateRun(db, p.Record, p.Approved)
	case opRunCompletion:
		var p completionPayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return observability.RecordCompletion(db, p.Record)
	case opRunArtifacts:
		var p artifactsPayload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			return err
		}
		return observability.RecordArtifacts(db, p.Records, p.Created)
	default:
		return fmt.Errorf("reconcile: unknown op_kind %q", item.OpKind)
	}
}

// reconcileWorkspaceDestroy re-attempts a workspace/container teardown from
// nothing but the Workspace fields recorded at enqueue time. Container
// removal goes through runner.RemoveContainer, which tolerates ONLY the
// already-gone case — any real failure (daemon down, permission) propagates
// so the outbox row stays pending instead of being marked done while a live
// container leaks. The worktree/copy teardown reuses
// LocalWorktreeRunner.Destroy, whose logic is identical for both runner
// kinds once the container itself is out of the picture.
func reconcileWorkspaceDestroy(ctx context.Context, p workspaceDestroyPayload) error {
	if p.Container != "" {
		if err := runner.RemoveContainer(ctx, p.Container); err != nil {
			return err
		}
	}
	ws := runner.Workspace{Path: p.Path, Root: p.Root, Branch: p.Branch, Git: p.Git, Container: p.Container}
	return runner.LocalWorktreeRunner{}.Destroy(ctx, ws, p.Approved)
}

// CleanupReport summarizes one `gov cleanup --stale` pass.
type CleanupReport struct {
	Deadened int     `json:"deadened"`
	IDs      []int64 `json:"ids"`
}

// CleanupStale terminalizes ("dead") every pending outbox row that has
// already failed at least maxAttempts retries, so `gov reconcile` stops
// looping on an operation that has proven unrecoverable. Rows are never
// deleted — the audit trail (operational_errors, plus the outbox row itself
// with its last_error) survives; only its "pending" status changes so it no
// longer competes for reconcile's attention.
func CleanupStale(maxAttempts int) (CleanupReport, error) {
	db, err := dbOpen(Home())
	if err != nil {
		return CleanupReport{}, err
	}
	defer db.Close()
	items, err := observability.StaleOutbox(db, maxAttempts)
	if err != nil {
		return CleanupReport{}, err
	}
	report := CleanupReport{}
	for _, item := range items {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		reason := fmt.Sprintf("gave up after %d attempts (last_error=%s)", item.Attempts, item.LastError)
		if err := observability.MarkOutboxDead(db, item.ID, reason, now); err != nil {
			return report, err
		}
		report.Deadened++
		report.IDs = append(report.IDs, item.ID)
	}
	return report, nil
}
