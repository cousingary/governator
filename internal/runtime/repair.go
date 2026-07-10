package runtime

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

// RunWithAutoRepair runs c and, when it quarantines and the contract opts
// into repair.auto, compiles and runs follow-up repair jobs against the same
// failure lineage, bounded by contracts.Repair.EffectiveMaxAttempts (which
// hard-clamps at 2 regardless of what the YAML requested). Each attempt goes
// through Run unmodified: its own lock, spend check, gate, and validators —
// a repair attempt can itself be refused by the spend cap or quarantine
// again with no special-casing.
//
// This is deliberately a wrapper around Run rather than logic nested inside
// it: Run holds an exclusive per-workspace lock for its own duration
// (released only via its deferred release() on return), so compiling and
// launching a repair attempt has to happen after the triggering run has
// fully returned and released that lock, not before. When repair.auto is
// unset or false — the default for every existing job YAML — this is a
// plain passthrough to Run with no behavior change.
func (r *Runner) RunWithAutoRepair(ctx context.Context, c contracts.Contract) (RunRecord, error) {
	rec, err := r.Run(ctx, c)
	if err != nil || rec.Status != "QUARANTINED" || c.Repair == nil || !c.Repair.Auto {
		return rec, err
	}
	// A run refused purely on the spend cap never reached a backend; firing
	// a repair would just be refused again for the identical reason.
	if rec.FailureTaxonomy == "SPEND_CAP" {
		return rec, nil
	}
	// Repairing a read-only job (scout/verifier/architect) makes no sense:
	// those modes carry an empty allowed.write/preflight.intended_writes by
	// contract, so a compiled repair attempt (which needs write.mode to make
	// any change) would fail Validate-shaped expectations even though Run
	// itself never calls Validate on a programmatically built contract.
	if c.Mode.ReadOnly() {
		return rec, nil
	}

	rootID := c.RepairLineage
	if rootID == "" {
		rootID = rec.ID
	}
	maxAttempts := c.Repair.EffectiveMaxAttempts()
	original := c
	current := rec

	for {
		db, dbErr := dbOpen(r.Home)
		if dbErr != nil {
			return current, dbErr
		}
		attempts, attErr := observability.RepairAttempts(db, rootID)
		db.Close()
		if attErr != nil {
			return current, attErr
		}
		if attempts >= maxAttempts {
			return current, nil
		}

		packet, packetErr := observability.GenerateRepairPacket(r.Home, current.ID)
		if packetErr != nil {
			return current, packetErr
		}
		repairContract := compileRepairContract(original, packet, rootID)

		next, runErr := r.Run(ctx, repairContract)
		if runErr != nil {
			return current, runErr
		}
		current = next
		if current.Status != "QUARANTINED" || current.FailureTaxonomy == "SPEND_CAP" {
			return current, nil
		}
	}
}

// compileRepairContract builds a governed repair job from a quarantined
// run's packet. It reuses the original contract's full envelope
// (workspace/allowed/forbidden/budget/preflight/success/output/repair) — the
// only differences are job_id, mode, the task text (which carries the
// packet), and the agent when repair.backend overrides it. RepairLineage
// tags the compiled contract so runtime.Run can attribute the resulting run
// to rootID without widening the public contract schema.
func compileRepairContract(original contracts.Contract, packet observability.RepairPacket, rootID string) contracts.Contract {
	repaired := original
	repaired.JobID = fmt.Sprintf("%s-repair-%d", original.JobID, time.Now().UTC().UnixNano())
	repaired.Mode = contracts.ModeRepair
	repaired.Task = repairTask(original.Task, packet)
	repaired.RepairLineage = rootID
	if original.Repair != nil && strings.TrimSpace(original.Repair.Backend) != "" {
		repaired.Agent = original.Repair.Backend
	}
	return repaired
}

// repairTask composes the repair job's task text from the original task plus
// the bounded evidence GenerateRepairPacket already gathered (taxonomy,
// message, violations, failed validators, touched files) — the same packet
// an operator would hand a manual `mode: repair` contract via
// `gov repair-packet`.
func repairTask(originalTask string, packet observability.RepairPacket) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Repair run %s (job %s), which quarantined as %s.\n\n", packet.RunID, packet.JobID, packet.Taxonomy)
	fmt.Fprintf(&b, "Original task:\n%s\n\n", strings.TrimSpace(originalTask))
	fmt.Fprintf(&b, "Quarantine message: %s\n", packet.Message)
	if len(packet.Violations) > 0 {
		fmt.Fprintf(&b, "\nViolations:\n- %s\n", strings.Join(packet.Violations, "\n- "))
	}
	if len(packet.Validators) > 0 {
		fmt.Fprintf(&b, "\nFailed validators:\n- %s\n", strings.Join(packet.Validators, "\n- "))
	}
	if len(packet.Files) > 0 {
		fmt.Fprintf(&b, "\nFiles touched by the failed attempt:\n- %s\n", strings.Join(packet.Files, "\n- "))
	}
	b.WriteString("\nDiagnose the failure and make the smallest change that satisfies the original task's success criteria without repeating the same violation.")
	return b.String()
}
