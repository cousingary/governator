package lifecycle

import (
	"math/rand"
	"testing"
)

// allStages enumerates every constant this package defines, used to drive
// exhaustive/randomized property tests below rather than hand-picking a
// subset of pairs.
var allStages = []Stage{
	Parsed, Preflighted, Routed, QuotaReserved, WorkspaceReady, AgentRunning,
	OutputTruncated, DescendantsTerminated, Audited, Validating, Assaying,
	FinalValidationBarrier, MergeIntent, MergeApplied, RootCommitted, Merged,
	MergedLedgerPending, LedgerFinalizing, Approved, Quarantined, Complete,
	RolledBack, CleanupPending, Abandoned,
}

func TestValidate_EmptyHistoryOnlyAcceptsParsed(t *testing.T) {
	if err := Validate(nil, Parsed); err != nil {
		t.Fatalf("Parsed as first stage: %v", err)
	}
	for _, s := range allStages {
		if s == Parsed {
			continue
		}
		if err := Validate(nil, s); err == nil {
			t.Fatalf("%s accepted as first stage, want rejected", s)
		}
	}
}

func TestValidate_IdempotentReplayAlwaysAllowed(t *testing.T) {
	// run_stages has ON CONFLICT(run_id,stage) DO NOTHING — reconcile.go's
	// opStageEvent replay depends on re-recording the same stage being a
	// legal no-op, including from every terminal stage.
	for _, s := range allStages {
		if err := Validate([]Stage{s}, s); err != nil {
			t.Fatalf("idempotent replay of %s rejected: %v", s, err)
		}
	}
}

func TestValidate_TerminalStagesRejectForwardProgress(t *testing.T) {
	for terminal := range terminalStages {
		declared := map[Stage]bool{}
		for _, s := range transitions[terminal] {
			declared[s] = true
		}
		for _, next := range allStages {
			if next == terminal {
				continue // idempotent replay, covered above
			}
			if declared[next] {
				// An explicit, deliberate exception (e.g. Complete ->
				// RolledBack for `gov run rollback`, which by design acts
				// on an already-completed run) — covered by
				// TestValidate_EveryDeclaredEdgeIsAccepted, not a forward-
				// progress leak this test is trying to catch.
				continue
			}
			if recoveryTargets[next] && terminal != next {
				// A terminal run can still be reclassified by a later
				// recovery pass in principle; only Complete/RolledBack are
				// truly closed to it. MergedLedgerPending and Abandoned are
				// the two terminal stages recoveryTargets could still touch.
				if terminal == Complete || terminal == RolledBack {
					if err := Validate([]Stage{terminal}, next); err == nil {
						t.Fatalf("%s -> %s accepted, want rejected: %s is closed to recovery", terminal, next, terminal)
					}
				}
				continue
			}
			if err := Validate([]Stage{terminal}, next); err == nil {
				t.Fatalf("%s -> %s accepted, want rejected: %s is terminal", terminal, next, terminal)
			}
		}
	}
}

func TestValidate_EveryDeclaredEdgeIsAccepted(t *testing.T) {
	for from, tos := range transitions {
		for _, to := range tos {
			if err := Validate([]Stage{from}, to); err != nil {
				t.Fatalf("declared edge %s -> %s rejected: %v", from, to, err)
			}
		}
	}
}

func TestValidate_RecoveryJumpAllowedFromAnyNonTerminalStage(t *testing.T) {
	for _, from := range allStages {
		if terminalStages[from] {
			continue
		}
		for target := range recoveryTargets {
			if err := Validate([]Stage{from}, target); err != nil {
				t.Fatalf("recovery jump %s -> %s rejected: %v", from, target, err)
			}
		}
	}
}

// TestValidate_UndeclaredEdgesAreRejected is the mutation-testing half of
// the graph's coverage: for every pair not in transitions, not an
// idempotent replay, and not a recovery jump, Validate must reject it. This
// is what makes the graph a real allowlist rather than decoration — without
// it, a typo'd extra edge in `transitions` (or Validate silently allowing
// too much) would pass every positive test above and still be broken.
func TestValidate_UndeclaredEdgesAreRejected(t *testing.T) {
	declared := map[[2]Stage]bool{}
	for from, tos := range transitions {
		for _, to := range tos {
			declared[[2]Stage{from, to}] = true
		}
	}
	for _, from := range allStages {
		for _, to := range allStages {
			if from == to {
				continue
			}
			if declared[[2]Stage{from, to}] {
				continue
			}
			if !terminalStages[from] && recoveryTargets[to] {
				continue
			}
			if err := Validate([]Stage{from}, to); err == nil {
				t.Fatalf("undeclared edge %s -> %s accepted, want rejected", from, to)
			}
		}
	}
}

// walk performs one randomized traversal of the graph starting at Parsed,
// always following a declared edge (never a recovery jump, so every walk
// models an uninterrupted run), and stops at the first terminal stage or
// after a generous step bound.
func walk(rng *rand.Rand) []Stage {
	history := []Stage{Parsed}
	for i := 0; i < 64; i++ {
		cur := history[len(history)-1]
		if terminalStages[cur] {
			return history
		}
		next := transitions[cur]
		if len(next) == 0 {
			return history
		}
		history = append(history, next[rng.Intn(len(next))])
	}
	return history
}

func indexOf(history []Stage, s Stage) int {
	for i, h := range history {
		if h == s {
			return i
		}
	}
	return -1
}

// TestProperty_NoApprovalBeforeFinalState is the plan's first S9 invariant:
// "no approval before final state." Every randomly generated valid run
// walk that reaches Approved must have passed through
// FinalValidationBarrier first — Approved has no in-edge from anywhere else
// in the graph (see transitions), so this also serves as a regression test
// against a future edit accidentally adding one.
func TestProperty_NoApprovalBeforeFinalState(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	found := false
	for i := 0; i < 2000; i++ {
		h := walk(rng)
		ai := indexOf(h, Approved)
		if ai < 0 {
			continue
		}
		found = true
		fi := indexOf(h, FinalValidationBarrier)
		if fi < 0 || fi >= ai {
			t.Fatalf("walk reached Approved without FinalValidationBarrier first: %v", h)
		}
	}
	if !found {
		t.Fatal("no random walk reached Approved in 2000 tries; property is vacuous — widen the walk bound")
	}
}

// TestProperty_NoMergeWithoutPriorApprovalIntent is the plan's second S9
// invariant: "no merge without an approved tree hash." MergeIntent's detail
// (runtime.go:3081-3082) is where the pre-merge path set is recorded before
// internal/gitplumb independently computes and verifies the tree hash
// (Sol redteam v4 S1); RootCommitted is only reachable through
// MergeApplied, whose only in-edge is MergeIntent. This test asserts that
// structural fact holds for every walk (and therefore that gitplumb's own
// hash verification, tested in internal/gitplumb, is never bypassable by a
// lifecycle-level shortcut straight to RootCommitted).
func TestProperty_NoMergeWithoutPriorApprovalIntent(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	found := false
	for i := 0; i < 2000; i++ {
		h := walk(rng)
		ri := indexOf(h, RootCommitted)
		if ri < 0 {
			continue
		}
		found = true
		mi := indexOf(h, MergeIntent)
		ma := indexOf(h, MergeApplied)
		if mi < 0 || ma < 0 || mi >= ma || ma >= ri {
			t.Fatalf("walk reached RootCommitted without MergeIntent -> MergeApplied strictly before it: %v", h)
		}
	}
	if !found {
		t.Fatal("no random walk reached RootCommitted in 2000 tries; property is vacuous — widen the walk bound")
	}
}

// TestProperty_CompleteOnlyAfterApprovedOrQuarantined guards the flip side
// of the first invariant: nothing reaches the durable-success terminal
// stage without first landing on one of the two decisions that are allowed
// to precede it.
func TestProperty_CompleteOnlyAfterApprovedOrQuarantined(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	found := false
	for i := 0; i < 2000; i++ {
		h := walk(rng)
		ci := indexOf(h, Complete)
		if ci < 0 {
			continue
		}
		found = true
		ai, qi := indexOf(h, Approved), indexOf(h, Quarantined)
		if (ai < 0 || ai >= ci) && (qi < 0 || qi >= ci) {
			t.Fatalf("walk reached Complete without Approved or Quarantined strictly before it: %v", h)
		}
	}
	if !found {
		t.Fatal("no random walk reached Complete in 2000 tries; property is vacuous — widen the walk bound")
	}
}

// TestMacro_EveryStageMaps is a cheap completeness check: Macro must have
// an explicit case for every constant this package declares (the default
// branch returning the raw stage name would otherwise hide a forgotten
// mapping instead of failing a test).
func TestMacro_EveryStageMaps(t *testing.T) {
	explicit := map[string]bool{
		"ENVIRONMENT_FROZEN": true, "RESOURCES_RESERVED": true, "WORKSPACE_READY": true,
		"BACKEND_RUNNING": true, "DESCENDANTS_TERMINATED": true, "FINAL_STATE_CAPTURED": true,
		"MERGE_INTENT": true, "TREE_COMMITTED": true, "TREE_APPROVED": true,
		"LEDGER_FINALIZED": true, "COMPLETE": true,
	}
	for _, s := range allStages {
		if s == CleanupPending || s == Abandoned || s == Quarantined || s == RolledBack {
			continue // alternate/recovery outcomes have no macro-narrative equivalent
		}
		if got := Macro(s); !explicit[got] {
			t.Fatalf("Macro(%s) = %q, not one of the plan's named macro-states — Macro's switch is missing a case for it", s, got)
		}
	}
}
