//go:build redteam

package redteam

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runtimePackageDir is internal/runtime, relative to this package's own
// directory (Go test binaries run with their own package directory as the
// working directory) — used by attack 17's cross-package existence check
// below, the same "assert the real fixture still exists" pattern S6 uses
// for the cross-repo Assayer attacks (13/14/16 in assayer_test.go).
const runtimePackageDir = "../runtime"
const observabilityPackageDir = "../observability"
const pathsafePackageDir = "../pathsafe"

func assertRuntimeTestFileContains(t *testing.T, relPath string, markers ...string) {
	t.Helper()
	assertPackageFileContains(t, runtimePackageDir, relPath, markers...)
}

func assertObservabilityTestFileContains(t *testing.T, relPath string, markers ...string) {
	t.Helper()
	assertPackageFileContains(t, observabilityPackageDir, relPath, markers...)
}

func assertPathsafeTestFileContains(t *testing.T, relPath string, markers ...string) {
	t.Helper()
	assertPackageFileContains(t, pathsafePackageDir, relPath, markers...)
}

func assertPackageFileContains(t *testing.T, packageDir, relPath string, markers ...string) {
	t.Helper()
	path := filepath.Join(packageDir, relPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture file missing (%s): %v -- the real regression test for this attack must live here", path, err)
	}
	content := string(data)
	for _, marker := range markers {
		if !strings.Contains(content, marker) {
			t.Fatalf("%s no longer contains %q -- the Sol redteam v4 regression fixture for this attack appears to have been removed", path, marker)
		}
	}
}

// TestAttack17DoctrineChangesBetweenEvaluationAndIdentity is report P1-3 /
// §9 attack 17: project doctrine (.governator-doctrine.yaml) used to be
// re-read independently during policy evaluation and again during identity
// construction; a change landing in that window let the policy decision and
// the recorded identity disagree about which doctrine ran. Fixed by S7:
// internal/runtime.PolicyBundle (policy_gate.go) compiles org policy +
// project doctrine + contract policy into one immutable object, loaded
// exactly once (loadPolicyBundle) before the first gate call in runOnce and
// passed unchanged to both evaluatePolicyGate and computeExecutionIdentity.
//
// The real regression test lives in internal/runtime (this package can't
// import another package's _test.go file, and simulating the actual mid-run
// timing race black-box would need a fault-injection hook that doesn't exist
// -- see internal/spend's equivalent gap noted for attack 20/P1-10). This
// test only proves that fixture still exists:
// internal/runtime/policy_gate_test.go::
// TestPolicyBundleSharedBetweenGateAndIdentityIgnoresLaterDoctrineEdit.
func TestAttack17DoctrineChangesBetweenEvaluationAndIdentity(t *testing.T) {
	assertRuntimeTestFileContains(t, "policy_gate_test.go",
		"func TestPolicyBundleSharedBetweenGateAndIdentityIgnoresLaterDoctrineEdit",
	)
	assertRuntimeTestFileContains(t, "policy_gate.go",
		"type PolicyBundle struct",
		"func loadPolicyBundle(",
	)
}

// TestAttack18SecondOneShotApprovalConsumptionFails is report P1-5 / §9
// attack 18: two one-shot approvals used to be consumed one by one; the
// second consumption failing after the first had already been burned meant
// execution never began but the first approval was gone anyway. Fixed by
// S7: observability.ConsumePolicyOverrideReservations consumes the whole
// expected approval set as one transaction (verify each still reserved,
// UPDATE each, commit only if every one succeeded) — runtime.go's execution
// boundary calls it once with the full pendingOneShotIDs slice instead of
// looping over ConsumePolicyOverrideReservation per id.
//
// The real regression test lives in internal/observability (a
// database/sql-transaction-level property, not something this black-box
// corpus can exercise without its own SQLite handle and direct override
// bookkeeping — same class of gap as attack 20/P1-10's spend settlement
// race). This test only proves that fixture still exists:
// internal/observability/policy_checkpoints_test.go::
// TestConsumePolicyOverrideReservationsIsAllOrNothing.
func TestAttack18SecondOneShotApprovalConsumptionFails(t *testing.T) {
	assertObservabilityTestFileContains(t, "policy_checkpoints_test.go",
		"func TestConsumePolicyOverrideReservationsIsAllOrNothing",
	)
	assertObservabilityTestFileContains(t, "policy_checkpoints.go",
		"func ConsumePolicyOverrideReservations(",
	)
}
