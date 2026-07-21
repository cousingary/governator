//go:build redteam

// v10_s3_cleanup_ordering_test.go implements Sol10 P0-3's mandatory
// red-team corpus (agents/governator-sol-upgrade10.md "P0-3: Cleanup can
// mutate the tree after it passed success validation",
// agents/governator-sol-upgrade10-rc4-plan.md Session 3, report cases
// 15-20): the pre-fix pipeline ran backend -> success validators -> cleanup
// validators -> PostRunValidate -> Assay -> final structural barrier ->
// merge, so an optional (Cleanup.Required: false) cleanup validator could
// mutate an already-approved file, exit nonzero, add no violation, and
// merge -- the final barrier only checks forbidden/protected paths,
// budgets, required files and artifact identities, never the
// contract-specific correctness tests a success validator embodies.
//
// Fixed (runtime.go's runOnce), cleanup now runs BEFORE success validators,
// so every mutation-capable stage precedes every stage that judges
// correctness; and a failed OPTIONAL cleanup validator that declared real
// write authority (ValidatorSpec.WriteRoots) has its exact declared files
// restored to their pre-attempt bytes (runtime.go's
// snapshotPathsUnderRoots/captureRecall/restoreRecall) before anything
// downstream ever sees the partial mutation.
//
// Case 15: a corrupting, nonzero-exit optional cleanup never merges its
// corrupted bytes (restore makes the run proceed on the ORIGINAL bytes
// instead -- "restore the pre-cleanup snapshot, or quarantine" sanctions
// either outcome; this fixture exercises the restore-then-proceed path and
// proves the corrupted bytes specifically never survive to the merge).
// Case 16: a SUCCESSFUL (exit 0) cleanup that spoils content a success
// validator was already going to check must still be caught, because that
// validator now runs after cleanup, not before it.
// Case 17: a cleanup validator killed mid-write by the run's own deadline
// (the "partial write" case) restores its pre-attempt bytes exactly like a
// clean nonzero exit -- restore triggers on any (code != 0 || err != nil)
// optional-cleanup failure, not just a clean process exit.
// Case 18: a cleanup mutation is exactly what the final structural
// barrier/merge sees -- proving there is no later mutation-capable stage
// that could still drop or revert it.
// Case 19: restore is unconditional on a declared write root, independent
// of whether any validator happens to check that specific file's content --
// a real safety net, not incidental coverage from a well-aimed validator.
// Case 20: a success validator that can only pass against cleanup's
// post-mutation bytes does pass -- direct proof success validators run
// strictly after the last cleanup mutation, never before it.
package redteam

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/toolregistry"
)

// v10s3EnrollTools registers each named tool's real resolved path in the
// trusted-tool registry, mirroring TestV7Case8's enrollment pattern:
// structured cleanup validators run under a sealed PATH built exclusively
// from ValidatorSpec.Tools (Sol9 P0-4), so every declared tool has to be
// enrolled before sealedValidatorToolsets can resolve it.
func v10s3EnrollTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("look up declared tool %q: %v", tool, err)
		}
		if canonical, cerr := filepath.EvalSymlinks(path); cerr == nil {
			path = canonical
		}
		if _, err := toolregistry.Enroll(tool, path); err != nil {
			t.Fatalf("enroll declared tool %q: %v", tool, err)
		}
	}
}

func TestV10Case15OptionalCleanupCorruptionWithNonzeroExitDoesNotMerge(t *testing.T) {
	v10s3EnrollTools(t, "printf")
	root := fixtureRepo(t)
	c := baseContract(root)
	// Without the restore, this validator would fail against the corrupted
	// bytes and the run would quarantine -- APPROVED here is only possible
	// because the failed cleanup's corruption never reached it.
	c.Success.Validators = append(c.Success.Validators, `[ "$(cat output/result.txt)" = "ok" ]`)
	corrupt := `printf 'CORRUPTED-BY-CLEANUP' > output/result.txt; exit 1`
	c.Cleanup = &contracts.Cleanup{
		Required:       false,
		Validators:     []string{corrupt},
		ValidatorSpecs: []contracts.ValidatorSpec{{Command: corrupt, Tools: []string{"printf"}, WriteRoots: []string{"output"}}},
	}
	bin := fakeBackend(t, standardBackendBody(""))
	rec := runGoverned(t, t.TempDir(), bin, c)
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED (a failed optional cleanup restores its pre-attempt bytes, so the success validator sees the ORIGINAL content), got status=%s message=%s", rec.Status, rec.Message)
	}
	got := gitOutput(t, root, "show", "HEAD:output/result.txt")
	if got != "ok\n" {
		t.Fatalf("merged output/result.txt = %q, want the original %q -- a failed optional cleanup's corrupted bytes must never merge", got, "ok\n")
	}
}

func TestV10Case16SuccessfulCleanupInvalidatingPassingValidatorBlocksApproval(t *testing.T) {
	v10s3EnrollTools(t, "printf")
	root := fixtureRepo(t)
	c := baseContract(root)
	c.Success.Validators = append(c.Success.Validators, `[ "$(cat output/result.txt)" = "ok" ]`)
	spoil := `printf 'SPOILED-BY-SUCCESSFUL-CLEANUP' > output/result.txt`
	c.Cleanup = &contracts.Cleanup{
		Required:       false,
		Validators:     []string{spoil},
		ValidatorSpecs: []contracts.ValidatorSpec{{Command: spoil, Tools: []string{"printf"}, WriteRoots: []string{"output"}}},
	}
	bin := fakeBackend(t, standardBackendBody(""))
	rec, err := runGovernedAllowError(t, t.TempDir(), bin, c)
	if err != nil {
		t.Fatalf("RunWithAutoRepair: %v", err)
	}
	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected QUARANTINED (a successful-but-content-altering cleanup pass must still be re-validated by the success validator that runs after it), got status=%s message=%s", rec.Status, rec.Message)
	}
	if !strings.Contains(rec.Message, "validator failed") {
		t.Fatalf("expected quarantine message naming the failed success validator, got: %s", rec.Message)
	}
}

// TestV10Case17CleanupPartialWriteBeforeTimeoutRestoresPreCleanupState needs
// the run's own deadline to genuinely expire mid-validator, so it runs for
// roughly the full budget.max_minutes=1 (60s) before the kill lands -- an
// int minute is the smallest unit Budget.MaxMinutes accepts (contracts
// rejects <= 0), so there is no faster real-timing way to exercise the
// "partial write, then the process is killed by the deadline" path.
//
// A cleanup validator killed by the run's OWN budget deadline is not the
// same case as a cleanup validator that merely exits nonzero (case 15): the
// run's shared ctx (runOnce binds it to budget.max_minutes via
// context.WithTimeout) is now permanently Done, so every downstream stage
// -- success validators, PostRunValidate, the final merge -- necessarily
// fails too and the run legitimately QUARANTINEs; there is no ctx left for
// any stage to still reach APPROVED on, restore or not. What restore must
// still guarantee even here is that the quarantine record it leaves behind
// captures the pre-cleanup bytes, not cleanup's partial write -- proven by
// reading the preserved quarantine commit itself (rec.Commit), independent
// of root's HEAD which a QUARANTINED run never touches.
func TestV10Case17CleanupPartialWriteBeforeTimeoutRestoresPreCleanupState(t *testing.T) {
	v10s3EnrollTools(t, "sleep", "sh", "printf")
	root := fixtureRepo(t)
	c := baseContract(root)
	c.Budget.MaxMinutes = 1
	c.Success.Validators = append(c.Success.Validators, `[ "$(cat output/result.txt)" = "ok" ]`)
	hang := `printf 'PARTIAL-BEFORE-TIMEOUT' > output/result.txt; sleep 90`
	c.Cleanup = &contracts.Cleanup{
		Required:       false,
		Validators:     []string{hang},
		ValidatorSpecs: []contracts.ValidatorSpec{{Command: hang, Tools: []string{"sleep", "sh", "printf"}, WriteRoots: []string{"output"}}},
	}
	bin := fakeBackend(t, standardBackendBody(""))
	rec := runGoverned(t, t.TempDir(), bin, c)
	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected QUARANTINED (the run's own budget.max_minutes deadline genuinely expired, so no later stage -- restore or not -- has a live ctx left to reach APPROVED on), got status=%s message=%s", rec.Status, rec.Message)
	}
	if rec.Commit == "" {
		t.Fatalf("expected a preserved quarantine commit despite the run's deadline having expired -- quarantine forensics must survive the exact deadline that caused the quarantine, message=%s", rec.Message)
	}
	got := gitOutput(t, root, "show", rec.Commit+":output/result.txt")
	if got != "ok\n" {
		t.Fatalf("preserved quarantine commit's output/result.txt = %q, want the original %q -- a cleanup validator killed mid-write by the run deadline must never leave partial bytes behind, even in the forensic record", got, "ok\n")
	}
}

func TestV10Case18CleanupArtifactMutationCapturedBeforeFinalMeasurement(t *testing.T) {
	v10s3EnrollTools(t, "printf")
	root := fixtureRepo(t)
	c := baseContract(root)
	mutate := `printf 'CLEANUP-MARKER' > output/marker.txt`
	c.Cleanup = &contracts.Cleanup{
		Required:       true,
		Validators:     []string{mutate},
		ValidatorSpecs: []contracts.ValidatorSpec{{Command: mutate, Tools: []string{"printf"}, WriteRoots: []string{"output"}}},
	}
	bin := fakeBackend(t, standardBackendBody(""))
	rec := runGoverned(t, t.TempDir(), bin, c)
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED, got status=%s message=%s", rec.Status, rec.Message)
	}
	got := gitOutput(t, root, "show", "HEAD:output/marker.txt")
	if got != "CLEANUP-MARKER" {
		t.Fatalf("merged output/marker.txt = %q, want %q -- cleanup's mutation must reach the final structural barrier and the merge, proving no stage after cleanup in the pipeline can drop or revert it", got, "CLEANUP-MARKER")
	}
}

func TestV10Case19PreCleanupStateRestoredOnOptionalCleanupFailureRegardlessOfValidatorCoverage(t *testing.T) {
	v10s3EnrollTools(t, "printf")
	root := fixtureRepo(t)
	c := baseContract(root)
	// No validator inspects output/untouched.txt's content at all -- proving
	// the restore is an unconditional safety net over the declared write
	// root, not merely something a well-aimed success validator happened to
	// catch (that's case 15/16's concern).
	seed := "mkdir -p output\nprintf 'SEEDED-BY-BACKEND' > output/untouched.txt"
	corrupt := `printf 'CORRUPTED-BY-CLEANUP' > output/untouched.txt; exit 1`
	c.Cleanup = &contracts.Cleanup{
		Required:       false,
		Validators:     []string{corrupt},
		ValidatorSpecs: []contracts.ValidatorSpec{{Command: corrupt, Tools: []string{"printf"}, WriteRoots: []string{"output"}}},
	}
	bin := fakeBackend(t, standardBackendBody(seed))
	rec := runGoverned(t, t.TempDir(), bin, c)
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED, got status=%s message=%s", rec.Status, rec.Message)
	}
	got := gitOutput(t, root, "show", "HEAD:output/untouched.txt")
	if got != "SEEDED-BY-BACKEND" {
		t.Fatalf("merged output/untouched.txt = %q, want the original %q -- a failed optional cleanup must restore its own declared write roots even when no validator checks that file's content", got, "SEEDED-BY-BACKEND")
	}
	if !strings.Contains(rec.Notes, "cleanup_restored_after_failure") {
		t.Fatalf("expected rec.Notes to record the restore, got: %q", rec.Notes)
	}
}

func TestV10Case20SuccessValidatorsExecuteAfterLastCleanupMutation(t *testing.T) {
	v10s3EnrollTools(t, "printf")
	root := fixtureRepo(t)
	c := baseContract(root)
	mutate := `printf 'MUTATED-BY-CLEANUP' > output/result.txt`
	c.Cleanup = &contracts.Cleanup{
		Required:       true,
		Validators:     []string{mutate},
		ValidatorSpecs: []contracts.ValidatorSpec{{Command: mutate, Tools: []string{"printf"}, WriteRoots: []string{"output"}}},
	}
	// This validator can only pass by observing cleanup's mutated bytes, not
	// the backend's original "ok\n" -- a failure here would mean success
	// validators still ran before cleanup.
	c.Success.Validators = append(c.Success.Validators, `[ "$(cat output/result.txt)" = "MUTATED-BY-CLEANUP" ]`)
	bin := fakeBackend(t, standardBackendBody(""))
	rec := runGoverned(t, t.TempDir(), bin, c)
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED (the success validator's check only passes against cleanup's post-mutation bytes), got status=%s message=%s", rec.Status, rec.Message)
	}
	got := gitOutput(t, root, "show", "HEAD:output/result.txt")
	if got != "MUTATED-BY-CLEANUP" {
		t.Fatalf("merged output/result.txt = %q, want %q", got, "MUTATED-BY-CLEANUP")
	}
}
