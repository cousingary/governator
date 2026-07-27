//go:build redteam

// v10_s1_consumed_artifact_immutability_test.go implements Sol10 P0-1's
// mandatory red-team corpus (agents/governator-sol-upgrade10.md "P0-1:
// Consumed artifacts are not read-only", agents/governator-sol-upgrade10-rc4-plan.md
// Session 1, report cases 1-8): a same-UID backend or validator process can
// always chmod its way past mode bits on a file inside its OWN writable
// workspace, so 0400 alone inside <work>/.governator/consumed was never a
// real boundary regardless of --map-root-user. Fixed, consumed artifacts are
// staged in a private controller-owned store outside the worktree and
// exposed to the backend/validators only through a genuinely separate mount
// Landlock grants RODirs on -- a mutation attempt must fail externally
// (kernel/mount refusal), never merely be re-copied around by Governator.
//
// Cases 1-4 exercise the real, active boundary (Landlock ABI + unshare
// --mount, skipped when the host cannot provide either): overwrite,
// truncate, rename-over, and hard-link replacement attempts against a
// consumed artifact, each guarded so the attacking shell script survives the
// failed attempt, then reads the artifact back and copies it into the
// committed output -- proving the bytes a downstream consumer sees are the
// producer's original bytes, never a swapped copy.
//
// Case 5 proves a VALIDATOR (a separate process from the backend, launched
// through internal/stage.Executor's own independently compiled enforce.Plan
// -- see stage.StageAuthority.ROBinds) is equally unable to mutate the
// artifact and equally sees the original bytes.
//
// Cases 6-8 exercise the hash-reverification detection layer itself
// (runtime.verifyConsumedArtifacts's four checkpoints), by deliberately
// running under the operator-accepted degraded posture
// (containment.local_effectful_tiering: off, authored to a config file via
// writeTieringConfig -- Sol11 P0-4 made the equivalent environment variable,
// GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING, inert, so the config-file route is
// the only sanctioned way to reach this posture now) where no OS-level
// boundary exists at all and a same-UID mutation genuinely succeeds --
// proving Governator's own before/after hashing still catches it and
// quarantines with exactly CONSUMED_ARTIFACT_MUTATED: at the backend-extinction
// checkpoint (6, a hard pre-merge failure), the after-cleanup-validator
// checkpoint (7), and the after-success-validation checkpoint (8).
package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
	govruntime "github.com/cousingary/governator/internal/runtime"
	"github.com/cousingary/governator/internal/toolregistry"
)

const v10OriginalContent = "original-content-v1"

// v10ExtraReadRoots resolves each tool's own ELF runtime closure so a
// fakeBackend/validator shell script can invoke it under a real
// Landlock-enforced run, matching shellReadRootsForFixtures's own doc
// comment -- some of these attacks need mv/ln/dd, and shellReadRootsForFixtures
// only already covers dd.
func v10ExtraReadRoots(t *testing.T, tools ...string) []string {
	t.Helper()
	var out []string
	for _, tool := range tools {
		path, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		closure, err := enforce.ExecutableReadClosure(path)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, closure...)
	}
	return out
}

func v10SkipUnlessSupported(t *testing.T) {
	t.Helper()
	if !enforce.Supported() {
		t.Skip("this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}
}

// v10ProducerConsumer runs a producer job that emits artifact "art" =
// v10OriginalContent and returns root/home/producerJobID for the caller to
// build a consumer contract (Consumes "art") against via v10ConsumerContract.
func v10ProducerConsumer(t *testing.T) (root, home, producerJobID string) {
	t.Helper()
	root = fixtureRepo(t)
	home = t.TempDir()
	producerJobID = "v10-s1-producer"
	producer := contracts.Contract{
		Task: "producer", JobID: producerJobID, JobType: "test", Agent: "claude-code", Mode: contracts.ModeSurgeon,
		Workspace:   contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:     contracts.Permissions{Read: []string{"**"}, Write: []string{"output/**", ".governator/artifacts/**"}, Execute: []string{"test"}},
		Forbidden:   contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}, Behaviors: []string{"network"}},
		Budget:      contracts.Budget{MaxMinutes: 1, MaxCommands: 5, MaxFilesChanged: 5, MaxLinesChanged: 20, MaxNewFiles: 5, MaxDeleted: 0},
		Preflight:   contracts.Preflight{IntendedWrites: []string{"output/**", ".governator/artifacts/**"}},
		Success:     contracts.Success{RequiredFiles: []string{"output/result.txt"}, Validators: []string{"test -f output/result.txt"}, ValidatorSpecs: []contracts.ValidatorSpec{{Command: "test -f output/result.txt", Tools: []string{"test"}}}},
		Produces:    []contracts.ArtifactSpec{{Name: "art", Path: ".governator/artifacts/art.txt", MaxBytes: 1024}},
		OnViolation: "quarantine",
		Local:       &contracts.LocalRunnerConfig{ReadRoots: shellReadRootsForFixtures()},
	}
	producerBody := `mkdir -p .governator/artifacts
printf '%s' '` + v10OriginalContent + `' > .governator/artifacts/art.txt
mkdir -p output
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt",".governator/artifacts/art.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`
	p := runGoverned(t, home, fakeBackend(t, producerBody), producer)
	if p.Status != "APPROVED" {
		t.Fatalf("producer expected APPROVED, got status=%s message=%s", p.Status, p.Message)
	}
	return root, home, producerJobID
}

// v10DegradedConsumerContract is v10ConsumerContract without an explicit
// network prohibition: RequiresHostContainment treats "forbids network" as
// an unconditional host-containment trigger regardless of
// enforce_local_effectful_tiering ("Explicit no-network is always
// externally enforced... deliberately no risk_class condition here" --
// containment.go), so a contract that forbids network can never actually
// reach the degraded/mode-bits fallback this test needs to exercise no
// matter what s6BypassHostContainment sets. Every other fixture in this file
// mirrors baseContract's forbidden.behaviors=["network"] convention on
// purpose (cases 1-5 want the real, active boundary); only the detection
// -layer cases (6-8) need this variant.
func v10DegradedConsumerContract(root, producerJobID string) contracts.Contract {
	c := v10ConsumerContract(root, producerJobID)
	c.Forbidden.Behaviors = nil
	return c
}

func v10ConsumerContract(root, producerJobID string, extraReadRoots ...string) contracts.Contract {
	return contracts.Contract{
		Task: "consumer", JobID: "v10-s1-consumer", JobType: "test", Agent: "claude-code", Mode: contracts.ModeSurgeon,
		Workspace:       contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:         contracts.Permissions{Read: []string{"**"}, Write: []string{"output/**"}, Execute: []string{"test"}},
		Forbidden:       contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}, Behaviors: []string{"network"}},
		Budget:          contracts.Budget{MaxMinutes: 1, MaxCommands: 5, MaxFilesChanged: 5, MaxLinesChanged: 20, MaxNewFiles: 5, MaxDeleted: 0},
		Preflight:       contracts.Preflight{IntendedWrites: []string{"output/**"}},
		Success:         contracts.Success{RequiredFiles: []string{"output/result.txt"}, Validators: []string{"test -f output/result.txt"}, ValidatorSpecs: []contracts.ValidatorSpec{{Command: "test -f output/result.txt", Tools: []string{"test"}}}},
		Consumes:        []string{"art"},
		ArtifactSources: map[string]string{"art": producerJobID},
		OnViolation:     "quarantine",
		Local:           &contracts.LocalRunnerConfig{ReadRoots: append(append([]string(nil), shellReadRootsForFixtures()...), extraReadRoots...)},
	}
}

// v10MutationAttack drives a consumer whose backend attempts attackShell
// (guarded so the script survives a failed attempt) against
// .governator/consumed/art, then copies whatever bytes remain into the
// committed output. A successfully blocked attack leaves the producer's
// original bytes in place and the run approved normally -- Governator never
// even needs to notice the attempt, because the kernel refused it before any
// workspace mutation occurred.
func v10MutationAttack(t *testing.T, attackShell string, extraTools ...string) {
	t.Helper()
	v10SkipUnlessSupported(t)
	root, home, producerJobID := v10ProducerConsumer(t)
	consumer := v10ConsumerContract(root, producerJobID, v10ExtraReadRoots(t, extraTools...)...)
	body := `mkdir -p output
` + attackShell + `
cat .governator/consumed/art > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`
	rec := runGoverned(t, home, fakeBackend(t, body), consumer)
	if rec.Status != "APPROVED" {
		t.Fatalf("consumer expected APPROVED (a fully blocked mutation attempt is not a contract violation), got status=%s message=%s", rec.Status, rec.Message)
	}
	got := gitOutput(t, root, "show", "HEAD:output/result.txt")
	if got != v10OriginalContent {
		t.Fatalf("consumer output = %q, want the producer's original %q -- the mutation attempt against the consumed artifact was not fully blocked", got, v10OriginalContent)
	}
}

func TestV10Case1BackendOverwriteOfConsumedArtifactRefused(t *testing.T) {
	v10MutationAttack(t, `(printf 'MUTATED-OVERWRITE' > .governator/consumed/art) 2>/dev/null || true`)
}

func TestV10Case2BackendTruncateOfConsumedArtifactRefused(t *testing.T) {
	v10MutationAttack(t, `(dd if=/dev/null of=.governator/consumed/art bs=1 count=0) 2>/dev/null || true`, "dd")
}

func TestV10Case3BackendRenameOverConsumedArtifactRefused(t *testing.T) {
	v10MutationAttack(t, `printf 'HOSTILE-RENAME' > output/hostile.txt
(mv output/hostile.txt .governator/consumed/art) 2>/dev/null || true`, "mv")
}

func TestV10Case4BackendHardLinkReplacementOfConsumedArtifactRefused(t *testing.T) {
	v10MutationAttack(t, `printf 'HOSTILE-HARDLINK' > output/hostile.txt
(ln -f output/hostile.txt .governator/consumed/art) 2>/dev/null || true`, "ln")
}

// TestV10Case5ValidatorObservesExactOriginalBytesDespiteMutationAttempt
// proves the SAME boundary holds for a validator -- a separate process from
// the backend, launched through internal/stage.Executor's own independently
// compiled enforce.Plan (stage.StageAuthority.ROBinds) rather than anything
// inherited from the backend's launch.
func TestV10Case5ValidatorObservesExactOriginalBytesDespiteMutationAttempt(t *testing.T) {
	v10SkipUnlessSupported(t)
	root, home, producerJobID := v10ProducerConsumer(t)
	consumer := v10ConsumerContract(root, producerJobID)
	consumer.Success.Validators = append(consumer.Success.Validators,
		`(printf 'MUTATED-BY-VALIDATOR' > .governator/consumed/art) 2>/dev/null || true`,
		`[ "$(cat .governator/consumed/art)" = "`+v10OriginalContent+`" ]`,
	)
	consumer.Success.ValidatorSpecs = append(consumer.Success.ValidatorSpecs,
		contracts.ValidatorSpec{Command: `(printf 'MUTATED-BY-VALIDATOR' > .governator/consumed/art) 2>/dev/null || true`, Tools: []string{"printf"}},
		contracts.ValidatorSpec{Command: `[ "$(cat .governator/consumed/art)" = "` + v10OriginalContent + `" ]`, Tools: []string{"cat"}},
	)
	body := `mkdir -p output
cat .governator/consumed/art > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`
	rec := runGoverned(t, home, fakeBackend(t, body), consumer)
	if rec.Status != "APPROVED" {
		t.Fatalf("consumer expected APPROVED (the validator's own mutation attempt should fail harmlessly and its bytes-equality check should pass), got status=%s message=%s", rec.Status, rec.Message)
	}
	got := gitOutput(t, root, "show", "HEAD:output/result.txt")
	if got != v10OriginalContent {
		t.Fatalf("consumer output = %q, want %q", got, v10OriginalContent)
	}
}

// TestV10Case6MutationDetectedAfterBackendExtinction exercises the
// hash-reverification detection layer directly: deliberately running under
// the operator-accepted degraded posture (no Landlock/mount boundary at all,
// the same reduced posture containment.local_effectful_tiering: off already
// gives every other control -- authored to a config file, since Sol11 P0-4
// made the GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING env variant inert), a
// same-UID backend genuinely succeeds at chmod+overwriting the consumed
// artifact. Governator's own verifyConsumedArtifacts, called immediately
// after the backend's descendant tree is confirmed extinct, must still catch
// the mismatch and refuse the run outright (a hard pre-merge failure,
// matching the severity of the adjacent descendant-extinction check) with
// exactly CONSUMED_ARTIFACT_MUTATED.
func TestV10Case6MutationDetectedAfterBackendExtinction(t *testing.T) {
	s6BypassHostContainment(t)
	root, home, producerJobID := v10ProducerConsumer(t)
	t.Setenv("GOV_CONFIG", writeTieringConfig(t, "off"))
	consumer := v10DegradedConsumerContract(root, producerJobID)
	body := `mkdir -p output
chmod u+w .governator/consumed/art 2>/dev/null || true
printf 'MUTATED-BY-BACKEND' > .governator/consumed/art 2>/dev/null || true
cat .governator/consumed/art > output/result.txt 2>/dev/null || printf 'read-failed\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`
	rec, err := runGovernedAllowError(t, home, fakeBackend(t, body), consumer)
	if err == nil {
		t.Fatalf("expected a hard failure once the backend's own consumed-artifact mutation succeeded under the degraded posture, got status=%s message=%s", rec.Status, rec.Message)
	}
	if !strings.Contains(err.Error(), govruntime.ConsumedArtifactMutated) {
		t.Fatalf("expected error containing %s, got: %v", govruntime.ConsumedArtifactMutated, err)
	}
}

// TestV10Case7MutationDetectedAfterCleanupValidator proves the same
// detection layer catches a mutation the BACKEND never attempted at all --
// here a (non-required, so its own exit code never gates the merge) cleanup
// validator performs it -- at the after-all-validation checkpoint, since
// nothing runs between the cleanup stage and that checkpoint to catch it
// earlier. Every validator is read-only over the whole workspace by default
// regardless of consumed-artifact handling (internal/stage.Executor compiles
// a read-only base plan unless a ValidatorSpec declares WriteRoots), so this
// validator explicitly declares .governator/consumed as a write root --
// standing in for an over-permissive contract author or a compromised
// validator spec -- to reach a state where the mutation genuinely lands
// under the degraded posture and Governator's own hash-reverification is the
// only thing left to catch it.
func TestV10Case7MutationDetectedAfterCleanupValidator(t *testing.T) {
	s6BypassHostContainment(t)
	if chmodPath, err := exec.LookPath("chmod"); err == nil {
		if _, err := toolregistry.Enroll("chmod", chmodPath); err != nil {
			t.Fatal(err)
		}
	}
	root, home, producerJobID := v10ProducerConsumer(t)
	t.Setenv("GOV_CONFIG", writeTieringConfig(t, "off"))
	consumer := v10DegradedConsumerContract(root, producerJobID)
	mutateCmd := `chmod u+w .governator/consumed/art 2>/dev/null || true; printf 'MUTATED-BY-CLEANUP' > .governator/consumed/art 2>/dev/null || true`
	consumer.Cleanup = &contracts.Cleanup{
		Required:       false,
		Validators:     []string{mutateCmd},
		ValidatorSpecs: []contracts.ValidatorSpec{{Command: mutateCmd, Tools: []string{"chmod"}, WriteRoots: []string{".governator/consumed"}}},
	}
	body := `mkdir -p output
cat .governator/consumed/art > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`
	rec, err := runGovernedAllowError(t, home, fakeBackend(t, body), consumer)
	if err != nil {
		t.Fatalf("RunWithAutoRepair: %v", err)
	}
	if rec.Status != "QUARANTINED" || !strings.Contains(rec.Message, govruntime.ConsumedArtifactMutated) {
		t.Fatalf("expected QUARANTINED containing %s after a cleanup validator mutated the consumed artifact, got status=%s message=%s", govruntime.ConsumedArtifactMutated, rec.Status, rec.Message)
	}
}

// TestV10Case8MutationDetectedAfterSuccessValidation proves the same
// after-all-validation checkpoint also catches a mutation that lands after
// every success validator has already passed cleanly, via a distinct vector
// from case 7's cleanup validator: success validators cannot mutate at all
// (contracts/schema.go hard-rejects write_roots on a success validator --
// "success validators are read-only; move mutations to cleanup.validators"),
// so this exercises PostRunValidate, the in-process Go hook that runs
// immediately after every success validator passes and strictly before Assay
// and the final barrier -- a same-UID mutation performed there is exactly as
// invisible to checkpoint 3 (which already ran, before any validator) as
// case 7's cleanup mutation, and is caught by the same after-all-validation
// checkpoint 4.
func TestV10Case8MutationDetectedAfterSuccessValidation(t *testing.T) {
	s6BypassHostContainment(t)
	root, home, producerJobID := v10ProducerConsumer(t)
	t.Setenv("GOV_CONFIG", writeTieringConfig(t, "off"))
	consumer := v10DegradedConsumerContract(root, producerJobID)
	consumer.PostRunValidate = func(work string) error {
		artPath := filepath.Join(work, ".governator", "consumed", "art")
		_ = os.Chmod(artPath, 0600)
		_ = os.WriteFile(artPath, []byte("MUTATED-BY-POSTRUN-VALIDATE"), 0600)
		return nil
	}
	body := `mkdir -p output
cat .governator/consumed/art > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`
	rec, err := runGovernedAllowError(t, home, fakeBackend(t, body), consumer)
	if err != nil {
		t.Fatalf("RunWithAutoRepair: %v", err)
	}
	if rec.Status != "QUARANTINED" || !strings.Contains(rec.Message, govruntime.ConsumedArtifactMutated) {
		t.Fatalf("expected QUARANTINED containing %s after PostRunValidate mutated the consumed artifact, got status=%s message=%s", govruntime.ConsumedArtifactMutated, rec.Status, rec.Message)
	}
}
