//go:build redteam

package redteam

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// v11_s3_release_checkpoint_test.go is the Sol v11 rc5 Session 3 corpus
// (agents/governator-sol-upgrade11-rc5-plan.md Session 3,
// agents/governator-sol-upgrade11.md P1-5): report corpus cases 9, 10, 13,
// 14, 15, 16, 18, 19 -- "The monolithic release pipeline is not
// crash-resumable". Every test below drives the REAL
// scripts/release_checkpoint.py and scripts/release_tier_pipeline.sh as
// actual OS subprocesses against synthetic identity/state fixtures, never
// an internal Go function.

// s3RepoRoot resolves the real governator repo root from this test file's
// own location.
func s3RepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve this test file's own path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

func s3CheckpointScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(s3RepoRoot(t), "scripts", "release_checkpoint.py")
}

func s3TierPipelineScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(s3RepoRoot(t), "scripts", "release_tier_pipeline.sh")
}

type s3Identity struct {
	GovernatorCommit  string
	GovernatorTag     string
	AssayerCommit     string
	GoSumHash         string
	ToolchainHash     string
	EnvironmentHash   string
	GoTestParallelism string
}

func s3DefaultIdentity() s3Identity {
	return s3Identity{
		GovernatorCommit:  "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee0",
		GovernatorTag:     "v1.0.2-rc5-test",
		AssayerCommit:     "a55a11a55a11a55a11a55a11a55a11a55a11a55",
		GoSumHash:         "gosum-hash-1",
		ToolchainHash:     "toolchain-hash-1",
		EnvironmentHash:   "environment-hash-1",
		GoTestParallelism: "2",
	}
}

// s3WriteIdentityFile runs `release_checkpoint.py identity` for the given
// identity and writes its output to path.
func s3WriteIdentityFile(t *testing.T, path string, id s3Identity) {
	t.Helper()
	cmd := exec.Command("python3", s3CheckpointScript(t), "identity",
		"--governator-commit", id.GovernatorCommit,
		"--governator-tag", id.GovernatorTag,
		"--assayer-commit", id.AssayerCommit,
		"--go-sum-hash", id.GoSumHash,
		"--toolchain-hash", id.ToolchainHash,
		"--environment-hash", id.EnvironmentHash,
		"--go-test-parallelism", id.GoTestParallelism,
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("release_checkpoint.py identity: %v", err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// s3InitAttempt runs `release_checkpoint.py init`, returning the resolved
// identity.json path (which subsequent check/write/aggregate calls use).
func s3InitAttempt(t *testing.T, stateDir string, id s3Identity, attemptID string) string {
	t.Helper()
	candidate := filepath.Join(t.TempDir(), "candidate.json")
	s3WriteIdentityFile(t, candidate, id)
	cmd := exec.Command("python3", s3CheckpointScript(t), "init",
		"--state-dir", stateDir, "--identity-file", candidate, "--attempt-id", attemptID)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("release_checkpoint.py init: %v\n%s", err, out)
	}
	return filepath.Join(stateDir, "identity.json")
}

func s3CheckpointCheck(t *testing.T, checkpoint, identityFile, command string) (string, error) {
	t.Helper()
	cmd := exec.Command("python3", s3CheckpointScript(t), "check",
		"--checkpoint", checkpoint, "--identity-file", identityFile, "--command", command)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func s3CheckpointWrite(t *testing.T, checkpoint, identityFile, command, result string) {
	t.Helper()
	cmd := exec.Command("python3", s3CheckpointScript(t), "write",
		"--checkpoint", checkpoint, "--identity-file", identityFile, "--command", command,
		"--started", "2026-01-01T00:00:00Z", "--completed", "2026-01-01T00:00:01Z",
		"--exit-code", map[string]string{"PASS": "0", "FAIL": "1"}[result],
		"--log-sha256", "deadbeef", "--result", result)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("release_checkpoint.py write: %v\n%s", err, out)
	}
}

// TestV11Case16CrashDuringUnitTierLeavesNoTrustedCheckpoint is corpus case
// 9: "crash during unit tier". release_tier_pipeline.sh's unit tier is a
// real subprocess that writes partial output and then is SIGKILLed from
// this test mid-run -- exactly what an OOM kill or a WSL restart does to a
// running go test invocation. Two things must hold afterward: (1) no
// unit.json checkpoint exists (a crash mid-tier must never be mistaken for
// a completed one), and (2) the partial raw log the killed process managed
// to flush is still on disk (so a human/resume can see how far it got),
// proving the checkpoint -- not the log -- is the trust boundary.
func TestV11Case16CrashDuringUnitTierLeavesNoTrustedCheckpoint(t *testing.T) {
	work := t.TempDir()
	stateDir := filepath.Join(work, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := s3DefaultIdentity()
	identityFile := s3InitAttempt(t, stateDir, id, "attempt-crash-during-unit")

	log := filepath.Join(work, "unit.log")
	spec := filepath.Join(work, "spec.tsv")
	// A long-lived command that flushes partial output immediately, then
	// blocks -- simulating a unit-test run that was making progress when
	// the host killed it.
	specBody := "unit\t" + log + "\techo partial-unit-output; sleep 300\n"
	if err := os.WriteFile(spec, []byte(specBody), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", s3TierPipelineScript(t), "run",
		"--state-dir", stateDir, "--identity-file", identityFile, "--spec", spec)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start release_tier_pipeline.sh: %v", err)
	}
	// Give the child's own `bash -c "$CMD"` time to run and flush its echo.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(log); err == nil && strings.Contains(string(b), "partial-unit-output") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// SIGKILL the whole process group is unnecessary here -- killing the
	// release_tier_pipeline.sh process itself (which is still inside `bash
	// -c "$CMD" >"$LOG"` waiting on `sleep 300`) is the crash this case
	// tests: the checkpoint write only happens AFTER that command returns,
	// so killing anywhere before it returns must leave zero checkpoint.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill: %v", err)
	}
	_ = cmd.Wait()

	logBytes, err := os.ReadFile(log)
	if err != nil || !strings.Contains(string(logBytes), "partial-unit-output") {
		t.Fatalf("expected the partial log to have been flushed to disk before the crash, got: %v %q", err, logBytes)
	}

	ckpt := filepath.Join(stateDir, "unit.json")
	if _, err := os.Stat(ckpt); !os.IsNotExist(err) {
		t.Fatalf("expected NO checkpoint at %s after a crash mid-tier, but stat returned err=%v", ckpt, err)
	}

	// And the resume-check machinery must therefore report MISSING, not a
	// false PASS.
	out, err := s3CheckpointCheck(t, ckpt, identityFile, "echo partial-unit-output; sleep 300")
	if err == nil {
		t.Fatalf("expected release_checkpoint.py check to refuse an absent checkpoint, got success:\n%s", out)
	}
	if !strings.Contains(out, "MISSING") {
		t.Fatalf("expected MISSING, got:\n%s", out)
	}
}

// TestV11Case17CrashBeforeCheckpointRenameLeavesNoCorruptCheckpoint is
// corpus case 10: "crash after unit completion but before checkpoint
// rename". release_checkpoint.py write's --inject-delay-before-rename
// test-only hook (a no-op at 0, every production call site's default)
// opens a wide, reliable window between "temp file fully written+fsynced"
// and "atomic rename commits it" -- this test SIGKILLs the write process
// inside that exact window and proves the checkpoint path never exists
// afterward: no half-written, corrupt, or otherwise-observable checkpoint
// ever appears at the committed path, so a resuming attempt sees MISSING
// (safe: re-run the tier) rather than trusting a torn write.
func TestV11Case17CrashBeforeCheckpointRenameLeavesNoCorruptCheckpoint(t *testing.T) {
	work := t.TempDir()
	stateDir := filepath.Join(work, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := s3DefaultIdentity()
	identityFile := s3InitAttempt(t, stateDir, id, "attempt-crash-before-rename")

	ckpt := filepath.Join(stateDir, "unit.json")
	cmd := exec.Command("python3", s3CheckpointScript(t), "write",
		"--checkpoint", ckpt, "--identity-file", identityFile, "--command", "go test ./...",
		"--started", "2026-01-01T00:00:00Z", "--completed", "2026-01-01T00:00:01Z",
		"--exit-code", "0", "--log-sha256", "deadbeef", "--result", "PASS",
		"--inject-delay-before-rename", "5")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start release_checkpoint.py write: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // well inside the 5s injected delay, before rename
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL: %v", err)
	}
	_ = cmd.Wait()

	if _, err := os.Stat(ckpt); !os.IsNotExist(err) {
		t.Fatalf("expected NO checkpoint at the committed path %s after a crash before rename, but stat returned err=%v", ckpt, err)
	}

	// A resume attempt against this state dir must see MISSING, not reuse
	// anything -- proving the crash-before-rename window never produces a
	// falsely-trusted checkpoint.
	out, err := s3CheckpointCheck(t, ckpt, identityFile, "go test ./...")
	if err == nil {
		t.Fatalf("expected check to refuse a checkpoint that never committed, got success:\n%s", out)
	}
	if !strings.Contains(out, "MISSING") {
		t.Fatalf("expected MISSING, got:\n%s", out)
	}
}

// TestV11Case20StaleCheckpointFromAnotherCommitNotReused is corpus case 13.
func TestV11Case20StaleCheckpointFromAnotherCommitNotReused(t *testing.T) {
	work := t.TempDir()
	stateDir := filepath.Join(work, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := s3DefaultIdentity()
	identityFile := s3InitAttempt(t, stateDir, id, "attempt-1")
	ckpt := filepath.Join(stateDir, "unit.json")
	s3CheckpointWrite(t, ckpt, identityFile, "go test ./...", "PASS")

	// Sanity: same identity reuses.
	if _, err := s3CheckpointCheck(t, ckpt, identityFile, "go test ./..."); err != nil {
		t.Fatalf("expected the baseline (unmodified) checkpoint to be reusable: %v", err)
	}

	otherCommitID := id
	otherCommitID.GovernatorCommit = "1111111111111111111111111111111111111a"
	otherIdentityFile := filepath.Join(work, "other-commit-identity.json")
	s3WriteIdentityFile(t, otherIdentityFile, otherCommitID)
	// Simulate the resolved identity (with attempt id) a "resume" would
	// compute for a DIFFERENT commit: same attempt id is irrelevant here --
	// what matters is release_checkpoint.py check compares every identity
	// field, including governator_commit, from the CURRENT identity file.
	resolvedOther := filepath.Join(work, "resolved-other.json")
	mergeAttemptID(t, otherIdentityFile, "attempt-1", resolvedOther)

	out, err := s3CheckpointCheck(t, ckpt, resolvedOther, "go test ./...")
	if err == nil {
		t.Fatalf("expected a checkpoint from a different governator_commit to be rejected, got success:\n%s", out)
	}
	if !strings.Contains(out, "STALE") || !strings.Contains(out, "governator_commit") {
		t.Fatalf("expected STALE naming governator_commit, got:\n%s", out)
	}
}

// TestV11Case21StaleCheckpointFromAnotherGoToolchainNotReused is corpus
// case 14.
func TestV11Case21StaleCheckpointFromAnotherGoToolchainNotReused(t *testing.T) {
	work := t.TempDir()
	stateDir := filepath.Join(work, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := s3DefaultIdentity()
	identityFile := s3InitAttempt(t, stateDir, id, "attempt-1")
	ckpt := filepath.Join(stateDir, "race.json")
	s3CheckpointWrite(t, ckpt, identityFile, "go test -race ./...", "PASS")

	otherToolchain := id
	otherToolchain.ToolchainHash = "toolchain-hash-DIFFERENT"
	otherIdentityFile := filepath.Join(work, "other-toolchain-identity.json")
	s3WriteIdentityFile(t, otherIdentityFile, otherToolchain)
	resolvedOther := filepath.Join(work, "resolved-other.json")
	mergeAttemptID(t, otherIdentityFile, "attempt-1", resolvedOther)

	out, err := s3CheckpointCheck(t, ckpt, resolvedOther, "go test -race ./...")
	if err == nil {
		t.Fatalf("expected a checkpoint from a different Go toolchain to be rejected, got success:\n%s", out)
	}
	if !strings.Contains(out, "STALE") || !strings.Contains(out, "toolchain_hash") {
		t.Fatalf("expected STALE naming toolchain_hash, got:\n%s", out)
	}
}

// TestV11Case22StaleCheckpointFromAnotherAssayerCommitNotReused is corpus
// case 15.
func TestV11Case22StaleCheckpointFromAnotherAssayerCommitNotReused(t *testing.T) {
	work := t.TempDir()
	stateDir := filepath.Join(work, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := s3DefaultIdentity()
	identityFile := s3InitAttempt(t, stateDir, id, "attempt-1")
	ckpt := filepath.Join(stateDir, "integration.json")
	s3CheckpointWrite(t, ckpt, identityFile, "go test -tags integration ./internal/assay/...", "PASS")

	otherAssayer := id
	otherAssayer.AssayerCommit = "9999999999999999999999999999999999999b"
	otherIdentityFile := filepath.Join(work, "other-assayer-identity.json")
	s3WriteIdentityFile(t, otherIdentityFile, otherAssayer)
	resolvedOther := filepath.Join(work, "resolved-other.json")
	mergeAttemptID(t, otherIdentityFile, "attempt-1", resolvedOther)

	out, err := s3CheckpointCheck(t, ckpt, resolvedOther, "go test -tags integration ./internal/assay/...")
	if err == nil {
		t.Fatalf("expected a checkpoint from a different Assayer commit to be rejected, got success:\n%s", out)
	}
	if !strings.Contains(out, "STALE") || !strings.Contains(out, "assayer_commit") {
		t.Fatalf("expected STALE naming assayer_commit, got:\n%s", out)
	}
}

// mergeAttemptID reads a bare identity JSON (identity fields only, no
// release_attempt_id) and writes a copy with release_attempt_id added --
// mirroring the shape `release_checkpoint.py init` produces, without
// actually calling init (which would also (re)write the state dir's own
// identity.json, which these staleness tests deliberately leave alone).
func mergeAttemptID(t *testing.T, identityFile, attemptID, out string) {
	t.Helper()
	raw, err := os.ReadFile(identityFile)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	data["release_attempt_id"] = attemptID
	merged, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, merged, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestV11Case23MixedTierEvidenceFromTwoAttemptsRejected is corpus case 16:
// "mixed tier evidence from two release attempts". Two tiers' checkpoints
// are written under the SAME state dir but carry different
// release_attempt_id values (exactly what a stale leftover checkpoint from
// an earlier, abandoned attempt sitting next to fresh ones from a new
// attempt looks like) -- release_checkpoint.py aggregate must refuse to
// treat them as one release's evidence.
func TestV11Case23MixedTierEvidenceFromTwoAttemptsRejected(t *testing.T) {
	work := t.TempDir()
	stateDir := filepath.Join(work, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := s3DefaultIdentity()
	identityFile := s3InitAttempt(t, stateDir, id, "attempt-current")

	s3CheckpointWrite(t, filepath.Join(stateDir, "unit.json"), identityFile, "go test ./...", "PASS")
	s3CheckpointWrite(t, filepath.Join(stateDir, "race.json"), identityFile, "go test -race ./...", "PASS")

	// A leftover checkpoint from a DIFFERENT (older, abandoned) attempt --
	// same tier name (integration), different release_attempt_id.
	staleAttemptDir := filepath.Join(work, "stale-state")
	if err := os.MkdirAll(staleAttemptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	staleIdentityFile := s3InitAttempt(t, staleAttemptDir, id, "attempt-OLD-abandoned")
	staleIntegration := filepath.Join(staleAttemptDir, "integration.json")
	s3CheckpointWrite(t, staleIntegration, staleIdentityFile, "go test -tags integration ./internal/assay/...", "PASS")
	// Copy the stale checkpoint into the CURRENT attempt's state dir, as if
	// it had been left there by an interrupted, different attempt.
	raw, err := os.ReadFile(staleIntegration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "integration.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("python3", s3CheckpointScript(t), "aggregate",
		"--state-dir", stateDir, "--identity-file", identityFile,
		"--required", "unit,race,integration")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected aggregate to reject mixed-attempt evidence, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "MIXED_RELEASE_EVIDENCE") {
		t.Fatalf("expected MIXED_RELEASE_EVIDENCE naming the mismatched tier, got:\n%s", out)
	}
}

// TestV11Case25ResumeAfterExactMatchingCheckpointSucceeds is corpus case
// 18 -- the ONE positive case in this file: a release_tier_pipeline.sh run
// against a state dir already carrying an exact-identity-matching PASS
// checkpoint for its one tier must REUSE it (not re-run), and the
// pipeline overall must still SUCCEED.
func TestV11Case25ResumeAfterExactMatchingCheckpointSucceeds(t *testing.T) {
	work := t.TempDir()
	stateDir := filepath.Join(work, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := s3DefaultIdentity()
	identityFile := s3InitAttempt(t, stateDir, id, "attempt-resume")

	log := filepath.Join(work, "unit.log")
	spec := filepath.Join(work, "spec.tsv")
	command := "echo ran-for-real"
	if err := os.WriteFile(spec, []byte("unit\t"+log+"\t"+command+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// First run: no checkpoint yet, must actually execute.
	first := runTierPipeline(t, stateDir, identityFile, spec)
	firstLines := jsonLines(t, first)
	if len(firstLines) != 1 || firstLines[0]["resumed"] != false {
		t.Fatalf("expected the first run to actually execute (resumed=false), got: %v", firstLines)
	}

	// Touch the raw log's mtime between runs -- the pipeline's reuse
	// decision must be driven by the checkpoint's own recorded identity
	// match, not by any mtime/staleness heuristic on the log file (which
	// still must exist on disk for a reuse to be trusted, matching
	// release.sh's real behavior where the raw log is only deleted after
	// gzip, much later in the pipeline).
	if err := os.Chtimes(log, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}

	// Second run: identical identity + spec. Must be REUSED, not re-run.
	second := runTierPipeline(t, stateDir, identityFile, spec)
	secondLines := jsonLines(t, second)
	if len(secondLines) != 1 || secondLines[0]["resumed"] != true {
		t.Fatalf("expected the second run (identical identity) to reuse the checkpoint (resumed=true), got: %v", secondLines)
	}
	if secondLines[0]["result"] != "PASS" {
		t.Fatalf("expected the reused tier's result to still be PASS, got: %v", secondLines[0])
	}
}

// runTierPipeline runs scripts/release_tier_pipeline.sh and returns its
// combined stdout (the JSON-lines tier records). Fails the test on a
// nonzero exit -- callers testing the FAILING path use
// runTierPipelineAllowError instead.
func runTierPipeline(t *testing.T, stateDir, identityFile, spec string) string {
	t.Helper()
	cmd := exec.Command("bash", s3TierPipelineScript(t), "run",
		"--state-dir", stateDir, "--identity-file", identityFile, "--spec", spec)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("release_tier_pipeline.sh: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func runTierPipelineAllowError(t *testing.T, stateDir, identityFile, spec string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", s3TierPipelineScript(t), "run",
		"--state-dir", stateDir, "--identity-file", identityFile, "--spec", spec)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	err := cmd.Run()
	return stdout.String(), err
}

func jsonLines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	scanner := bufio.NewScanner(strings.NewReader(s))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("unparseable JSON line %q: %v", line, err)
		}
		out = append(out, obj)
	}
	return out
}

// TestV11Case26RequiredTierFailsLaterTiersDoNotRun is corpus case 19:
// "required tier fails and later tiers do not run". A three-tier spec
// (unit passes, race fails, integration would prove it ran by writing a
// marker file) is driven through the real pipeline script end to end;
// integration's marker file must never be created, and the pipeline's own
// exit code must be nonzero.
func TestV11Case26RequiredTierFailsLaterTiersDoNotRun(t *testing.T) {
	work := t.TempDir()
	stateDir := filepath.Join(work, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	id := s3DefaultIdentity()
	identityFile := s3InitAttempt(t, stateDir, id, "attempt-failfast")

	unitLog := filepath.Join(work, "unit.log")
	raceLog := filepath.Join(work, "race.log")
	integrationLog := filepath.Join(work, "integration.log")
	marker := filepath.Join(work, "integration-ran.marker")

	spec := filepath.Join(work, "spec.tsv")
	specBody := "unit\t" + unitLog + "\techo unit-ok\n" +
		"race\t" + raceLog + "\tfalse\n" +
		"integration\t" + integrationLog + "\ttouch " + marker + "\n"
	if err := os.WriteFile(spec, []byte(specBody), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runTierPipelineAllowError(t, stateDir, identityFile, spec)
	if err == nil {
		t.Fatalf("expected release_tier_pipeline.sh to exit nonzero when a required tier (race) fails, got success:\n%s", out)
	}

	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("integration tier ran (marker file exists) even though the earlier required race tier failed -- fail-fast did not stop later tiers")
	}
	if _, statErr := os.Stat(integrationLog); !os.IsNotExist(statErr) {
		t.Fatalf("integration.log exists even though the earlier required race tier failed -- integration should never have started")
	}

	lines := jsonLines(t, out)
	var sawUnit, sawRace, sawIntegration bool
	for _, l := range lines {
		switch l["tier"] {
		case "unit":
			sawUnit = true
			if l["result"] != "PASS" {
				t.Fatalf("expected unit to PASS, got %v", l)
			}
		case "race":
			sawRace = true
			if l["result"] != "FAIL" {
				t.Fatalf("expected race to FAIL, got %v", l)
			}
		case "integration":
			sawIntegration = true
		}
	}
	if !sawUnit || !sawRace {
		t.Fatalf("expected unit and race tier records in the output, got: %v", lines)
	}
	if sawIntegration {
		t.Fatalf("expected NO integration tier record (it must never have run), got: %v", lines)
	}
	if !strings.Contains(out, `"aborted": true`) || !strings.Contains(out, `"failed_tier": "race"`) {
		t.Fatalf("expected an __pipeline__ aborted=true record naming race as failed_tier, got:\n%s", out)
	}
}
