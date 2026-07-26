package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/breaker"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/toolregistry"
)

// assayProducerContract builds on artifactProducerContract (same fixture
// used by the produced-artifact tests above) with an assay block attached,
// so the ledgered "reconnaissance" artifact is what gets evaluated.
func assayProducerContract(root, enforcement string) contracts.Contract {
	c := artifactProducerContract(root)
	c.Assay = &contracts.Assay{Profile: "coding-output-v1", Enforcement: enforcement}
	return c
}

// multiArtifactProducerContract produces three artifacts (alpha, beta,
// gamma) instead of artifactProducerContract's one — the fixture for Sol
// audit finding #16 ("Assayer evaluates only the first produced artifact").
func multiArtifactProducerContract(root string) contracts.Contract {
	c := contract(root)
	c.JobID = "multi-artifact-producer"
	c.Produces = []contracts.ArtifactSpec{
		{Name: "alpha", Path: ".governator/artifacts/alpha.json", MaxBytes: 262144},
		{Name: "beta", Path: ".governator/artifacts/beta.json", MaxBytes: 262144},
		{Name: "gamma", Path: ".governator/artifacts/gamma.json", MaxBytes: 262144},
	}
	return c
}

func writeMultiArtifactFakeBackend(t *testing.T) string {
	t.Helper()
	return writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"alpha"}' > .governator/artifacts/alpha.json
printf '{"summary":"beta"}' > .governator/artifacts/beta.json
printf '{"summary":"gamma"}' > .governator/artifacts/gamma.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
}

// stubAssayerFailsNamedArtifact is a conditional Assayer stub (unlike
// writeAssayerStub's fixed-response bodies): it reads the real evaluate
// request off stdin and returns FAIL only for the artifact named
// failArtifact, PASS for every other artifact — letting a test prove that
// every produced artifact reached its own independent subprocess call
// rather than only artifactRecords[0].
func stubAssayerFailsNamedArtifact(t *testing.T, failArtifact string) string {
	t.Helper()
	return writeAssayerStub(t, `import json, sys
req = json.loads(sys.stdin.read())
name = req.get("artifact_name")
if name == "`+failArtifact+`":
    verdict, failed = "fail", ["no_boilerplate:content"]
else:
    verdict, failed = "pass", []
print(json.dumps({
    "verdict": verdict, "failed_checks": failed, "had_error": False,
    "evaluation_id": "e", "trace_id": None, "quarantine_id": "",
    "checks_result_hash": "h-" + str(name), "profile_definition_hash": "p",
    "validator_implementation_hash": "vi", "validator_config_hash": "vc",
    "policy_version": "v1",
}))
`)
}

// TestSol3AssayEvaluatesEveryProducedArtifactThirdFailureBlocks is the
// literal corpus #12 reproduction: a contract producing three artifacts
// under a blocking assay where artifact #3 (by evaluation order, "gamma" —
// alphabetically last, matching collectProducedArtifacts's sort) fails.
// Pre-fix, runAssayStep evaluated only artifactRecords[0] ("alpha") and
// would have approved the run outright; the fix must block on gamma's
// failure and must still have evaluated alpha and beta independently (three
// ledger rows, not one).
func TestSol3AssayEvaluatesEveryProducedArtifactThirdFailureBlocks(t *testing.T) {
	root, _ := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	setAssayEnv(t, stubAssayerFailsNamedArtifact(t, "gamma"))
	t.Setenv("GOV_CLAUDE_BIN", writeMultiArtifactFakeBackend(t))
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	c := multiArtifactProducerContract(root)
	c.Assay = &contracts.Assay{Profile: "coding-output-v1", Enforcement: "blocking"}

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected the third artifact's FAIL verdict to quarantine the run, got status=%s message=%s", rec.Status, rec.Message)
	}
	if rec.FailureTaxonomy != "ASSAY_FAILED" {
		t.Fatalf("expected ASSAY_FAILED taxonomy, got %s", rec.FailureTaxonomy)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := observability.AssayEvaluationsForRun(db, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected all three produced artifacts to be independently evaluated (3 ledger rows), got %d: %+v", len(rows), rows)
	}
	byName := map[string]observability.AssayEvaluationRecord{}
	for _, row := range rows {
		byName[row.ArtifactName] = row
	}
	for _, name := range []string{"alpha", "beta"} {
		if row, ok := byName[name]; !ok || row.Verdict != "pass" {
			t.Fatalf("expected artifact %q to have an independent pass verdict, got %+v (ok=%v)", name, row, ok)
		}
	}
	if row, ok := byName["gamma"]; !ok || row.Verdict != "fail" {
		t.Fatalf("expected artifact %q to have a fail verdict, got %+v (ok=%v)", "gamma", row, ok)
	}
}

// TestSol3UndeclaredProducedArtifactFailsClosed covers the other half of
// finding #16: a contract using the new per-artifact assays[] list that
// does not cover every produced artifact, and declares no contract-wide
// default profile either, must fail closed on the uncovered artifact — not
// silently skip it.
func TestSol3UndeclaredProducedArtifactFailsClosed(t *testing.T) {
	root, _ := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	setAssayEnv(t, writeAssayerStub(t, stubPassVerdict))
	t.Setenv("GOV_CLAUDE_BIN", writeMultiArtifactFakeBackend(t))
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	c := multiArtifactProducerContract(root)
	// No contract-wide Profile: alpha and beta are covered, gamma is not —
	// gamma must be Undeclared and fail closed regardless of enforcement.
	c.Assay = &contracts.Assay{Artifacts: []contracts.ArtifactAssay{
		{Artifact: "alpha", Profile: "coding-output-v1", Enforcement: "blocking"},
		{Artifact: "beta", Profile: "coding-output-v1", Enforcement: "blocking"},
	}}

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected the undeclared artifact to quarantine the run, got status=%s message=%s", rec.Status, rec.Message)
	}
	if !strings.Contains(rec.Message, "gamma") || !strings.Contains(rec.Message, "no declared assay") {
		t.Fatalf("expected the quarantine reason to name the undeclared artifact, got message=%q", rec.Message)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := observability.AssayEvaluationsForRun(db, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]observability.AssayEvaluationRecord{}
	for _, row := range rows {
		byName[row.ArtifactName] = row
	}
	if row, ok := byName["gamma"]; !ok || row.Verdict != "error" {
		t.Fatalf("expected an error-verdict ledger row for the undeclared artifact, got %+v (ok=%v)", row, ok)
	}
	if row, ok := byName["alpha"]; !ok || row.Verdict != "pass" {
		t.Fatalf("expected alpha (covered by assays[]) to still evaluate normally, got %+v (ok=%v)", row, ok)
	}
}

// TestSol3ArtifactAssayNoneExemptsWithoutOverBlocking proves the third valid
// resolution from finding #16 ("explicitly declare assay: none"): an
// exempted artifact is recorded as skipped but never blocks, while its
// siblings still evaluate and gate the merge normally.
func TestSol3ArtifactAssayNoneExemptsWithoutOverBlocking(t *testing.T) {
	root, _ := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	setAssayEnv(t, writeAssayerStub(t, stubPassVerdict))
	t.Setenv("GOV_CLAUDE_BIN", writeMultiArtifactFakeBackend(t))
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	c := multiArtifactProducerContract(root)
	c.Assay = &contracts.Assay{Artifacts: []contracts.ArtifactAssay{
		{Artifact: "alpha", Profile: "coding-output-v1", Enforcement: "blocking"},
		{Artifact: "beta", Profile: "coding-output-v1", Enforcement: "blocking"},
		{Artifact: "gamma", Profile: contracts.AssayProfileNone},
	}}

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected the exempt artifact to never block an otherwise-passing run, got status=%s message=%s", rec.Status, rec.Message)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := observability.AssayEvaluationsForRun(db, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected all three artifacts to have a ledger row (two evaluated, one exempt), got %d: %+v", len(rows), rows)
	}
	byName := map[string]observability.AssayEvaluationRecord{}
	for _, row := range rows {
		byName[row.ArtifactName] = row
	}
	if row, ok := byName["gamma"]; !ok || row.Verdict != "skipped" {
		t.Fatalf("expected the exempt artifact to be recorded as skipped, got %+v (ok=%v)", row, ok)
	}
	for _, name := range []string{"alpha", "beta"} {
		if row, ok := byName[name]; !ok || row.Verdict != "pass" {
			t.Fatalf("expected artifact %q to still evaluate and pass, got %+v (ok=%v)", name, row, ok)
		}
	}
}

// writeAssayerStub writes a minimal fake `cli.py` that plays the Assayer
// subprocess role without depending on the real Python package — this
// mirrors the plan's "fake/stub python3 script" option (the real CLI is
// exercised separately and exhaustively by internal/assay's own tests
// against a temp copy of the actual repo). body is Python source; it must
// print exactly one verdict JSON object to stdout (or exit nonzero to
// simulate a crash).
func writeAssayerStub(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cli.py"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

const stubPassVerdict = `import json
print(json.dumps({"verdict":"pass","failed_checks":[],"had_error":False,"evaluation_id":"e","trace_id":None,"quarantine_id":"","checks_result_hash":"h-pass","profile_definition_hash":"p-pass","validator_implementation_hash":"vi-pass","validator_config_hash":"vc-pass","policy_version":"v1"}))
`

const stubFailVerdict = `import json
print(json.dumps({"verdict":"fail","failed_checks":["no_boilerplate:content"],"had_error":False,"evaluation_id":"e","trace_id":None,"quarantine_id":"","checks_result_hash":"h-fail","profile_definition_hash":"p-fail","validator_implementation_hash":"vi-fail","validator_config_hash":"vc-fail","policy_version":"v1"}))
`

const stubCrash = `import sys
sys.stderr.write("simulated assayer crash")
sys.exit(1)
`

func setAssayEnv(t *testing.T, repo string) {
	t.Helper()
	t.Setenv("GOV_ASSAY_REPO", repo)
	t.Setenv("GOV_ASSAY_PYTHON", "python3")
	t.Setenv("GOV_ASSAY_TIMEOUT_SECONDS", "10")
	if _, err := toolregistry.Enroll("python3", resolveTestTool(t, "python3")); err != nil {
		t.Fatalf("enroll python3: %v", err)
	}
}

// TestAssayNotConfiguredSkipsAndRecordsSkipped covers the plan's
// "not configured -> skipped and recorded as skipped" default for the
// non-blocking enforcement modes: an advisory contract still runs and
// merges exactly as it would have before assay existed when Governator's
// own config never points at an assayer checkout. (Blocking enforcement
// deliberately does NOT get this grace — see
// TestAssayBlockingUnconfiguredQuarantines.)
func TestAssayNotConfiguredSkipsAndRecordsSkipped(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	// Isolate from the host's real ~/.governator/config.yaml: GOV_HOME does
	// not redirect config file lookup (config.Path() uses $HOME), so an
	// operator config with assay.repo set would otherwise leak in and make
	// this "not configured" case actually configured. Same isolation
	// pattern used by batch_test.go / plan_test.go.
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	t.Setenv("GOV_ASSAY_REPO", "") // explicit: unconfigured
	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	rec, err := New().Run(context.Background(), assayProducerContract(root, "advisory"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected assay-not-configured advisory to leave the run unaffected, got status=%s message=%s", rec.Status, rec.Message)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := observability.AssayEvaluationsForRun(db, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Verdict != "skipped" {
		t.Fatalf("expected exactly one skipped assay_evaluations row, got %+v", rows)
	}
}

// TestAssayBlockingUnconfiguredQuarantines: a contract that explicitly
// declares blocking assay enforcement on a Governator with no assayer
// configured must quarantine, not silently skip-and-merge — "the gating
// tool isn't installed" is fail-open, the same reason runner: docker
// errors rather than quietly running local. The skipped ledger row is
// still written so the operator can see exactly why.
func TestAssayBlockingUnconfiguredQuarantines(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	// See TestAssayNotConfiguredSkipsAndRecordsSkipped: isolate from the
	// host's real config so this "unconfigured blocking" case is genuinely
	// unconfigured, not inheriting an operator assay.repo.
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing-config.yaml"))
	t.Setenv("GOV_ASSAY_REPO", "") // explicit: unconfigured
	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	rec, err := New().Run(context.Background(), assayProducerContract(root, "blocking"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected blocking assay with no assayer configured to quarantine, got status=%s message=%s", rec.Status, rec.Message)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := observability.AssayEvaluationsForRun(db, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Verdict != "skipped" {
		t.Fatalf("expected exactly one skipped assay_evaluations row, got %+v", rows)
	}
}

// TestAssayBlockingFailQuarantines proves a blocking FAIL verdict routes
// into the existing quarantine machinery (the same `violations` slice a
// failed validator uses), not a parallel one.
func TestAssayBlockingFailQuarantines(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	setAssayEnv(t, writeAssayerStub(t, stubFailVerdict))
	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	rec, err := New().Run(context.Background(), assayProducerContract(root, "blocking"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected blocking assay FAIL to quarantine, got status=%s message=%s", rec.Status, rec.Message)
	}
	if rec.FailureTaxonomy != "ASSAY_FAILED" {
		t.Fatalf("expected ASSAY_FAILED taxonomy, got %s (message=%s)", rec.FailureTaxonomy, rec.Message)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := observability.AssayEvaluationsForRun(db, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Verdict != "fail" || rows[0].ChecksHash != "h-fail" {
		t.Fatalf("expected one fail assay_evaluations row, got %+v", rows)
	}
}

// TestAssayAdvisoryFailRecordedButMergeProceeds proves the same FAIL
// verdict, under advisory enforcement, is ledgered but never blocks the
// merge — "Supabase down / assay unhappy" must never quarantine a run the
// operator explicitly marked non-blocking.
func TestAssayAdvisoryFailRecordedButMergeProceeds(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	setAssayEnv(t, writeAssayerStub(t, stubFailVerdict))
	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	rec, err := New().Run(context.Background(), assayProducerContract(root, "advisory"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected advisory assay FAIL to leave the run APPROVED, got status=%s message=%s", rec.Status, rec.Message)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := observability.AssayEvaluationsForRun(db, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Verdict != "fail" {
		t.Fatalf("expected the FAIL verdict to still be recorded under advisory enforcement, got %+v", rows)
	}
}

// TestAssayBlockingErrorQuarantines proves an ERROR verdict (here: the
// subprocess itself crashing/exiting nonzero) is treated exactly like a
// FAIL under blocking enforcement. This exercises the same
// assay.Blocks()-gated violations path that a pre/post artifact sha256
// mismatch would also travel through (both produce a Verdict{Verdict:
// "error"}); the sha256 mismatch detection itself — both before and after
// the subprocess call — is exhaustively unit-tested at the
// internal/assay package level (TestEvaluateShaMismatchBeforeEvaluationIsError
// / TestEvaluateShaMismatchAfterEvaluationIsError), since reproducing a
// genuine artifact-file TOCTOU race through this package's black-box
// Run() API would need a test-only mutation hook that doesn't otherwise
// exist in this codebase.
func TestAssayBlockingErrorQuarantines(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	setAssayEnv(t, writeAssayerStub(t, stubCrash))
	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	rec, err := New().Run(context.Background(), assayProducerContract(root, "blocking"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" || rec.FailureTaxonomy != "ASSAY_FAILED" {
		t.Fatalf("expected blocking assay ERROR to quarantine with ASSAY_FAILED, got status=%s taxonomy=%s message=%s", rec.Status, rec.FailureTaxonomy, rec.Message)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := observability.AssayEvaluationsForRun(db, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Verdict != "error" {
		t.Fatalf("expected one error assay_evaluations row, got %+v", rows)
	}
}

// TestAssayPassApproves is the sanity-check companion: a PASS verdict must
// never quarantine, and both blocking and advisory contracts merge
// identically on a clean verdict.
func TestAssayPassApproves(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	setAssayEnv(t, writeAssayerStub(t, stubPassVerdict))
	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	rec, err := New().Run(context.Background(), assayProducerContract(root, "blocking"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected pass verdict to approve, got status=%s message=%s", rec.Status, rec.Message)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := observability.AssayEvaluationsForRun(db, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Verdict != "pass" || rows[0].ChecksHash != "h-pass" {
		t.Fatalf("expected one pass assay_evaluations row, got %+v", rows)
	}
}

// TestAssayEvaluationRecordsEnvironmentMetadata proves plan Session 2 item 3
// ("record in every evaluation: Assayer commit, profile hash, validator
// versions, Python environment") end to end through the real runtime call
// site, not just internal/assay's own unit tests. It points GOV_ASSAY_REPO
// at the real pinned fixture (not a stub) so ProfileHash/ValidatorsHash come
// from real assayer/profiles.py and assayer/checks.py bytes, and
// AssayerCommit comes from the fixture's PINNED_COMMIT marker (the fixture
// has no .git of its own).
func TestAssayEvaluationRecordsEnvironmentMetadata(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	fixtureRepo, err := filepath.Abs(filepath.Join("..", "assay", "testdata", "assayer_fixture"))
	if err != nil {
		t.Fatal(err)
	}
	setAssayEnv(t, fixtureRepo)
	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	rec, err := New().Run(context.Background(), assayProducerContract(root, "blocking"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected the real fixture to pass and approve, got status=%s message=%s", rec.Status, rec.Message)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := observability.AssayEvaluationsForRun(db, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly one assay_evaluations row, got %+v", rows)
	}
	row := rows[0]
	pinned, err := os.ReadFile(filepath.Join(fixtureRepo, "PINNED_COMMIT"))
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimSpace(string(pinned)); row.AssayerCommit != want {
		t.Fatalf("AssayerCommit = %q, want pinned fixture commit %q", row.AssayerCommit, want)
	}
	if len(row.ProfileHash) != 64 {
		t.Fatalf("expected a 64-hex-char ProfileHash, got %q", row.ProfileHash)
	}
	if len(row.ValidatorsHash) != 64 {
		t.Fatalf("expected a 64-hex-char ValidatorsHash, got %q", row.ValidatorsHash)
	}
	if !strings.Contains(strings.ToLower(row.PythonVersion), "python") {
		t.Fatalf("expected PythonVersion to mention python, got %q", row.PythonVersion)
	}
}

// TestAssayBlockingFailNeverOpensBreaker is the plan Session 2 item 5
// regression: a quality-only failure (a blocking assay FAIL verdict) must
// never open or degrade the infra circuit breaker for the backend that
// produced it. The fake backend in this test "ran fine" — it exited 0,
// produced its artifact, wrote a clean RESULT.json — so infraKind stays
// agents.InfraNone; only the artifact *content* failed assay's checks. Rule
// 3 (internal/breaker's own doc comment: "bad output must never open a
// breaker") says the breaker must read this exactly like an ordinary
// approved run, not like an outage.
func TestAssayBlockingFailNeverOpensBreaker(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	setAssayEnv(t, writeAssayerStub(t, stubFailVerdict))
	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	rec, err := New().Run(context.Background(), assayProducerContract(root, "blocking"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" || rec.FailureTaxonomy != "ASSAY_FAILED" {
		t.Fatalf("expected a quality-only ASSAY_FAILED quarantine, got status=%s taxonomy=%s", rec.Status, rec.FailureTaxonomy)
	}
	if rec.Agent == "" {
		t.Fatal("expected the run to record which backend ran it")
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	snap := breaker.Snapshot(db, rec.Agent, time.Now().UTC())
	if snap.EffectiveState != breaker.Closed {
		t.Fatalf("a quality-only assay failure must never move the breaker off CLOSED, got %s (failure_kind=%q)", snap.EffectiveState, snap.FailureKind)
	}
	if snap.FailureKind != "" || snap.ConsecutiveFailures != 0 {
		t.Fatalf("expected no infra failure ever recorded for this backend, got failure_kind=%q consecutive_failures=%d", snap.FailureKind, snap.ConsecutiveFailures)
	}
}

// TestAssayBlockingErrorNeverOpensBreaker is the ERROR-verdict twin of
// TestAssayBlockingFailNeverOpensBreaker: the Assayer subprocess itself
// crashing is still an assay-boundary (quality-pipeline) failure, not an
// infra failure of the coding backend — agents.ClassifyInfra never even
// looks at assay verdicts, only at the coding backend's own exit
// code/launch error/transcript. The breaker must stay untouched here too.
func TestAssayBlockingErrorNeverOpensBreaker(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	setAssayEnv(t, writeAssayerStub(t, stubCrash))
	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	rec, err := New().Run(context.Background(), assayProducerContract(root, "blocking"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "QUARANTINED" || rec.FailureTaxonomy != "ASSAY_FAILED" {
		t.Fatalf("expected a quality-only ASSAY_FAILED quarantine, got status=%s taxonomy=%s", rec.Status, rec.FailureTaxonomy)
	}

	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	snap := breaker.Snapshot(db, rec.Agent, time.Now().UTC())
	if snap.EffectiveState != breaker.Closed {
		t.Fatalf("an assay subprocess crash must never move the breaker off CLOSED, got %s (failure_kind=%q)", snap.EffectiveState, snap.FailureKind)
	}
	if snap.FailureKind != "" || snap.ConsecutiveFailures != 0 {
		t.Fatalf("expected no infra failure ever recorded for this backend, got failure_kind=%q consecutive_failures=%d", snap.FailureKind, snap.ConsecutiveFailures)
	}
}
