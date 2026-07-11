package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

// assayProducerContract builds on artifactProducerContract (same fixture
// used by the produced-artifact tests above) with an assay block attached,
// so the ledgered "reconnaissance" artifact is what gets evaluated.
func assayProducerContract(root, enforcement string) contracts.Contract {
	c := artifactProducerContract(root)
	c.Assay = &contracts.Assay{Profile: "coding-output-v1", Enforcement: enforcement}
	return c
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
print(json.dumps({"verdict":"pass","failed_checks":[],"had_error":False,"trace_id":"t","quarantine_id":"","checks_hash":"h-pass","policy_version":"v1"}))
`

const stubFailVerdict = `import json
print(json.dumps({"verdict":"fail","failed_checks":["no_boilerplate:content"],"had_error":False,"trace_id":"t","quarantine_id":"","checks_hash":"h-fail","policy_version":"v1"}))
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
}

// TestAssayNotConfiguredSkipsAndRecordsSkipped is the Phase 3A regression
// test (plan item 7, "assay not configured -> skipped and recorded as
// skipped, run proceeds normally"): a contract that declares an assay block
// must still run and merge exactly as it would have before assay existed
// when Governor's own config never points at an assayer checkout.
func TestAssayNotConfiguredSkipsAndRecordsSkipped(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
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
	if rec.Status != "APPROVED" {
		t.Fatalf("expected assay-not-configured to leave the run unaffected, got status=%s message=%s", rec.Status, rec.Message)
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
