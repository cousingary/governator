//go:build redteam

// v6_s9_assayer_lifecycle_test.go is the Sol redteam v6 Permanent
// Regression Corpus, cases 31-33, owned by Session 9 (Phase 9: Assayer
// lifecycle hardening + close-out). See
// agents/governator-sol-upgrade6-plan.md Session 9 and
// agents/governator-sol-upgrade6.md P1-3/P1-4/P1-5. Assayer
// (/mnt/e/downloads/assayer) is a separate Python repository/process this
// Go corpus cannot execute (see assayer_test.go's
// assertAssayerTestFileContains and its doc comment) -- cases 31 and 32
// follow that existing cross-repo-pointer pattern exactly, pointing at real
// pytest fixtures that S9 must add (they do not exist yet, which is exactly
// why these are skipped). Case 33 is the one case in the whole corpus
// explicitly permitted to deviate from the runGoverned/fixtureRepo pattern
// (it isn't testing `gov` at all): it shells out to the real pytest run
// under a bounded timeout and checks actual process exit, not merely a
// parsed summary line. Every test here is scaffolding only (Session 0):
// t.Skip(...) is the literal first statement, before any fixture
// construction.
package redteam

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestV6Case31AssayerLeaseRenewedThroughSlowDownstreamCallPreventsDuplicate
// is corpus case 31 (report P1-4): follows
// TestAttack13TwoAssayerWorkersReclaimOneExpiredLease's existing pattern
// (assayer_test.go) but for a DIFFERENT scenario than simultaneous-worker
// reclaim: a lease renewed once before a downstream call, where the
// downstream call itself outlives that single renewal and the lease
// expires mid-flight -- the fix (continuous renewal for the full downstream
// operation + an idempotency key + mark-complete-only-if-still-owns-the-
// lease) must prevent DUPLICATE EXECUTION of the same downstream operation,
// not just prevent a duplicate row in a compatible target store (which
// stable event IDs already do today). The real fixture belongs in
// tests/test_outbox.py; this only proves it exists once S9 adds it.
func TestV6Case31AssayerLeaseRenewedThroughSlowDownstreamCallPreventsDuplicate(t *testing.T) {
	assertAssayerTestFileContains(t, "tests/test_outbox.py",
		"class Sol6OutboxLeaseHeartbeatTests",
		"def test_attack31_lease_renewed_through_slow_downstream_call_prevents_duplicate_execution",
	)
}

// TestV6Case32UnknownOutboxOperationIsDeadLettered is corpus case 32
// (report P1-5): follows TestAttack16InventedAssayerLanguagePasses's
// existing pattern's shape, but for an unrecognized outbox
// operation/table_hint rather than an invented language. Confirmed from
// source (assayer/outbox.py's replay dispatch): the current routing is
// exactly `if entry["table_hint"] == "assayer_quarantine": ... else:
// store.insert_trace(entry["row"])` -- ANY unrecognized table_hint (a typo,
// a future incompatible operation) is silently reinterpreted as a trace
// rather than rejected. The fix needs a strict operation allowlist with
// unknown operations dead-lettered as UNKNOWN_OUTBOX_OPERATION, never
// silently misrouted to a different evidence type.
func TestV6Case32UnknownOutboxOperationIsDeadLettered(t *testing.T) {
	assertAssayerTestFileContains(t, "tests/test_outbox.py",
		"class Sol6OutboxUnknownOperationTests",
		"def test_attack32_unknown_table_hint_is_dead_lettered_not_reinterpreted_as_trace",
		"UNKNOWN_OUTBOX_OPERATION",
	)
}

// TestV6Case33AssayerPytestExitsCleanlyOnSupportedPythonVersions is corpus
// case 33 (report P1-3): a genuine process-hygiene check, not a per-request
// attack -- the report's independent audit reproduced "184 passed in
// 32.55s" followed by the pytest PROCESS remaining alive until externally
// killed (a multi-threaded fork() deadlock warning accompanied it). A
// release script that merely parses "N passed" out of captured output
// would report PASS while CI silently hangs. This test shells out to the
// real `python3 -m pytest -q` inside the Assayer repo under a bounded
// timeout (mirroring scripts/release.sh's own ASSAYER_REPO resolution) and
// asserts the PROCESS actually exits (context not deadline-exceeded) with
// code 0 -- not just that a summary line looked like a pass. This is the
// one corpus case explicitly permitted to deviate from the
// runGoverned/fixtureRepo pattern, since it does not exercise `gov` at all.
func TestV6Case33AssayerPytestExitsCleanlyOnSupportedPythonVersions(t *testing.T) {
	repo := os.Getenv("ASSAYER_REPO")
	if repo == "" {
		repo = assayerRepoRoot()
	}
	if _, err := os.Stat(repo); err != nil {
		t.Skipf("ASSAYER_REPO %q not present on this machine: %v", repo, err)
	}
	python := os.Getenv("ASSAYER_TEST_PYTHON")
	if python == "" {
		python = "python3"
	}
	if _, err := exec.LookPath(python); err != nil {
		t.Skipf("Assayer test interpreter %q not available: %v", python, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-m", "pytest", "-q")
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("pytest process did not exit within the bounded timeout (hung past its own summary, mirroring the report's reproduction) -- output tail:\n%s", tail(string(out), 2000))
	}
	if err != nil {
		t.Fatalf("pytest process exited nonzero: %v -- output tail:\n%s", err, tail(string(out), 2000))
	}
	if !strings.Contains(string(out), " passed") {
		t.Fatalf("pytest exited 0 but its output does not look like a real passing summary -- output tail:\n%s", tail(string(out), 2000))
	}
}

// tail returns the last n bytes of s (or all of s if shorter), for
// legible failure output without dumping an entire pytest transcript.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
