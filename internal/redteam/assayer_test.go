//go:build redteam

package redteam

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// assayerRepoRoot is the pinned Python repo these three attacks are actually
// fixed and fixture-tested in. CI supplies ASSAYER_REPO explicitly; the
// sibling default preserves the established local workspace layout.
func assayerRepoRoot() string {
	if repo := strings.TrimSpace(os.Getenv("ASSAYER_REPO")); repo != "" {
		return repo
	}
	return "/mnt/e/downloads/assayer"
}

// assertAssayerTestFileContains is the cross-repo traceability primitive
// shared by attacks 13/14/16: this Go corpus cannot execute Python, so it
// cannot re-run the real fixture -- but it CAN prove the real fixture still
// exists, so a future edit that silently deletes the Python-side regression
// test (rather than this Go file merely being forgotten) fails loudly here
// too. Real behavioral proof lives in the Assayer pytest run, not this
// check.
func assertAssayerTestFileContains(t *testing.T, relPath string, markers ...string) {
	t.Helper()
	path := filepath.Join(assayerRepoRoot(), relPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Assayer fixture file missing (%s): %v -- the real regression test for this attack must live here", path, err)
	}
	content := string(data)
	for _, marker := range markers {
		if !strings.Contains(content, marker) {
			t.Fatalf("%s no longer contains %q -- the Sol redteam v4 regression fixture for this attack appears to have been removed", path, marker)
		}
	}
}

// TestAttack13TwoAssayerWorkersReclaimOneExpiredLease is report P0-8 / §9
// attack 13: a worker leases an outbox row, the lease expires mid-flight
// (slow downstream store operation), and a second worker reclaims and
// concurrently processes the same row. Fixed by S6: stable event_id +
// uniqueness constraint on the target store, lease renewal, and
// mark-complete-only-if-still-owns-the-lease
// (assayer/outbox.py, assayer/store.py).
//
// The real fixture lives in the Assayer pytest suite (a separate
// process/language from this Go corpus, so it cannot be executed here):
// tests/test_outbox.py::Sol4OutboxDuplicateProcessingTests::
// test_attack13_two_workers_reclaim_one_expired_lease_no_duplicate_insert.
// This test only proves that fixture still exists.
func TestAttack13TwoAssayerWorkersReclaimOneExpiredLease(t *testing.T) {
	assertAssayerTestFileContains(t, "tests/test_outbox.py",
		"class Sol4OutboxDuplicateProcessingTests",
		"def test_attack13_two_workers_reclaim_one_expired_lease_no_duplicate_insert",
	)
}

// TestAttack14DownstreamInsertSucceedsBeforeOutboxWorkerCrashes is report
// P0-8 / §9 attack 14: a crash between downstream insertion and outbox row
// deletion re-processes the same entry on restart. Same fix and same
// cross-repo pointer pattern as attack 13:
// tests/test_outbox.py::Sol4OutboxDuplicateProcessingTests::
// test_attack14_crash_between_downstream_insert_and_outbox_delete_is_idempotent.
func TestAttack14DownstreamInsertSucceedsBeforeOutboxWorkerCrashes(t *testing.T) {
	assertAssayerTestFileContains(t, "tests/test_outbox.py",
		"class Sol4OutboxDuplicateProcessingTests",
		"def test_attack14_crash_between_downstream_insert_and_outbox_delete_is_idempotent",
	)
}

// TestAttack16InventedAssayerLanguagePasses is report P1-12 / §9 attack 16:
// a coding-output artifact declaring a fabricated language (e.g. "madeup")
// passes because no language-specific validation exists for it. Fixed by
// S6: profiles declare allowed languages + required validators per
// language; unknown language -> fail, known language with no installed
// validator -> fail (strict coding profile -- assayer/checks.py's
// language_allowlist + domain_validator(require_validator=True),
// assayer/profiles.py's coding-output-v2 2.2.0).
//
// Real fixture: tests/test_evaluate.py::EvaluateCLITests::
// test_v2_rejects_fabricated_language_sol_attack_16. This test only proves
// that fixture still exists.
func TestAttack16InventedAssayerLanguagePasses(t *testing.T) {
	assertAssayerTestFileContains(t, "tests/test_evaluate.py",
		"def test_v2_rejects_fabricated_language_sol_attack_16",
		"language_allowlist:language",
	)
}
