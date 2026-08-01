package runtime

import (
	"context"
	"os/exec"
	goruntime "runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/lifecycle"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/toolregistry"
)

// This file covers Sol redteam v4 S9's "chaos/concurrency suite" bullets not
// already exercised elsewhere in the corpus:
//
//   - "process kill at every lifecycle stage" is
//     TestLifecycleInvariant_RecoveryNeverLeaksReservationOrWorkspace
//     (lifecycle_invariant_test.go), added this same session.
//   - "duplicated reconcilers" is
//     TestSol3ConcurrentReconcilersNeverDoubleApplyBreakerFailure and
//     TestSol3ClaimOutboxNeverDoubleClaimsAcrossTwoConnections
//     (sol3_reconcile_leasing_test.go, S10).
//   - "lease expiry" is TestSol3SettleGlobalRacingExpiryNeverSilentlyLosesSettlement
//     (internal/spend) and the Assayer outbox lease tests (Python, S6).
//   - "binary replacement" is report §9 attacks 6/7/10/11/12 (S3, redteam
//     corpus).
//   - "config replacement" is TestSol3ConfigMutationDuringRunDoesNotAlterDoctrineEnforcement
//     (S1 Critical 1 follow-up).
//   - "clock jumps" is internal/spend/chaos_clock_test.go, added this
//     session.
//   - "hook failures" has no scenario left to chaos-test: S1's isolated-index
//     commit path (internal/gitplumb) never executes a repository hook at
//     all (core.hooksPath points at an empty dir) — a hook that fails has
//     nothing to fail *in*, by construction. Noted in the S9 findings log
//     rather than fabricated a test for something structurally impossible.
//   - "disk full" has no clean injection seam in this codebase (no
//     filesystem abstraction layer to fault-inject through, and this
//     environment cannot create a size-capped tmpfs without root) — flagged
//     in the S9 findings log as a gap for a future session rather than
//     approximated with a misleading substitute (e.g. a read-only directory
//     produces EACCES, not ENOSPC, and several of the write paths this would
//     need to hit already branch on error string content).
//
// "DB busy" and "validator hangs" are new tests below.

// TestChaos_ConcurrentLifecycleRecordersUnderRealSQLiteContention is the "DB
// busy" chaos scenario: many goroutines racing lifecycle.Record (and
// therefore observability.RecordStage/StageHistory) against the same
// on-disk ledger through independent *sql.DB connections — standing in for
// several `gov` processes sharing one ledger.db, not a mocked lock — must
// all either succeed or fail with a real application-level error, never
// hang or return a raw SQLITE_BUSY (the busy_timeout configured in
// observability.Open is what this test would catch a regression in).
func TestChaos_ConcurrentLifecycleRecordersUnderRealSQLiteContention(t *testing.T) {
	home := t.TempDir()
	// Initialize the schema once before the concurrent writer phase. The
	// chaos property under test is lifecycle.Record contention, not racing
	// CREATE TABLE bootstrap on every connection; under -race that bootstrap
	// contention can exceed SQLite's busy timeout and make the fixture flaky.
	bootstrap, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.Close(); err != nil {
		t.Fatal(err)
	}

	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each goroutine opens its own connection (its own *sql.DB, like
			// a separate `gov` process would) to the same ledger.db, and
			// drives one run through a legal stage sequence — a real,
			// non-trivial write pattern under contention, not a single bare
			// INSERT.
			db, err := observability.Open(home)
			if err != nil {
				errs[i] = err
				return
			}
			defer db.Close()
			id := "run-busy-" + time.Now().UTC().Format("150405.000000000") + "-" + strconv.Itoa(i)
			for _, st := range []lifecycle.Stage{lifecycle.Parsed, lifecycle.Preflighted, lifecycle.Routed} {
				if err := lifecycle.Record(db, id, st, "", lifecycle.Now()); err != nil {
					errs[i] = err
					return
				}
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}

// TestChaos_HungValidatorKilledAtContextDeadline is the "validator hangs"
// chaos scenario. A command that never returns (a genuine hang, not a
// slow-but-finite command) must not hang the run past its own remaining
// budget — shell() kills the whole process group on ctx cancellation
// (runtime.go:606-612); this test proves that against a real `sleep`
// subprocess rather than trusting the context-plumbing by inspection.
// Actual validators run through shellStage, not shell() directly (Sol12
// P0-6 scoped shell() to git porcelain alone, with PATH private to the
// sealed git+bash directories); an absolute path sidesteps that PATH
// restriction since this test is proving the ctx-kill mechanism, not
// PATH-based tool resolution.
func TestChaos_HungValidatorKilledAtContextDeadline(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("validator shell execution requires Linux sealed controller-tool launch")
	}
	dir := t.TempDir()
	registry, rerr := toolregistry.Load()
	if rerr != nil {
		t.Fatalf("load trusted-tool registry: %v", rerr)
	}
	sleepBin, lerr := exec.LookPath("sleep")
	if lerr != nil {
		t.Fatalf("look up sleep: %v", lerr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	code, out, err := shell(ctx, dir, shQuote(sleepBin)+" 30", registry)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("hung validator was not killed at its context deadline: took %s (deadline was 200ms)", elapsed)
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("ctx.Err() = %v, want DeadlineExceeded", ctx.Err())
	}
	// The subprocess was killed, not gracefully completed — code/err should
	// reflect that rather than a clean 0 exit, though the exact shape is
	// platform-dependent, so this only guards against the dangerous case: a
	// silent success report for a command that never actually ran to
	// completion.
	if code == 0 && err == nil {
		t.Fatalf("hung validator reported a clean success (code=0, err=nil, out=%q) — a killed command must never look like it passed", out)
	}
}
