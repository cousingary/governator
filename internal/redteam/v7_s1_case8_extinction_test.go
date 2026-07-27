//go:build redteam

// v7_s1_case8_extinction_test.go implements Sol redteam v7 corpus case 8
// (agents/governator-sol-upgrade7-plan.md Session 1, "cleanup-specific
// fail-open defect"). Every other case in this corpus forces its security
// outcome from a hostile shell script alone; case 8 needs a descendant that
// genuinely survives SIGKILL past containment.DefaultExtinctionDeadline --
// real kernel-level uninterruptible sleep, not a script trick. That
// mechanism (hangfuse_test.go: a minimal, dependency-free FUSE daemon whose
// read() handler never replies) was previously judged infeasible from a
// portable black-box fixture and left as a t.Skip placeholder (see
// agents/governator-sol-upgrade7-findings.md's "Case 8 stays a t.Skip
// placeholder" entries) -- built and empirically verified here instead:
// per fs/fuse/dev.c's request_wait_answer, a request that is FR_SENT (not
// merely FR_PENDING) when a fatal signal arrives falls through to a plain,
// non-killable wait_event, and this host's kernel honors that for a raw,
// capability-minimal FUSE connection (confirmed by direct measurement: a
// reader blocked on such a connection remains alive, and cgroup.procs
// remains populated, for 10+ seconds after cgroup.kill -- see this file's
// git history / session notes for the probe).
package redteam

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
	govruntime "github.com/cousingary/governator/internal/runtime"
	"github.com/cousingary/governator/internal/toolregistry"
)

// TestV7Case8CleanupValidatorDetachedDescendantExtinctionFailureBlocksApproval:
// a cleanup validator (Required: false, so a nonzero cleanup exit code alone
// would never block) spawns a detached, setsid'd descendant that issues a
// single blocking read against a file served by a hangfuse daemon living
// OUTSIDE the governed run's containment scope entirely -- the daemon must
// survive the run's own SIGKILL blast for the descendant to stay stuck, so
// it is started directly by the test, not by any command the run executes.
// The validator's own visible process exits 0 immediately after
// backgrounding the reader, exactly like every other "detached descendant"
// fixture in this corpus (descendants_test.go, v6_s1_network_process_test.go
// TestV6Case4). containment.Scope.Extinguish must then fail to confirm
// descendant extinction within DefaultExtinctionDeadline (5s) and the run
// must be blocked -- optional cleanup governs whether a nonzero cleanup
// EXIT CODE rejects the result, never whether a containment/extinction
// failure is acceptable (see runtime.go's cleanup-validator loop comment
// this case exists to prove).
func TestV7Case8CleanupValidatorDetachedDescendantExtinctionFailureBlocksApproval(t *testing.T) {
	if reason, ok := hangfuseAvailable(); !ok {
		t.Skipf("conditional: case8 hangfuse extinction fixture unavailable: unprivileged FUSE mount not usable on this host (%s) -- needs /dev/fuse plus fusermount3/fusermount and a kernel with CONFIG_FUSE_FS, not root", reason)
	}
	if !enforce.Supported() {
		t.Skip("conditional: case8 hangfuse extinction fixture needs external containment (Landlock/unshare required) -- case 8 needs a real governed scope teardown to prove extinction failure")
	}
	// Sol12 rc5 Session 2 (P0-1): empirically prove THIS kernel keeps a
	// FUSE-blocked reader genuinely unkillable before asserting an Extinguish
	// timeout on it. Some kernels (this project's own WSL2 dev sandbox among
	// them) patch FUSE's request wait to stay killable even for in-flight
	// requests (see hangfuse_test.go's header) -- on such a kernel SIGKILL
	// reaps the reader, extinction succeeds and the run would be (correctly)
	// APPROVED, which this assertion must not mis-report as a regression.
	// hangfuseProbeSurvivesSIGKILL was built to be exactly this per-host gate;
	// wiring it in here turns the old post-hoc "did not reach a blocking READ
	// before its deadline" timing flake into a deterministic, proven
	// host-capability skip. settle/kill windows mirror the probe's own
	// defaults: long enough to distinguish genuine D-state survival from
	// scheduler noise, short enough to keep the corpus fast.
	if survived, detail := hangfuseProbeSurvivesSIGKILL(t, 1*time.Second, 2*time.Second); !survived {
		t.Skipf("conditional: case8 hangfuse extinction fixture: this kernel terminates FUSE-blocked readers on SIGKILL (%s) -- the unkillable-descendant extinction invariant cannot reproduce here", detail)
	}

	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()

	// Sol9 P0-4 compatibility: structured cleanup validators now run under
	// the sealed-tool-PATH policy (rc3 Session 4), so every name in
	// ValidatorSpec.Tools has to be registry-enrolled before the run's
	// sealedValidatorToolsets can resolve + seal it. Pre-fix, the
	// ambient base PATH made /usr/bin/dd etc. reachable without ever
	// enrolling -- exactly the defect P0-5 closes. Enroll the exact
	// paths the validator command actually invokes (dd, setsid, sleep,
	// sh) so a hangfuse-capable host reaches the descendant-spawn step
	// this test exists to exercise, instead of failing earlier at
	// sealedValidatorToolsets's "resolve cleanup validator tool" check.
	for _, tool := range []string{"dd", "setsid", "sleep", "sh"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("look up case 8 declared tool %q: %v", tool, err)
		}
		if canonical, cerr := filepath.EvalSymlinks(path); cerr == nil {
			path = canonical
		}
		if _, err := toolregistry.Enroll(tool, path); err != nil {
			t.Fatalf("enroll case 8 declared tool %q: %v", tool, err)
		}
	}

	// Sol13 rc6 Session 9: the mount is staged INSIDE the governed worktree,
	// at the workspace-relative path below, via the WorkspaceReadyForTesting
	// seam. Before this it lived in the test's own TempDir, which Landlock
	// denies a governed descendant outright -- so the descendant's open()
	// failed before it could ever block, the readiness gate reported "did not
	// reach a confirmed blocking-read state", and case 8 skipped on every
	// host with real containment. That is the exact opposite of where this
	// case needs to run, and no capability host could have fixed it: the
	// stronger the containment, the more certainly it skipped.
	//
	// .codegraph is the deliberate choice of prefix: it is the one workspace
	// path fingerprint, validateFinalWorktreeShape, the change-set
	// computation and the merge-tree verification all exclude by name, so the
	// scaffolding cannot perturb what the run measures -- and, critically, no
	// measurement walk can ever open the file that never answers a read.
	const hangDirRel = ".codegraph/case8-hang"
	var (
		daemon     *hangfuseDaemon
		stopDaemon func()
		mountErr   error
	)
	// The daemon is owned by the test process, never by the governed run --
	// it must outlive the run's own containment teardown for the reader to
	// stay genuinely stuck. Stopped only after the assertion below.
	govruntime.WorkspaceReadyForTesting = func(work string) error {
		mnt := filepath.Join(work, filepath.FromSlash(hangDirRel))
		if err := os.MkdirAll(mnt, 0755); err != nil {
			mountErr = fmt.Errorf("mkdir in-workspace mountpoint: %w", err)
			return nil
		}
		d, stop, err := mountHangfuse(mnt)
		if err != nil {
			mountErr = fmt.Errorf("mount hangfuse in workspace: %w", err)
			return nil
		}
		daemon, stopDaemon = d, stop
		return nil
	}
	defer func() {
		govruntime.WorkspaceReadyForTesting = nil
		if stopDaemon != nil {
			stopDaemon()
		}
	}()

	// Sol12 rc5 Session 2 (P0-1): EXPLICIT SYNCHRONIZATION replaces the old
	// timing assumption. The previous form ran the whole governed run (whose
	// containment teardown fires Extinguish at an unspecified moment) and only
	// AFTERWARDS checked whether the detached descendant had happened to reach
	// its blocking read in time -- a race that flaked into a conditional skip
	// whenever the descendant lost to the extinction deadline. The
	// containment.ExtinguishGateForTesting seam blocks Extinguish at its
	// kill-boundary until this closure confirms the daemon has actually
	// observed a FUSE_READ from the descendant, so extinction can NEVER fire
	// before the blocking-read state is reached.
	//
	// Sol13 rc6 Session 9: SUCCESS is sticky, FAILURE is not. Extinguish is
	// called at more than one boundary and the FIRST of them is the backend
	// stage's scope -- which tears down before the cleanup validator has run,
	// so no descendant exists yet and no read can possibly have been seen.
	// The original form latched that first non-observation as a permanent
	// gateErr and returned it from every later call, which aborted the run at
	// "pre-extinction readiness gate failed" before the cleanup validator's
	// own extinction boundary was ever reached. Measured directly: the same
	// fixture with a non-latching gate reaches the blocking read and
	// quarantines the run. So each boundary re-waits, and only a confirmed
	// read is remembered; the synchronization guarantee S2 wanted (extinction
	// never fires ahead of the blocking-read state) is unchanged, while an
	// early boundary can no longer poison a later one.
	//
	// The gate never returns an error now. A window that elapses without a
	// read is not a refusal to extinguish -- it just means this boundary had
	// nothing to wait for. Whether the descendant EVER reached the read is
	// decided once, after the run, from readConfirmed.
	var (
		gateCalled    bool
		readConfirmed bool
	)
	containment.ExtinguishGateForTesting = func() error {
		gateCalled = true
		if readConfirmed || daemon == nil {
			return nil
		}
		if daemon.waitForRead(6 * time.Second) {
			readConfirmed = true
		}
		return nil
	}
	defer func() { containment.ExtinguishGateForTesting = nil }()

	root := fixtureRepo(t)
	c := baseContract(root)
	// Now that the mount is inside the workspace, the hang file is reachable
	// through an ORDINARY workspace-relative validator read_root -- the same
	// declaration any real contract would make, no widening of the sandbox
	// and no absolute host path (validatePathPatterns rejects those outright).
	// The descendant runs under exactly production's Landlock policy and is
	// granted exactly one extra readable directory, which is the mechanism
	// under test, never the invariant under test.
	// setsid'd, backgrounded, and pointed at declared workspace paths on both
	// ends. Two incidental details of the old command are gone because both
	// aborted the validator before it could spawn anything, and neither was
	// ever part of what case 8 asserts: the /dev/null redirects (Landlock
	// grants no access to /dev, which forbiddenBroadReadRoots refuses to
	// declare as a read root at all) and the nested `sh -c` wrapper around dd
	// (measured: `setsid sh -c 'dd ...' &` never reaches the read, while
	// `setsid dd ... &` does). The shape that matters is unchanged and is the
	// whole point of the case -- the validator's own visible process exits 0
	// immediately, leaving a detached descendant in a session of its own,
	// stuck in an unkillable FUSE read.
	cleanupCommand := "setsid dd if=" + hangDirRel + "/hang of=output/case8-sink bs=1 count=1 & sleep 1"
	c.Cleanup = &contracts.Cleanup{
		Required:   false,
		Validators: []string{cleanupCommand},
		ValidatorSpecs: []contracts.ValidatorSpec{{
			Command:    cleanupCommand,
			Tools:      []string{"dd", "setsid", "sleep", "sh"},
			ReadRoots:  []string{hangDirRel},
			WriteRoots: []string{"output"},
		}},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, runErr := runGovernedAllowError(t, t.TempDir(), bin, c)
	// The gate is the P0-1 synchronization primitive. If the run never
	// reached any extinction boundary (gateCalled=false -- contract rejected
	// or the chain aborted early) OR the descendant never reached a confirmed
	// blocking read at ANY boundary, this host cannot drive the full
	// deterministic chain case 8 asserts. Skip honestly: a structural
	// host-capability limit, not the timing race the old form hid behind. The
	// manifest authorizes this skip via the
	// case8_hangfuse_extinction_fixture predicate (Session 2 makes that skip
	// reflect capability, not timing).
	if !gateCalled || !readConfirmed {
		t.Skipf("conditional: case8 hangfuse extinction fixture: the cleanup-validator descendant did not reach a confirmed blocking-read state before extinction on this host (gateCalled=%v, readConfirmed=%v, mountErr=%v, runErr=%v)", gateCalled, readConfirmed, mountErr, runErr)
	}
	// The gate fired AND confirmed the blocking read: the descendant is
	// genuinely stuck in an unkillable FUSE read, so Extinguish must have
	// failed and the run must report a descendant-containment/extinction
	// failure regardless of Cleanup.Required=false.
	if rec.Status == "APPROVED" {
		t.Fatalf("cleanup validator's detached descendant survived SIGKILL past the extinction deadline (genuine kernel-level uninterruptible sleep via an unanswered FUSE read), yet the run was still APPROVED -- extinction failure must block approval regardless of Cleanup.Required=false")
	}
	// ...and it must be blocked for THIS reason. Sol13 rc6 Session 9: the
	// reason now surfaces where a blocked run's reason belongs -- the
	// quarantine record -- rather than as a returned error. Before this
	// session the fixture never reached a real extinction boundary, so the
	// only non-nil runErr it ever saw was the readiness gate refusing to
	// extinguish at all; with the gate no longer latching, the run proceeds,
	// extinction genuinely fails, and the runtime quarantines and records it.
	// Quarantine IS the block this case asserts, so accept the reason from
	// either channel and refuse a pass that names neither -- otherwise an
	// unrelated violation (a stage timeout, a contract rejection) could
	// masquerade as the extinction failure.
	reason := rec.Message + "\n" + rec.Notes
	if runErr != nil {
		reason += "\n" + runErr.Error()
	}
	if !strings.Contains(reason, "extinction") && !strings.Contains(reason, "descendant containment") {
		t.Fatalf("run was blocked (status=%q) after the confirmed blocking read, but for the wrong reason -- expected a descendant-containment/extinction failure, got runErr=%v message=%q notes=%q", rec.Status, runErr, rec.Message, rec.Notes)
	}
}
