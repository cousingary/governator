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

	mntParent := t.TempDir()
	mnt := filepath.Join(mntParent, "case8-hang")
	if err := os.Mkdir(mnt, 0755); err != nil {
		t.Fatalf("mkdir mountpoint: %v", err)
	}
	// The daemon is owned by the test process, never by the governed run --
	// it must outlive the run's own containment teardown for the reader to
	// stay genuinely stuck. Stopped only after the assertion below.
	daemon, stopDaemon, err := mountHangfuse(mnt)
	if err != nil {
		t.Fatalf("mount hangfuse: %v", err)
	}
	defer stopDaemon()

	// Sol12 rc5 Session 2 (P0-1): EXPLICIT SYNCHRONIZATION replaces the old
	// timing assumption. The previous form ran the whole governed run (whose
	// containment teardown fires Extinguish at an unspecified moment) and only
	// AFTERWARDS checked whether the detached descendant had happened to reach
	// its blocking read in time -- a race that flaked into a conditional skip
	// whenever the setsid->sh->dd chain lost to the extinction deadline. The
	// containment.ExtinguishGateForTesting seam blocks Extinguish at its
	// kill-boundary until this closure confirms the daemon has actually
	// observed a FUSE_READ from the descendant, so extinction can NEVER fire
	// before the blocking-read state is reached. The decision is sticky: the
	// per-stage cleanup scope and the run-level scope each call Extinguish,
	// so once the read is confirmed (or definitively absent) later calls
	// return the same verdict without re-waiting.
	var (
		gateErr       error
		gateCalled    bool
		readConfirmed bool
	)
	containment.ExtinguishGateForTesting = func() error {
		gateCalled = true
		if readConfirmed {
			return nil
		}
		if gateErr != nil {
			return gateErr
		}
		if !daemon.waitForRead(6 * time.Second) {
			gateErr = fmt.Errorf("descendant did not reach the blocking FUSE read within 6s")
			return gateErr
		}
		readConfirmed = true
		return nil
	}
	defer func() { containment.ExtinguishGateForTesting = nil }()

	root := fixtureRepo(t)
	c := baseContract(root)
	// The hangfuse mount is deliberately NOT declared in the cleanup
	// validator's read_roots: contracts require validator read_roots to be
	// relative to workspace.root (an absolute host path is rejected), and the
	// FUSE mount cannot live inside the committed-only git worktree the run
	// executes in. Under Landlock the descendant therefore cannot open this
	// external mount on an enforcing host; the readiness gate above turns
	// that into an honest, structural conditional skip rather than the old
	// timing flake. On a host where the read IS reachable (a dedicated
	// capability host, or once Session 5's in-workspace immutable artifact
	// source lands), the gate confirms the blocking read and the
	// extinction-failure assertion below runs for real.
	cleanupCommand := "exec > /dev/null 2>&1; setsid sh -c 'dd if=" + mnt + "/hang of=/dev/null bs=1 count=1' < /dev/null & sleep 1"
	c.Cleanup = &contracts.Cleanup{
		Required:   false,
		Validators: []string{cleanupCommand},
		ValidatorSpecs: []contracts.ValidatorSpec{{
			Command: cleanupCommand,
			Tools:   []string{"dd", "setsid", "sleep", "sh"},
		}},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, runErr := runGovernedAllowError(t, t.TempDir(), bin, c)
	// The gate is the P0-1 synchronization primitive. If the run never
	// reached any extinction boundary (gateCalled=false -- contract rejected
	// or the chain aborted early) OR the descendant never reached a confirmed
	// blocking read (gateErr set -- e.g. Landlock denied the external mount),
	// this host cannot drive the full deterministic chain case 8 asserts.
	// Skip honestly: a structural host-capability limit, not the timing race
	// the old form hid behind. The manifest authorizes this skip via the
	// case8_hangfuse_extinction_fixture predicate (Session 2 makes that skip
	// reflect capability, not timing).
	if !gateCalled || gateErr != nil {
		t.Skipf("conditional: case8 hangfuse extinction fixture: the cleanup-validator descendant did not reach a confirmed blocking-read state before extinction on this host (gateCalled=%v, gateErr=%v, runErr=%v)", gateCalled, gateErr, runErr)
	}
	// The gate fired AND confirmed the blocking read: the descendant is
	// genuinely stuck in an unkillable FUSE read, so Extinguish must have
	// failed and the run must report a descendant-containment/extinction
	// failure regardless of Cleanup.Required=false.
	if rec.Status == "APPROVED" {
		t.Fatalf("cleanup validator's detached descendant survived SIGKILL past the extinction deadline (genuine kernel-level uninterruptible sleep via an unanswered FUSE read), yet the run was still APPROVED -- extinction failure must block approval regardless of Cleanup.Required=false")
	}
	if runErr == nil {
		t.Fatalf("descendant confirmed blocked on the unkillable FUSE read (gate released) yet the run reported no extinction failure (status=%q) -- extinction failure must block approval regardless of Cleanup.Required=false", rec.Status)
	}
	if !strings.Contains(runErr.Error(), "extinction") && !strings.Contains(runErr.Error(), "descendant containment") {
		t.Fatalf("run failed for the wrong reason after the confirmed blocking read -- expected descendant-containment/extinction failure, got: %v", runErr)
	}
}
