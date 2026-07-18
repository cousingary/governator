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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
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
		t.Skipf("conditional: unprivileged FUSE mount unavailable on this host (%s) -- this fixture needs /dev/fuse plus a fusermount3/fusermount binary; requires a kernel-capable host with CONFIG_FUSE_FS, not root", reason)
	}
	if !enforce.Supported() {
		t.Skip("conditional: external containment unavailable on this host (Landlock/unshare required) -- case 8 needs a real governed scope teardown to prove extinction failure")
	}

	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()

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

	root := fixtureRepo(t)
	c := baseContract(root)
	c.Local.ReadRoots = append(append([]string(nil), c.Local.ReadRoots...), mntParent)
	cleanupCommand := "exec > /dev/null 2>&1; setsid sh -c 'dd if=" + mnt + "/hang of=/dev/null bs=1 count=1' < /dev/null & sleep 1"
	c.Cleanup = &contracts.Cleanup{
		Required:   false,
		Validators: []string{cleanupCommand},
		ValidatorSpecs: []contracts.ValidatorSpec{{
			Command:   cleanupCommand,
			Tools:     []string{"dd", "setsid", "sleep", "sh"},
			ReadRoots: []string{mntParent},
		}},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	if !daemon.waitForRead(5 * time.Second) {
		t.Skip("conditional: case8 hangfuse extinction fixture did not reach a blocking READ on this host/kernel before timeout")
	}

	if rec.Status == "APPROVED" {
		t.Fatalf("cleanup validator's detached descendant survived SIGKILL past the extinction deadline (genuine kernel-level uninterruptible sleep via an unanswered FUSE read), yet the run was still APPROVED -- extinction failure must block approval regardless of Cleanup.Required=false")
	}
	if !strings.Contains(rec.Message, "descendant containment") && !strings.Contains(rec.Message, "extinction") {
		t.Fatalf("run was correctly not APPROVED (status=%s) but for the wrong reason -- expected the message to name descendant-containment/extinction failure, got: %s", rec.Status, rec.Message)
	}
}
