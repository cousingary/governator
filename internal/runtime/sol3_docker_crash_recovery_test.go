package runtime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/runner"
	"github.com/cousingary/governator/internal/toolregistry"
)

// requireDockerCLI skips cleanly when Docker isn't usable in this
// environment, matching internal/runner's own requireDocker gate (unexported
// there, so runtime's tests need their own copy) — this is the plan's
// "build-tag/env guard" applied as a runtime capability check.
func requireDockerCLI(t *testing.T) {
	t.Helper()
	if err := runner.CheckDockerAvailable(); err != nil {
		t.Skipf("docker unavailable, skipping: %v", err)
	}
}

// workspaceReadyDockerDetail builds the WORKSPACE_READY stage detail exactly
// as newWorkspaceDescriptor would (Sol P1.6), but as a raw JSON literal
// rather than constructing the workspaceDescriptor struct directly — kept
// deliberately decoupled from the type so this same test file can be run
// against the pre-S10 runtime.go (which has no such type, and never wrote
// this detail at all) to verify these tests actually fail against the code
// this session replaces.
func workspaceReadyDockerDetail(path, root, container string) string {
	return fmt.Sprintf(`{"runner":"docker","path":%q,"root":%q,"branch":"","git":false,"container":%q}`, path, root, container)
}

// TestSol3RecoveryRemovesLeftoverDockerContainer reproduces audit corpus #10:
// a Docker run's process is killed mid-flight (simulated here by starting
// the exact container Prepare would have named, then never letting runOnce
// finish), leaving a RUNNING run row and a live gov-<id> container. Pre-S10,
// destroyLeftoverWorkspace only ever looked at RunRecord.Worktree/Branch —
// never a container name, because none was persisted anywhere — so recovery
// would mark the run ABANDONED while the container kept running forever.
func TestSol3RecoveryRemovesLeftoverDockerContainer(t *testing.T) {
	requireDockerCLI(t)
	db, _, root := recoveryFixture(t)
	work := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}

	runID := "run-docker-crash"
	container := "gov-" + runID
	startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(startCtx, "docker", "run", "-d", "--name", container, "busybox:1.36", "sleep", "300").CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })

	seedInterruptedRun(t, db, runID, root, work, "")
	stage(t, db, runID, "WORKSPACE_READY", workspaceReadyDockerDetail(work, root, container))

	v, err := recoverInterruptedRun(context.Background(), db, RunRecord{ID: runID, Root: root, Worktree: work, Status: "RUNNING"}, false)
	if err != nil {
		t.Fatalf("recoverInterruptedRun: %v", err)
	}
	if v.Action != "safe_resume" {
		t.Fatalf("action = %q, want safe_resume (detail=%s)", v.Action, v.Detail)
	}
	if got := runStatus(t, db, runID); got != "ABANDONED" {
		t.Fatalf("run status = %q, want ABANDONED", got)
	}

	out, err := exec.Command("docker", "ps", "-a", "--filter", "name=^/"+container+"$", "--format", "{{.Names}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("container %s still present after recovery (regression: crash recovery never removed it): %q", container, out)
	}
}

// TestSol3RecoveryLeavesRunRunningWhenContainerCleanupFails reproduces the
// other half of audit finding #13's correction: a cleanup failure must never
// be silently absorbed into an ABANDONED/QUARANTINED verdict. A fake "docker"
// binary enrolled in an isolated tool registry always fails with a message
// that is not the tolerable "no such container" case, forcing a genuine
// teardown failure. DOCKER_HOST cannot be used for this anymore:
// RemoveContainer runs docker under controllerenv's frozen, allowlisted
// environment (Sol P1-1/S3), which does not pass DOCKER_HOST through to the
// child process at all, so pointing it at an unreachable socket from the
// test process no longer has any effect on the confined docker invocation --
// and docker itself normalizes any never-existed name (even a syntactically
// odd one) to "No such container", so an invalid container name doesn't
// force a real failure either.
func TestSol3RecoveryLeavesRunRunningWhenContainerCleanupFails(t *testing.T) {
	requireDockerCLI(t)
	db, _, root := recoveryFixture(t)
	work := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}

	fakeDocker := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(fakeDocker, []byte("#!/bin/sh\necho 'Cannot connect to the Docker daemon: fake unreachable daemon' >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	toolsReg := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", toolsReg)
	if _, err := toolregistry.Enroll("docker", fakeDocker); err != nil {
		t.Fatal(err)
	}

	runID := "run-docker-cleanup-fail"
	container := "gov-" + runID
	seedInterruptedRun(t, db, runID, root, work, "")
	stage(t, db, runID, "WORKSPACE_READY", workspaceReadyDockerDetail(work, root, container))

	v, err := recoverInterruptedRun(context.Background(), db, RunRecord{ID: runID, Root: root, Worktree: work, Status: "RUNNING"}, false)
	if err != nil {
		t.Fatalf("recoverInterruptedRun: %v", err)
	}
	if v.Action != "cleanup_pending" {
		t.Fatalf("action = %q, want cleanup_pending (a failed teardown must never be reported as safe_resume/quarantined)", v.Action)
	}
	if got := runStatus(t, db, runID); got != "RUNNING" {
		t.Fatalf("run status = %q, want unchanged RUNNING — must not mark recovered/abandoned while cleanup fails", got)
	}

	pending, err := observability.PendingOutbox(db)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pending {
		if p.RunID == runID && p.OpKind == opWorkspaceDestroy {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a pending opWorkspaceDestroy outbox row enqueued for %s so gov reconcile retries it, got %+v", runID, pending)
	}
}
