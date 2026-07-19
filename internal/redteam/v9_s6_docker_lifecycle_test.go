//go:build redteam

// v9_s6_docker_lifecycle_test.go is Sol redteam v9's rc3 Session 6 corpus
// (agents/governator-sol-upgrade9-rc3-plan.md Session 6,
// agents/governator-sol-upgrade9.md P1-1/P1-2): "cases 28-32".
//
// P1-1 was that DockerRunner.verifyStartedContainer polled for the expected
// container up to a fixed deadline and, when it never appeared, returned
// nil -- treating "the container never showed up" as a clean verification
// pass.
// P1-2 was that once verification failed (or the transaction timed out), the
// executor issued daemon-side cleanup and then blocked on `<-done` with no
// deadline at all: a stuck docker CLI (wedged daemon socket, or daemon-side
// stop/rm themselves failing) could hang Governator for however much of the
// run's timeout budget remained.
//
// TestV9Case28 proves a container that never appears is now a hard
// DOCKER_CONTAINER_NOT_OBSERVED failure. TestV9Case29 proves a docker CLI
// that stays blocked after the daemon-side container is gone no longer
// hangs the executor. TestV9Case30 proves a hung `docker inspect` call
// during verification can't block the poll loop past its own bounded
// per-call context. TestV9Case31 proves the executor still returns even
// when BOTH `docker stop` and `docker rm -f` fail during cleanup.
// TestV9Case32 proves the container-extinction proof (descendantsGone) is
// refused -- not silently assumed true -- when the daemon still reports the
// container running after cleanup, which is what gates workspace
// measurement downstream (internal/runtime.go's `if !ar.DescendantsGone`
// check).
package redteam

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/runner"
	"github.com/cousingary/governator/internal/toolregistry"
)

// dockerLifecycleBoundedRegressionMargin is how long TestV9Case29 and
// TestV9Case31 wait for Launch to return before declaring the Sol9 P1-2
// "unbounded wait" regression reintroduced. It has to clear the real
// worst-case path those tests drive Launch through: the full container-
// observation poll (verifyStartedContainer's fake CLI always reports the
// container absent, so this always runs to its deadline) plus the CLI
// shutdown wait that follows, with margin for scheduling jitter. Derived
// from runner's own exported constants rather than a second hardcoded
// number, so a future retune of either deadline can't silently desync this
// margin from what Launch will actually take (as happened when rc3 Session
// 6 widened the observation deadline from 2s to 20s for real Docker Desktop/
// WSL2 startup latency and this margin was still hardcoded at the old 8s).
const dockerLifecycleBoundedRegressionMargin = runner.DockerContainerObservationDeadline + runner.DockerCLIShutdownDeadline + 5*time.Second

// dockerLifecycleFakeAgent is a minimal agents.Agent whose Run does nothing
// but invoke req.Executor -- the same shape internal/runner's own fakeAgent
// uses -- so these black-box tests can drive runner.DockerRunner.Launch
// (the only exported entry point into the executor closure this corpus
// needs to exercise) without a real backend CLI.
type dockerLifecycleFakeAgent struct{}

func (dockerLifecycleFakeAgent) Name() string                    { return "fake" }
func (dockerLifecycleFakeAgent) Capabilities() agents.Capability { return agents.Capability{} }

func (dockerLifecycleFakeAgent) Run(ctx context.Context, req agents.Request) (agents.Result, error) {
	var out bytes.Buffer
	code, timedOut, descendantsGone, err := req.Executor(ctx, "bin", nil, req.Workdir, &out, req.Timeout)
	return agents.Result{ExitCode: code, TimedOut: timedOut, DescendantsGone: descendantsGone}, err
}

// dockerLifecycleSecureTempDir mirrors internal/runner's secureRunnerTempDir:
// the trusted-tool registry refuses an executable with a group/world-writable
// ancestor directory unless the sticky bit is set, so a fake docker binary is
// written under $HOME rather than an arbitrary t.TempDir() to sidestep any
// environment where that isn't true.
func dockerLifecycleSecureTempDir(t *testing.T) string {
	t.Helper()
	home := "/home/lam"
	if _, err := os.Stat(home); err != nil {
		var homeErr error
		home, homeErr = os.UserHomeDir()
		if homeErr != nil {
			t.Fatal(homeErr)
		}
	}
	dir, err := os.MkdirTemp(home, ".gov-redteam-docker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// pinFakeDockerLifecycle enrolls script as the trusted "docker" controller
// tool in an isolated registry file, so this test's fake CLI -- not any real
// docker on the host -- is what runner.DockerRunner actually launches.
func pinFakeDockerLifecycle(t *testing.T, script string) {
	t.Helper()
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	fakeDocker := filepath.Join(dockerLifecycleSecureTempDir(t), "docker")
	if err := os.WriteFile(fakeDocker, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("docker", fakeDocker); err != nil {
		t.Fatal(err)
	}
}

func dockerLifecycleRunner(container string) (*runner.DockerRunner, runner.Workspace) {
	d := &runner.DockerRunner{
		Config:                contracts.DockerRunnerConfig{Image: "agent:latest"},
		ResolvedImage:         &runner.ImageIdentity{ID: "sha256:" + strings.Repeat("a", 64)},
		ControllerEnvironment: controllerenv.Freeze(),
	}
	return d, runner.Workspace{Container: container, Path: "/ws"}
}

func launchDockerLifecycle(t *testing.T, d *runner.DockerRunner, ws runner.Workspace, timeout time.Duration) (agents.Result, error) {
	t.Helper()
	return d.Launch(context.Background(), ws, runner.LaunchRequest{
		Agent:   dockerLifecycleFakeAgent{},
		Request: agents.Request{Workdir: ws.Path, Timeout: timeout},
	})
}

// TestV9Case28DockerContainerNeverAppearsHardFails is report case 28
// (P1-1): a container that never appears throughout the poll window must be
// a hard DOCKER_CONTAINER_NOT_OBSERVED failure -- absence is no longer
// treated as a successful verification.
func TestV9Case28DockerContainerNeverAppearsHardFails(t *testing.T) {
	pinFakeDockerLifecycle(t, `#!/bin/sh
set -eu
cmd=${1:-}
shift || true
case "$cmd" in
  run)
    sleep 0.2
    ;;
  inspect)
    echo "Error response from daemon: No such object: $1" >&2
    exit 1
    ;;
  stop|rm)
    exit 0
    ;;
  *)
    echo 'unexpected command' >&2
    exit 1
    ;;
esac
`)
	d, ws := dockerLifecycleRunner("gov-redteam-case28")
	res, err := launchDockerLifecycle(t, d, ws, 10*time.Second)
	if res.TimedOut {
		t.Fatal("expected a verification failure, not a transaction timeout")
	}
	if err == nil || !strings.Contains(err.Error(), "DOCKER_CONTAINER_NOT_OBSERVED") {
		t.Fatalf("expected a DOCKER_CONTAINER_NOT_OBSERVED error, got %v", err)
	}
}

// TestV9Case29DockerCLIBlockedAfterContainerRemovalIsBounded is report case
// 29 (P1-2): once the daemon-side container is stopped/removed, a docker CLI
// that itself stays blocked (never notices, or is otherwise wedged) must not
// hang the executor -- the process-group kill plus bounded wait must still
// return control within the fixed shutdown deadline, not the transaction's
// (potentially much larger) timeout budget.
func TestV9Case29DockerCLIBlockedAfterContainerRemovalIsBounded(t *testing.T) {
	pinFakeDockerLifecycle(t, `#!/bin/sh
set -eu
cmd=${1:-}
shift || true
case "$cmd" in
  run)
    sleep 300
    ;;
  inspect)
    echo "Error response from daemon: No such object: $1" >&2
    exit 1
    ;;
  stop|rm)
    exit 0
    ;;
  *)
    echo 'unexpected command' >&2
    exit 1
    ;;
esac
`)
	d, ws := dockerLifecycleRunner("gov-redteam-case29")
	done := make(chan struct{})
	var res agents.Result
	var err error
	go func() {
		res, err = launchDockerLifecycle(t, d, ws, 30*time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(dockerLifecycleBoundedRegressionMargin):
		t.Fatalf("Launch did not return within %s -- a docker CLI blocked after container removal was not bounded (Sol9 P1-2 regression)", dockerLifecycleBoundedRegressionMargin)
	}
	if res.TimedOut {
		t.Fatal("expected a verification failure, not a transaction timeout")
	}
	if err == nil || !strings.Contains(err.Error(), "DOCKER_CONTAINER_NOT_OBSERVED") {
		t.Fatalf("expected a DOCKER_CONTAINER_NOT_OBSERVED error, got %v", err)
	}
}

// TestV9Case30DockerDaemonInspectionHangIsBounded is report case 30 (P1-2):
// a `docker inspect` call that never returns (an unresponsive daemon) must
// not block verifyStartedContainer's poll loop past its own bounded
// per-call context -- the whole launch must still resolve promptly instead
// of hanging for as long as the daemon stays wedged.
func TestV9Case30DockerDaemonInspectionHangIsBounded(t *testing.T) {
	pinFakeDockerLifecycle(t, `#!/bin/sh
set -eu
cmd=${1:-}
shift || true
case "$cmd" in
  run)
    sleep 0.2
    ;;
  inspect)
    # exec (not a plain "sleep 300") replaces this shell process in place
    # rather than forking a child -- so the single resulting process is a
    # direct child of the Go inspectContainer call, and killing it on
    # context cancellation actually unblocks the pipe read. A forked child
    # would keep the stdout/stderr pipe open (inherited fd) even after this
    # script's own top-level process is killed, hanging the read regardless
    # of the bounded context -- an artifact of this shell-script fixture,
    # not something a real single-process docker CLI binary exhibits.
    exec sleep 300
    ;;
  stop|rm)
    exit 0
    ;;
  *)
    echo 'unexpected command' >&2
    exit 1
    ;;
esac
`)
	d, ws := dockerLifecycleRunner("gov-redteam-case30")
	done := make(chan struct{})
	var res agents.Result
	var err error
	go func() {
		res, err = launchDockerLifecycle(t, d, ws, 30*time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Launch did not return within 15s -- a hung docker inspect blocked verification (Sol9 P1-2 regression)")
	}
	if res.TimedOut {
		t.Fatal("expected a verification failure, not a transaction timeout")
	}
	// A killed inspect call isn't recognized as "container absent" (its
	// output is empty, not a "no such container" message), so verification
	// fails closed on the kill itself rather than falling through to
	// DOCKER_CONTAINER_NOT_OBSERVED -- the important proof here is that this
	// error surfaces within the per-call bound instead of after the hung
	// inspect's full duration (asserted above via the 15s outer bound).
	if err == nil || !strings.Contains(err.Error(), "docker runtime image verification") {
		t.Fatalf("expected a bounded docker inspect verification failure, got %v", err)
	}
}

// TestV9Case31DockerStopAndForceRemoveBothFailingStillReturns is report case
// 31 (P1-2): when BOTH `docker stop` and `docker rm -f` fail during cleanup
// after a verification failure, the executor must still return -- via the
// process-group kill and bounded CLI wait -- rather than depending on
// daemon-side cleanup succeeding to ever make forward progress.
func TestV9Case31DockerStopAndForceRemoveBothFailingStillReturns(t *testing.T) {
	pinFakeDockerLifecycle(t, `#!/bin/sh
set -eu
cmd=${1:-}
shift || true
case "$cmd" in
  run)
    sleep 300
    ;;
  inspect)
    echo "Error response from daemon: No such object: $1" >&2
    exit 1
    ;;
  stop)
    echo 'permission denied' >&2
    exit 1
    ;;
  rm)
    echo 'daemon unavailable' >&2
    exit 1
    ;;
  *)
    echo 'unexpected command' >&2
    exit 1
    ;;
esac
`)
	d, ws := dockerLifecycleRunner("gov-redteam-case31")
	done := make(chan struct{})
	var res agents.Result
	var err error
	go func() {
		res, err = launchDockerLifecycle(t, d, ws, 30*time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(dockerLifecycleBoundedRegressionMargin):
		t.Fatalf("Launch did not return within %s -- stop AND rm both failing left the executor hanging (Sol9 P1-2 regression)", dockerLifecycleBoundedRegressionMargin)
	}
	if res.TimedOut {
		t.Fatal("expected a verification failure, not a transaction timeout")
	}
	if err == nil || !strings.Contains(err.Error(), "DOCKER_CONTAINER_NOT_OBSERVED") {
		t.Fatalf("expected the verification failure in the joined error, got %v", err)
	}
	// Stop() surfaces only cmd.Run()'s exit-status error (it doesn't capture
	// output), so "permission denied" itself doesn't propagate -- but the
	// fallback docker rm -f DOES use CombinedOutput, so its failure text
	// ("daemon unavailable") must appear, proving the code reached and
	// reported both cleanup attempts rather than stopping after the first.
	if !strings.Contains(err.Error(), "docker stop") || !strings.Contains(err.Error(), "daemon unavailable") {
		t.Fatalf("expected both the stop and rm cleanup attempts joined into the error, got %v", err)
	}
}

// TestV9Case32WorkspaceMeasurementRefusedBeforeExtinctionProof is report
// case 32: when the daemon still reports the container running after
// cleanup, the executor's descendantsGone proof must come back false --
// never assumed true just because cleanup was attempted -- since
// internal/runtime.go gates workspace/final-state measurement on exactly
// this bit (`if !ar.DescendantsGone { ... refuse ... }`).
func TestV9Case32WorkspaceMeasurementRefusedBeforeExtinctionProof(t *testing.T) {
	pinFakeDockerLifecycle(t, `#!/bin/sh
set -eu
cmd=${1:-}
shift || true
case "$cmd" in
  run)
    sleep 300
    ;;
  inspect)
    printf '{"Image":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","State":{"Running":true,"Status":"running"}}'
    ;;
  stop|rm)
    exit 0
    ;;
  *)
    echo 'unexpected command' >&2
    exit 1
    ;;
esac
`)
	d, ws := dockerLifecycleRunner("gov-redteam-case32")
	res, err := launchDockerLifecycle(t, d, ws, 50*time.Millisecond)
	if !res.TimedOut {
		t.Fatalf("expected a transaction timeout, got res=%+v err=%v", res, err)
	}
	if res.DescendantsGone {
		t.Fatal("descendantsGone must be false: the fake daemon still reports the container running after cleanup, so extinction was never proven")
	}
	if err == nil || !strings.Contains(err.Error(), "docker extinction proof") {
		t.Fatalf("expected a docker extinction proof error, got %v", err)
	}
}
