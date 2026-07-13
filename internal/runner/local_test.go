package runner

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
)

func gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func gitFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	gitCmd(t, root, "init", "-b", "main")
	gitCmd(t, root, "config", "user.email", "test@example.invalid")
	gitCmd(t, root, "config", "user.name", "Runner Test")
	if err := os.WriteFile(filepath.Join(root, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, root, "add", ".")
	gitCmd(t, root, "commit", "-m", "seed")
	return root
}

// testLocalExecutor is a minimal agents.Executor used only by fakeAgent below,
// standing in for agents' own (unexported) defaultExecutor so tests can drive
// LaunchRequest without a real backend CLI binary.
func testLocalExecutor(ctx context.Context, bin string, args []string, workdir string, out io.Writer, timeout time.Duration) (int, bool, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Dir = workdir
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	if cctx.Err() != nil {
		return -1, true, cctx.Err()
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), false, nil
		}
		return 0, false, err
	}
	return 0, false, nil
}

// fakeAgent is a minimal agents.Agent whose Run always delegates process
// spawning to req.Executor (defaulting to testLocalExecutor), exactly like
// every real backend adapter funnels through runCLI. This lets tests exercise
// a Runner's Launch/executor injection without a real CLI binary.
type fakeAgent struct {
	bin  string
	args []string
}

func (fakeAgent) Name() string                    { return "fake" }
func (fakeAgent) Capabilities() agents.Capability { return agents.Capability{} }

func (f fakeAgent) Run(ctx context.Context, req agents.Request) (agents.Result, error) {
	bin, args := f.bin, f.args
	if bin == "" {
		bin = "/bin/sh"
		args = []string{"-c", "printf ok > " + shQuote(filepath.Join(req.Workdir, "output.txt"))}
	}
	execute := req.Executor
	if execute == nil {
		execute = testLocalExecutor
	}
	var out bytes.Buffer
	code, timedOut, err := execute(ctx, bin, args, req.Workdir, &out, req.Timeout)
	if timedOut {
		return agents.Result{ExitCode: -1, TimedOut: true}, err
	}
	if err != nil {
		return agents.Result{}, err
	}
	return agents.Result{ExitCode: code}, nil
}

func TestLocalWorktreeRunnerGitLifecycleApproved(t *testing.T) {
	root := gitFixture(t)
	home := t.TempDir()
	r := &LocalWorktreeRunner{}
	ctx := context.Background()

	ws, err := r.Prepare(ctx, PrepareRequest{Root: root, Home: home, ID: "run-1", Git: true})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if ws.Path == "" || ws.Branch == "" || !ws.Git {
		t.Fatalf("unexpected workspace: %+v", ws)
	}
	if _, err := os.Stat(filepath.Join(ws.Path, "seed.txt")); err != nil {
		t.Fatalf("worktree missing seeded file: %v", err)
	}

	res, err := r.Launch(ctx, ws, LaunchRequest{
		Agent:   fakeAgent{},
		Request: agents.Request{Workdir: ws.Path, Timeout: 5 * time.Second},
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Launch: res=%+v err=%v", res, err)
	}
	if _, err := os.Stat(filepath.Join(ws.Path, "output.txt")); err != nil {
		t.Fatalf("launch did not run in the worktree: %v", err)
	}

	if obs, err := r.Observe(ctx, ws); err != nil || obs.Notes != "" || obs.Limits != nil {
		t.Fatalf("LocalWorktreeRunner.Observe must be a no-op, got %+v err=%v", obs, err)
	}
	if err := r.Stop(ctx, ws); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if err := r.Destroy(ctx, ws, true); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := os.Stat(ws.Path); !os.IsNotExist(err) {
		t.Fatalf("worktree still exists after Destroy: %v", err)
	}
	_, out, _ := shell(ctx, root, "git branch --list "+shQuote(ws.Branch))
	if out != "" {
		t.Fatalf("branch %s should have been deleted (approved=true), git branch --list returned %q", ws.Branch, out)
	}
}

func TestLocalWorktreeRunnerGitLifecycleQuarantinedKeepsBranch(t *testing.T) {
	root := gitFixture(t)
	home := t.TempDir()
	r := &LocalWorktreeRunner{}
	ctx := context.Background()

	ws, err := r.Prepare(ctx, PrepareRequest{Root: root, Home: home, ID: "run-2", Git: true})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := r.Destroy(ctx, ws, false); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := os.Stat(ws.Path); !os.IsNotExist(err) {
		t.Fatalf("worktree still exists after Destroy: %v", err)
	}
	_, out, _ := shell(ctx, root, "git branch --list "+shQuote(ws.Branch))
	if out == "" {
		t.Fatalf("branch %s should survive a quarantined (approved=false) Destroy", ws.Branch)
	}
}

func TestLocalWorktreeRunnerNonGitCopy(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	r := &LocalWorktreeRunner{}
	ctx := context.Background()

	ws, err := r.Prepare(ctx, PrepareRequest{Root: root, Home: home, ID: "run-3", Git: false})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if ws.Branch != "" || ws.Git {
		t.Fatalf("non-git prepare should not report a branch: %+v", ws)
	}
	if _, err := os.Stat(filepath.Join(ws.Path, "seed.txt")); err != nil {
		t.Fatalf("copy missing seeded file: %v", err)
	}
	if err := r.Destroy(ctx, ws, true); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := os.Stat(ws.Path); !os.IsNotExist(err) {
		t.Fatalf("copy still exists after Destroy: %v", err)
	}
}

func TestNewDefaultsToLocal(t *testing.T) {
	rn, err := New("", nil, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := rn.(*LocalWorktreeRunner); !ok {
		t.Fatalf("New(\"\", nil, nil) = %T, want *LocalWorktreeRunner", rn)
	}
	rn, err = New("local", nil, nil, nil)
	if err != nil || rn == nil {
		t.Fatalf("New(\"local\", nil, nil): rn=%v err=%v", rn, err)
	}
}

func TestNewUnknownModeErrors(t *testing.T) {
	if _, err := New("bogus", nil, nil, nil); err == nil {
		t.Fatal("want error for unknown runner mode")
	}
}

// TestNewDockerWithoutConfigFailsClosed pins the plan rule: runner: docker
// without a docker config block must error immediately, never silently run
// locally instead.
func TestNewDockerWithoutConfigFailsClosed(t *testing.T) {
	if _, err := New("docker", nil, nil, nil); err == nil {
		t.Fatal("want error when runner: docker has no docker config")
	}
}

// TestNewDockerUnavailableFailsClosed pins the plan rule using a deliberately
// bogus PATH so CheckDockerAvailable fails regardless of whether the host
// running this test actually has Docker installed.
func TestNewDockerUnavailableFailsClosed(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := New("docker", &contracts.DockerRunnerConfig{Image: "example/image:latest"}, nil, nil)
	if err == nil {
		t.Fatal("want error when docker is unavailable")
	}
}

// TestNewThreadsLocalConfig pins that New("local", ...) actually plumbs the
// supplied LocalRunnerConfig into the returned runner (not silently dropped),
// mirroring TestNewDockerUnavailableFailsClosed's config-threading coverage
// on the Docker side.
func TestNewThreadsLocalConfig(t *testing.T) {
	rn, err := New("local", nil, &contracts.LocalRunnerConfig{OutputCapBytes: 7}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	lr, ok := rn.(*LocalWorktreeRunner)
	if !ok {
		t.Fatalf("New(\"local\", ...) = %T, want *LocalWorktreeRunner", rn)
	}
	if got := lr.Config.EffectiveOutputCapBytes(); got != 7 {
		t.Fatalf("Config.OutputCapBytes not threaded through: EffectiveOutputCapBytes()=%d, want 7", got)
	}
}

// TestLocalWorktreeRunnerLaunchCapsOutput pins Sol High 11's local half:
// LocalWorktreeRunner.Launch now bounds transcript growth exactly like
// DockerRunner.Launch, and Observe surfaces the accepted/discarded tally.
func TestLocalWorktreeRunnerLaunchCapsOutput(t *testing.T) {
	work := t.TempDir()
	r := &LocalWorktreeRunner{Config: contracts.LocalRunnerConfig{OutputCapBytes: 5}}
	ctx := context.Background()

	res, err := r.Launch(ctx, Workspace{Path: work}, LaunchRequest{
		Agent: fakeAgent{bin: "/bin/sh", args: []string{"-c", "printf '0123456789'"}},
		Request: agents.Request{
			Workdir: work,
			Timeout: 5 * time.Second,
		},
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Launch: res=%+v err=%v", res, err)
	}
	obs, err := r.Observe(ctx, Workspace{})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !obs.OutputTruncated || obs.BytesAccepted != 5 || obs.BytesDiscarded != 5 {
		t.Fatalf("truncation not surfaced: %+v, want accepted=5 discarded=5 truncated=true", obs)
	}
}

// TestLocalWorktreeRunnerObserveNoTruncationByDefault pins the zero state,
// mirroring TestDockerObserveNoTruncationByDefault: a run whose output never
// exceeded the (default 20MiB) cap reports no truncation.
func TestLocalWorktreeRunnerObserveNoTruncationByDefault(t *testing.T) {
	work := t.TempDir()
	r := &LocalWorktreeRunner{}
	ctx := context.Background()

	res, err := r.Launch(ctx, Workspace{Path: work}, LaunchRequest{
		Agent:   fakeAgent{},
		Request: agents.Request{Workdir: work, Timeout: 5 * time.Second},
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Launch: res=%+v err=%v", res, err)
	}
	obs, err := r.Observe(ctx, Workspace{})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.OutputTruncated || obs.BytesAccepted != 0 || obs.BytesDiscarded != 0 {
		t.Fatalf("fresh runner must report no truncation, got %+v", obs)
	}
}
