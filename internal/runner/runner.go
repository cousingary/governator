// Package runner abstracts how a governed agent actually executes: preparing
// an isolated workspace, launching the agent inside it, observing
// runner-specific diagnostics, stopping an in-flight launch, and tearing the
// workspace back down. LocalWorktreeRunner is the pre-Phase-5 behavior
// (git worktree or plain copy, agent run as a host subprocess) extracted
// unchanged from internal/runtime; DockerRunner (docker.go) adds host-level
// containment for the agent process itself — worktrees only ever isolated
// the repo, never the OS the agent ran against.
package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
)

// Workspace is what Prepare hands back and every later stage (Launch,
// Observe, Stop, Destroy) operates on. Path is always a host filesystem
// path — even a Docker-backed run bind-mounts it, so Governator-level
// concerns (fingerprinting, contextgraph, the canary file) keep working
// against it unchanged regardless of which Runner produced it.
type Workspace struct {
	Path      string
	Root      string
	Branch    string // git worktree branch name; "" for the non-git copy path
	Git       bool
	Container string // docker container name; "" for LocalWorktreeRunner
}

// PrepareRequest is Prepare's input: enough to create the same disposable
// workspace every runner uses (a git worktree off root, or a plain copy for
// a non-git root).
type PrepareRequest struct {
	Root string
	Home string
	ID   string
	Git  bool
}

// LaunchRequest is Launch's input: the resolved agent plus the request it
// would otherwise be given directly.
type LaunchRequest struct {
	Agent   agents.Agent
	Request agents.Request
}

// ObserveResult carries runner-specific diagnostics gathered after Launch
// completes. LocalWorktreeRunner has none to report; DockerRunner reports
// the resource limits actually applied to the container (verified via
// `docker inspect`) and, since Session 3a, output-truncation accounting so
// the runtime can emit OUTPUT_TRUNCATED and quarantine runs that required a
// complete transcript.
type ObserveResult struct {
	Notes           string
	Limits          map[string]string
	OutputTruncated bool
	BytesAccepted   int64
	BytesDiscarded  int64
}

// Runner is the Phase 5 execution abstraction: Prepare an isolated
// workspace, Launch the agent inside it, Observe runner-specific
// diagnostics, Stop an in-flight launch, Destroy the workspace.
type Runner interface {
	Prepare(ctx context.Context, req PrepareRequest) (Workspace, error)
	Launch(ctx context.Context, ws Workspace, req LaunchRequest) (agents.Result, error)
	Observe(ctx context.Context, ws Workspace) (ObserveResult, error)
	Stop(ctx context.Context, ws Workspace) error
	Destroy(ctx context.Context, ws Workspace, approved bool) error
}

// New resolves the Runner a contract asks for. mode is
// Contract.EffectiveRunner() ("local" or "docker"). A docker request that
// can't be satisfied returns an error immediately — never a silent local
// fallback (plan rule). localCfg is Contract.Local (nil on every job that
// doesn't set an explicit output cap — the zero value already defaults
// correctly via LocalRunnerConfig.EffectiveOutputCapBytes) and is ignored
// for mode "docker", matching how dockerCfg is ignored for mode "local".
func New(mode string, dockerCfg *contracts.DockerRunnerConfig, localCfg *contracts.LocalRunnerConfig) (Runner, error) {
	switch mode {
	case "", "local":
		cfg := contracts.LocalRunnerConfig{}
		if localCfg != nil {
			cfg = *localCfg
		}
		return &LocalWorktreeRunner{Config: cfg}, nil
	case "docker":
		if dockerCfg == nil {
			return nil, fmt.Errorf("runner: docker requested but no docker config was supplied")
		}
		if err := CheckDockerAvailable(); err != nil {
			return nil, fmt.Errorf("runner: docker requested but unavailable: %w", err)
		}
		return &DockerRunner{Config: *dockerCfg}, nil
	default:
		return nil, fmt.Errorf("runner: unknown mode %q", mode)
	}
}

// shell runs command via bash -lc in dir, killing the process group if ctx
// is done before it exits. Copied verbatim from internal/runtime's identical
// helper — both packages need the same "run a git plumbing command, honor
// ctx cancellation" primitive, and runner must not import runtime.
func shell(ctx context.Context, dir, command string) (int, string, error) {
	cmd := exec.CommandContext(ctx, "bash", "-lc", command)
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return -1, string(out), err
		}
	}
	return code, string(out), nil
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

// prepareWorktree creates the disposable workspace shared by every Runner: a
// git worktree off root (git == true) or a plain reflink copy (git == false).
// Copied verbatim from internal/runtime's prior createWorkspace.
func prepareWorktree(ctx context.Context, root, home, id string, git bool) (Workspace, error) {
	p := filepath.Join(home, "worktrees", id)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return Workspace{}, err
	}
	branch := "gov/job/" + id
	if git {
		c, o, e := shell(ctx, root, fmt.Sprintf("git worktree add -b %s %s HEAD", shQuote(branch), shQuote(p)))
		if e != nil || c != 0 {
			return Workspace{}, fmt.Errorf("git worktree: %s", o)
		}
		return Workspace{Path: p, Root: root, Branch: branch, Git: true}, nil
	}
	if err := os.MkdirAll(p, 0700); err != nil {
		return Workspace{}, err
	}
	c, o, e := shell(ctx, root, fmt.Sprintf("cp -a --reflink=auto ./. %s", shQuote(p)))
	if e != nil || c != 0 {
		return Workspace{}, fmt.Errorf("copy workspace: %s", o)
	}
	return Workspace{Path: p, Root: root}, nil
}

// destroyWorktree tears down a workspace prepareWorktree created. approved
// controls whether the git branch is deleted: a quarantined run keeps its
// branch around for inspection, exactly as before Phase 5 extracted this
// logic out of internal/runtime's runOnce tail.
func destroyWorktree(ctx context.Context, ws Workspace, approved bool) error {
	if ws.Git {
		if _, o, e := shell(ctx, ws.Root, "git worktree remove --force "+shQuote(ws.Path)); e != nil {
			return fmt.Errorf("git worktree remove: %s", o)
		}
		if approved {
			_, _, _ = shell(ctx, ws.Root, "git branch -D "+shQuote(ws.Branch))
		}
		return nil
	}
	return os.RemoveAll(ws.Path)
}

// LocalWorktreeRunner is the pre-Phase-5 execution path: the agent runs as a
// direct host subprocess against a git worktree (or plain copy) of root.
//
// Sol High 11 (repair Session 3c/6) originally scoped output capping to
// Docker only, matching DockerRunner's cappedWriter accounting: Launch
// supplies an executor that bounds the subprocess's stdout/stderr the same
// way, and the truncation tally is read back by Observe. One
// LocalWorktreeRunner serves a single run (runner.New builds a fresh
// instance per run), so this mutable state does not leak across runs.
type LocalWorktreeRunner struct {
	Config contracts.LocalRunnerConfig

	mu    sync.Mutex
	trunc truncationStats
}

func (r *LocalWorktreeRunner) Prepare(ctx context.Context, req PrepareRequest) (Workspace, error) {
	return prepareWorktree(ctx, req.Root, req.Home, req.ID, req.Git)
}

// Launch adds no host containment beyond what the worktree itself already
// provides — local runs isolate the repo, never the OS the agent runs
// against (see docs/containment.md) — but it does bound the transcript size
// via req.Request.Executor, matching DockerRunner.executor's cappedWriter.
func (r *LocalWorktreeRunner) Launch(ctx context.Context, ws Workspace, req LaunchRequest) (agents.Result, error) {
	launchReq := req.Request
	launchReq.Executor = r.executor()
	return req.Agent.Run(ctx, launchReq)
}

// executor wraps the same host-subprocess launch agents.defaultExecutor
// performs (agents.Request.Executor nil), but through a cappedWriter so an
// unbounded local transcript can no longer grow past Config's cap the way a
// Docker run's already couldn't. Kept in this package (not
// agents.defaultExecutor, which is unexported) so every backend adapter's
// runCLI keeps funneling through Request.Executor unchanged.
func (r *LocalWorktreeRunner) executor() agents.Executor {
	return func(ctx context.Context, bin string, args []string, workdir string, out io.Writer, timeout time.Duration) (int, bool, error) {
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(runCtx, bin, args...)
		cmd.Dir = workdir
		capped := &cappedWriter{w: out, remaining: r.Config.EffectiveOutputCapBytes()}
		cmd.Stdout, cmd.Stderr = capped, capped
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			return 0, false, err
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		var code int
		var timedOut bool
		var runErr error
		select {
		case err := <-done:
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					code = ee.ExitCode()
				} else {
					runErr = err
				}
			}
		case <-runCtx.Done():
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			<-done
			code = -1
			timedOut = true
			runErr = runCtx.Err()
		}
		// Loud accounting, same as DockerRunner.executor: how much transcript
		// was retained vs. discarded past the cap, read back by Observe.
		capped.mu.Lock()
		stats := truncationStats{accepted: capped.accepted, discarded: capped.discarded, truncated: capped.discarded > 0}
		capped.mu.Unlock()
		r.mu.Lock()
		r.trunc = stats
		r.mu.Unlock()
		return code, timedOut, runErr
	}
}

// Observe reports the truncation tally Launch's executor stashed — the local
// equivalent of DockerRunner.Observe's OutputTruncated/BytesAccepted/
// BytesDiscarded (a host subprocess has no container to inspect, so Notes
// and Limits stay empty).
func (r *LocalWorktreeRunner) Observe(context.Context, Workspace) (ObserveResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return ObserveResult{
		OutputTruncated: r.trunc.truncated,
		BytesAccepted:   r.trunc.accepted,
		BytesDiscarded:  r.trunc.discarded,
	}, nil
}

// Stop is a no-op: the agent subprocess already honors ctx cancellation
// internally (the executor's SIGKILL-on-ctx.Done above), and
// LocalWorktreeRunner has no separate process handle of its own to signal.
func (r *LocalWorktreeRunner) Stop(context.Context, Workspace) error { return nil }

func (r *LocalWorktreeRunner) Destroy(ctx context.Context, ws Workspace, approved bool) error {
	return destroyWorktree(ctx, ws, approved)
}
