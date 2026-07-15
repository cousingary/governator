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
	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/gitplumb"
	"github.com/cousingary/governator/internal/toolregistry"
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
// credentialRoots is the caller's frozen RunEnvironment.CredentialRoots (Sol
// Finding 2 / Session 3) — DockerRunner used to read config.Current().
// Credentials.Roots itself at credential-mount time, independently of
// whatever the rest of the run had already frozen. Ignored for mode "local"
// (LocalWorktreeRunner never mounts credentials).
func New(mode string, dockerCfg *contracts.DockerRunnerConfig, localCfg *contracts.LocalRunnerConfig, credentialRoots []string) (Runner, error) {
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
		return &DockerRunner{Config: *dockerCfg, CredentialRoots: credentialRoots}, nil
	default:
		return nil, fmt.Errorf("runner: unknown mode %q", mode)
	}
}

// shell runs command via bash -lc in dir, killing the process group if ctx
// is done before it exits. Copied verbatim from internal/runtime's identical
// helper — both packages need the same "run a git plumbing command, honor
// ctx cancellation" primitive, and runner must not import runtime.
func shell(ctx context.Context, dir, command string) (int, string, error) {
	// Sol report attack 10 / P0-5: see internal/runtime's identical helper
	// for why this prepends the trusted-tool registry's verified git
	// directory to the subprocess's PATH rather than trusting whatever the
	// calling process's own PATH resolves "git" to.
	gitPath, gerr := gitplumb.TrustedGitPath()
	if gerr != nil {
		return -1, "", gerr
	}
	// Session 2 (post-v4 hardening plan item C): bash itself is the
	// controller tool actually running this command string (including
	// every deterministic validator/formatter/linter a job contract
	// declares) -- the PATH-prepend above only protects "git" once bash is
	// already running, so bash's own resolution needs the same
	// registry-verified treatment git already got, or a hostile bash
	// earlier on this process's PATH would run with full Governator
	// authority before the prepend ever mattered.
	bashIdentity, berr := toolregistry.ResolveTrusted("bash", "bash")
	if berr != nil {
		return -1, "", fmt.Errorf("resolve trusted bash: %w", berr)
	}
	cmd := exec.CommandContext(ctx, bashIdentity.CanonicalPath, "--noprofile", "--norc", "-c", command)
	cmd.Dir = dir
	cmd.Env = controllerenv.With(map[string]string{"PATH": filepath.Dir(gitPath) + string(os.PathListSeparator) + os.Getenv("PATH")})
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

// Launch itself adds no host containment beyond what the worktree provides
// — local runs isolate the repo, never the OS the agent runs against, on
// their own (see docs/containment.md) — but its executor (below) wraps the
// launch in Governator's own externally enforced sandbox (Session 5, Sol
// P0-3: internal/enforce) whenever enforceContainment attached an active
// Plan to ctx, and it does bound the transcript size via req.Request.Executor,
// matching DockerRunner.executor's cappedWriter.
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
		handle, _ := agents.HandleFromContext(runCtx)
		var cmd *exec.Cmd
		var launchErr error
		scope, hasScope := containment.ScopeFromContext(runCtx)
		plan, _ := enforce.PlanFromContext(runCtx)
		if hasScope {
			cmd, launchErr = agents.LaunchCommand(runCtx, handle, bin, args, func(c context.Context, b string, a []string) *exec.Cmd {
				// Session 5 (Sol P0-3): wrap bin/args in Governator's own
				// externally enforced sandbox (Landlock + network namespace)
				// BEFORE the S2 descendant-owning Scope wraps the launch
				// again -- identical composition to agents.defaultExecutor.
				// A no-op Plan (most runs) returns b/a unchanged.
				wb, wa := plan.Wrap(b, a)
				return scope.Command(c, wb, wa, workdir)
			})
		} else {
			cmd, launchErr = agents.LaunchCommand(runCtx, handle, bin, args, nil)
			if launchErr == nil {
				cmd.Dir = workdir
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			}
		}
		if launchErr != nil {
			return 0, false, launchErr
		}
		var allowedEnv []string
		if handle != nil {
			allowedEnv = handle.AllowedEnv
		}
		cmd.Env = agents.BuildAllowedEnv(allowedEnv)
		if len(cmd.Env) == 0 {
			cmd.Env = controllerenv.Base()
		}
		capped := &cappedWriter{w: out, remaining: r.Config.EffectiveOutputCapBytes()}
		cmd.Stdout, cmd.Stderr = capped, capped
		if err := cmd.Start(); err != nil {
			return 0, false, err
		}
		if hasScope && cmd.Process != nil {
			scope.Started(cmd.Process.Pid)
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
