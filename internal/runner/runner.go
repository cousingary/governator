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
	// ConsumedDir is the host absolute path of the private, controller-owned
	// consumed-artifact store for this run (Sol10 P0-1's
	// runtime.consumedArtifactStoreDir), set by the caller after Prepare
	// returns, only when the contract declares Consumes and this run's
	// consumed artifacts are staged externally rather than into the legacy
	// <work>/.governator/consumed location. DockerRunner.runArgs bind-mounts
	// it read-only onto /workspace/.governator/consumed when non-empty;
	// LocalWorktreeRunner ignores it (the local path's equivalent protection
	// goes through enforce.Plan.ROBinds instead, attached via context).
	ConsumedDir string
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
//
// registry is the run's frozen trusted-tool registry (RunEnvironment.ToolRegistry,
// Sol12 P0-6): both runners store it and thread it into their shell() calls
// so git/bash are resolved from the same frozen toolset across the whole
// transaction instead of reloading the registry per call. dockerEnv is the
// run's one frozen DockerEnvironment (Sol12 P0-7), required for mode
// "docker" on the governed path; when non-nil its daemon query already
// proved availability, so CheckDockerAvailable is skipped. A nil dockerEnv
// (recovery-constructed callers) falls back to the standalone availability
// check + per-op resolver.
func New(mode string, dockerCfg *contracts.DockerRunnerConfig, localCfg *contracts.LocalRunnerConfig, credentialRoots []string, resolvedImage *ImageIdentity, registry *toolregistry.Registry, dockerEnv *DockerEnvironment, controllerEnvironments ...controllerenv.Frozen) (Runner, error) {
	frozen := controllerenv.Freeze()
	if len(controllerEnvironments) > 0 {
		frozen = controllerEnvironments[0]
	}
	if err := frozen.Validate(); err != nil {
		return nil, fmt.Errorf("runner: %w", err)
	}
	switch mode {
	case "", "local":
		cfg := contracts.LocalRunnerConfig{}
		if localCfg != nil {
			cfg = *localCfg
		}
		return &LocalWorktreeRunner{Config: cfg, ControllerEnvironment: frozen, Registry: registry}, nil
	case "docker":
		if dockerCfg == nil {
			return nil, fmt.Errorf("runner: docker requested but no docker config was supplied")
		}
		// Sol12 P0-7: a frozen DockerEnvironment already proved the daemon
		// is reachable (ResolveDockerEnvironment's version query); only the
		// standalone/recovery path (no dockerEnv) re-checks availability here.
		if dockerEnv == nil {
			if err := CheckDockerAvailable(frozen); err != nil {
				return nil, fmt.Errorf("runner: docker requested but unavailable: %w", err)
			}
		}
		if resolvedImage == nil || strings.TrimSpace(resolvedImage.ID) == "" {
			return nil, fmt.Errorf("runner: docker requested but no resolved image identity was supplied for %q", dockerCfg.Image)
		}
		return &DockerRunner{Config: *dockerCfg, CredentialRoots: credentialRoots, ControllerEnvironment: frozen, ResolvedImage: resolvedImage, Docker: dockerEnv, Registry: registry}, nil
	default:
		return nil, fmt.Errorf("runner: unknown mode %q", mode)
	}
}

// shell runs command via bash -lc in dir, killing the process group if ctx
// is done before it exits. Copied verbatim from internal/runtime's identical
// helper — both packages need the same "run a git plumbing command, honor
// ctx cancellation" primitive, and runner must not import runtime.
//
// Sol12 P0-6: registry is the run's frozen trusted-tool registry (stored on
// each Runner by New); shell resolves git/bash from it rather than reloading
// the registry per call, so two shell calls in one transaction can never see
// different toolsets after a registry rotation. PATH is private to the
// declared controller tool (the sealed git directory) alone — the ambient
// base PATH is no longer appended, so undeclared tools (grep/sed/cp/find/
// sort/awk) the command string might otherwise resolve through PATH cannot
// affect the transaction. The recovery path (recovery.go) loads a one-shot
// registry and passes it in; a nil registry fails closed.
func shell(ctx context.Context, dir, command string, registry *toolregistry.Registry, environments ...controllerenv.Frozen) (int, string, error) {
	frozen := controllerenv.Freeze()
	if len(environments) > 0 {
		frozen = environments[0]
	}
	if err := frozen.Validate(); err != nil {
		return -1, "", err
	}
	if registry == nil {
		return -1, "", fmt.Errorf("controller tool registry is not frozen")
	}
	// Sol9 P0-6: see internal/runtime's identical helper for the full
	// rationale. The prior fix (Sol report attack 10 / P0-5) prepended the
	// trusted-tool registry's verified git directory to the subprocess's
	// PATH, but that directory is a live, mutable path a same-uid process
	// could still repopulate between resolution and bash's own lookup.
	// Sealing the verified handle's bytes into a private immutable copy
	// (the same primitive structured validators use, P0-5) and prepending
	// that instead removes the window entirely.
	gitHandle, gerr := registry.ResolveHandle("git", "git", toolregistry.KindTrustedController)
	if gerr != nil {
		return -1, "", fmt.Errorf("resolve trusted git handle: %w", gerr)
	}
	sealedGit, gerr := gitHandle.SealedExecutablePath()
	_ = gitHandle.Close()
	if gerr != nil {
		return -1, "", fmt.Errorf("seal trusted git: %w", gerr)
	}
	defer sealedGit.Close()
	// Session 2 (post-v4 hardening plan item C) / Sol9 P0-6: bash itself is
	// the controller tool actually running this command string (including
	// every deterministic validator/formatter/linter a job contract
	// declares). It now launches from a held, verified descriptor
	// (/proc/self/fd/<n>, via Handle.CommandWith -- the same fd-argv
	// mechanic enforce.Plan.Wrap uses for unshare/self-exec, Sol9
	// P0-1/P0-2) instead of a pathname exec.CommandContext would have to
	// re-resolve.
	bashHandle, berr := registry.ResolveHandle("bash", "bash", toolregistry.KindTrustedController)
	if berr != nil {
		return -1, "", fmt.Errorf("resolve trusted bash handle: %w", berr)
	}
	defer bashHandle.Close()
	// Sol12 P0-6 gap (mirrors internal/runtime's identical helper): the
	// sealed git copy may itself be a script (e.g. an `#!/usr/bin/env bash`
	// wrapper some git installs use) whose shebang needs to find "bash" on
	// PATH. bash is already a second declared, verified controller tool in
	// this exact call, so sealing it too and adding its directory alongside
	// git's keeps PATH limited to exactly the tools this transaction already
	// resolved and verified.
	sealedBash, berr := bashHandle.SealedExecutablePath()
	if berr != nil {
		return -1, "", fmt.Errorf("seal trusted bash: %w", berr)
	}
	defer sealedBash.Close()
	build := func(c context.Context, bin string, a []string) *exec.Cmd {
		cc := exec.CommandContext(c, bin, a...) // govratchet:exec-allow(production_launch_factory) -- bin is bashHandle's verified/sealed path, substituted by the caller
		cc.Dir = dir
		cc.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		return cc
	}
	cmd, err := bashHandle.CommandWith(ctx, []string{"--noprofile", "--norc", "-c", command}, build)
	if err != nil {
		return -1, "", err
	}
	// Sol12 P0-6: PATH is private to the declared controller tools this call
	// already resolved and verified — the sealed git and bash directories
	// alone. The ambient base PATH is deliberately NOT appended, so the
	// command string (and any shebang interpreter lookup a script-shaped
	// sealed tool needs) cannot accidentally invoke undeclared ambient tools
	// (grep/sed/cp/find/sort/awk) the way the prior sealedGitDir + base PATH
	// formulation let it. Every non-git file operation this package performs
	// goes through in-process Go (copyWorkspace) instead of shelling out.
	pathValue := filepath.Dir(sealedGit.Path) + string(os.PathListSeparator) + filepath.Dir(sealedBash.Path)
	cmd.Env = frozen.With(map[string]string{"PATH": pathValue}).Values
	// Sol9 P1-4: re-verify the sealed copies immediately before they can be
	// found through PATH below -- a private read-only copy is not
	// kernel-immutable, so this is the last point Governator can catch a
	// same-UID tamper before launch.
	if verr := sealedGit.Verify(); verr != nil {
		return -1, "", fmt.Errorf("verify sealed git before launch: %w", verr)
	}
	if verr := sealedBash.Verify(); verr != nil {
		return -1, "", fmt.Errorf("verify sealed bash before launch: %w", verr)
	}
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
// git worktree off root (git == true) or an in-process recursive copy
// (git == false). Copied from internal/runtime's prior createWorkspace and
// adapted for Sol12 P0-6: the non-git copy is now a pure-Go recursive copy
// rather than `cp -a --reflink=auto`, so this helper never depends on an
// ambient-PATH coreutils binary the private-PATH shell() launch would not
// resolve. registry is the run's frozen trusted-tool registry (Sol12 P0-6).
func prepareWorktree(ctx context.Context, root, home, id string, git bool, frozen controllerenv.Frozen, registry *toolregistry.Registry) (Workspace, error) {
	p := filepath.Join(home, "worktrees", id)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return Workspace{}, err
	}
	branch := "gov/job/" + id
	if git {
		c, o, e := shell(ctx, root, fmt.Sprintf("git worktree add -b %s %s HEAD", shQuote(branch), shQuote(p)), registry, frozen)
		if e != nil || c != 0 {
			return Workspace{}, fmt.Errorf("git worktree: %v: %s", e, o)
		}
		return Workspace{Path: p, Root: root, Branch: branch, Git: true}, nil
	}
	if err := os.MkdirAll(p, 0700); err != nil {
		return Workspace{}, err
	}
	if err := copyWorkspace(root, p); err != nil {
		return Workspace{}, fmt.Errorf("copy workspace: %w", err)
	}
	return Workspace{Path: p, Root: root}, nil
}

// destroyWorktree tears down a workspace prepareWorktree created. approved
// controls whether the git branch is deleted: a quarantined run keeps its
// branch around for inspection, exactly as before Phase 5 extracted this
// logic out of internal/runtime's runOnce tail. registry is the run's frozen
// trusted-tool registry (Sol12 P0-6).
func destroyWorktree(ctx context.Context, ws Workspace, approved bool, frozen controllerenv.Frozen, registry *toolregistry.Registry) error {
	if ws.Git {
		if _, o, e := shell(ctx, ws.Root, "git worktree remove --force "+shQuote(ws.Path), registry, frozen); e != nil {
			return fmt.Errorf("git worktree remove: %s", o)
		}
		if approved {
			_, _, _ = shell(ctx, ws.Root, "git branch -D "+shQuote(ws.Branch), registry, frozen)
		}
		return nil
	}
	return os.RemoveAll(ws.Path)
}

// copyWorkspace is the in-process recursive copy of root into dst, replacing
// the prior `cp -a --reflink=auto` shell call (Sol12 P0-6): a pure-Go copy
// has no dependency on an ambient-PATH coreutils binary, so the private-PATH
// shell() launch this package uses for git porcelain never has to expose cp
// (or any other undeclared tool) to a command string. Mode bits and symlink
// shape are preserved the way `cp -a` preserved them; reflink (CoW) is not —
// correctness of the isolation boundary is not worth a host-filesystem
// optimization this codebase never asserted.
func copyWorkspace(root, dst string) error {
	root = filepath.Clean(root)
	dst = filepath.Clean(dst)
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		mode := info.Mode()
		switch {
		case mode&os.ModeSymlink != 0:
			link, lerr := os.Readlink(path)
			if lerr != nil {
				return lerr
			}
			return os.Symlink(link, target)
		case mode.IsDir():
			if path == root {
				return nil
			}
			return os.MkdirAll(target, mode.Perm())
		case mode.IsRegular():
			if cerr := copyFileMode(path, target, mode.Perm()); cerr != nil {
				return cerr
			}
			if rel == "." {
				return nil
			}
			return nil
		default:
			return fmt.Errorf("copy workspace: skipping non-regular file %q (mode %s)", path, mode)
		}
	})
}

func copyFileMode(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
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
	Config                contracts.LocalRunnerConfig
	ControllerEnvironment controllerenv.Frozen
	// Registry is the run's frozen trusted-tool registry (Sol12 P0-6):
	// shell() resolves git/bash from this rather than reloading the registry
	// per call. nil on recovery-constructed runners, which load a one-shot
	// registry into destroyWorktree themselves.
	Registry *toolregistry.Registry

	mu    sync.Mutex
	trunc truncationStats
}

func (r *LocalWorktreeRunner) controllerEnvironment() controllerenv.Frozen {
	if r.ControllerEnvironment.Validate() == nil {
		return r.ControllerEnvironment
	}
	// Preserve direct struct construction for package clients and tests. Runs
	// constructed through New always carry the single run-frozen snapshot.
	return controllerenv.Freeze()
}

func (r *LocalWorktreeRunner) Prepare(ctx context.Context, req PrepareRequest) (Workspace, error) {
	return prepareWorktree(ctx, req.Root, req.Home, req.ID, req.Git, r.controllerEnvironment(), r.Registry)
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
	return func(ctx context.Context, bin string, args []string, workdir string, out io.Writer, timeout time.Duration) (int, bool, bool, error) {
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		handle, _ := agents.HandleFromContext(runCtx)
		scope, hasScope := containment.ScopeFromContext(runCtx)
		capped := &cappedWriter{w: out, remaining: r.Config.EffectiveOutputCapBytes()}
		if hasScope {
			// Sol redteam v7 S1 gap-closure: identical composition to
			// agents.defaultExecutor's own hasScope branch, shared via
			// agents.LaunchStaged so both callers get the same unique
			// per-stage scope naming and descendant-extinction proof.
			plan, _ := enforce.PlanFromContext(runCtx)
			code, descendantsGone, runErr := agents.LaunchStaged(runCtx, handle, bin, args, workdir, capped, scope, plan)
			timedOut := runCtx.Err() != nil
			capped.mu.Lock()
			stats := truncationStats{accepted: capped.accepted, discarded: capped.discarded, truncated: capped.discarded > 0}
			capped.mu.Unlock()
			r.mu.Lock()
			r.trunc = stats
			r.mu.Unlock()
			return code, timedOut, descendantsGone, runErr
		}
		cmd, launchErr := agents.LaunchCommand(runCtx, handle, bin, args)
		if launchErr != nil {
			return 0, false, true, launchErr
		}
		cmd.Dir = workdir
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		var allowedEnv []string
		if handle != nil {
			allowedEnv = handle.AllowedEnv
		}
		cmd.Env = agents.BuildAllowedEnv(allowedEnv)
		if len(cmd.Env) == 0 {
			cmd.Env = controllerenv.Base()
		}
		cmd.Stdout, cmd.Stderr = capped, capped
		if err := cmd.Start(); err != nil {
			return 0, false, true, err
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
		return code, timedOut, true, runErr
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
	return destroyWorktree(ctx, ws, approved, r.controllerEnvironment(), r.Registry)
}
