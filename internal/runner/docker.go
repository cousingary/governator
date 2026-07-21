package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/toolregistry"
)

// ImageIdentity is the resolved, replay-bindable identity of a Docker image
// reference (Sol P1-1). Reference is whatever the operator configured --
// commonly a mutable tag, which can be repointed at a different image
// between an attested run and a later replay. ID (the image's content-
// addressed config hash) and RepoDigests (immutable repo@sha256:... registry
// references, when the image was pulled/pushed rather than only built
// locally) cannot be silently repointed the way a tag can; Entrypoint/Cmd/
// User record what will actually execute inside the container, so
// attestation binds to the in-container reality instead of assuming it
// matches whatever the host CLI reports.
type ImageIdentity struct {
	Reference   string
	ID          string
	RepoDigests []string
	Entrypoint  []string
	Cmd         []string
	User        string
}

// dockerImageInspect is the subset of `docker image inspect` this package
// reads to build an ImageIdentity.
type dockerImageInspect struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
	Config      struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		User       string   `json:"User"`
	} `json:"Config"`
}

// ResolveImageIdentity inspects image (a tag or digest reference) and
// returns its content-addressed identity. Fails closed -- never a
// sentinel -- when the image cannot be inspected: not present locally,
// daemon unreachable, or a malformed reference. Callers needing a
// replay-safe identity must use ID/RepoDigests here, never Reference alone.
func ResolveImageIdentity(ctx context.Context, image string, environments ...controllerenv.Frozen) (ImageIdentity, error) {
	env := controllerenv.Freeze()
	if len(environments) > 0 {
		env = environments[0]
	}
	if err := env.Validate(); err != nil {
		return ImageIdentity{}, err
	}
	if strings.TrimSpace(image) == "" {
		return ImageIdentity{}, fmt.Errorf("resolve image identity: empty image reference")
	}
	handle, berr := resolveDockerHandle()
	if berr != nil {
		return ImageIdentity{}, fmt.Errorf("resolve image identity %q: %w", image, berr)
	}
	defer handle.Close()
	out, err := func() ([]byte, error) {
		cmd, cerr := handle.Command(ctx, "image", "inspect", image, "--format", "{{json .}}")
		if cerr != nil {
			return nil, cerr
		}
		cmd.Env = append([]string(nil), env.Values...)
		return cmd.Output()
	}()
	if err != nil {
		return ImageIdentity{}, fmt.Errorf("resolve image identity %q: %w", image, err)
	}
	var insp dockerImageInspect
	if err := json.Unmarshal(out, &insp); err != nil {
		return ImageIdentity{}, fmt.Errorf("resolve image identity %q: parse inspect output: %w", image, err)
	}
	if insp.ID == "" {
		return ImageIdentity{}, fmt.Errorf("resolve image identity %q: inspect returned no image ID", image)
	}
	return ImageIdentity{
		Reference:   image,
		ID:          insp.ID,
		RepoDigests: append([]string(nil), insp.RepoDigests...),
		Entrypoint:  append([]string(nil), insp.Config.Entrypoint...),
		Cmd:         append([]string(nil), insp.Config.Cmd...),
		User:        insp.Config.User,
	}, nil
}

// resolveDocker resolves and verifies the docker CLI through the
// trusted-tool registry (Session 2, post-v4 hardening plan item C) --
// docker is the DockerRunner containment boundary itself, so every one of
// its own invocations trusting a bare ambient "docker" argv0 would let a
// PATH substitution defeat the containment DockerRunner exists to provide.
// Resolved fresh at each call site rather than cached, matching every other
// registry-backed call site in this codebase (gitplumb.TrustedGitPath,
// enforce.NewPlan): callers must see the current trust state, not a stale
// snapshot from earlier in the process's life.
func resolveDockerHandle() (*toolregistry.Handle, error) {
	registry, err := toolregistry.Load()
	if err != nil {
		return nil, fmt.Errorf("load trusted-tool registry: %w", err)
	}
	handle, err := registry.ResolveHandle("docker", "docker", toolregistry.KindTrustedController)
	if err != nil {
		return nil, fmt.Errorf("resolve trusted docker handle: %w", err)
	}
	return handle, nil
}

// CheckDockerAvailable reports whether a working `docker` CLI and a
// reachable daemon exist, so New can fail closed: a contract that asks for
// runner: docker without a usable Docker install must error, never silently
// fall back to LocalWorktreeRunner.
func CheckDockerAvailable(environments ...controllerenv.Frozen) error {
	env := controllerenv.Freeze()
	if len(environments) > 0 {
		env = environments[0]
	}
	if err := env.Validate(); err != nil {
		return err
	}
	handle, err := resolveDockerHandle()
	if err != nil {
		return err
	}
	defer handle.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd, cerr := handle.Command(ctx, "info")
	if cerr != nil {
		return cerr
	}
	cmd.Env = append([]string(nil), env.Values...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker daemon unreachable: %v: %s", err, trimmed(out))
	}
	return nil
}

func trimmed(b []byte) string {
	s := string(b)
	if len(s) > 500 {
		s = s[:500] + "...(truncated)"
	}
	return s
}

// DockerRunner launches the agent subprocess inside a container instead of
// directly on the host. Prepare/Destroy share LocalWorktreeRunner's worktree
// plumbing unchanged (worktrees isolate the repo either way); Launch adds
// the container boundary — resource limits, network policy, and credential
// exposure are enforced there instead of trusted to the agent's own
// restraint.
//
// Session 3 (Phase 2) adds hardening flags (see Config.IsHardened) and makes
// output truncation loud: the cappedWriter records how many bytes were kept
// vs. discarded, surfaced through Observe so the runtime can emit an
// OUTPUT_TRUNCATED ledger event and quarantine runs that required a complete
// transcript. One DockerRunner serves a single run (runner.New builds a fresh
// instance per run), so the truncation tally is read after Launch by Observe.
type DockerRunner struct {
	Config contracts.DockerRunnerConfig
	// CredentialRoots is the caller's frozen RunEnvironment.CredentialRoots
	// (Config.Credentials.Roots), set once by runner.New. credentialMountArgs
	// no longer calls config.Current() itself — see runner.New's doc
	// comment.
	CredentialRoots       []string
	ControllerEnvironment controllerenv.Frozen
	ResolvedImage         *ImageIdentity

	mu    sync.Mutex
	trunc truncationStats
}

func (d *DockerRunner) controllerEnvironment() controllerenv.Frozen {
	if d.ControllerEnvironment.Values != nil {
		return d.ControllerEnvironment
	}
	return controllerenv.Freeze()
}

// truncationStats is the loud accounting Session 3a replaces the silent
// cappedWriter discard with: how much transcript was retained, how much was
// dropped past the cap, and whether any drop happened at all.
type truncationStats struct {
	accepted  int64
	discarded int64
	truncated bool
}

// metadataSinkholeHosts are the cloud-metadata endpoints redirected to
// loopback via docker --add-host when SinkholeMetadataHostnames is set under
// a network: allow config. Raw-IP access (e.g. dialling 169.254.169.254
// directly) is not blocked by /etc/hosts; the safe default remains network:
// deny. These entries cover name-based lookups, which is all the CLI can do.
var metadataSinkholeHosts = []string{
	"metadata.google.internal", // GCP
	"metadata",                 // GCP alias
	"metadata.azure.com",       // Azure
}

func (d *DockerRunner) Prepare(ctx context.Context, req PrepareRequest) (Workspace, error) {
	ws, err := prepareWorktree(ctx, req.Root, req.Home, req.ID, req.Git, d.controllerEnvironment())
	if err != nil {
		return Workspace{}, err
	}
	ws.Container = "gov-" + req.ID
	return ws, nil
}

// Launch runs the exact CLI invocation agent.Run would have run directly on
// the host, but inside a container: it supplies req.Request.Executor so the
// backend's own Run (with all its side effects — flag projection, scoped
// config files, transcript handling) is unchanged, only how the final
// process is spawned differs.
func (d *DockerRunner) Launch(ctx context.Context, ws Workspace, req LaunchRequest) (agents.Result, error) {
	launchReq := req.Request
	launchReq.Executor = d.executor(ws)
	return req.Agent.Run(ctx, launchReq)
}

func (d *DockerRunner) executor(ws Workspace) agents.Executor {
	return func(ctx context.Context, bin string, args []string, workdir string, out io.Writer, timeout time.Duration) (int, bool, bool, error) {
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		dockerArgs, err := d.runArgs(ws, bin, args)
		if err != nil {
			return 0, false, false, err
		}
		dockerHandle, dberr := resolveDockerHandle()
		if dberr != nil {
			return 0, false, false, dberr
		}
		defer dockerHandle.Close()
		// Sol9 P1-2: the docker CLI process launches with its own process
		// group (Setpgid) so a same-uid kill signal issued after this
		// package has already given up on it (below) reaches every process
		// in the group, not only the CLI's own top-level pid -- the same
		// mechanic internal/runner's and internal/runtime's shell() helpers
		// use for bash.
		build := func(c context.Context, bin string, a []string) *exec.Cmd {
			cc := exec.CommandContext(c, bin, a...) // govratchet:exec-allow(production_launch_factory) -- bin is dockerHandle's verified/sealed path, substituted by the caller
			cc.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			return cc
		}
		cmd, cerr := dockerHandle.CommandWith(runCtx, dockerArgs, build)
		if cerr != nil {
			return 0, false, false, cerr
		}
		env := d.controllerEnvironment()
		cmd.Env = append([]string(nil), env.Values...)
		capped := &cappedWriter{w: out, remaining: d.Config.EffectiveOutputCapBytes()}
		cmd.Stdout, cmd.Stderr = capped, capped
		launchStart := time.Now()
		if err := cmd.Start(); err != nil {
			return 0, false, false, err
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		var code int
		var timedOut bool
		var runErr error
		if err := d.verifyStartedContainer(context.Background(), ws, launchStart); err != nil {
			stopErr := d.forceStopAndRemove(context.Background(), ws)
			killProcessGroup(cmd)
			runErr = errors.Join(err, stopErr, waitDockerCLIBounded(done, DockerCLIShutdownDeadline))
			code = -1
		} else {
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
				code = -1
				timedOut = true
				stopErr := d.forceStopAndRemove(context.Background(), ws)
				killProcessGroup(cmd)
				runErr = errors.Join(runCtx.Err(), stopErr, waitDockerCLIBounded(done, DockerCLIShutdownDeadline))
			}
		}
		// Record truncation accounting (Session 3a): loud, never silent. The
		// cap protects the transcript from unbounded growth; surfacing how much
		// was kept vs. discarded keeps the audit trail honest and lets the
		// runtime quarantine runs that required a complete transcript.
		capped.mu.Lock()
		stats := truncationStats{accepted: capped.accepted, discarded: capped.discarded, truncated: capped.discarded > 0}
		capped.mu.Unlock()
		d.mu.Lock()
		d.trunc = stats
		d.mu.Unlock()
		descendantsGone, extinctionErr := d.proveContainerExtinction(context.Background(), ws)
		if extinctionErr != nil {
			runErr = errors.Join(runErr, extinctionErr)
		}
		return code, timedOut, descendantsGone, runErr
	}
}

// runArgs builds the `docker run` argument list: bind-mount the workspace,
// apply resource limits, default-deny network (contract opt-in to allow),
// mount only the explicitly allowlisted credential paths (read-only, under a
// dedicated container path), then the image and the backend's own bin+args
// as the container command. Session 3 (Phase 2) appends the hardening
// controls from Config when set. Session 6 (Sol High 9) makes credential
// mount resolution fallible: a mount that fails containment (symlink escape,
// wrong file type, outside the configured roots, a control socket) fails the
// whole launch rather than silently mounting something else.
func (d *DockerRunner) runArgs(ws Workspace, bin string, args []string) ([]string, error) {
	// Canonicalize the workspace bind so a trailing slash or ../ noise in the
	// worktree path can't shift where the repo lands inside the container.
	wsPath := filepath.Clean(ws.Path)
	out := []string{"run", "--name", ws.Container, "-v", wsPath + ":/workspace", "-w", "/workspace"}
	// Sol10 P0-1: a second, more specific bind mount layered read-only over
	// the writable /workspace mount above -- standard docker/mount-layering
	// behavior, the more specific mount path wins for paths beneath it. The
	// consumed-artifact store lives outside the host worktree entirely (see
	// runtime.consumedArtifactStoreDir); mounting it here, instead of
	// relying on the workspace bind's own permission bits, means even a
	// container running as root (the common non-remapped-userns default)
	// cannot write through this path without first defeating the mount
	// itself, which requires CAP_SYS_ADMIN -- absent from Docker's default
	// capability set and never added by this config.
	if ws.ConsumedDir != "" {
		out = append(out, "-v", filepath.Clean(ws.ConsumedDir)+":/workspace/.governator/consumed:ro")
	}
	if d.Config.MemoryLimit != "" {
		out = append(out, "--memory", d.Config.MemoryLimit)
	}
	if d.Config.CPULimit != "" {
		out = append(out, "--cpus", d.Config.CPULimit)
	}
	if d.Config.PIDsLimit > 0 {
		out = append(out, "--pids-limit", strconv.Itoa(d.Config.PIDsLimit))
	}
	// Session 3 (Phase 2) hardening controls — emitted only when the contract
	// opts into each, so every prior job YAML produces byte-identical args.
	if d.Config.User != "" {
		out = append(out, "--user", d.Config.User)
	}
	if d.Config.ReadOnlyRootfs {
		out = append(out, "--read-only")
	}
	if d.Config.CapDropAll {
		out = append(out, "--cap-drop=ALL")
	}
	if d.Config.NoNewPrivileges {
		out = append(out, "--security-opt", "no-new-privileges")
	}
	if d.Config.SeccompProfile != "" {
		out = append(out, "--security-opt", "seccomp="+d.Config.SeccompProfile)
	}
	if d.Config.AppArmorProfile != "" {
		out = append(out, "--security-opt", "apparmor="+d.Config.AppArmorProfile)
	}
	for _, t := range d.Config.Tmpfs {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, "--tmpfs", t)
		}
	}
	// Network policy: default-deny (--network none). An allow opt-in may
	// additionally sinkhole cloud-metadata endpoints when configured.
	if d.Config.EffectiveNetwork() != "allow" {
		out = append(out, "--network", "none")
	} else if d.Config.SinkholeMetadataHostnames {
		for _, host := range metadataSinkholeHosts {
			out = append(out, "--add-host", host+":127.0.0.1")
		}
	}
	credArgs, err := d.credentialMountArgs()
	if err != nil {
		return nil, err
	}
	out = append(out, credArgs...)
	runtimeImage, err := d.runtimeImageRef()
	if err != nil {
		return nil, err
	}
	out = append(out, runtimeImage, bin)
	out = append(out, args...)
	return out, nil
}

func (d *DockerRunner) runtimeImageRef() (string, error) {
	if d.ResolvedImage != nil && strings.TrimSpace(d.ResolvedImage.ID) != "" {
		return d.ResolvedImage.ID, nil
	}
	return "", fmt.Errorf("docker runtime image is unresolved; refusing mutable configured reference %q", d.Config.Image)
}

// dockerCreationClockSkew tolerates minor variance between this process
// recording launchStart and the daemon stamping the container's own Created
// timestamp -- a genuine container from this launch always follows
// launchStart, but by an amount that varies with daemon load, image pull
// state, and host clock precision.
const dockerCreationClockSkew = 3 * time.Second

// DockerContainerObservationDeadline bounds how long verifyStartedContainer
// polls before treating a container as genuinely never-appeared
// (DOCKER_CONTAINER_NOT_OBSERVED). It must exceed real daemon-side container
// creation latency, not just inspect-call latency: on a Docker
// Desktop/WSL2 backend, `docker run` creating and starting even a trivial
// container was empirically observed to take >10s end to end, while
// `docker inspect` itself resolves in milliseconds once the container
// exists. A short deadline here doesn't make failures happen faster, it
// makes REAL, eventually-successful launches misreported as
// DOCKER_CONTAINER_NOT_OBSERVED -- the same "absence looks like success (or
// here, failure) when it isn't" class of bug Sol9 P1-1 flagged, just
// inverted. 20s gives comfortable headroom above the observed ~10.5s while
// staying well inside typical per-stage transaction budgets.
const DockerContainerObservationDeadline = 20 * time.Second

// verifyStartedContainer proves the transaction's container actually started
// -- Sol9 P1-1's "absence counts as success" -- rather than merely polling
// until a deadline and treating "still absent" as a clean pass. A successful
// proof requires: the container exists; its running/exited state is known;
// its image ID equals the resolved identity; and (when the daemon reports a
// creation time) that time is not older than this launch, so a stale
// container left behind under the same name cannot be mistaken for this
// launch's own container. The name/ID match to "the transaction's
// container" is structural: inspectContainer is queried by ws.Container
// itself, and Docker enforces container-name uniqueness, so a hit can only
// ever be this transaction's container or nothing.
func (d *DockerRunner) verifyStartedContainer(ctx context.Context, ws Workspace, launchStart time.Time) error {
	if d.ResolvedImage == nil || strings.TrimSpace(d.ResolvedImage.ID) == "" || ws.Container == "" {
		return nil
	}
	env := d.controllerEnvironment()
	deadline := time.Now().Add(DockerContainerObservationDeadline)
	for {
		// Sol9 P1-2: bound each poll's inspect call so a daemon that never
		// responds can't block this loop past its own deadline check --
		// see waitDockerCLIBounded for the equivalent bound on the CLI's
		// own shutdown wait.
		inspectCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		insp, absent, err := inspectContainer(inspectCtx, ws.Container, env)
		cancel()
		if err == nil {
			if insp.Image != d.ResolvedImage.ID {
				return fmt.Errorf("docker runtime image mismatch: resolved %s, running %s", d.ResolvedImage.ID, insp.Image)
			}
			if insp.State.Status == "" {
				return fmt.Errorf("docker runtime state verification: container %s reported no running/exited state", ws.Container)
			}
			if !launchStart.IsZero() && insp.Created != "" {
				created, perr := time.Parse(time.RFC3339Nano, insp.Created)
				if perr != nil {
					return fmt.Errorf("docker runtime verification: parse container %s creation time %q: %w", ws.Container, insp.Created, perr)
				}
				if created.Before(launchStart.Add(-dockerCreationClockSkew)) {
					return fmt.Errorf("docker runtime verification: container %s was created at %s, before this launch started at %s -- a stale container reused the name instead of this launch's own container", ws.Container, created, launchStart)
				}
			}
			return nil
		}
		if !absent {
			return fmt.Errorf("docker runtime image verification: %w", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("DOCKER_CONTAINER_NOT_OBSERVED: container %s did not appear within %s", ws.Container, DockerContainerObservationDeadline)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (d *DockerRunner) forceStopAndRemove(ctx context.Context, ws Workspace) error {
	if ws.Container == "" {
		return nil
	}
	stopCtx, stopCancel := context.WithTimeout(ctx, 10*time.Second)
	stopErr := d.Stop(stopCtx, ws)
	stopCancel()
	if stopErr == nil {
		return nil
	}
	rmCtx, rmCancel := context.WithTimeout(ctx, 10*time.Second)
	rmErr := RemoveContainer(rmCtx, ws.Container, d.controllerEnvironment())
	rmCancel()
	if rmErr != nil {
		return errors.Join(fmt.Errorf("docker stop %s: %w", ws.Container, stopErr), rmErr)
	}
	return fmt.Errorf("docker stop %s: %w (forced removal succeeded)", ws.Container, stopErr)
}

// DockerCLIShutdownDeadline bounds how long the executor waits for the
// docker CLI's Wait to return once this package has already stopped/removed
// the daemon-side container and sent the CLI's process group a kill signal
// (Sol9 P1-2). The prior code blocked on `<-done` with no deadline
// whatsoever, so a stuck CLI -- daemon socket wedged, stop/rm both failing
// -- could hang Governator for however much of the run's timeout budget
// remained, which could be very large.
const DockerCLIShutdownDeadline = 5 * time.Second

// killProcessGroup sends SIGKILL to a docker CLI invocation's whole process
// group (Sol9 P1-2). The executor's cmd is built with
// SysProcAttr{Setpgid: true} specifically so this reaches every process the
// CLI may have spawned, not only its own top-level pid. Safe to call on a
// cmd that never started or has already exited: Process is nil in the
// former case, and killing an empty/already-reaped process group is a
// harmless no-op (ESRCH), not an error worth surfacing.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// waitDockerCLIBounded waits for the docker CLI's exit signal up to
// deadline, returning a hard lifecycle error instead of blocking forever
// when it never arrives -- the direct fix for Sol9 P1-2's unbounded
// `<-done`. Called only after daemon-side cleanup and a process-group kill
// have both already been attempted, so anything still outstanding past the
// deadline is a genuine stuck-CLI lifecycle failure, not a process this
// package simply hasn't gotten around to terminating yet.
func waitDockerCLIBounded(done <-chan error, deadline time.Duration) error {
	select {
	case <-done:
		return nil
	case <-time.After(deadline):
		return fmt.Errorf("docker CLI did not exit within %s after forced daemon cleanup and a process-group kill signal", deadline)
	}
}

func (d *DockerRunner) proveContainerExtinction(ctx context.Context, ws Workspace) (bool, error) {
	if ws.Container == "" {
		return true, nil
	}
	inspectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	insp, absent, err := inspectContainer(inspectCtx, ws.Container, d.controllerEnvironment())
	if absent {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("docker extinction proof: inspect %s: %w", ws.Container, err)
	}
	if insp.State.Running {
		return false, fmt.Errorf("docker extinction proof: container %s still running (status=%s)", ws.Container, insp.State.Status)
	}
	return true, nil
}

// credentialContainerRoot is where every docker.credential_mounts entry
// lands inside the container (Session 6, Sol High 9): a single, dedicated
// path distinct from the workspace or any agent-writable path, so an
// operator can no longer choose an arbitrary container-side destination for
// a host secret (the retired host:container override form), and a
// credential mount can never be mistaken for, or shadow, an
// agent-controlled path.
const credentialContainerRoot = "/run/governator-credentials"

// dockerControlSockets are host paths Session 6 (Sol High 9) refuses to
// mount as a credential under any circumstances — not even via an
// authorized directory containing them. Mounting the container/daemon
// control socket into a "credential" is a direct host/daemon escape, not a
// credential-exposure risk that authorization can responsibly scope down.
// Checked both before and after symlink resolution, since /var/run is
// itself commonly a symlink to /run.
var dockerControlSockets = map[string]bool{
	"/var/run/docker.sock":                  true,
	"/run/docker.sock":                      true,
	"/var/run/containerd/containerd.sock":   true,
	"/run/containerd/containerd.sock":       true,
	"/run/containerd/containerd.sock.ttrpc": true,
	"/var/run/crio/crio.sock":               true,
	"/run/crio/crio.sock":                   true,
}

// credentialMountArgs resolves every configured credential mount to a `-v`
// docker argument, or fails the whole launch on the first mount that can't
// be safely resolved — see resolveCredentialMount for the containment
// rules. Two entries resolving to the same container basename is also an
// error (fail closed on ambiguity) rather than one silently shadowing the
// other.
func (d *DockerRunner) credentialMountArgs() ([]string, error) {
	if len(d.Config.CredentialMounts) == 0 {
		return nil, nil
	}
	roots := d.CredentialRoots
	var out []string
	seen := map[string]string{}
	for _, mount := range d.Config.CredentialMounts {
		containerPath, resolved, err := d.resolveCredentialMount(mount, roots)
		if err != nil {
			return nil, fmt.Errorf("docker credential mount %q: %w", mount, err)
		}
		if prior, dup := seen[containerPath]; dup {
			return nil, fmt.Errorf("docker credential mount %q collides with %q at container path %s", mount, prior, containerPath)
		}
		seen[containerPath] = mount
		out = append(out, "-v", resolved+":"+containerPath+":ro")
	}
	return out, nil
}

// resolveCredentialMount validates and canonicalizes one credential_mounts
// entry (Session 6, Sol High 9):
//   - symlinks are resolved rather than trusted at face value (a tracked
//     symlink could otherwise point the "credential" anywhere on the host);
//   - the resolved path must fall under one of the operator-configured
//     credential roots (config.Credentials.Roots / GOV_CREDENTIAL_ROOTS) —
//     no roots configured means every credential mount is refused;
//   - it must be a regular file unless its resolved path is explicitly
//     authorized as a directory (docker.credential_mount_allow_dirs);
//   - sockets, devices, FIFOs and character devices are refused
//     unconditionally — unlike directories, none of them has a legitimate
//     "credential" use, so there is no authorization path for them at all;
//   - known Docker/containerd/CRI-O control sockets are refused even before
//     the general socket check, so the specific reason is never masked by
//     the generic one.
//
// Returns the container-side destination under credentialContainerRoot and
// the resolved (real, symlink-free) host path to bind-mount.
func (d *DockerRunner) resolveCredentialMount(hostRaw string, roots []string) (containerPath, resolvedHost string, err error) {
	cleaned := filepath.Clean(strings.TrimSpace(hostRaw))
	if dockerControlSockets[cleaned] {
		return "", "", fmt.Errorf("refusing to mount a container/daemon control socket")
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", "", fmt.Errorf("resolve symlinks: %w", err)
	}
	resolved = filepath.Clean(resolved)
	if dockerControlSockets[resolved] {
		return "", "", fmt.Errorf("refusing to mount a container/daemon control socket")
	}
	if len(roots) == 0 {
		return "", "", fmt.Errorf("no credential roots configured (credentials.roots / GOV_CREDENTIAL_ROOTS); refusing every credential mount")
	}
	underRoot := false
	for _, root := range roots {
		if pathUnderRoot(resolved, filepath.Clean(strings.TrimSpace(root))) {
			underRoot = true
			break
		}
	}
	if !underRoot {
		return "", "", fmt.Errorf("resolved path %s is outside every configured credential root", resolved)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", "", fmt.Errorf("stat resolved path: %w", err)
	}
	mode := info.Mode()
	switch {
	case mode.IsRegular():
		// OK — the safe default.
	case mode.IsDir():
		if !authorizedCredentialDir(resolved, d.Config.CredentialMountAllowDirs) {
			return "", "", fmt.Errorf("resolved path %s is a directory, not listed in docker.credential_mount_allow_dirs", resolved)
		}
	default:
		return "", "", fmt.Errorf("resolved path %s is not a regular file or an authorized directory (mode %s)", resolved, mode)
	}
	return credentialContainerRoot + "/" + filepath.Base(resolved), resolved, nil
}

// pathUnderRoot reports whether path is root itself or falls beneath it.
// Both arguments must already be filepath.Clean'd absolute paths.
func pathUnderRoot(path, root string) bool {
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}

// authorizedCredentialDir reports whether resolved (already cleaned) exactly
// matches one of the operator's explicitly authorized directory mounts.
func authorizedCredentialDir(resolved string, allow []string) bool {
	for _, a := range allow {
		if filepath.Clean(strings.TrimSpace(a)) == resolved {
			return true
		}
	}
	return false
}

// Observe inspects the container's applied HostConfig so tests (and
// operators) can verify the resource limits actually took effect, not just
// that they were requested. Session 3 also surfaces output-truncation
// accounting (kept vs. discarded bytes) gathered during Launch, and records
// image provenance so a "hardened" run can be tied back to the exact image.
// dockerInspect is the subset of `docker inspect <container>` this package
// verifies. Field names/casing/shapes were confirmed against a live daemon
// (busybox:1.36) rather than assumed: Config.User echoes --user verbatim
// (docker never resolves it), the top-level Image is the running image's
// resolved ID ("sha256:<64hex>"), CapDrop/SecurityOpt are string slices
// ("ALL", "no-new-privileges"), and PidsLimit is JSON null (decodes to zero)
// when no --pids-limit was set.
type dockerInspect struct {
	Image string `json:"Image"`
	// Created is the daemon-stamped RFC3339Nano creation timestamp -- Sol9
	// P1-1's "creation timestamp belongs to this launch" proof element.
	Created string `json:"Created"`
	State   struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
	} `json:"State"`
	Config struct {
		User string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		Memory         int64    `json:"Memory"`
		NanoCpus       int64    `json:"NanoCpus"`
		PidsLimit      int64    `json:"PidsLimit"`
		NetworkMode    string   `json:"NetworkMode"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		CapDrop        []string `json:"CapDrop"`
		SecurityOpt    []string `json:"SecurityOpt"`
	} `json:"HostConfig"`
	Mounts []struct {
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

// hardenedMismatches compares a hardened DockerRunnerConfig's declared
// controls against what docker inspect reports was actually applied to the
// running container, Session 6 (Sol High 8/10): "verify the running
// container's effective user and image ID, not just the request", and "for
// hardened/high-risk runs, inspection failure or configuration mismatch
// must block approval." Returns one human-readable string per mismatch;
// empty means the applied configuration matches the declaration. A pure
// function (no docker/network access) so it is fully unit-testable against
// fabricated inspect payloads.
func hardenedMismatches(cfg contracts.DockerRunnerConfig, insp dockerInspect) []string {
	var out []string
	if insp.Config.User != cfg.User {
		out = append(out, fmt.Sprintf("user: declared %q, applied %q", cfg.User, insp.Config.User))
	}
	if cfg.EffectiveNetwork() != "allow" && insp.HostConfig.NetworkMode != "none" {
		out = append(out, fmt.Sprintf("network: declared deny, applied network_mode %q", insp.HostConfig.NetworkMode))
	}
	if cfg.ReadOnlyRootfs && !insp.HostConfig.ReadonlyRootfs {
		out = append(out, "read_only_rootfs: declared true, applied false")
	}
	if cfg.CapDropAll && !stringSliceContains(insp.HostConfig.CapDrop, "ALL") {
		out = append(out, fmt.Sprintf("cap_drop_all: declared true, applied CapDrop=%v", insp.HostConfig.CapDrop))
	}
	if cfg.NoNewPrivileges && !anyHasPrefix(insp.HostConfig.SecurityOpt, "no-new-privileges") {
		out = append(out, fmt.Sprintf("no_new_privileges: declared true, applied SecurityOpt=%v", insp.HostConfig.SecurityOpt))
	}
	if cfg.SeccompProfile != "" && !anyHasPrefix(insp.HostConfig.SecurityOpt, "seccomp=") {
		out = append(out, "seccomp_profile: declared but no seccomp= security profile applied")
	}
	if cfg.AppArmorProfile != "" && !anyHasPrefix(insp.HostConfig.SecurityOpt, "apparmor=") {
		out = append(out, "apparmor_profile: declared but no apparmor= security profile applied")
	}
	if digest := strings.TrimPrefix(imageDigestSuffix(cfg.Image), "@"); digest != "" {
		wantID := "sha256:" + strings.TrimPrefix(digest, "sha256:")
		if insp.Image != wantID {
			out = append(out, fmt.Sprintf("image: declared digest %s, applied running image id %s", wantID, insp.Image))
		}
	}
	if cfg.MemoryLimit != "" && insp.HostConfig.Memory <= 0 {
		out = append(out, "memory_limit: declared but not applied (HostConfig.Memory <= 0)")
	}
	if cfg.CPULimit != "" && insp.HostConfig.NanoCpus <= 0 {
		out = append(out, "cpu_limit: declared but not applied (HostConfig.NanoCpus <= 0)")
	}
	if cfg.PIDsLimit > 0 && insp.HostConfig.PidsLimit != int64(cfg.PIDsLimit) {
		out = append(out, fmt.Sprintf("pids_limit: declared %d, applied %d", cfg.PIDsLimit, insp.HostConfig.PidsLimit))
	}
	// Mounted paths: every read-write mount must land at a path this
	// runner actually requested (the workspace) — a write-capable mount
	// showing up anywhere else means the applied container diverged from
	// what runArgs built. Credential mounts are always read-only (runArgs
	// appends ":ro"), so they're intentionally not required to appear here.
	for _, m := range insp.Mounts {
		if m.RW && m.Destination != "/workspace" {
			out = append(out, fmt.Sprintf("unexpected read-write mount at %s", m.Destination))
		}
	}
	return out
}

// imageDigestSuffix returns "@sha256:<hex>" when image carries a real
// digest reference, else "".
func imageDigestSuffix(image string) string {
	idx := strings.Index(image, "@sha256:")
	if idx < 0 {
		return ""
	}
	return image[idx:]
}

func inspectContainer(ctx context.Context, name string, frozen controllerenv.Frozen) (dockerInspect, bool, error) {
	if err := frozen.Validate(); err != nil {
		return dockerInspect{}, false, err
	}
	handle, err := resolveDockerHandle()
	if err != nil {
		return dockerInspect{}, false, err
	}
	defer handle.Close()
	cmd, cerr := handle.Command(ctx, "inspect", name, "--format", "{{json .}}")
	if cerr != nil {
		return dockerInspect{}, false, cerr
	}
	cmd.Env = append([]string(nil), frozen.Values...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if containerAbsent(string(out)) {
			return dockerInspect{}, true, fmt.Errorf("docker inspect %s: %v: %s", name, err, trimmed(out))
		}
		return dockerInspect{}, false, fmt.Errorf("docker inspect %s: %v: %s", name, err, trimmed(out))
	}
	var insp dockerInspect
	if err := json.Unmarshal(out, &insp); err != nil {
		return dockerInspect{}, false, fmt.Errorf("docker inspect %s: parse inspect output: %w", name, err)
	}
	return insp, false, nil
}

func stringSliceContains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func anyHasPrefix(list []string, prefix string) bool {
	for _, v := range list {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}

// appendDockerNote joins runner-observation notes the same way
// internal/runtime's appendNote does (comma-separated); duplicated here
// rather than imported since internal/runner must not depend on
// internal/runtime.
func appendDockerNote(notes, note string) string {
	if notes == "" {
		return note
	}
	return notes + "," + note
}

// Observe inspects the container's applied configuration so tests (and
// operators) can verify what actually took effect, not just what was
// requested. Session 3a surfaces output-truncation accounting and image
// provenance. Session 6 (Sol High 8/10) adds fail-closed verification for
// hardened configs: when d.Config.IsHardened(), an inspection failure or any
// applied-vs-declared mismatch returns a non-nil error so the caller
// (internal/runtime) can quarantine the run rather than approve it on an
// unverified hardened claim. Non-hardened configs keep the original
// notes-only, never-erroring behavior — ordinary jobs are unaffected.
func (d *DockerRunner) Observe(ctx context.Context, ws Workspace) (ObserveResult, error) {
	d.mu.Lock()
	trunc := d.trunc
	d.mu.Unlock()
	base := ObserveResult{
		OutputTruncated: trunc.truncated,
		BytesAccepted:   trunc.accepted,
		BytesDiscarded:  trunc.discarded,
	}
	// Image provenance: record the image reference the contract requested so a
	// hardened/digest-pinned run is auditable back to its source, even when no
	// container is left to inspect (e.g. after Destroy or in unit tests).
	if d.Config.Image != "" {
		if base.Limits == nil {
			base.Limits = map[string]string{}
		}
		base.Limits["image"] = d.Config.Image
	}
	hardened := d.Config.IsHardened()
	if d.Config.MutableTagException() {
		// Session 6 (Sol High 8): AllowMutableTag is a logged exception, never
		// silent containment — surfaced here regardless of hardened status so
		// the choice is visible in every run's notes.
		base.Notes = appendDockerNote(base.Notes, "mutable_tag_exception: "+d.Config.Image)
	}
	if ws.Container == "" {
		if hardened {
			return base, fmt.Errorf("docker hardened observation: no container recorded to inspect")
		}
		return base, nil
	}
	insp, _, err := inspectContainer(ctx, ws.Container, d.controllerEnvironment())
	if err != nil {
		base.Notes = appendDockerNote(base.Notes, "docker_inspect_failed: "+err.Error())
		if hardened {
			return base, fmt.Errorf("docker hardened observation: inspect failed: %w", err)
		}
		return base, nil
	}
	base.Notes = appendDockerNote(base.Notes, "docker_limits_observed")
	base.Limits = map[string]string{
		"memory":       strconv.FormatInt(insp.HostConfig.Memory, 10),
		"nano_cpus":    strconv.FormatInt(insp.HostConfig.NanoCpus, 10),
		"pids_limit":   strconv.FormatInt(insp.HostConfig.PidsLimit, 10),
		"network_mode": insp.HostConfig.NetworkMode,
	}
	// Preserve the image provenance set above on the freshly-allocated Limits
	// map (the inspect path replaces Limits wholesale with the hostconfig
	// readings, so re-attach the image reference operators declared).
	if d.Config.Image != "" {
		base.Limits["image"] = d.Config.Image
	}
	if !hardened {
		return base, nil
	}
	if mismatches := hardenedMismatches(d.Config, insp); len(mismatches) > 0 {
		detail := strings.Join(mismatches, "; ")
		base.Notes = appendDockerNote(base.Notes, "hardened_mismatch: "+detail)
		return base, fmt.Errorf("docker hardened observation: applied configuration does not match declared hardened config: %s", detail)
	}
	return base, nil
}

// Stop issues a graceful (then, after 5s, forceful) docker stop. Called both
// externally (recovery/abandon tooling) and internally by the executor's own
// ctx-cancellation handling.
func (d *DockerRunner) Stop(ctx context.Context, ws Workspace) error {
	if ws.Container == "" {
		return nil
	}
	handle, err := resolveDockerHandle()
	if err != nil {
		return err
	}
	defer handle.Close()
	cmd, cerr := handle.Command(ctx, "stop", "-t", "5", ws.Container)
	if cerr != nil {
		return cerr
	}
	cmd.Env = append([]string(nil), d.controllerEnvironment().Values...)
	return cmd.Run()
}

// Destroy removes the container and then the worktree, identically to
// LocalWorktreeRunner. An already-stopped-and-gone container is not an error
// (see RemoveContainer), but any other removal failure — daemon down,
// permission — is surfaced so the runtime's Session 4 outbox can retry it: a
// silently-leaked live container is exactly the vanishing failure that
// session exists to prevent.
func (d *DockerRunner) Destroy(ctx context.Context, ws Workspace, approved bool) error {
	if ws.Container != "" {
		if err := RemoveContainer(ctx, ws.Container, d.controllerEnvironment()); err != nil {
			return err
		}
	}
	return destroyWorktree(ctx, ws, approved, d.controllerEnvironment())
}

// RemoveContainer force-removes a container, tolerating only the
// already-gone case: `docker rm -f` on a missing container exits nonzero
// with "No such container", which for teardown purposes is success. Every
// other failure is returned so callers (Destroy, `gov reconcile`'s
// workspace-destroy retry) never mark a teardown done while the container
// may still be alive. Exposed so internal/runtime's reconciler and this
// runner cannot drift on what counts as tolerable.
func RemoveContainer(ctx context.Context, name string, environments ...controllerenv.Frozen) error {
	env := controllerenv.Freeze()
	if len(environments) > 0 {
		env = environments[0]
	}
	if err := env.Validate(); err != nil {
		return err
	}
	handle, berr := resolveDockerHandle()
	if berr != nil {
		return berr
	}
	defer handle.Close()
	cmd, cerr := handle.Command(ctx, "rm", "-f", name)
	if cerr != nil {
		return cerr
	}
	cmd.Env = append([]string(nil), env.Values...)
	out, err := cmd.CombinedOutput()
	if err != nil && !containerAlreadyGone(string(out)) {
		return fmt.Errorf("docker rm -f %s: %v: %s", name, err, trimmed(out))
	}
	return nil
}

// containerAlreadyGone reports whether docker rm's combined output indicates
// the container simply no longer exists (idempotent-success), as opposed to
// a real failure like an unreachable daemon or a permission error.
func containerAlreadyGone(out string) bool {
	return containerAbsent(out)
}

func containerAbsent(out string) bool {
	low := strings.ToLower(out)
	return strings.Contains(low, "no such container") || strings.Contains(low, "no such object")
}

// cappedWriter forwards at most `remaining` bytes to w, and since Session 3a
// records how many bytes were accepted vs. discarded past the cap instead of
// dropping them silently. It always reports the full length written so
// callers (os/exec's stdout/stderr plumbing) never see a short-write error.
// The mutex guards remaining/accepted/discarded because os/exec copies Stdout
// and Stderr from separate goroutines into the same writer.
type cappedWriter struct {
	mu        sync.Mutex
	w         io.Writer
	remaining int64
	accepted  int64
	discarded int64
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining <= 0 {
		c.discarded += int64(len(p))
		return len(p), nil
	}
	chunk := p
	if int64(len(chunk)) > c.remaining {
		chunk = chunk[:c.remaining]
	}
	n, err := c.w.Write(chunk)
	c.accepted += int64(n)
	c.remaining -= int64(n)
	if rem := int64(len(p)) - int64(n); rem > 0 {
		c.discarded += rem
	}
	if err != nil {
		return n, err
	}
	return len(p), nil
}
