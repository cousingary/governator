package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
)

// CheckDockerAvailable reports whether a working `docker` CLI and a
// reachable daemon exist, so New can fail closed: a contract that asks for
// runner: docker without a usable Docker install must error, never silently
// fall back to LocalWorktreeRunner.
func CheckDockerAvailable() error {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker binary not found on PATH: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, bin, "info").CombinedOutput(); err != nil {
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

	mu    sync.Mutex
	trunc truncationStats
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
// loopback via docker --add-host when DenyMetadataAndLocalNet is set under a
// network: allow config. Raw-IP access (e.g. dialling 169.254.169.254
// directly) is not blocked by /etc/hosts; the safe default remains network:
// deny. These entries cover name-based lookups, which is all the CLI can do.
var metadataSinkholeHosts = []string{
	"metadata.google.internal", // GCP
	"metadata",                 // GCP alias
	"metadata.azure.com",       // Azure
}

func (d *DockerRunner) Prepare(ctx context.Context, req PrepareRequest) (Workspace, error) {
	ws, err := prepareWorktree(ctx, req.Root, req.Home, req.ID, req.Git)
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
	return func(ctx context.Context, bin string, args []string, workdir string, out io.Writer, timeout time.Duration) (int, bool, error) {
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		dockerArgs := d.runArgs(ws, bin, args)
		cmd := exec.CommandContext(runCtx, "docker", dockerArgs...)
		capped := &cappedWriter{w: out, remaining: d.Config.EffectiveOutputCapBytes()}
		cmd.Stdout, cmd.Stderr = capped, capped
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
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = d.Stop(stopCtx, ws)
			stopCancel()
			<-done
			code = -1
			timedOut = true
			runErr = runCtx.Err()
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
		return code, timedOut, runErr
	}
}

// runArgs builds the `docker run` argument list: bind-mount the workspace,
// apply resource limits, default-deny network (contract opt-in to allow),
// mount only the explicitly allowlisted credential paths (read-only), then
// the image and the backend's own bin+args as the container command. Session
// 3 (Phase 2) appends the hardening controls from Config when set.
func (d *DockerRunner) runArgs(ws Workspace, bin string, args []string) []string {
	// Canonicalize the workspace bind so a trailing slash or ../ noise in the
	// worktree path can't shift where the repo lands inside the container.
	wsPath := filepath.Clean(ws.Path)
	out := []string{"run", "--name", ws.Container, "-v", wsPath + ":/workspace", "-w", "/workspace"}
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
	} else if d.Config.DenyMetadataAndLocalNet {
		for _, host := range metadataSinkholeHosts {
			out = append(out, "--add-host", host+":127.0.0.1")
		}
	}
	for _, mount := range d.Config.CredentialMounts {
		// canonicalMount cleans each side so a relative segment or trailing
		// slash can't point the bind elsewhere than validation intended; a
		// bare host path (the form contract validation blesses) still mounts
		// at the same path inside the container.
		out = append(out, "-v", canonicalMount(mount)+":ro")
	}
	out = append(out, d.Config.Image, bin)
	out = append(out, args...)
	return out
}

// canonicalMount resolves a credential mount to a canonical host:container
// pair, filepath.Clean-ing each side. A bare host path (the only form contract
// validation blesses) mounts at the same path inside the container; a
// host:container pair passes through with both sides cleaned.
func canonicalMount(mount string) string {
	if !strings.Contains(mount, ":") {
		cleaned := filepath.Clean(mount)
		return cleaned + ":" + cleaned
	}
	parts := strings.SplitN(mount, ":", 2)
	return filepath.Clean(parts[0]) + ":" + filepath.Clean(parts[1])
}

// Observe inspects the container's applied HostConfig so tests (and
// operators) can verify the resource limits actually took effect, not just
// that they were requested. Session 3 also surfaces output-truncation
// accounting (kept vs. discarded bytes) gathered during Launch, and records
// image provenance so a "hardened" run can be tied back to the exact image.
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
	if ws.Container == "" {
		return base, nil
	}
	out, err := exec.CommandContext(ctx, "docker", "inspect", ws.Container, "--format", "{{json .HostConfig}}").Output()
	if err != nil {
		base.Notes = "docker_inspect_failed: " + err.Error()
		return base, nil
	}
	var hc struct {
		Memory      int64  `json:"Memory"`
		NanoCpus    int64  `json:"NanoCpus"`
		PidsLimit   int64  `json:"PidsLimit"`
		NetworkMode string `json:"NetworkMode"`
	}
	if err := json.Unmarshal(out, &hc); err != nil {
		base.Notes = "docker_inspect_parse_failed: " + err.Error()
		return base, nil
	}
	base.Notes = "docker_limits_observed"
	base.Limits = map[string]string{
		"memory":       strconv.FormatInt(hc.Memory, 10),
		"nano_cpus":    strconv.FormatInt(hc.NanoCpus, 10),
		"pids_limit":   strconv.FormatInt(hc.PidsLimit, 10),
		"network_mode": hc.NetworkMode,
	}
	// Preserve the image provenance set above on the freshly-allocated Limits
	// map (the inspect path replaces Limits wholesale with the hostconfig
	// readings, so re-attach the image reference operators declared).
	if d.Config.Image != "" {
		base.Limits["image"] = d.Config.Image
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
	return exec.CommandContext(ctx, "docker", "stop", "-t", "5", ws.Container).Run()
}

// Destroy removes the container (best-effort — an already-stopped-and-gone
// container is not an error) and then the worktree, identically to
// LocalWorktreeRunner.
func (d *DockerRunner) Destroy(ctx context.Context, ws Workspace, approved bool) error {
	if ws.Container != "" {
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", ws.Container).Run()
	}
	return destroyWorktree(ctx, ws, approved)
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
