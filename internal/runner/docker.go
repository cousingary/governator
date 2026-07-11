package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
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
type DockerRunner struct {
	Config contracts.DockerRunnerConfig
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
		select {
		case err := <-done:
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					return ee.ExitCode(), false, nil
				}
				return 0, false, err
			}
			return 0, false, nil
		case <-runCtx.Done():
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = d.Stop(stopCtx, ws)
			stopCancel()
			<-done
			return -1, true, runCtx.Err()
		}
	}
}

// runArgs builds the `docker run` argument list: bind-mount the workspace,
// apply resource limits, default-deny network (contract opt-in to allow),
// mount only the explicitly allowlisted credential paths (read-only), then
// the image and the backend's own bin+args as the container command.
func (d *DockerRunner) runArgs(ws Workspace, bin string, args []string) []string {
	out := []string{"run", "--name", ws.Container, "-v", ws.Path + ":/workspace", "-w", "/workspace"}
	if d.Config.MemoryLimit != "" {
		out = append(out, "--memory", d.Config.MemoryLimit)
	}
	if d.Config.CPULimit != "" {
		out = append(out, "--cpus", d.Config.CPULimit)
	}
	if d.Config.PIDsLimit > 0 {
		out = append(out, "--pids-limit", strconv.Itoa(d.Config.PIDsLimit))
	}
	if d.Config.EffectiveNetwork() != "allow" {
		out = append(out, "--network", "none")
	}
	for _, mount := range d.Config.CredentialMounts {
		out = append(out, "-v", mount+":ro")
	}
	out = append(out, d.Config.Image, bin)
	out = append(out, args...)
	return out
}

// Observe inspects the container's applied HostConfig so tests (and
// operators) can verify the resource limits actually took effect, not just
// that they were requested.
func (d *DockerRunner) Observe(ctx context.Context, ws Workspace) (ObserveResult, error) {
	if ws.Container == "" {
		return ObserveResult{}, nil
	}
	out, err := exec.CommandContext(ctx, "docker", "inspect", ws.Container, "--format", "{{json .HostConfig}}").Output()
	if err != nil {
		return ObserveResult{Notes: "docker_inspect_failed: " + err.Error()}, nil
	}
	var hc struct {
		Memory      int64  `json:"Memory"`
		NanoCpus    int64  `json:"NanoCpus"`
		PidsLimit   int64  `json:"PidsLimit"`
		NetworkMode string `json:"NetworkMode"`
	}
	if err := json.Unmarshal(out, &hc); err != nil {
		return ObserveResult{Notes: "docker_inspect_parse_failed: " + err.Error()}, nil
	}
	return ObserveResult{
		Notes: "docker_limits_observed",
		Limits: map[string]string{
			"memory":       strconv.FormatInt(hc.Memory, 10),
			"nano_cpus":    strconv.FormatInt(hc.NanoCpus, 10),
			"pids_limit":   strconv.FormatInt(hc.PidsLimit, 10),
			"network_mode": hc.NetworkMode,
		},
	}, nil
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

// cappedWriter forwards at most `remaining` bytes to w, silently discarding
// anything past the cap (plan rule: output-size cap), while always reporting
// the full length written so callers (os/exec's stdout/stderr plumbing)
// never see a short-write error.
type cappedWriter struct {
	w         io.Writer
	remaining int64
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.remaining <= 0 {
		return len(p), nil
	}
	chunk := p
	if int64(len(chunk)) > c.remaining {
		chunk = chunk[:c.remaining]
	}
	n, err := c.w.Write(chunk)
	c.remaining -= int64(n)
	if err != nil {
		return n, err
	}
	return len(p), nil
}
