package runner

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
)

// dockerTestImage is a tiny, near-universally-cached image used only to
// prove the container boundary and resource limits actually apply — it does
// not need to contain any real agent CLI.
const dockerTestImage = "busybox:1.36"

// requireDocker skips the test cleanly whenever Docker (or the test image)
// isn't available, so CI without Docker installed — or without registry
// egress to pull dockerTestImage — never fails here. This is the "build
// tag / env check" the plan calls for, applied as a runtime capability
// check rather than a compile-time tag, so `go test ./...` still exercises
// this file's syntax/compilation everywhere.
func requireDocker(t *testing.T) {
	t.Helper()
	if err := CheckDockerAvailable(); err != nil {
		t.Skipf("docker unavailable, skipping: %v", err)
	}
	if err := exec.Command("docker", "image", "inspect", dockerTestImage).Run(); err == nil {
		return
	}
	pullCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(pullCtx, "docker", "pull", dockerTestImage).CombinedOutput(); err != nil {
		t.Skipf("docker test image %s unavailable and could not be pulled, skipping: %v: %s", dockerTestImage, err, out)
	}
}

func TestDockerRunnerLifecycleAndResourceLimits(t *testing.T) {
	requireDocker(t)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	ctx := context.Background()

	d := &DockerRunner{Config: contracts.DockerRunnerConfig{
		Image:       dockerTestImage,
		MemoryLimit: "128m",
		CPULimit:    "0.5",
		PIDsLimit:   64,
		Network:     "deny",
	}}
	t.Cleanup(func() {
		ws := Workspace{Container: "gov-docker-test"}
		_ = d.Destroy(context.Background(), ws, true)
	})

	ws, err := d.Prepare(ctx, PrepareRequest{Root: root, Home: home, ID: "docker-test", Git: false})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if ws.Container == "" {
		t.Fatalf("docker workspace must carry a container name: %+v", ws)
	}

	res, err := d.Launch(ctx, ws, LaunchRequest{
		Agent:   fakeAgent{bin: "ls", args: []string{"/workspace"}},
		Request: agents.Request{Workdir: ws.Path, Timeout: 30 * time.Second},
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Launch: res=%+v err=%v", res, err)
	}

	obs, err := d.Observe(ctx, ws)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.Limits["memory"] != "134217728" { // 128m in bytes
		t.Errorf("memory limit not applied: got %q", obs.Limits["memory"])
	}
	if obs.Limits["pids_limit"] != "64" {
		t.Errorf("pids limit not applied: got %q", obs.Limits["pids_limit"])
	}
	if obs.Limits["network_mode"] != "none" {
		t.Errorf("network policy not applied: got %q, want none (default deny)", obs.Limits["network_mode"])
	}

	if err := d.Destroy(ctx, ws, true); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := os.Stat(ws.Path); !os.IsNotExist(err) {
		t.Fatalf("workspace still exists after Destroy: %v", err)
	}
	if out, err := exec.Command("docker", "inspect", ws.Container).CombinedOutput(); err == nil {
		t.Fatalf("container %s should have been removed by Destroy: %s", ws.Container, out)
	}
}

// TestDockerRunnerNetworkAllowOptIn pins the plan rule: network is deny by
// default, but a contract may explicitly opt in.
func TestDockerRunnerNetworkAllowOptIn(t *testing.T) {
	requireDocker(t)

	root := t.TempDir()
	home := t.TempDir()
	ctx := context.Background()

	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: dockerTestImage, Network: "allow"}}
	ws, err := d.Prepare(ctx, PrepareRequest{Root: root, Home: home, ID: "docker-test-net", Git: false})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = d.Destroy(context.Background(), ws, true) }()

	res, err := d.Launch(ctx, ws, LaunchRequest{
		Agent:   fakeAgent{bin: "true"},
		Request: agents.Request{Workdir: ws.Path, Timeout: 30 * time.Second},
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Launch: res=%+v err=%v", res, err)
	}
	obs, err := d.Observe(ctx, ws)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.Limits["network_mode"] == "none" {
		t.Errorf("network: allow should not apply --network none, got %q", obs.Limits["network_mode"])
	}
}

// TestDockerRunArgsCredentialMounts needs no docker daemon: runArgs is a
// pure function. A bare host path (the only form contract validation
// requires) must become host:host:ro — appending ":ro" directly would hand
// docker "ro" as the container path and fail every bare-path mount at
// launch. A host:container pair passes through with ":ro" appended.
func TestDockerRunArgsCredentialMounts(t *testing.T) {
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{
		Image:            dockerTestImage,
		CredentialMounts: []string{"/host/.netrc", "/host/creds:/root/creds"},
	}}
	args := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil)
	joined := ""
	for _, a := range args {
		joined += a + "\n"
	}
	for _, want := range []string{"/host/.netrc:/host/.netrc:ro", "/host/creds:/root/creds:ro"} {
		found := false
		for _, a := range args {
			if a == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected mount arg %q in runArgs output:\n%s", want, joined)
		}
	}
}

// TestDockerRunArgsCanonicalizesMounts pins Session 3b: mount paths are
// filepath.Clean'd so a relative segment or trailing slash can't point the
// bind elsewhere than validation intended. No daemon required.
func TestDockerRunArgsCanonicalizesMounts(t *testing.T) {
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{
		Image:            dockerTestImage,
		CredentialMounts: []string{"/host/../host/.netrc", "/host/creds/:/root/creds/"},
	}}
	args := d.runArgs(Workspace{Container: "c", Path: "/ws/"}, "bin", nil)
	want := map[string]bool{
		"/host/.netrc:/host/.netrc:ro": true,
		"/host/creds:/root/creds:ro":   true,
	}
	for _, a := range args {
		if want[a] {
			delete(want, a)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing canonicalized mount args %v in: %v", want, args)
	}
	// Workspace bind is also canonicalized (trailing slash dropped).
	foundWS := false
	for _, a := range args {
		if a == "/ws:/workspace" {
			foundWS = true
		}
	}
	if !foundWS {
		t.Errorf("workspace bind not canonicalized, got args: %v", args)
	}
}

// TestDockerRunArgsHardeningFlags pins Session 3b: each hardened control maps
// to the expected docker flag, and absent controls produce no flag (so prior
// job YAML stays byte-identical). No daemon required.
func TestDockerRunArgsHardeningFlags(t *testing.T) {
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{
		Image:                   "img@sha256:" + strings.Repeat("a", 64),
		User:                    "65532:65532",
		ReadOnlyRootfs:          true,
		CapDropAll:              true,
		NoNewPrivileges:         true,
		SeccompProfile:          "/etc/docker/seccomp.json",
		AppArmorProfile:         "governator",
		Tmpfs:                   []string{"/tmp", "/run"},
		Network:                 "allow",
		DenyMetadataAndLocalNet: true,
	}}
	args := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil)
	joined := strings.Join(args, "\n")
	wants := []string{
		"--user", "65532:65532",
		"--read-only",
		"--cap-drop=ALL",
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=/etc/docker/seccomp.json",
		"--security-opt", "apparmor=governator",
		"--tmpfs", "/tmp",
		"--tmpfs", "/run",
		"--add-host", "metadata.google.internal:127.0.0.1",
		"--add-host", "metadata:127.0.0.1",
		"--add-host", "metadata.azure.com:127.0.0.1",
	}
	for _, w := range wants {
		if !strings.Contains(joined, "\n"+w) && !strings.HasPrefix(joined, w) {
			t.Errorf("expected %q in runArgs:\n%s", w, joined)
		}
	}
	// network: allow must NOT emit --network none when metadata denial is on.
	if strings.Contains(joined, "--network") {
		t.Errorf("network: allow with no --network none expected, got:\n%s", joined)
	}
}

// TestDockerRunArgsDefaultDenyNoHardening pins that an ordinary config
// (no hardening fields) produces args with none of the new flags — the
// regression guard for "prior job YAML stays byte-identical."
func TestDockerRunArgsDefaultDenyNoHardening(t *testing.T) {
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: dockerTestImage}}
	args := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil)
	joined := strings.Join(args, "\n")
	for _, forbidden := range []string{"--read-only", "--cap-drop", "--user", "--tmpfs", "no-new-privileges", "seccomp", "apparmor", "--add-host"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("plain config must not emit %q, got:\n%s", forbidden, joined)
		}
	}
	if !strings.Contains(joined, "--network") {
		t.Errorf("plain config must default-deny via --network none, got:\n%s", joined)
	}
}

// TestCappedWriterAccounting pins Session 3a: truncation is no longer silent.
// Under-cap writes are fully accepted; over-cap writes split into accepted +
// discarded exactly; the exact-cap boundary discards nothing.
func TestCappedWriterAccounting(t *testing.T) {
	t.Run("under cap", func(t *testing.T) {
		var buf bytes.Buffer
		c := &cappedWriter{w: &buf, remaining: 100}
		n, err := c.Write([]byte("hello"))
		if err != nil || n != 5 {
			t.Fatalf("Write: n=%d err=%v", n, err)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.accepted != 5 || c.discarded != 0 {
			t.Fatalf("accepted=%d discarded=%d, want 5/0", c.accepted, c.discarded)
		}
	})

	t.Run("over cap discards the tail", func(t *testing.T) {
		var buf bytes.Buffer
		c := &cappedWriter{w: &buf, remaining: 3}
		// First write consumes the whole cap; second is entirely discarded.
		c.Write([]byte("abc"))
		n, _ := c.Write([]byte("DEFGH"))
		if n != 5 {
			t.Fatalf("Write must report full length 5 (no short-write), got %d", n)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.accepted != 3 || c.discarded != 5 {
			t.Fatalf("accepted=%d discarded=%d, want 3/5", c.accepted, c.discarded)
		}
		if buf.String() != "abc" {
			t.Fatalf("buffer=%q, want \"abc\"", buf.String())
		}
	})

	t.Run("exact boundary discards nothing", func(t *testing.T) {
		var buf bytes.Buffer
		c := &cappedWriter{w: &buf, remaining: 4}
		c.Write([]byte("abcd"))
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.accepted != 4 || c.discarded != 0 {
			t.Fatalf("accepted=%d discarded=%d, want 4/0", c.accepted, c.discarded)
		}
	})
}

// TestDockerObserveSurfacesTruncationAndProvenance pins Session 3a/3b: Observe
// reports the truncation tally stashed during Launch and records image
// provenance — without needing a live container (the truncation path is
// exercised by setting the stats directly, exactly as Launch would).
func TestDockerObserveSurfacesTruncationAndProvenance(t *testing.T) {
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: "img@sha256:abc"}}
	d.mu.Lock()
	d.trunc = truncationStats{accepted: 100, discarded: 50, truncated: true}
	d.mu.Unlock()

	obs, err := d.Observe(context.Background(), Workspace{})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !obs.OutputTruncated || obs.BytesAccepted != 100 || obs.BytesDiscarded != 50 {
		t.Fatalf("truncation not surfaced: %+v", obs)
	}
	if obs.Limits["image"] != "img@sha256:abc" {
		t.Errorf("image provenance not recorded: got %q", obs.Limits["image"])
	}
}

// TestDockerObserveNoTruncationByDefault pins the zero state: a run that did
// not overflow the cap reports no truncation.
func TestDockerObserveNoTruncationByDefault(t *testing.T) {
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: dockerTestImage}}
	obs, err := d.Observe(context.Background(), Workspace{})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.OutputTruncated || obs.BytesAccepted != 0 || obs.BytesDiscarded != 0 {
		t.Fatalf("fresh runner must report no truncation, got %+v", obs)
	}
}
