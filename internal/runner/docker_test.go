package runner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
