//go:build redteam

package redteam

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/runner"
	govruntime "github.com/cousingary/governator/internal/runtime"
)

// dockerFakeBackendScript is a governed-backend stand-in baked into the
// images dockerBuildFakeBackendImage produces: it ignores every CLI flag the
// Claude adapter projects (-p, --output-format, --add-dir, etc.) and just
// declares output/result.txt as the sole intended change, exactly like this
// corpus's host-side fakeBackend/standardBackendBody fixtures.
const dockerFakeBackendScript = `#!/bin/sh
set -eu
mkdir -p output
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.10}\n'
`

var (
	dockerBaseImage = "busybox:1.36"
	dockerBuildOnce sync.Map // tag string -> *sync.Once, so each distinct tag is built exactly once per test process
)

// requireDockerRedteam skips cleanly when Docker (or its base test image)
// isn't available, mirroring internal/runner's requireDocker -- this corpus
// must not fail in an environment without Docker or registry egress.
func requireDockerRedteam(t *testing.T) {
	t.Helper()
	if err := runner.CheckDockerAvailable(); err != nil {
		t.Skipf("docker unavailable, skipping: %v", err)
	}
	if err := exec.Command("docker", "image", "inspect", dockerBaseImage).Run(); err == nil {
		return
	}
	pullCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(pullCtx, "docker", "pull", dockerBaseImage).CombinedOutput(); err != nil {
		t.Skipf("docker test image %s unavailable and could not be pulled, skipping: %v: %s", dockerBaseImage, err, out)
	}
}

// dockerBuildFakeBackendImage builds (once per distinct tag per test
// process) a tiny image on top of dockerBaseImage with dockerFakeBackendScript
// baked in at /usr/local/bin/claude, and returns the tag. variant lets a test
// bake in a DIFFERENT script body for a second, distinguishable image.
func dockerBuildFakeBackendImage(t *testing.T, tag, script string) {
	t.Helper()
	onceIface, _ := dockerBuildOnce.LoadOrStore(tag, &sync.Once{})
	once := onceIface.(*sync.Once)
	var buildErr error
	once.Do(func() {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "claude"), []byte(script), 0755); err != nil {
			buildErr = err
			return
		}
		dockerfile := "FROM " + dockerBaseImage + "\nCOPY claude /usr/local/bin/claude\nRUN chmod +x /usr/local/bin/claude\n"
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0644); err != nil {
			buildErr = err
			return
		}
		buildCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(buildCtx, "docker", "build", "-t", tag, dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("docker build %s: %w: %s", tag, err, out)
		}
	})
	if buildErr != nil {
		t.Fatalf("build fake backend image %s: %v", tag, buildErr)
	}
}

// dockerContract is baseContract with an explicit docker runner pointed at
// image, so a redteam contract exercises DockerRunner instead of
// LocalWorktreeRunner. User pins the container process to this host
// process's own UID/GID (busybox runs as root by default) so files the fake
// backend writes into the bind-mounted worktree are host-owned -- without
// this, t.TempDir()'s cleanup can't remove root-owned output it created.
func dockerContract(root, image string) contracts.Contract {
	c := baseContract(root)
	c.Runner = "docker"
	c.Docker = &contracts.DockerRunnerConfig{
		Image:   image,
		Network: "deny",
		User:    fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
	}
	return c
}

// setUpDockerHostFallback arranges for the bare backend name "claude" to
// resolve, via PATH, to a throwaway HOST-side placeholder script -- so
// agents.ResolveHandle's host-side resolution (which still runs
// unconditionally regardless of runner kind) succeeds instead of failing
// closed on a path that only exists inside the container. The placeholder's
// content is never actually executed for a docker-runner contract: Docker
// runs pass the bare configured name through to `docker run <image> claude
// <args>`, which the CONTAINER's own PATH resolves to whatever script
// dockerBuildFakeBackendImage baked in at /usr/local/bin/claude -- a
// completely separate binary from this host-side placeholder, by design
// (this decoupling IS what report attack 12 exercises).
func setUpDockerHostFallback(t *testing.T) {
	t.Helper()
	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "claude"), []byte("#!/bin/sh\necho host-side-placeholder-never-executed-for-docker-runs\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", hostDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOV_CLAUDE_BIN", "claude")
}

// runGovernedDocker runs c (a docker-runner contract) through the real
// runtime engine, mirroring runGoverned but without forcing GOV_CLAUDE_BIN to
// an absolute host path -- callers must call setUpDockerHostFallback first.
func runGovernedDocker(t *testing.T, home string, c contracts.Contract) govruntime.RunRecord {
	t.Helper()
	t.Setenv("GOV_HOME", home)
	rec, err := govruntime.New().RunWithAutoRepair(context.Background(), c)
	if err != nil {
		t.Fatalf("RunWithAutoRepair: %v", err)
	}
	return rec
}
