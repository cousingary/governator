package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/toolregistry"
)

// dockerTestImage is a tiny, near-universally-cached image used only to
// prove the container boundary and resource limits actually apply — it does
// not need to contain any real agent CLI.
const dockerTestImage = "busybox:1.36"

func secureRunnerTempDir(t *testing.T) string {
	t.Helper()
	home := "/home/lam"
	if _, err := os.Stat(home); err != nil {
		var homeErr error
		home, homeErr = os.UserHomeDir()
		if homeErr != nil {
			t.Fatal(homeErr)
		}
	}
	dir, err := os.MkdirTemp(home, ".gov-runner-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// requireDocker skips the test cleanly whenever Docker (or the test image)
// isn't available, so CI without Docker installed — or without registry
// egress to pull dockerTestImage — never fails here. This is the "build
// tag / env check" the plan calls for, applied as a runtime capability
// check rather than a compile-time tag, so `go test ./...` still exercises
// this file's syntax/compilation everywhere.
func pinFakeDocker(t *testing.T, script string) string {
	t.Helper()
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	fakeDocker := filepath.Join(secureRunnerTempDir(t), "docker")
	if err := os.WriteFile(fakeDocker, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("docker", fakeDocker); err != nil {
		t.Fatal(err)
	}
	return fakeDocker
}

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
	}, ControllerEnvironment: controllerenv.Freeze()}
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

	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: dockerTestImage, Network: "allow"}, ControllerEnvironment: controllerenv.Freeze()}
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

// isolateConfig points config.Current() at a nonexistent config file (so no
// real operator config leaks into the test) and, when root != "", declares
// it as the sole credential root via GOV_CREDENTIAL_ROOTS. Mirrors the
// isolation pattern internal/config's own tests use.
func isolateConfig(t *testing.T, root string) {
	t.Helper()
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "nonexistent-config.yaml"))
	if root != "" {
		t.Setenv("GOV_CREDENTIAL_ROOTS", root)
	}
}

// TestDockerRunArgsCredentialMounts needs no docker daemon: runArgs is a
// pure function over the filesystem and config. Session 6 (Sol High 9)
// retired the host:container override form and requires every mount to
// resolve, under an operator-configured credential root, to a real regular
// file — so this test now mounts a real temp file rather than an arbitrary
// unchecked path, and asserts the fixed container-side destination.
func TestDockerRunArgsCredentialMounts(t *testing.T) {
	root := t.TempDir()
	netrc := filepath.Join(root, ".netrc")
	if err := os.WriteFile(netrc, []byte("machine example login x"), 0600); err != nil {
		t.Fatal(err)
	}
	isolateConfig(t, root)

	d := &DockerRunner{Config: contracts.DockerRunnerConfig{
		Image:            dockerTestImage,
		CredentialMounts: []string{netrc},
	}, CredentialRoots: []string{root}}
	args, err := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil)
	if err != nil {
		t.Fatalf("runArgs: %v", err)
	}
	want := netrc + ":" + credentialContainerRoot + "/.netrc:ro"
	found := false
	for _, a := range args {
		if a == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected mount arg %q in runArgs output:\n%s", want, strings.Join(args, "\n"))
	}
}

// TestDockerRunArgsCanonicalizesMounts pins Session 3b: the workspace bind is
// filepath.Clean'd so a trailing slash can't shift where the repo lands.
func TestDockerRunArgsCanonicalizesMounts(t *testing.T) {
	isolateConfig(t, "")
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: dockerTestImage}}
	args, err := d.runArgs(Workspace{Container: "c", Path: "/ws/"}, "bin", nil)
	if err != nil {
		t.Fatalf("runArgs: %v", err)
	}
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
func TestDockerRunArgsUsesResolvedImageID(t *testing.T) {
	isolateConfig(t, "")
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: "agent:latest"}, ResolvedImage: &ImageIdentity{ID: "sha256:" + strings.Repeat("a", 64)}}
	args, err := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil)
	if err != nil {
		t.Fatalf("runArgs: %v", err)
	}
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, d.ResolvedImage.ID) {
		t.Fatalf("expected resolved image ID %q in runArgs:\n%s", d.ResolvedImage.ID, joined)
	}
	if strings.Contains(joined, d.Config.Image+"\n") || strings.HasSuffix(joined, d.Config.Image) {
		t.Fatalf("runArgs should not pass mutable configured image %q once resolved:\n%s", d.Config.Image, joined)
	}
}

func TestDockerRunArgsHardeningFlags(t *testing.T) {
	isolateConfig(t, "")
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
	args, err := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil)
	if err != nil {
		t.Fatalf("runArgs: %v", err)
	}
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
	isolateConfig(t, "")
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: dockerTestImage}}
	args, err := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil)
	if err != nil {
		t.Fatalf("runArgs: %v", err)
	}
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

// TestCredentialMountNoRootsConfiguredRefuses is the direct regression test
// for the fail-closed default: with no credential root configured, every
// credential mount is refused, even a mount that would otherwise be a
// perfectly ordinary regular file.
func TestCredentialMountNoRootsConfiguredRefuses(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret")
	if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	isolateConfig(t, "")
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: dockerTestImage, CredentialMounts: []string{f}}}
	if _, err := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil); err == nil {
		t.Fatal("expected an error with no credential roots configured")
	}
}

// TestCredentialMountOutsideRootsRejected is Sol High 9's "restrict host
// paths to configured credential roots": a mount resolving outside every
// configured root must be refused even though it's a perfectly ordinary file.
func TestCredentialMountOutsideRootsRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	f := filepath.Join(outside, "secret")
	if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	isolateConfig(t, root)
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: dockerTestImage, CredentialMounts: []string{f}}, CredentialRoots: []string{root}}
	if _, err := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil); err == nil {
		t.Fatal("expected an error for a mount outside every configured credential root")
	}
}

// TestCredentialMountSymlinkEscapeRejected is Sol High 9's "resolve
// symlinks": a symlink inside an authorized root pointing OUTSIDE every
// root must not smuggle an arbitrary host file in as a "credential" just
// because its link lives in the right place.
func TestCredentialMountSymlinkEscapeRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	realSecret := filepath.Join(outside, "real-secret")
	if err := os.WriteFile(realSecret, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "innocuous-looking-cred")
	if err := os.Symlink(realSecret, link); err != nil {
		t.Fatal(err)
	}
	isolateConfig(t, root)
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: dockerTestImage, CredentialMounts: []string{link}}, CredentialRoots: []string{root}}
	if _, err := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil); err == nil {
		t.Fatal("expected an error for a symlink resolving outside every configured credential root")
	}
}

// TestCredentialMountDirectoryRequiresAuthorization is Sol High 9's
// "allow only regular files by default": a directory mount must be refused
// unless explicitly authorized, even though it's under a configured root.
func TestCredentialMountDirectoryRequiresAuthorization(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "aws")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	isolateConfig(t, root)

	unauthorized := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: dockerTestImage, CredentialMounts: []string{sub}}, CredentialRoots: []string{root}}
	if _, err := unauthorized.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil); err == nil {
		t.Fatal("expected an error for an unauthorized directory mount")
	}

	authorized := &DockerRunner{Config: contracts.DockerRunnerConfig{
		Image: dockerTestImage, CredentialMounts: []string{sub},
		CredentialMountAllowDirs: []string{sub},
	}, CredentialRoots: []string{root}}
	args, err := authorized.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil)
	if err != nil {
		t.Fatalf("expected an explicitly authorized directory to mount, got: %v", err)
	}
	want := sub + ":" + credentialContainerRoot + "/aws:ro"
	found := false
	for _, a := range args {
		if a == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected authorized directory mount %q in args:\n%s", want, strings.Join(args, "\n"))
	}
}

// TestCredentialMountSpecialFilesRejectedEvenIfDirAuthorized is Sol High 9's
// "reject sockets, devices, FIFOs ... unless separately authorized" read
// conservatively: unlike directories, non-regular special files have no
// legitimate "credential" use, so there is no authorization path for them —
// not even by authorizing the directory that contains them.
func TestCredentialMountSpecialFilesRejectedEvenIfDirAuthorized(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("mkfifo unavailable on this platform: %v", err)
	}
	isolateConfig(t, root)
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{
		Image: dockerTestImage, CredentialMounts: []string{fifo},
		CredentialMountAllowDirs: []string{root},
	}, CredentialRoots: []string{root}}
	if _, err := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil); err == nil {
		t.Fatal("expected a FIFO credential mount to be rejected even under an authorized directory")
	}
}

// TestCredentialMountDockerSocketRejected is the direct regression test for
// Sol High 9's explicit callout: "reject Docker/container runtime sockets."
// Refused even when it happens to live under a configured root and even
// with directory authorization on its parent — the strongest of the
// containment checks, with no escape hatch.
func TestCredentialMountDockerSocketRejected(t *testing.T) {
	root := t.TempDir()
	fakeVarRun := filepath.Join(root, "var-run")
	if err := os.Mkdir(fakeVarRun, 0700); err != nil {
		t.Fatal(err)
	}
	isolateConfig(t, root)
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{
		Image:                    dockerTestImage,
		CredentialMounts:         []string{"/var/run/docker.sock"},
		CredentialMountAllowDirs: []string{"/var/run"},
	}, CredentialRoots: []string{root}}
	if _, err := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil); err == nil {
		t.Fatal("expected the docker socket path to be rejected unconditionally")
	}
}

// TestCredentialMountBasenameCollisionRejected: two distinct host files that
// would land at the same container basename must fail closed on the
// ambiguity rather than one silently shadowing the other.
func TestCredentialMountBasenameCollisionRejected(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	fileA := filepath.Join(rootA, "cred")
	fileB := filepath.Join(rootB, "cred")
	if err := os.WriteFile(fileA, []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileB, []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}
	isolateConfig(t, rootA+string(os.PathListSeparator)+rootB)
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{
		Image: dockerTestImage, CredentialMounts: []string{fileA, fileB},
	}, CredentialRoots: []string{rootA, rootB}}
	if _, err := d.runArgs(Workspace{Container: "c", Path: "/ws"}, "bin", nil); err == nil {
		t.Fatal("expected a container-basename collision between two distinct credential mounts to error")
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

func TestContainerAlreadyGoneMatching(t *testing.T) {
	// RemoveContainer tolerates ONLY the already-gone case; everything else
	// (daemon down, permission denied) must propagate so `gov reconcile`
	// never marks a teardown done while the container may still be alive.
	if !containerAlreadyGone("Error response from daemon: No such container: gov-x") {
		t.Fatal("missing-container output must count as already gone")
	}
	if containerAlreadyGone("Cannot connect to the Docker daemon at unix:///var/run/docker.sock") {
		t.Fatal("daemon-unreachable must NOT count as already gone")
	}
	if containerAlreadyGone("permission denied while trying to connect to the Docker daemon socket") {
		t.Fatal("permission failure must NOT count as already gone")
	}
}

// hardenedTestConfig is a fully-hardened DockerRunnerConfig matching what
// dockerTestInspectMatching reports back, so tests can mutate a single field
// off this baseline to produce exactly one mismatch.
func hardenedTestConfig(digest string) contracts.DockerRunnerConfig {
	return contracts.DockerRunnerConfig{
		Image: "busybox@sha256:" + digest, User: "65532:65532",
		ReadOnlyRootfs: true, CapDropAll: true, NoNewPrivileges: true,
		MemoryLimit: "128m", CPULimit: "0.5", PIDsLimit: 64,
	}
}

func dockerTestInspectMatching(digest string) dockerInspect {
	var insp dockerInspect
	insp.Image = "sha256:" + digest
	insp.Config.User = "65532:65532"
	insp.HostConfig.NetworkMode = "none"
	insp.HostConfig.ReadonlyRootfs = true
	insp.HostConfig.CapDrop = []string{"ALL"}
	insp.HostConfig.SecurityOpt = []string{"no-new-privileges"}
	insp.HostConfig.Memory = 134217728
	insp.HostConfig.NanoCpus = 500000000
	insp.HostConfig.PidsLimit = 64
	insp.Mounts = []struct {
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	}{{Destination: "/workspace", RW: true}}
	return insp
}

// TestHardenedMismatchesCleanConfigNoMismatch is the positive control: a
// docker inspect payload matching the declared hardened config exactly must
// report zero mismatches. No daemon required — hardenedMismatches is pure.
func TestHardenedMismatchesCleanConfigNoMismatch(t *testing.T) {
	digest := strings.Repeat("a", 64)
	cfg := hardenedTestConfig(digest)
	if got := hardenedMismatches(cfg, dockerTestInspectMatching(digest)); len(got) != 0 {
		t.Fatalf("expected no mismatches for a matching inspect payload, got: %v", got)
	}
}

// TestHardenedMismatchesDetectsEachControl is the direct regression test for
// Sol High 8/10: each hardening control gets its own applied-vs-declared
// check, and a single divergence in any one of them is caught. No daemon
// required.
func TestHardenedMismatchesDetectsEachControl(t *testing.T) {
	digest := strings.Repeat("a", 64)
	cases := []struct {
		name    string
		mutate  func(*dockerInspect)
		wantSub string
	}{
		{"user mismatch", func(i *dockerInspect) { i.Config.User = "0:0" }, "user:"},
		{"network not none", func(i *dockerInspect) { i.HostConfig.NetworkMode = "bridge" }, "network:"},
		{"rootfs not readonly", func(i *dockerInspect) { i.HostConfig.ReadonlyRootfs = false }, "read_only_rootfs:"},
		{"cap drop missing ALL", func(i *dockerInspect) { i.HostConfig.CapDrop = nil }, "cap_drop_all:"},
		{"no-new-privileges missing", func(i *dockerInspect) { i.HostConfig.SecurityOpt = nil }, "no_new_privileges:"},
		{"image id mismatch", func(i *dockerInspect) { i.Image = "sha256:" + strings.Repeat("b", 64) }, "image:"},
		{"memory not applied", func(i *dockerInspect) { i.HostConfig.Memory = 0 }, "memory_limit:"},
		{"cpu not applied", func(i *dockerInspect) { i.HostConfig.NanoCpus = 0 }, "cpu_limit:"},
		{"pids limit mismatch", func(i *dockerInspect) { i.HostConfig.PidsLimit = 999 }, "pids_limit:"},
		{"unexpected rw mount", func(i *dockerInspect) {
			i.Mounts = append(i.Mounts, struct {
				Destination string `json:"Destination"`
				RW          bool   `json:"RW"`
			}{Destination: "/etc/passwd", RW: true})
		}, "unexpected read-write mount"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			insp := dockerTestInspectMatching(digest)
			c.mutate(&insp)
			got := hardenedMismatches(hardenedTestConfig(digest), insp)
			if len(got) == 0 {
				t.Fatal("expected at least one mismatch, got none")
			}
			found := false
			for _, m := range got {
				if strings.Contains(m, c.wantSub) {
					found = true
				}
			}
			if !found {
				t.Errorf("expected a mismatch containing %q, got: %v", c.wantSub, got)
			}
		})
	}
}

// TestDockerObserveHardenedNoContainerFailsClosed is the direct regression
// test for Sol High 10: a hardened config with nothing to inspect (Container
// == "") must error, not silently return a clean-looking ObserveResult.
func TestDockerObserveHardenedNoContainerFailsClosed(t *testing.T) {
	d := &DockerRunner{Config: hardenedTestConfig(strings.Repeat("a", 64))}
	if _, err := d.Observe(context.Background(), Workspace{}); err == nil {
		t.Fatal("expected an error for a hardened config with no container to inspect")
	}
}

// TestDockerObserveNonHardenedInspectFailureStaysSoft pins that Session 6's
// fail-closed behavior is scoped to hardened configs only: an ordinary
// (non-hardened) config with a bogus container name still returns a soft
// note and no error, exactly as before Session 6.
func TestDockerObserveNonHardenedInspectFailureStaysSoft(t *testing.T) {
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: dockerTestImage}}
	obs, err := d.Observe(context.Background(), Workspace{Container: "gov-nonexistent-container-xyz"})
	if err != nil {
		t.Fatalf("non-hardened config must not fail closed on inspect failure, got: %v", err)
	}
	if !strings.Contains(obs.Notes, "docker_inspect_failed") {
		t.Errorf("expected a soft inspect-failure note, got notes=%q", obs.Notes)
	}
}

// TestDockerObserveMutableTagExceptionLogged pins Session 6's replacement
// for the old AllowMutableTag containment escape: it's surfaced as a loud
// note on every Observe call, hardened or not.
func TestDockerObserveMutableTagExceptionLogged(t *testing.T) {
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: "agent:latest", AllowMutableTag: true}}
	obs, err := d.Observe(context.Background(), Workspace{})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !strings.Contains(obs.Notes, "mutable_tag_exception") {
		t.Errorf("expected mutable_tag_exception note, got notes=%q", obs.Notes)
	}
}

// dockerTestImageDigest resolves dockerTestImage's pulled digest for tests
// that need a real @sha256: reference to launch a genuinely hardened
// container. Skips (never fails) if the local image has no recorded
// RepoDigest, e.g. a locally-built image with no registry pull provenance.
func dockerTestImageDigest(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", dockerTestImage, "--format", "{{index .RepoDigests 0}}").Output()
	if err != nil {
		t.Skipf("could not resolve %s digest: %v", dockerTestImage, err)
	}
	ref := strings.TrimSpace(string(out))
	idx := strings.Index(ref, "@sha256:")
	if idx < 0 {
		t.Skipf("%s has no recorded RepoDigest, skipping", dockerTestImage)
	}
	return ref[idx+len("@sha256:"):]
}

// TestDockerObserveHardenedLiveMatchApproves is the positive end-to-end
// control for Sol High 8/10: a container actually launched with every
// hardened flag runArgs would emit passes Observe with no error.
func TestDockerExecutorTimeoutRequiresProvenContainerExtinction(t *testing.T) {
	stateDir := t.TempDir()
	stateFile := filepath.Join(stateDir, "state")
	if err := os.WriteFile(stateFile, []byte("running"), 0644); err != nil {
		t.Fatal(err)
	}
	pinFakeDocker(t, fmt.Sprintf(`#!/bin/sh
set -eu
state=$(cat %q)
cmd=${1:-}
shift || true
case "$cmd" in
  run)
    sleep 30
    ;;
  inspect)
    name=$1
    shift
    if [ "$state" = removed ]; then
      echo "Error response from daemon: No such object: $name" >&2
      exit 1
    fi
    printf '{"Image":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","State":{"Running":true,"Status":"running"}}'
    ;;
  stop)
    echo 'permission denied' >&2
    exit 1
    ;;
  rm)
    echo 'daemon unavailable' >&2
    exit 1
    ;;
  *)
    echo 'unexpected command' >&2
    exit 1
    ;;
esac
`, stateFile))
	d := &DockerRunner{Config: contracts.DockerRunnerConfig{Image: "agent:latest"}, ResolvedImage: &ImageIdentity{ID: "sha256:" + strings.Repeat("a", 64)}, ControllerEnvironment: controllerenv.Freeze()}
	execFn := d.executor(Workspace{Container: "gov-timeout-test", Path: "/ws"})
	var out bytes.Buffer
	code, timedOut, descendantsGone, err := execFn(context.Background(), "bin", nil, "/ws", &out, 50*time.Millisecond)
	if !timedOut || code != -1 {
		t.Fatalf("expected timeout with code -1, got code=%d timedOut=%v err=%v", code, timedOut, err)
	}
	if descendantsGone {
		t.Fatal("executor reported descendants gone even though fake docker inspect still reported the container running")
	}
	if err == nil || !strings.Contains(err.Error(), "docker extinction proof") {
		t.Fatalf("expected extinction-proof error, got %v", err)
	}
}

func TestDockerObserveHardenedLiveMatchApproves(t *testing.T) {
	requireDocker(t)
	digest := dockerTestImageDigest(t)
	isolateConfig(t, "")

	d := &DockerRunner{Config: hardenedTestConfig(digest)}
	ws := Workspace{Container: "gov-hardened-match-test", Path: t.TempDir()}
	t.Cleanup(func() { _ = RemoveContainer(context.Background(), ws.Container) })

	args, err := d.runArgs(ws, "sleep", []string{"30"})
	if err != nil {
		t.Fatalf("runArgs: %v", err)
	}
	// Insert -d (detached) right after "run" so the container stays alive
	// for inspection instead of blocking this test for 30s.
	createArgs := append([]string{args[0], "-d"}, args[1:]...)
	if out, err := exec.Command("docker", createArgs...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v: %s", err, out)
	}

	obs, err := d.Observe(context.Background(), ws)
	if err != nil {
		t.Fatalf("expected a genuinely hardened container to pass Observe, got: %v (notes=%q)", err, obs.Notes)
	}
}

// TestDockerObserveHardenedLiveMismatchBlocks is the negative end-to-end
// control: a real, running container that does NOT satisfy the declared
// hardened config (launched as root, no cap drop) must fail Observe.
func TestDockerObserveHardenedLiveMismatchBlocks(t *testing.T) {
	requireDocker(t)
	digest := dockerTestImageDigest(t)
	isolateConfig(t, "")

	ws := Workspace{Container: "gov-hardened-mismatch-test"}
	t.Cleanup(func() { _ = RemoveContainer(context.Background(), ws.Container) })
	if out, err := exec.Command("docker", "run", "-d", "--name", ws.Container,
		"busybox@sha256:"+digest, "sleep", "30").CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v: %s", err, out)
	}

	// Declares hardening the container above was never actually launched
	// with (no --user, no --cap-drop, no --network none).
	d := &DockerRunner{Config: hardenedTestConfig(digest)}
	if _, err := d.Observe(context.Background(), ws); err == nil {
		t.Fatal("expected Observe to block approval for a container that doesn't match its declared hardened config")
	}
}

// TestResolveImageIdentityReturnsContentAddressedID proves ResolveImageIdentity
// (Sol P1-1) reports the image's real content-addressed ID, matching what
// `docker image inspect` itself reports -- not a sentinel or the bare
// reference string.
func TestResolveImageIdentityReturnsContentAddressedID(t *testing.T) {
	requireDocker(t)
	out, err := exec.Command("docker", "image", "inspect", dockerTestImage, "--format", "{{.Id}}").Output()
	if err != nil {
		t.Fatalf("docker image inspect: %v", err)
	}
	want := strings.TrimSpace(string(out))

	got, err := ResolveImageIdentity(context.Background(), dockerTestImage)
	if err != nil {
		t.Fatalf("ResolveImageIdentity: %v", err)
	}
	if got.ID != want {
		t.Fatalf("ID = %q, want %q (from docker image inspect directly)", got.ID, want)
	}
	if !strings.HasPrefix(got.ID, "sha256:") {
		t.Fatalf("ID = %q, want a sha256: content-addressed identity", got.ID)
	}
	if got.Reference != dockerTestImage {
		t.Fatalf("Reference = %q, want %q", got.Reference, dockerTestImage)
	}
}

// TestResolveImageIdentityFailsClosedForUnknownImage proves an image
// reference that cannot be inspected (never pulled/built locally) is a hard
// error, never a sentinel value that lets a run proceed as if resolution
// quietly succeeded.
func TestResolveImageIdentityFailsClosedForUnknownImage(t *testing.T) {
	requireDocker(t)
	if _, err := ResolveImageIdentity(context.Background(), "gov-test-definitely-not-a-real-image:latest"); err == nil {
		t.Fatal("expected ResolveImageIdentity to fail closed for an unresolvable image reference, got nil error")
	}
}

// TestResolveImageIdentityDetectsRetaggedMutableTag is the direct proof of
// report P1-1's core claim: a mutable tag can be repointed at a completely
// different image between an attested run and a later replay, and the tag
// string alone never reveals this. It creates a local tag pointing at
// dockerTestImage, resolves it, retags the SAME name at a different image,
// and resolves again -- the two resolved IDs must differ even though the
// configured "image" string (the tag) never changed.
func TestResolveImageIdentityDetectsRetaggedMutableTag(t *testing.T) {
	requireDocker(t)
	if err := exec.Command("docker", "image", "inspect", "hello-world:latest").Run(); err != nil {
		t.Skip("hello-world:latest not available locally, skipping retag test")
	}
	tag := "gov-test-mutable-tag:latest"
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", tag).Run() })

	if out, err := exec.Command("docker", "tag", dockerTestImage, tag).CombinedOutput(); err != nil {
		t.Fatalf("docker tag (initial): %v: %s", err, out)
	}
	first, err := ResolveImageIdentity(context.Background(), tag)
	if err != nil {
		t.Fatalf("ResolveImageIdentity (first): %v", err)
	}

	// Repoint the exact same tag at a different image -- no change to
	// whatever "image: gov-test-mutable-tag:latest" a contract had on file.
	if out, err := exec.Command("docker", "tag", "hello-world:latest", tag).CombinedOutput(); err != nil {
		t.Fatalf("docker tag (retag): %v: %s", err, out)
	}
	second, err := ResolveImageIdentity(context.Background(), tag)
	if err != nil {
		t.Fatalf("ResolveImageIdentity (second): %v", err)
	}

	if first.ID == second.ID {
		t.Fatal("resolved image ID did not change after the tag was repointed at a different image -- replay would not detect the swap")
	}
}

// TestResolveDockerHonorsRegistryPin is Session 2 (post-v4 hardening plan
// item C): every DockerRunner call site used to hand exec.CommandContext
// the bare literal "docker", letting os/exec's own ambient PATH lookup
// resolve it -- a hostile "docker" placed earlier on Governator's own
// process PATH would run with full authority instead of the real one (and,
// since the attacker only needs to write a self-owned file somewhere on
// PATH, the registry's owner/mode hygiene checks alone would not have
// caught it -- only a pin, read before the poisoned PATH entry is ever
// consulted, closes this). This test pins docker's path in the trusted-tool
// registry, then prepends a different, hostile "docker" earlier on PATH,
// and asserts resolveDocker() still returns the pinned path.
func TestVerifyStartedContainerRejectsImageMismatch(t *testing.T) {
	pinFakeDocker(t, "#!/bin/sh\nset -eu\nif [ \"${1:-}\" = inspect ]; then\n  printf '{\"Image\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"State\":{\"Running\":true,\"Status\":\"running\"}}'\n  exit 0\nfi\nexit 1\n")
	d := &DockerRunner{ResolvedImage: &ImageIdentity{ID: "sha256:" + strings.Repeat("a", 64)}, ControllerEnvironment: controllerenv.Freeze()}
	err := d.verifyStartedContainer(context.Background(), Workspace{Container: "gov-image-mismatch"})
	if err == nil || !strings.Contains(err.Error(), "runtime image mismatch") {
		t.Fatalf("expected runtime image mismatch, got %v", err)
	}
}

func TestContainerAbsentRecognizesDockerNotFoundPhrases(t *testing.T) {
	for _, out := range []string{"Error: No such container: x", "Error response from daemon: No such object: x"} {
		if !containerAbsent(out) {
			t.Fatalf("containerAbsent(%q)=false, want true", out)
		}
	}
	if containerAbsent("permission denied") {
		t.Fatal("containerAbsent reported true for a real failure")
	}
}

func TestResolveDockerHonorsRegistryPin(t *testing.T) {
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)

	pinnedDocker := filepath.Join(secureRunnerTempDir(t), "real-docker")
	if err := os.WriteFile(pinnedDocker, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("docker", pinnedDocker); err != nil {
		t.Fatal(err)
	}

	hostileDir := t.TempDir()
	hostileDocker := filepath.Join(hostileDir, "docker")
	if err := os.WriteFile(hostileDocker, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", hostileDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	bin, err := resolveDocker()
	if err != nil {
		t.Fatalf("resolveDocker: %v", err)
	}
	if bin != pinnedDocker {
		t.Fatalf("resolveDocker returned %q, want the registry-pinned %q (ambient PATH would have resolved the hostile one first)", bin, pinnedDocker)
	}
}
