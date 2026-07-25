package runner

// v12_s5_consumed_volume_test.go holds the Sol v12 rc5 Session 5 corpus for
// P0-8 (agents/governator-sol-upgrade12-rc5-plan.md Session 5, report "P0-8:
// Docker consumed artifacts still rely on mutable host paths"). Before this
// session, the docker-backend consumed-artifact source was an ordinary
// same-UID-writable host directory bind-mounted read-only into the
// container; a same-UID sibling process (or, worse, anyone with Docker
// daemon authority) could alter the source, let the container read the
// modified bytes, then restore the original bytes before the next
// verification checkpoint. docker_consumed_volume.go replaces that host
// directory with an immutable Docker volume populated directly from sealed
// bytes via `docker cp` -- no host filesystem path is ever created for the
// artifact content.
//
// Cases 27-30 exercise ProvisionConsumedVolume/VerifyConsumedVolume through
// a fake docker CLI script (this file's v12s5DockerScript, mirroring
// v12_s4_frozen_docker_test.go's fake-docker pattern): the script backs
// "volumes" with a real local directory and shells out to the real `tar`
// binary to answer `docker cp -`'s tar-stream protocol, so the Go-side
// hashing/detection logic under test runs against genuine tar bytes with no
// live daemon required. A test manipulating that backing directory directly
// stands in for the one adversary Sol's report says structural immutability
// cannot remove at Governator's own runtime privilege level: an actor with
// independent Docker daemon authority (report: "Docker daemon authority
// must be part of the trust model").
//
// Case 31 is the real-daemon acceptance case the report's P2 companion
// finding calls for ("Docker tests need a real release host"): it runs the
// full provision/verify/mutate/detect/remove cycle against an actual
// dockerd. It skips (never fakes) on a host without a reachable daemon --
// this dev host's dockerd is not running (`docker info` refuses to
// connect), so it is expected to skip here per this plan's standing rule
// 11, authorized by the has_docker_daemon capability predicate
// (proven-absent by scripts/release.sh's capability probe) rather than
// silently vanishing from the gate's accounting.
//
// Enrolled by exact name in internal/redteam/manifest.yaml (cases 222-226).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/toolregistry"
)

// v12s5DockerScript is a fake docker CLI answering the subcommands
// ProvisionConsumedVolume/VerifyConsumedVolume/RemoveConsumedVolume issue:
// version, image inspect, volume create/rm, create (with a -v NAME:/consumed
// mount), cp (both directions of the tar-stream protocol), and rm. fakeHome
// backs every "volume" as an ordinary directory the test can reach directly
// (fakeHome/vol/<name>) to simulate an actor with independent Docker daemon
// authority mutating content out from under Governator. `docker volume
// create` on an already-existing name deliberately does NOT wipe its
// directory -- real Docker volume create is a non-destructive no-op on an
// existing volume -- so case 29 genuinely exercises ProvisionConsumedVolume's
// own pre-create removal, not an artifact of the fake.
func v12s5DockerScript(fakeHome string) string {
	return "#!/bin/sh\n" +
		"set -eu\n" +
		"FAKE_HOME='" + fakeHome + "'\n" +
		"mkdir -p \"$FAKE_HOME/vol\" \"$FAKE_HOME/ctr\"\n" +
		"case \"${1:-}\" in\n" +
		"  version)\n" +
		"    printf '{\"APIVersion\":\"1.43\",\"Version\":\"fake\",\"Os\":\"linux\",\"Arch\":\"amd64\",\"KernelVersion\":\"6.0\"}'\n" +
		"    ;;\n" +
		"  image)\n" +
		"    printf '{\"Id\":\"sha256:" + strings.Repeat("f", 64) + "\",\"RepoDigests\":[],\"Config\":{\"Entrypoint\":[],\"Cmd\":[],\"User\":\"\"}}'\n" +
		"    ;;\n" +
		"  volume)\n" +
		"    sub=\"${2:-}\"\n" +
		"    shift 2 2>/dev/null || shift $#\n" +
		"    case \"$sub\" in\n" +
		"      create)\n" +
		"        name=\"\"\n" +
		"        for a in \"$@\"; do case \"$a\" in -*) ;; *) name=\"$a\" ;; esac; done\n" +
		"        mkdir -p \"$FAKE_HOME/vol/$name\"\n" +
		"        ;;\n" +
		"      rm)\n" +
		"        for a in \"$@\"; do case \"$a\" in -*) ;; *) rm -rf \"$FAKE_HOME/vol/$a\" ;; esac; done\n" +
		"        ;;\n" +
		"    esac\n" +
		"    ;;\n" +
		"  create)\n" +
		"    shift\n" +
		"    name=\"\"; vol=\"\"; prev=\"\"\n" +
		"    for a in \"$@\"; do\n" +
		"      if [ \"$prev\" = \"--name\" ]; then name=\"$a\"; fi\n" +
		"      if [ \"$prev\" = \"-v\" ]; then vol=\"${a%%:*}\"; fi\n" +
		"      prev=\"$a\"\n" +
		"    done\n" +
		"    mkdir -p \"$FAKE_HOME/vol/$vol\"\n" +
		"    echo \"$vol\" > \"$FAKE_HOME/ctr/$name\"\n" +
		"    ;;\n" +
		"  cp)\n" +
		"    shift\n" +
		"    src=\"$1\"; dst=\"$2\"\n" +
		"    case \"$src\" in\n" +
		"      -)\n" +
		"        name=\"${dst%%:*}\"\n" +
		"        vol=$(cat \"$FAKE_HOME/ctr/$name\")\n" +
		"        mkdir -p \"$FAKE_HOME/vol/$vol\"\n" +
		"        tar -x -C \"$FAKE_HOME/vol/$vol\"\n" +
		"        ;;\n" +
		"      *)\n" +
		"        name=\"${src%%:*}\"\n" +
		"        vol=$(cat \"$FAKE_HOME/ctr/$name\")\n" +
		"        tar -c -C \"$FAKE_HOME/vol/$vol\" .\n" +
		"        ;;\n" +
		"    esac\n" +
		"    ;;\n" +
		"  rm)\n" +
		"    shift\n" +
		"    for a in \"$@\"; do case \"$a\" in -*) ;; *) rm -f \"$FAKE_HOME/ctr/$a\" ;; esac; done\n" +
		"    ;;\n" +
		"  *)\n" +
		"    exit 0\n" +
		"    ;;\n" +
		"esac\n"
}

// v12s5Setup enrolls a fresh fake docker script and resolves one
// DockerEnvironment through it, returning the environment, the frozen
// controller environment, and fakeHome for direct backing-store
// manipulation. Every case gets its own registry file and fake docker
// binary (t.TempDir()-scoped) so cases never share state.
func v12s5Setup(t *testing.T) (de *DockerEnvironment, frozen controllerenv.Frozen, fakeHome string) {
	t.Helper()
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	fakeHome = t.TempDir()
	path := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(path, []byte(v12s5DockerScript(fakeHome)), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("docker", path); err != nil {
		t.Fatal(err)
	}
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	frozen = controllerenv.Freeze()
	de, err = ResolveDockerEnvironment(context.Background(), registry, frozen)
	if err != nil {
		t.Fatalf("ResolveDockerEnvironment: %v", err)
	}
	t.Cleanup(func() { _ = de.Close() })
	return de, frozen, fakeHome
}

func v12s5Content(name, body string) ConsumedArtifactContent {
	sum := sha256.Sum256([]byte(body))
	return ConsumedArtifactContent{Name: name, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(body)), Data: []byte(body)}
}

// v12s5MutateFile overwrites an already-provisioned artifact's bytes on the
// fake volume's backing store. ProvisionConsumedVolume writes artifacts mode
// 0400 (docker_consumed_volume.go's buildConsumedArtifactTar); a real
// same-UID or daemon-authority actor can always chmod its way past that (the
// exact same posture artifacts.go's own doc comments establish for the
// legacy host-directory store this replaces), so the chmod here is the
// faithful adversary action, not a test workaround.
func v12s5MutateFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// TestV12Case27DockerVolumeMutationDuringReadDetected is corpus 27: an actor
// with independent access to the volume's backing store (standing in for
// Docker daemon authority, the one adversary structural immutability at
// Governator's own runtime privilege cannot remove) alters an artifact's
// bytes after ProvisionConsumedVolume, and VerifyConsumedVolume -- run
// exactly as a Sol10 P0-1 checkpoint would -- must detect it.
func TestV12Case27DockerVolumeMutationDuringReadDetected(t *testing.T) {
	de, frozen, fakeHome := v12s5Setup(t)
	ctx := context.Background()
	artifacts := []ConsumedArtifactContent{v12s5Content("recon.json", `{"summary":"ok"}`)}
	volumeName := ConsumedVolumeName("case27")
	if err := ProvisionConsumedVolume(ctx, de, frozen, "example/agent:latest", volumeName, artifacts); err != nil {
		t.Fatalf("ProvisionConsumedVolume: %v", err)
	}
	t.Cleanup(func() { _ = RemoveConsumedVolume(context.Background(), de, frozen, volumeName) })

	if verr := VerifyConsumedVolume(ctx, de, frozen, "example/agent:latest", volumeName, artifacts); verr != nil {
		t.Fatalf("expected the untampered volume to verify clean, got %v", verr)
	}

	target := filepath.Join(fakeHome, "vol", volumeName, "recon.json")
	v12s5MutateFile(t, target, "MUTATED-BY-DAEMON-AUTHORITY-ACTOR")
	if verr := VerifyConsumedVolume(ctx, de, frozen, "example/agent:latest", volumeName, artifacts); verr == nil {
		t.Fatal("expected VerifyConsumedVolume to detect the mutated artifact content, got nil")
	}
}

// TestV12Case28DockerVolumeMutationCaughtAtCheckpointThenRestoredVerifiesClean
// is corpus 28: mirrors Sol10 P0-1's four-checkpoint model honestly. A
// mutation IN FLIGHT at a checkpoint is always caught (this is what closes
// P0-8); a mutation that is restored before the NEXT checkpoint runs
// necessarily verifies clean again there -- a fundamental property of
// hash-based re-verification, not a new gap introduced by the volume
// mechanism, and the same limitation the pre-existing sealed-memfd and
// mode-bits-degraded verification paths already have.
func TestV12Case28DockerVolumeMutationCaughtAtCheckpointThenRestoredVerifiesClean(t *testing.T) {
	de, frozen, fakeHome := v12s5Setup(t)
	ctx := context.Background()
	original := "original-consumed-bytes"
	artifacts := []ConsumedArtifactContent{v12s5Content("recon.json", original)}
	volumeName := ConsumedVolumeName("case28")
	if err := ProvisionConsumedVolume(ctx, de, frozen, "example/agent:latest", volumeName, artifacts); err != nil {
		t.Fatalf("ProvisionConsumedVolume: %v", err)
	}
	t.Cleanup(func() { _ = RemoveConsumedVolume(context.Background(), de, frozen, volumeName) })

	target := filepath.Join(fakeHome, "vol", volumeName, "recon.json")
	v12s5MutateFile(t, target, "MUTATED-THEN-WILL-BE-RESTORED")
	if verr := VerifyConsumedVolume(ctx, de, frozen, "example/agent:latest", volumeName, artifacts); verr == nil {
		t.Fatal("expected the checkpoint during mutation to fail, got nil")
	}

	v12s5MutateFile(t, target, original)
	if verr := VerifyConsumedVolume(ctx, de, frozen, "example/agent:latest", volumeName, artifacts); verr != nil {
		t.Fatalf("expected a checkpoint after full restoration to verify clean, got %v", verr)
	}
}

// TestV12Case29PreexistingVolumeContentNotTrustedOnProvision is corpus 29
// ("Docker volume identity changes"): a volume already exists under this
// run's exact deterministic name, pre-seeded with attacker-planted content
// (a leftover from an interrupted prior attempt at the same run id, or a
// same-UID/daemon-authority actor pre-staging it), before
// ProvisionConsumedVolume is ever called. `docker volume create` on an
// existing name is a non-destructive no-op in real Docker, so this proves
// ProvisionConsumedVolume does its own explicit discard rather than
// silently trusting/reusing whatever identity that volume name already
// carried.
func TestV12Case29PreexistingVolumeContentNotTrustedOnProvision(t *testing.T) {
	de, frozen, fakeHome := v12s5Setup(t)
	ctx := context.Background()
	volumeName := ConsumedVolumeName("case29")

	planted := filepath.Join(fakeHome, "vol", volumeName)
	if err := os.MkdirAll(planted, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(planted, "attacker-planted"), []byte("evil-preexisting-content"), 0644); err != nil {
		t.Fatal(err)
	}

	artifacts := []ConsumedArtifactContent{v12s5Content("recon.json", `{"summary":"ok"}`)}
	if err := ProvisionConsumedVolume(ctx, de, frozen, "example/agent:latest", volumeName, artifacts); err != nil {
		t.Fatalf("ProvisionConsumedVolume: %v", err)
	}
	t.Cleanup(func() { _ = RemoveConsumedVolume(context.Background(), de, frozen, volumeName) })

	if verr := VerifyConsumedVolume(ctx, de, frozen, "example/agent:latest", volumeName, artifacts); verr != nil {
		t.Fatalf("expected a freshly provisioned volume to verify clean against only the legitimate artifacts, got %v", verr)
	}
	if _, err := os.Stat(filepath.Join(planted, "attacker-planted")); !os.IsNotExist(err) {
		t.Fatal("expected ProvisionConsumedVolume to discard a pre-existing volume's content rather than trust/reuse it, but the attacker-planted file survived")
	}
}

// TestV12Case30DockerVolumeContentReplacementDetected is corpus 30
// ("daemon-side volume mutation"): a coarser attack than case 27's
// single-file tamper -- the whole volume content set is replaced (a
// different file count, none of the original names present) -- proving
// VerifyConsumedVolume's entry-count/name check, not just its per-file hash
// check, closes the gap.
func TestV12Case30DockerVolumeContentReplacementDetected(t *testing.T) {
	de, frozen, fakeHome := v12s5Setup(t)
	ctx := context.Background()
	artifacts := []ConsumedArtifactContent{
		v12s5Content("recon-a.json", `{"a":1}`),
		v12s5Content("recon-b.json", `{"b":2}`),
	}
	volumeName := ConsumedVolumeName("case30")
	if err := ProvisionConsumedVolume(ctx, de, frozen, "example/agent:latest", volumeName, artifacts); err != nil {
		t.Fatalf("ProvisionConsumedVolume: %v", err)
	}
	t.Cleanup(func() { _ = RemoveConsumedVolume(context.Background(), de, frozen, volumeName) })

	volDir := filepath.Join(fakeHome, "vol", volumeName)
	if err := os.RemoveAll(volDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(volDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volDir, "recon-a.json"), []byte("REPLACED-CONTENT-SET"), 0644); err != nil {
		t.Fatal(err)
	}

	if verr := VerifyConsumedVolume(ctx, de, frozen, "example/agent:latest", volumeName, artifacts); verr == nil {
		t.Fatal("expected VerifyConsumedVolume to detect the wholesale content-set replacement, got nil")
	}
}

// TestV12Case31RealDockerDaemonConsumedArtifactVolumeRoundTrip is corpus 31
// (report P2 "Docker tests need a real release host"): the real-daemon
// acceptance test for the whole Sol12 P0-8 mechanism -- provision, verify
// clean, mutate for real through a live throwaway container, verify the
// mutation is detected, then remove. Skips (never fakes) when this host has
// no reachable Docker daemon, per standing rule 11; the skip is authorized
// via the has_docker_daemon capability predicate (internal/redteam/manifest.yaml,
// scripts/release.sh's capability probe), never left unexplained.
func TestV12Case31RealDockerDaemonConsumedArtifactVolumeRoundTrip(t *testing.T) {
	// Skip text must contain the manifest's allowed_skip reason verbatim
	// (internal/redteam/manifest.yaml case 226, predicate has_docker_daemon)
	// -- the gate matches the observed skip text against that reason string,
	// mirroring the has_systemd_user cases' exact idiom
	// (internal/containment/descendants_test.go). requireDocker's own
	// generic message does not contain it, so this case checks daemon
	// reachability directly instead of delegating to that shared helper.
	if err := CheckDockerAvailable(); err != nil {
		t.Skipf("no reachable docker daemon on this host: %v", err)
	}
	requireDocker(t)
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		t.Fatalf("docker on PATH: %v", err)
	}
	if _, err := toolregistry.Enroll("docker", dockerPath); err != nil {
		t.Fatal(err)
	}
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	frozen := controllerenv.Freeze()
	ctx := context.Background()
	de, err := ResolveDockerEnvironment(ctx, registry, frozen)
	if err != nil {
		t.Fatalf("ResolveDockerEnvironment: %v", err)
	}
	defer func() { _ = de.Close() }()

	artifacts := []ConsumedArtifactContent{v12s5Content("recon.json", `{"summary":"real-daemon-ok"}`)}
	volumeName := ConsumedVolumeName("case31-real")
	if err := ProvisionConsumedVolume(ctx, de, frozen, dockerTestImage, volumeName, artifacts); err != nil {
		t.Fatalf("ProvisionConsumedVolume against a real daemon: %v", err)
	}
	defer func() { _ = RemoveConsumedVolume(context.Background(), de, frozen, volumeName) }()

	if verr := VerifyConsumedVolume(ctx, de, frozen, dockerTestImage, volumeName, artifacts); verr != nil {
		t.Fatalf("expected the untampered real volume to verify clean, got %v", verr)
	}

	// Mutate through a real, live, throwaway container mounting the same
	// volume read-write -- standing in for genuine Docker daemon authority,
	// not the test's own fake filesystem.
	mutator := volumeName + "-real-mutator"
	mutateCmd, cerr := de.CLI.Command(ctx, "run", "--rm", "--name", mutator, "-v", volumeName+":/consumed", dockerTestImage,
		"sh", "-c", "printf 'MUTATED-BY-A-REAL-CONTAINER' > /consumed/recon.json")
	if cerr != nil {
		t.Fatal(cerr)
	}
	mutateCmd.Env = append([]string(nil), frozen.Values...)
	if out, err := mutateCmd.CombinedOutput(); err != nil {
		t.Fatalf("real-daemon mutation container: %v: %s", err, out)
	}

	if verr := VerifyConsumedVolume(ctx, de, frozen, dockerTestImage, volumeName, artifacts); verr == nil {
		t.Fatal("expected VerifyConsumedVolume to detect a real-daemon mutation, got nil")
	}
}
