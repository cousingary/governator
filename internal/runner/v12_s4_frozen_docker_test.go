package runner

// v12_s4_frozen_docker_test.go holds the Sol v12 rc5 Session 4 corpus for
// P0-7 (agents/governator-sol-upgrade12-rc5-plan.md Session 4, report
// "Docker CLI identity changes during the transaction"). ResolveDockerEnvironment
// resolves ONE frozen DockerEnvironment (CLI handle, CLI identity, daemon
// identity, endpoint) before replay, and every later docker operation for a
// governed run's whole transaction -- inspect, launch, extinction -- must
// reuse that exact object rather than re-resolving per operation. These
// cases prove a same-UID docker registry rotation mid-transaction, at every
// lifecycle boundary the report names, has no effect on a DockerEnvironment
// already held. No live daemon is required: a fake docker script (this
// package's existing pinFakeDocker pattern) answers `docker version`,
// `docker image inspect`, and `docker rm -f`. Enrolled by exact name in
// internal/redteam/manifest.yaml (cases 219-221).

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/toolregistry"
)

// v12s4DockerScript is a fake docker CLI that answers the three subcommands
// ResolveDockerEnvironment/InspectImage/removeContainerWith actually issue.
// marker distinguishes which physical script instance ran: it is folded
// into the reported server version (so InspectImage's daemon-identity-free
// path doesn't need it) and, for "rm", appended to a marker file so a
// same-UID rotation's *effect* (or lack of one) is directly observable.
func v12s4DockerScript(marker, imageID, rmMarkerFile string) string {
	return "#!/bin/sh\nset -eu\ncase \"${1:-}\" in\n" +
		"  version)\n    printf '{\"APIVersion\":\"1.43\",\"Version\":\"" + marker + "\",\"Os\":\"linux\",\"Arch\":\"amd64\",\"KernelVersion\":\"6.0\"}'\n    ;;\n" +
		"  image)\n    printf '{\"Id\":\"sha256:" + imageID + "\",\"RepoDigests\":[],\"Config\":{\"Entrypoint\":[],\"Cmd\":[],\"User\":\"\"}}'\n    ;;\n" +
		"  rm)\n    printf '" + marker + "' >> " + rmMarkerFile + "\n    ;;\n" +
		"  *)\n    exit 0\n    ;;\n" +
		"esac\n"
}

// v12s4EnrollFakeDockerAt pins a fake docker script at a fresh path and
// (re-)enrolls "docker" to point at it, returning the path.
func v12s4EnrollFakeDockerAt(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("docker", path); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestV12Case24DockerCLIRotatesBetweenInspectAndLaunchHasNoEffect is corpus
// 24. It resolves one DockerEnvironment against fake docker "A", rotates the
// registry's docker entry to fake docker "B" (proving the rotation itself
// took effect via a fresh, independent resolve), then performs a SECOND
// image-inspect through the already-held DockerEnvironment -- standing in
// for the launch-adjacent inspect a real transaction performs -- and asserts
// it still executed through "A", never "B".
func TestV12Case24DockerCLIRotatesBetweenInspectAndLaunchHasNoEffect(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("frozen Docker CLI handles require Linux sealed launch")
	}
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	imageA := strings.Repeat("a", 64)
	imageB := strings.Repeat("b", 64)
	rmMarker := filepath.Join(t.TempDir(), "rm-marker")
	pathA := v12s4EnrollFakeDockerAt(t, v12s4DockerScript("A", imageA, rmMarker))

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
	if de.CLIIdentity.CanonicalPath != pathA {
		t.Fatalf("resolved CLI identity %q, want %q", de.CLIIdentity.CanonicalPath, pathA)
	}

	firstInsp, err := de.InspectImage(ctx, "example/agent:latest", frozen)
	if err != nil {
		t.Fatalf("InspectImage (pre-rotation): %v", err)
	}
	if firstInsp.ID != "sha256:"+imageA {
		t.Fatalf("pre-rotation inspect ID = %q, want the fake-docker-A image", firstInsp.ID)
	}

	// Same-UID rotation between "inspect" and "launch".
	pathB := v12s4EnrollFakeDockerAt(t, v12s4DockerScript("B", imageB, rmMarker))
	reloaded, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	freshHandle, err := reloaded.ResolveHandle("docker", "docker", toolregistry.KindTrustedController)
	if err != nil {
		t.Fatal(err)
	}
	if freshHandle.Identity.CanonicalPath != pathB {
		freshHandle.Close()
		t.Fatalf("test bug: rotation did not take effect, a fresh resolve got %q, want %q", freshHandle.Identity.CanonicalPath, pathB)
	}
	freshHandle.Close()

	secondInsp, err := de.InspectImage(ctx, "example/agent:latest", frozen)
	if err != nil {
		t.Fatalf("InspectImage (post-rotation, frozen DockerEnvironment): %v", err)
	}
	if secondInsp.ID != "sha256:"+imageA {
		t.Fatalf("post-rotation inspect through the already-frozen DockerEnvironment returned %q, want the ORIGINAL fake-docker-A image (%q) -- a mid-transaction docker registry rotation between inspect and launch must have no effect", secondInsp.ID, "sha256:"+imageA)
	}
}

// TestV12Case25DockerCLIRotatesBetweenLaunchAndExtinctionHasNoEffect is
// corpus 25: the same property at the launch->extinction boundary.
// removeContainerWith (the primitive Destroy/forceStopAndRemove use) is
// invoked through the frozen DockerEnvironment's CLI handle after a
// same-UID rotation, and must still execute through the ORIGINAL binary.
func TestV12Case25DockerCLIRotatesBetweenLaunchAndExtinctionHasNoEffect(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("frozen Docker CLI handles require Linux sealed launch")
	}
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	rmMarkerA := filepath.Join(t.TempDir(), "rm-marker-a")
	rmMarkerB := filepath.Join(t.TempDir(), "rm-marker-b")
	v12s4EnrollFakeDockerAt(t, v12s4DockerScript("A", strings.Repeat("a", 64), rmMarkerA))

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

	// Same-UID rotation between "launch" and "extinction": docker B writes
	// its rm marker to a DIFFERENT file, so which physical binary actually
	// ran is unambiguous from the filesystem afterward.
	v12s4EnrollFakeDockerAt(t, v12s4DockerScript("B", strings.Repeat("b", 64), rmMarkerB))
	reloaded, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	rotatedIdentity, rerr := reloaded.Resolve("docker", "docker")
	if rerr != nil {
		t.Fatalf("test bug: resolve rotated docker: %v", rerr)
	}
	if rotatedIdentity.CanonicalPath == de.CLIIdentity.CanonicalPath {
		t.Fatal("test bug: rotation did not take effect")
	}

	if err := removeContainerWith(ctx, "v12-case25-container", frozen, de.CLI); err != nil {
		t.Fatalf("removeContainerWith through the frozen DockerEnvironment after rotation: %v", err)
	}
	if _, err := os.Stat(rmMarkerB); err == nil {
		t.Fatal("extinction ran through the ROTATED docker binary (marker B was written) -- a mid-transaction rotation between launch and extinction must have no effect on the frozen DockerEnvironment's CLI handle")
	}
	if _, err := os.Stat(rmMarkerA); err != nil {
		t.Fatalf("extinction did not run through the original docker binary as expected: %v", err)
	}
}

// TestV12Case26DockerDaemonEndpointChangeDuringRunHasNoEffect is corpus 26:
// the daemon endpoint (and self-reported identity) DockerEnvironment
// captures at resolution time must stay bound into replay identity even if
// the ambient DOCKER_HOST changes mid-transaction -- neither is re-derived
// by any later docker operation the frozen environment performs.
func TestV12Case26DockerDaemonEndpointChangeDuringRunHasNoEffect(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("frozen Docker CLI handles require Linux sealed launch")
	}
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	imageA := strings.Repeat("a", 64)
	rmMarker := filepath.Join(t.TempDir(), "rm-marker")
	v12s4EnrollFakeDockerAt(t, v12s4DockerScript("A", imageA, rmMarker))

	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	original := controllerenv.Freeze().With(map[string]string{"DOCKER_HOST": "unix:///var/run/docker-original.sock"})
	ctx := context.Background()
	de, err := ResolveDockerEnvironment(ctx, registry, original)
	if err != nil {
		t.Fatalf("ResolveDockerEnvironment: %v", err)
	}
	defer func() { _ = de.Close() }()
	if de.Endpoint != "unix:///var/run/docker-original.sock" {
		t.Fatalf("captured endpoint = %q, want the original DOCKER_HOST", de.Endpoint)
	}
	originalSummary := de.IdentitySummary()

	// The daemon endpoint changes mid-run (an operator or same-UID process
	// alters the ambient environment). A later docker operation performed
	// with the CHANGED environment must not silently re-bind the
	// transaction's already-captured endpoint.
	changed := controllerenv.Freeze().With(map[string]string{"DOCKER_HOST": "unix:///var/run/docker-DIFFERENT.sock"})
	if _, err := de.InspectImage(ctx, "example/agent:latest", changed); err != nil {
		t.Fatalf("InspectImage with a changed ambient environment: %v", err)
	}
	if de.Endpoint != "unix:///var/run/docker-original.sock" {
		t.Fatalf("de.Endpoint drifted to %q after a later operation ran under a changed DOCKER_HOST -- the transaction's frozen daemon endpoint must never be silently re-derived mid-run", de.Endpoint)
	}
	if summary, ok := de.IdentitySummary().(map[string]any); !ok || summary["endpoint"] != "unix:///var/run/docker-original.sock" {
		t.Fatalf("IdentitySummary()'s endpoint drifted after a later operation: %+v", summary)
	}
	if got := de.IdentitySummary(); !identitySummaryEqual(originalSummary, got) {
		t.Fatalf("DockerEnvironment.IdentitySummary() changed after a later operation under a different ambient DOCKER_HOST:\nbefore: %+v\nafter:  %+v", originalSummary, got)
	}
}

func identitySummaryEqual(a, b any) bool {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if !aok || !bok || len(am) != len(bm) {
		return false
	}
	for k, v := range am {
		if bm[k] != v {
			return false
		}
	}
	return true
}
