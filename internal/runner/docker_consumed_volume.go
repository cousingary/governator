package runner

// docker_consumed_volume.go closes Sol12 P0-8 (agents/governator-sol-upgrade12.md
// "P0-8: Docker consumed artifacts still rely on mutable host paths",
// agents/governator-sol-upgrade12-rc5-plan.md Session 5). Before this, the
// docker-backend consumed-artifact source was consumedArtifactStoreDir(home,
// runID) -- an ordinary same-UID-writable host directory, bind-mounted
// read-only into the container. The container's VIEW was read-only, but the
// underlying host directory entries remained writable by any other process
// running as Governator's own OS user: a same-UID sibling could alter the
// source after the pre-launch hash check, let the container read the
// modified bytes, then restore the original bytes before the next
// verification checkpoint -- Sol's exact attack (report P0-8, options
// enumerated: immutable Docker volume, read-only image layer,
// fs-verity-backed file, content-addressed store under a dedicated UID, or a
// dedicated artifact-serving sidecar).
//
// This file implements the first of those options: an immutable-by-host-path
// Docker volume. ProvisionConsumedVolume writes the sealed artifact bytes
// directly into a fresh Docker volume via `docker cp -` (a tar stream on
// stdin) through a throwaway, never-started seed container built from the
// run's own already-verified image -- no host filesystem path is ever
// created for the bytes, so no same-UID host process has anywhere to locate
// and mutate them. The only entity that can now alter the artifact source is
// whoever controls the Docker daemon itself, which Sol's report requires be
// folded into the trust model explicitly ("Docker daemon authority must be
// part of the trust model") -- already true here: DockerEnvironment.DaemonIdentity
// (Sol12 P0-7) binds the daemon's self-reported identity into replay
// identity, and VerifyConsumedVolume re-reads the volume's actual content
// through that same frozen CLI+daemon identity at every Sol10 P0-1
// verification checkpoint, so a daemon-side mutation is detected exactly
// like a host-path mutation used to be.
//
// A same-UID process with independent Docker daemon access (dockerd socket
// permission, not merely Governator's own OS user) could still create a
// throwaway container mounting the same volume read-write and alter it --
// that residual is the daemon-authority trust boundary itself, which no
// software change at Governator's own runtime privilege level can close
// (Governator has no CAP_SYS_ADMIN/CAP_LINUX_IMMUTABLE in the host mount
// namespace and no root-owned dedicated-service-UID store to hand this to);
// it is honestly the boundary Sol's report says must be named, not silently
// engineered around.

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/toolregistry"
)

// ConsumedArtifactContent is one consumed artifact's already-verified sealed
// content, as the runtime package's stagedArtifact represents it, handed
// across the package boundary so this package never has to reach back into
// runtime's ledger/sealing logic. Name is a validated safe basename (the
// runtime package rejects anything else before this is ever constructed).
type ConsumedArtifactContent struct {
	Name   string
	SHA256 string
	Bytes  int64
	Data   []byte
}

// ConsumedVolumeName returns the deterministic Docker volume name for run
// runID's consumed-artifact store (Sol12 P0-8).
func ConsumedVolumeName(runID string) string {
	return "gov-consumed-" + runID
}

func consumedSeedContainerName(volumeName string) string {
	return volumeName + "-io"
}

// ProvisionConsumedVolume creates a fresh Docker volume and populates it with
// artifacts' sealed content, entirely through the frozen DockerEnvironment's
// CLI handle: no host directory entry is ever written. image is the run's
// own already-verified image reference (ImageIdentity.Reference) -- reused
// rather than pulling a separate helper image, so provisioning introduces no
// new trusted-image dependency. On any failure the volume (and any partially
// created seed container) is removed before returning.
func ProvisionConsumedVolume(ctx context.Context, de *DockerEnvironment, env controllerenv.Frozen, image, volumeName string, artifacts []ConsumedArtifactContent) error {
	if de == nil || de.CLI == nil {
		return fmt.Errorf("provision consumed-artifact volume: docker environment is not frozen")
	}
	if err := env.Validate(); err != nil {
		return fmt.Errorf("provision consumed-artifact volume: %w", err)
	}
	if strings.TrimSpace(image) == "" {
		return fmt.Errorf("provision consumed-artifact volume: no resolved image reference")
	}
	tarBytes, err := buildConsumedArtifactTar(artifacts)
	if err != nil {
		return err
	}
	// `docker volume create` on an already-existing name is a non-destructive
	// no-op in real Docker -- it does NOT clear prior content. volumeName is
	// deterministic per run id, so the only way a volume already exists here
	// is a leftover from an interrupted prior attempt at this exact run, or a
	// same-UID/daemon-authority actor pre-staging it (Sol12 P0-8 report's
	// "Docker volume identity changes" case). Discard unconditionally before
	// creating so this run never inherits a volume it did not itself
	// populate. `docker volume rm` refuses while any container (even a
	// stopped, never-started one) still references the volume, so any
	// leftover seed/verify container from a prior interrupted attempt at
	// this exact volume name is removed first. Every step here is
	// best-effort, ignored when nothing exists yet.
	_ = runDockerCLI(ctx, de.CLI, env, nil, "rm", "-f", consumedSeedContainerName(volumeName))
	_ = runDockerCLI(ctx, de.CLI, env, nil, "rm", "-f", consumedSeedContainerName(volumeName)+"-verify")
	_ = runDockerCLI(ctx, de.CLI, env, nil, "volume", "rm", "-f", volumeName)
	if err := runDockerCLI(ctx, de.CLI, env, nil, "volume", "create", "--label", "governator=consumed", "--label", "governator.volume_name="+volumeName, volumeName); err != nil {
		return fmt.Errorf("create consumed-artifact volume %q: %w", volumeName, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = runDockerCLI(context.Background(), de.CLI, env, nil, "volume", "rm", "-f", volumeName)
		}
	}()
	seed := consumedSeedContainerName(volumeName)
	if err := runDockerCLI(ctx, de.CLI, env, nil, "create", "--name", seed, "-v", volumeName+":/consumed", image); err != nil {
		return fmt.Errorf("create consumed-artifact seed container: %w", err)
	}
	defer func() { _ = runDockerCLI(context.Background(), de.CLI, env, nil, "rm", "-f", seed) }()
	if err := runDockerCLI(ctx, de.CLI, env, bytes.NewReader(tarBytes), "cp", "-", seed+":/consumed"); err != nil {
		return fmt.Errorf("populate consumed-artifact volume %q: %w", volumeName, err)
	}
	ok = true
	return nil
}

// VerifyConsumedVolume re-reads volumeName's actual content -- through a
// fresh, throwaway container mounting the same volume, via `docker cp`'s
// tar-stream-to-stdout form -- and hash-verifies every artifact against the
// sealed identity ProvisionConsumedVolume wrote. This is the docker leg of
// Sol10 P0-1's four verification checkpoints (before backend launch, after
// backend extinction, before validation, after all validation): unlike a
// host-directory hash check, this proves the exact bytes reachable through
// Docker's own storage for this volume, which is what the run container
// actually reads.
func VerifyConsumedVolume(ctx context.Context, de *DockerEnvironment, env controllerenv.Frozen, image, volumeName string, artifacts []ConsumedArtifactContent) error {
	if de == nil || de.CLI == nil {
		return fmt.Errorf("verify consumed-artifact volume: docker environment is not frozen")
	}
	if err := env.Validate(); err != nil {
		return fmt.Errorf("verify consumed-artifact volume: %w", err)
	}
	reader := consumedSeedContainerName(volumeName) + "-verify"
	if err := runDockerCLI(ctx, de.CLI, env, nil, "create", "--name", reader, "-v", volumeName+":/consumed", image); err != nil {
		return fmt.Errorf("create consumed-artifact verify container: %w", err)
	}
	defer func() { _ = runDockerCLI(context.Background(), de.CLI, env, nil, "rm", "-f", reader) }()
	tarBytes, err := readDockerCLI(ctx, de.CLI, env, "cp", reader+":/consumed/.", "-")
	if err != nil {
		return fmt.Errorf("read consumed-artifact volume %q: %w", volumeName, err)
	}
	actual, err := parseConsumedArtifactTar(tarBytes)
	if err != nil {
		return fmt.Errorf("consumed-artifact volume %q: %w", volumeName, err)
	}
	if len(actual) != len(artifacts) {
		return fmt.Errorf("consumed-artifact volume %q entry count changed: staged=%d now=%d", volumeName, len(artifacts), len(actual))
	}
	for _, want := range artifacts {
		got, ok := actual[want.Name]
		if !ok {
			return fmt.Errorf("consumed artifact %q missing from volume %q", want.Name, volumeName)
		}
		if got.Bytes != want.Bytes || got.SHA256 != want.SHA256 {
			return fmt.Errorf("consumed artifact %q content changed in volume %q", want.Name, volumeName)
		}
	}
	return nil
}

// RemoveConsumedVolume best-effort removes volumeName once a run's whole
// transaction (including every verification checkpoint) has finished. The
// artifact bytes are always reproducible from the ledger that produced them
// -- never the sole copy -- so an occasional leaked volume from a crashed
// process is a cleanup residual, not a data-loss or security concern; the
// same crash-cleanup gap already exists for consumedArtifactStoreDir's
// legacy host-directory store and is not newly introduced here.
func RemoveConsumedVolume(ctx context.Context, de *DockerEnvironment, env controllerenv.Frozen, volumeName string) error {
	if de == nil || de.CLI == nil || volumeName == "" {
		return nil
	}
	_ = runDockerCLI(ctx, de.CLI, env, nil, "rm", "-f", consumedSeedContainerName(volumeName))
	_ = runDockerCLI(ctx, de.CLI, env, nil, "rm", "-f", consumedSeedContainerName(volumeName)+"-verify")
	return runDockerCLI(ctx, de.CLI, env, nil, "volume", "rm", "-f", volumeName)
}

// runDockerCLI runs one docker subcommand through the already-verified,
// open handle, optionally feeding stdin, and folds stderr into the error on
// failure. Never reloads the trusted-tool registry (Sol12 P0-7).
func runDockerCLI(ctx context.Context, cli *toolregistry.Handle, env controllerenv.Frozen, stdin io.Reader, args ...string) error {
	cmd, cerr := cli.Command(ctx, args...)
	if cerr != nil {
		return cerr
	}
	cmd.Env = append([]string(nil), env.Values...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, trimmed(out))
	}
	return nil
}

// readDockerCLI runs one docker subcommand and returns its stdout, keeping
// stderr separate so binary tar output on stdout is never corrupted by
// interleaved diagnostic text.
func readDockerCLI(ctx context.Context, cli *toolregistry.Handle, env controllerenv.Frozen, args ...string) ([]byte, error) {
	cmd, cerr := cli.Command(ctx, args...)
	if cerr != nil {
		return nil, cerr
	}
	cmd.Env = append([]string(nil), env.Values...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, trimmed(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}

// buildConsumedArtifactTar builds the tar stream ProvisionConsumedVolume
// feeds to `docker cp -`: one regular-file entry per artifact, mode 0400,
// named exactly artifact.Name. Rejects any name that is not a safe plain
// basename as defense-in-depth -- the runtime package's ledger lookup
// already enforces this before an artifact ever reaches here, but a tar
// entry name containing a path separator or ".." is exactly the kind of
// input this function must never trust blindly.
func buildConsumedArtifactTar(artifacts []ConsumedArtifactContent) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, a := range artifacts {
		if a.Name == "" || a.Name == "." || strings.ContainsAny(a.Name, "/\\") {
			return nil, fmt.Errorf("build consumed-artifact tar: %q is not a safe basename", a.Name)
		}
		hdr := &tar.Header{Name: a.Name, Mode: 0400, Size: int64(len(a.Data)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("build consumed-artifact tar: %w", err)
		}
		if _, err := tw.Write(a.Data); err != nil {
			return nil, fmt.Errorf("build consumed-artifact tar: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("build consumed-artifact tar: %w", err)
	}
	return buf.Bytes(), nil
}

// parseConsumedArtifactTar parses the tar stream `docker cp
// container:/consumed/. -` produces, hashing every regular-file entry.
// Non-regular entries (symlink, hardlink, device, etc.) fail closed rather
// than being silently skipped: a compromised or substituted volume returning
// a symlink in place of an artifact's expected regular file is exactly the
// kind of substitution this function must refuse, mirroring
// runtime.readRegularBeneath's "non-regular artifact refused" posture for
// the host-path store this replaces.
func parseConsumedArtifactTar(data []byte) (map[string]ConsumedArtifactContent, error) {
	out := map[string]ConsumedArtifactContent{}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse consumed-artifact tar: %w", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name == "" || name == "." {
			continue
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("consumed-artifact volume entry %q is not a regular file (tar type %q)", name, string(hdr.Typeflag))
		}
		if strings.ContainsAny(name, "/\\") {
			return nil, fmt.Errorf("consumed-artifact volume entry %q is not a safe basename", name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("parse consumed-artifact tar: %w", err)
		}
		sum := sha256.Sum256(body)
		out[name] = ConsumedArtifactContent{Name: name, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(body)), Data: body}
	}
	return out, nil
}
