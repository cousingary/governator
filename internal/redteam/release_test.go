//go:build redteam

package redteam

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestAttack24ExtractedReleaseBinaryHasWrongMode is report P0-7 / §9
// attack 24: the archived gov binary ships at mode 0777 (world-writable).
// Fixed by S8: scripts/release_verify.sh (invoked by scripts/release.sh as
// its acceptance-and-release-blocking gate) extracts the archive fresh and
// asserts the extracted binary's mode is exactly 0755, refusing before it
// ever calls `gov claims verify`.
//
// The fixture's manifest/artifact identity fields are deliberately fully
// consistent (same commit, matching sha256, matching claims hash) so the
// ONLY reason release_verify.sh can refuse is the mode -- isolating this
// test from attack 25's identity-drift assertion.
func TestAttack24ExtractedReleaseBinaryHasWrongMode(t *testing.T) {
	commit := "24242424242424242424242424242424242424"
	dist, repoRoot, platform := buildReleaseFixtureDist(t, releaseFixtureOpts{
		version:        "1.0.0-redteam24",
		manifestCommit: commit,
		mode:           0777,
	})

	out, err := runReleaseVerify(t, dist, repoRoot, platform)
	if err == nil {
		t.Fatalf("release_verify.sh accepted an archived binary shipped at mode 0777; output:\n%s", out)
	}
	if !strings.Contains(out, "755") {
		t.Fatalf("expected release_verify.sh to fail on the mode-755 assertion, got:\n%s", out)
	}
}

// TestAttack25ReleaseBinaryCommitDiffersFromSourceAndClaims is report P0-7
// / §9 attack 25: the shipped binary's embedded source_commit can differ
// from both the submitted source HEAD and the claims-verification commit
// -- security-relevant drift (attestation behavior, policy acceptance
// evidence, claims/evidence data) shipped without full claims verification
// ever running against the exact archived artifact. Fixed by S8:
// scripts/release_verify.sh runs `gov claims verify --release --artifact
// --manifest` (cmd/gov/main.go now refuses to run without both flags in
// --release mode) against the exact extracted binary; a binary whose own
// `version --json` reports a commit other than the one build-manifest.json
// (and the operator's docs/claims.yaml-bearing repo) records fails
// verification.
//
// The fixture ships the binary at the correct mode 0755, so the ONLY
// possible failure reason is the identity mismatch this test targets.
func TestAttack25ReleaseBinaryCommitDiffersFromSourceAndClaims(t *testing.T) {
	manifestCommit := "25252525252525252525252525252525252525"
	driftedCommit := "9999999999999999999999999999999999999a"
	dist, repoRoot, platform := buildReleaseFixtureDist(t, releaseFixtureOpts{
		version:        "1.0.0-redteam25",
		manifestCommit: manifestCommit,
		artifactCommit: driftedCommit,
		mode:           0755,
	})

	out, err := runReleaseVerify(t, dist, repoRoot, platform)
	if err == nil {
		t.Fatalf("release_verify.sh accepted an archived binary whose self-reported commit drifted from build-manifest.json; output:\n%s", out)
	}
	if !strings.Contains(out, "source_commit") {
		t.Fatalf("expected release_verify.sh's claims-verify call to fail on source_commit drift, got:\n%s", out)
	}
}

// TestAttack26DirtyReleaseBinaryReportsAContradictoryRelease identity check:
// even when version/commit/claims hash all match, a release artifact that
// self-reports dirty=true must fail the release gate.
func TestAttack26DirtyReleaseBinaryReportsAContradictoryRelease(t *testing.T) {
	commit := "2626262626262626262626262626262626262626"
	dist, repoRoot, platform := buildReleaseFixtureDist(t, releaseFixtureOpts{
		version:        "1.0.0-redteam26",
		manifestCommit: commit,
		mode:           0755,
		artifactDirty:  true,
	})

	out, err := runReleaseVerify(t, dist, repoRoot, platform)
	if err == nil {
		t.Fatalf("release_verify.sh accepted an archived binary whose version --json reported dirty=true; output:\n%s", out)
	}
	if !strings.Contains(out, "dirty=true") {
		t.Fatalf("expected release_verify.sh's claims-verify call to fail on dirty=true, got:\n%s", out)
	}
}

// runReleaseVerify invokes the real scripts/release_verify.sh against a
// synthetic dist directory, using the real cmd/gov binary (govBinary(t),
// built from this repo's actual current source -- the same binary S8's
// cmd/gov/main.go --release change lives in) to run `claims verify`. The
// archived ARTIFACT under test is a separate, minimal, purpose-built fake
// binary (buildFakeArtifactBinary) -- exactly like
// internal/claims/claims_test.go's TestVerifyReleaseArtifactChecksExactBinaryAndSelfReportedVersion
// fixture, the closest prior art -- because what's under test is release
// identity verification, not a full governator build.
func runReleaseVerify(t *testing.T, distDir, repoRoot, platform string) (string, error) {
	t.Helper()
	script := releaseVerifyScript(t)
	cmd := exec.Command(script, "--out-dir", distDir, "--repo", repoRoot, "--platform", platform, "--gov-bin", govBinary(t))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func releaseVerifyScript(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	return filepath.Join(repoRoot, "scripts", "release_verify.sh")
}

type releaseFixtureOpts struct {
	version        string
	manifestCommit string
	artifactCommit string // defaults to manifestCommit when empty
	mode           os.FileMode

	// artifactVersion, when non-empty, is compiled into the fake artifact
	// binary in place of version -- so build-manifest.json's declared
	// "version" and the artifact's own `version --json` report can be made
	// to drift independently (Session 7 / TestV7Case32).
	artifactVersion string
	artifactDirty   bool
	// manifestArtifactSHAOverride, when non-empty, replaces the manifest's
	// recorded artifact_sha256 with an arbitrary value instead of the
	// archive's real hash (Session 7 / TestV7Case36: an installed/local
	// binary whose hash no longer matches what the release manifest
	// recorded).
	manifestArtifactSHAOverride string
	// omitArchive, when true, writes build-manifest.json referencing the
	// expected archive name but never actually writes that file to distDir
	// (Session 7 / TestV7Case31: a release with a missing current binary).
	omitArchive bool
}

// buildReleaseFixtureDist assembles a synthetic release dist/ directory --
// claims.yaml, build-manifest.json, and one gov_<version>_<platform>.tar.gz
// -- shaped exactly like scripts/release.sh's real output, small and fast
// enough to build per-test rather than driving the real (multi-minute,
// multi-platform, full-test-suite) release pipeline end to end.
func buildReleaseFixtureDist(t *testing.T, opts releaseFixtureOpts) (distDir, repoRoot, platform string) {
	t.Helper()
	platform = "linux_amd64"
	artifactCommit := opts.artifactCommit
	if artifactCommit == "" {
		artifactCommit = opts.manifestCommit
	}

	repoRoot = t.TempDir()
	claimsYAML := "version: 1\nclaims: []\n"
	if err := os.MkdirAll(filepath.Join(repoRoot, "docs"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "docs", "claims.yaml"), []byte(claimsYAML), 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(claimsYAML))
	claimsHash := hex.EncodeToString(sum[:])

	distDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(distDir, "claims.yaml"), []byte(claimsYAML), 0644); err != nil {
		t.Fatal(err)
	}

	artifactVersion := opts.artifactVersion
	if artifactVersion == "" {
		artifactVersion = opts.version
	}
	artifactBin := buildFakeArtifactBinary(t, artifactVersion, artifactCommit, claimsHash, opts.artifactDirty)
	artifactSHA := fileSHA256Hex(t, artifactBin)
	if opts.manifestArtifactSHAOverride != "" {
		artifactSHA = opts.manifestArtifactSHAOverride
	}

	archiveName := fmt.Sprintf("gov_%s_%s.tar.gz", opts.version, platform)
	archiveSHA := ""
	if !opts.omitArchive {
		archivePath := filepath.Join(distDir, archiveName)
		writeSingleFileTarGz(t, archivePath, "gov", artifactBin, opts.mode)
		archiveSHA = fileSHA256Hex(t, archivePath)
	}

	manifest := map[string]any{
		"version":                  opts.version,
		"source_commit":            opts.manifestCommit,
		"build_timestamp":          time.Now().UTC().Format(time.RFC3339),
		"go_version":               "",
		"build_flags":              "redteam-fixture",
		"claims_hash":              claimsHash,
		"adapter_protocol_version": "adapter-protocol-v1",
		"artifacts":                []any{},
		"archive_path":             archiveName,
		"archive_sha256":           archiveSHA,
		"extracted_binary_sha256":  artifactSHA,
		"artifact_path":            archiveName,
		"artifact_sha256":          artifactSHA,
		"build_info":               map[string]string{"vcs_revision": opts.manifestCommit},
		"test_run_id":              "redteam-fixture-test-run",
		"test_result":              "PASS",
		"acceptance_run_id":        "redteam-fixture-acceptance-run",
		"acceptance_result":        "PASS",
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distDir, "build-manifest.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	return distDir, repoRoot, platform
}

// buildFakeArtifactBinary compiles a minimal standalone Go program (not the
// real governator CLI) that answers `version --json` the way build-manifest
// verification expects -- mirroring internal/claims/claims_test.go's build()
// helper.
func buildFakeArtifactBinary(t *testing.T, version, sourceCommit, claimsHash string, dirty bool) string {
	t.Helper()
	modDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(modDir, "go.mod"), []byte("module example.com/fakegov\n\ngo 1.22\n"), 0644); err != nil {
		t.Fatal(err)
	}
	mainGo := `package main

import (
	"encoding/json"
	"fmt"
	"os"
)

var version = "dev"
var sourceCommit = "unknown"
var claimsHash = "unknown"

func main() {
	if len(os.Args) == 3 && os.Args[1] == "version" && os.Args[2] == "--json" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"version": version, "source_commit": sourceCommit, "claims_hash": claimsHash, "dirty": ` + map[bool]string{true: "true", false: "false"}[dirty] + `})
		return
	}
	fmt.Println("fakegov", version)
}
`
	if err := os.WriteFile(filepath.Join(modDir, "main.go"), []byte(mainGo), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "fakegov")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out,
		"-ldflags", "-X main.version="+version+" -X main.sourceCommit="+sourceCommit+" -X main.claimsHash="+claimsHash,
		".")
	cmd.Dir = modDir
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake artifact binary: %v: %s", err, combined)
	}
	return out
}

func fileSHA256Hex(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// writeSingleFileTarGz packs srcPath's content into destPath as a
// single-entry gzipped tar archive named entryName, with the header mode
// set explicitly to mode -- exactly what `tar -xzf destPath` (both the
// acceptance smoke test and scripts/release_verify.sh use plain `tar -xzf`)
// will reproduce on extraction, regardless of the writer's own umask.
func writeSingleFileTarGz(t *testing.T, destPath, entryName, srcPath string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(destPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{
		Name: entryName,
		Mode: int64(mode.Perm()),
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}
