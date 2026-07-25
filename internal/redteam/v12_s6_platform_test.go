//go:build redteam

// v12_s6_platform_test.go implements Sol12 P1-1's mandatory red-team corpus
// (agents/governator-sol-upgrade12-rc5-plan.md Session 6,
// agents/governator-sol-upgrade12.md "P1-1: Darwin production support is
// unproven after Linux memfd changes", manifest cases 227-230 / report
// corpus 33, 34, 35, 36 -- case 32 lives in internal/assay, white-box,
// since it exercises that package's Linux-only sealed-memfd seam directly).
//
// The defect: internal/assay/snapshot.go and internal/runtime/artifacts.go
// used memfd_create/F_ADD_SEALS/F_SEAL_* unconditionally, so this codebase
// failed to even cross-compile for darwin/amd64 or darwin/arm64 (confirmed
// before this session: `GOOS=darwin GOARCH=arm64 go build ./...` failed
// with nine `undefined: unix.F_SEAL_*`/`unix.MemfdCreate` errors). Fixed by
// splitting the Linux-only syscalls into snapshot_linux.go/artifacts_linux.go
// (real implementation) and their _other.go counterparts (fail-closed
// stubs, mirroring internal/enforce/consumed_linux.go's pre-existing
// pattern), so the package now cross-compiles for every scripts/release.sh
// PLATFORMS target.
//
// Cross-compiling is NOT the same claim as "Darwin is production-approved":
// this dev host (standing rule 11) cannot produce real Darwin acceptance
// evidence, and faking it is explicitly forbidden. rc5 instead declares
// Darwin explicitly NON-APPROVING (internal/redteamgate.ClassifyPlatform),
// ships it anyway (buildable, degraded), and refuses anything outside
// {linux, darwin} outright rather than defaulting an unrecognized platform
// to approving (scripts/release.sh's new PLATFORMS validation loop, plus
// the artifact-labeling and architecture-metadata blocks it feeds).
//
// Cases 34/35 are real acceptance tests, not placeholders: on a genuine
// Darwin host they exercise the actual containment/Assayer refusal paths.
// They skip (never fake) on every host that isn't literally Darwin, via the
// has_darwin_native_host capability predicate (internal/redteamgate/gate.go
// KnownPredicates, scripts/release.sh's capability probe) -- mirroring
// TestV12Case31's has_docker_daemon precedent exactly.
package redteam

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/assay"
	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/redteamgate"
	"github.com/cousingary/governator/internal/toolregistry"
)

// darwinNativeHostSkipReason is the manifest's allowed_skip reason text for
// both case 34 and case 35 (internal/redteam/manifest.yaml, predicate
// has_darwin_native_host) -- the gate matches the observed SKIP line
// against this string, so it must appear verbatim (as a substring) in both
// t.Skip calls below.
const darwinNativeHostSkipReason = "no Darwin acceptance host available for this run"

// TestV12Case33DarwinCrossBuildSucceeds is corpus case 33: proves the exact
// production build scripts/release.sh performs (`go build ./cmd/gov`,
// CGO_ENABLED=0) succeeds for both darwin/amd64 and darwin/arm64 --
// scripts/release.sh's own PLATFORMS default -- and that the full
// `redteam`-tagged test source (not just production code) still typechecks
// under GOOS=darwin too, catching the exact class of regression this
// session found and fixed (a Linux-only symbol reachable from a
// `redteam`-tagged _test.go file with no platform restriction; see
// internal/assay/v10_s4_snapshot_immutability_test.go's `&& linux` tag,
// added because fixing only the production files left `go vet -tags
// redteam` failing on darwin with `undefined: unix.F_GET_SEALS`).
func TestV12Case33DarwinCrossBuildSucceeds(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available")
	}
	repoRoot := governatorRepoRoot(t)

	for _, arch := range []string{"amd64", "arm64"} {
		arch := arch
		t.Run("cmd_gov_"+arch, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, goBin, "build", "-o", filepath.Join(t.TempDir(), "gov"), "./cmd/gov")
			cmd.Dir = repoRoot
			cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH="+arch, "CGO_ENABLED=0")
			if out, berr := cmd.CombinedOutput(); berr != nil {
				t.Fatalf("cross-build darwin/%s ./cmd/gov failed (Sol12 P1-1): %v\n%s", arch, berr, out)
			}
		})
	}

	t.Run("redteam_test_source_darwin_arm64", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, goBin, "vet", "-tags", "redteam", "./...")
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0")
		if out, verr := cmd.CombinedOutput(); verr != nil {
			t.Fatalf("go vet -tags redteam ./... under GOOS=darwin/arm64 failed (Sol12 P1-1): %v\n%s", verr, out)
		}
	})
}

// TestV12Case34DarwinNativeContainmentNeverClaimsStrongScope is corpus case
// 34 ("Darwin native validator acceptance"): on a real Darwin host,
// containment.NewScope(requireStrong=true) must refuse outright rather than
// silently returning a scope that reports itself as strong/non-degraded --
// Governator implements no native Darwin descendant-owning primitive
// (systemd --user, cgroup v2, and PID namespaces are all Linux-only), so a
// requireStrong caller on Darwin must get the same "no descendant-owning
// primitive available" refusal NewScope already gives any host with none of
// the three, never a falsely-claimed strong scope.
func TestV12Case34DarwinNativeContainmentNeverClaimsStrongScope(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("%s (Sol12 P1-1, Session 6: rc5 declares Darwin non-approving pending real native containment evidence)", darwinNativeHostSkipReason)
	}
	scope, err := containment.NewScope("v12-case34-darwin-native", true, containment.ContainmentEnvironment{})
	if err == nil {
		defer func() { _, _ = scope.Extinguish(context.Background(), 5*time.Second, t.TempDir()) }()
		t.Fatalf("expected NewScope(requireStrong=true) to refuse on darwin (no native strong-containment primitive implemented), got a scope using method %q", scope.Method())
	}
}

// TestV12Case35DarwinNativeAssayerRefusesRatherThanDegrades is corpus case
// 35 ("Darwin native Assayer acceptance"): on a real Darwin host,
// assay.BuildSnapshot must refuse with its documented platform-refusal
// error (snapshot.go's `runtime.GOOS != "linux"` guard) rather than
// silently proceeding -- proving the sealed-memfd Assayer package mechanism
// fails closed on the one platform it has no native implementation for,
// instead of degrading to some weaker unsealed form.
func TestV12Case35DarwinNativeAssayerRefusesRatherThanDegrades(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("%s (Sol12 P1-1, Session 6: rc5 declares Darwin non-approving pending real native Assayer evidence)", darwinNativeHostSkipReason)
	}
	enrollRealPython3(t)
	registry, rerr := toolregistry.Load()
	if rerr != nil {
		t.Fatal(rerr)
	}
	stubDir := t.TempDir()
	stub := "import json\nprint(json.dumps({'verdict':'pass','failed_checks':[],'had_error':False}))\n"
	if werr := os.WriteFile(filepath.Join(stubDir, "cli.py"), []byte(stub), 0o755); werr != nil {
		t.Fatal(werr)
	}
	_, serr := assay.BuildSnapshot(registry, assay.Config{Repo: stubDir, Python: "python3"})
	if serr == nil {
		t.Fatal("expected BuildSnapshot to refuse sealed-memfd package execution on darwin, got nil error")
	}
	if !strings.Contains(serr.Error(), "unsupported on darwin") {
		t.Fatalf("expected the documented platform-refusal error (\"unsupported on darwin\"), got %v", serr)
	}
}

// TestV12Case36UnsupportedPlatformRefusedProductionApproval is corpus case
// 36: an unsupported platform (anything outside {linux, darwin}) must never
// claim production approval -- internal/redteamgate.ApprovedForProduction /
// ClassifyPlatform is the one authoritative decision this codebase makes
// about which platforms a release may name, and this proves it refuses an
// unrecognized GOOS outright rather than defaulting it to approving (the
// gap scripts/release.sh had before this session: its per-artifact
// "approving" flag defaulted true for anything that didn't literally start
// with "darwin_").
func TestV12Case36UnsupportedPlatformRefusedProductionApproval(t *testing.T) {
	for _, goos := range []string{"windows", "freebsd", "plan9", "js", "solaris"} {
		if approved, reason := redteamgate.ApprovedForProduction(goos); approved || reason == "" {
			t.Fatalf("ApprovedForProduction(%q) = (%v, %q), want (false, non-empty reason) -- an unsupported platform must never claim production approval", goos, approved, reason)
		}
		if status := redteamgate.ClassifyPlatform(goos); status != redteamgate.PlatformUnsupported {
			t.Fatalf("ClassifyPlatform(%q) = %q, want %q", goos, status, redteamgate.PlatformUnsupported)
		}
	}
	// Sanity companions: the two real release platforms must classify
	// exactly as rc5 declares, so this test fails loud if a future change
	// silently widens or narrows the approved/degraded sets.
	if approved, reason := redteamgate.ApprovedForProduction("linux"); !approved || reason != "" {
		t.Fatalf(`ApprovedForProduction("linux") = (%v, %q), want (true, "")`, approved, reason)
	}
	if status := redteamgate.ClassifyPlatform("linux"); status != redteamgate.PlatformApproving {
		t.Fatalf(`ClassifyPlatform("linux") = %q, want %q`, status, redteamgate.PlatformApproving)
	}
	if approved, reason := redteamgate.ApprovedForProduction("darwin"); approved || reason == "" {
		t.Fatalf(`ApprovedForProduction("darwin") = (%v, %q), want (false, non-empty reason) -- Darwin is explicitly non-approving for rc5 (Sol12 P1-1)`, approved, reason)
	}
	if status := redteamgate.ClassifyPlatform("darwin"); status != redteamgate.PlatformNonApproving {
		t.Fatalf(`ClassifyPlatform("darwin") = %q, want %q`, status, redteamgate.PlatformNonApproving)
	}
}
