//go:build redteam

// v10_s5_managed_runtime_test.go implements Sol10 P0-5's mandatory red-team
// corpus (agents/governator-sol-upgrade10.md "P0-5: Assayer's Python
// runtime is not part of the frozen evaluator",
// agents/governator-sol-upgrade10-rc4-plan.md Session 5, manifest cases
// 124-127 / report cases 25-28).
//
// The pre-P0-5 defect: pythonStdlibReadRoots discovered and granted read
// access to *live* stdlib/platstdlib/purelib/platlib directories on every
// Evaluate call, and Evaluate launched python with no isolation flag at
// all -- so Python's `site` module always initialized, meaning any
// sitecustomize.py/.pth file reachable on sys.path at launch time executed
// before cli.py's own code ever ran, and the probe that discovered the
// read roots was itself subject to the same ambient site configuration.
//
// The fix (assay.go's evaluateArguments, snapshot.go's buildRuntimeManifest)
// always launches with "-S": Python's `site` module is never imported, so
// no .pth file is ever processed and neither sitecustomize.py nor
// usercustomize.py is ever imported, structurally, regardless of what's on
// PYTHONPATH or what a real site-packages directory contains --
// evaluateArguments is the single function Evaluate calls to build its
// argument list, so driving it directly here ties every assertion below to
// the exact code path a real evaluation takes.
//
// Cases 25/26 deliberately drive snap.Python.Command directly (the same
// held handle Evaluate uses) rather than the full Evaluate/stage.Executor
// pipeline: that pipeline requires this host to also provide external
// Landlock/unshare enforcement (StageAuthority.RequireStrongScope), which
// this package's fast unit tier already documents as unavailable in a
// plain `go test` sandbox (see TestMain's doc comment, and every other
// stub-based test in assay_test.go skipping via requireExternalSandbox).
// The "-S" mechanism itself is a pure Python-interpreter property,
// independent of any OS-level sandboxing, so proving it directly against
// the real held handle is a strictly stronger, host-independent proof than
// gating the whole corpus case on this host also having Landlock.
//
// Cases 25/26 also deliberately avoid writing into this host's real,
// already-installed site-packages directory (whatever sysconfig resolves
// it to): that directory may not be writable by this process, and even
// where it is, planting files there would mutate shared host state outside
// this repo for the duration of a test run -- exactly the kind of
// side-effect this corpus should never risk. Instead each case attacks a
// throwaway fixture directory the test owns, first proving empirically
// that Python's real site/`.pth` machinery *would* process it absent the
// fix (so the case is not vacuous), then proving the "-S" flag Evaluate
// always passes prevents it structurally.
package assay

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/cousingary/governator/internal/controllerenv"
)

// TestV10Case25SitecustomizeAttemptsToAlterEvaluationHasNoEffect proves a
// sitecustomize.py reachable on sys.path at interpreter startup (site.py's
// execsitecustomize does a plain `import sitecustomize`, found via whatever
// is on sys.path once the `site` module itself has been imported) has no
// effect on the exact launch Evaluate performs, because that launch never
// imports `site` at all.
func TestV10Case25SitecustomizeAttemptsToAlterEvaluationHasNoEffect(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("requires Linux sealed Python runtime execution; TestV12Case35DarwinNativeAssayerRefusesRatherThanDegrades verifies the paired Darwin fail-closed boundary")
	}
	requirePython3(t)
	repo := fixtureRepo(t)
	snap := buildTestSnapshot(t, repo)

	if got := evaluateArguments(snap, "coding-output-v1"); len(got) == 0 || got[0] != "-S" {
		t.Fatalf("expected evaluateArguments to lead with -S, got %v", got)
	}

	hostileDir := t.TempDir()
	canary := filepath.Join(t.TempDir(), "sitecustomize-ran.marker")
	sitecustomizeSrc := "open(" + strconv.Quote(canary) + ", 'w').close()\n"
	if err := os.WriteFile(filepath.Join(hostileDir, "sitecustomize.py"), []byte(sitecustomizeSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	env := controllerenv.Base()
	env = append(env, "PYTHONPATH="+hostileDir)

	// Negative control: without -S, a sitecustomize.py anywhere on
	// PYTHONPATH really does execute at interpreter startup -- proves the
	// attack is real, not a vacuous no-op the fix gets undeserved credit
	// for blocking.
	ctx := context.Background()
	unisolated, err := snap.Python.Command(ctx, "-c", "pass")
	if err != nil {
		t.Fatalf("construct unisolated probe: %v", err)
	}
	unisolated.Env = env
	if err := unisolated.Run(); err != nil {
		t.Fatalf("run unisolated probe: %v", err)
	}
	if _, statErr := os.Stat(canary); statErr != nil {
		t.Fatalf("expected sitecustomize.py to execute and create the canary without -S, got: %v", statErr)
	}
	if err := os.Remove(canary); err != nil {
		t.Fatalf("reset canary between control and fixed run: %v", err)
	}

	// Fixed path: the exact "-S" argument Evaluate always leads with.
	isolated, err := snap.Python.Command(ctx, "-S", "-c", "pass")
	if err != nil {
		t.Fatalf("construct isolated probe: %v", err)
	}
	isolated.Env = env
	if err := isolated.Run(); err != nil {
		t.Fatalf("run isolated probe: %v", err)
	}
	if _, statErr := os.Stat(canary); statErr == nil {
		t.Fatal("sitecustomize.py executed despite -S: isolated-startup mechanism failed to prevent it")
	}

	// Directly confirm the mechanism: `site` is never imported under -S,
	// so nothing could call execsitecustomize regardless of PYTHONPATH.
	assertSiteNeverImportedUnderDashS(t, snap)
}

// TestV10Case26PthFileAttemptsStartupExecutionHasNoEffect proves a `.pth`
// file's "import ..." execution line -- processed by site.addsitedir, which
// only ever runs from inside the `site` module -- has no effect on the
// exact launch Evaluate performs, for the same structural reason as case
// 25: that launch never imports `site`.
func TestV10Case26PthFileAttemptsStartupExecutionHasNoEffect(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("requires Linux sealed Python runtime execution; TestV12Case35DarwinNativeAssayerRefusesRatherThanDegrades verifies the paired Darwin fail-closed boundary")
	}
	requirePython3(t)
	repo := fixtureRepo(t)
	snap := buildTestSnapshot(t, repo)

	hostileDir := t.TempDir()
	canary := filepath.Join(t.TempDir(), "pth-ran.marker")
	pthSrc := "import os; open(" + strconv.Quote(canary) + ", 'w').close()\n"
	if err := os.WriteFile(filepath.Join(hostileDir, "zzz_attack.pth"), []byte(pthSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Negative control: site.addsitedir really does execute a .pth file's
	// "import ..." line -- the real, documented mechanism, exercised
	// directly (addsitedir is what site.main() calls on every real
	// site-packages directory when `site` is imported at all) rather than
	// assumed. This proves the attack is real without needing this host's
	// own live site-packages directory to be writable.
	control, err := snap.Python.Command(ctx, "-c",
		"import site; site.addsitedir("+strconv.Quote(hostileDir)+")\n")
	if err != nil {
		t.Fatalf("construct addsitedir control: %v", err)
	}
	control.Env = controllerenv.Base()
	if err := control.Run(); err != nil {
		t.Fatalf("run addsitedir control: %v", err)
	}
	if _, statErr := os.Stat(canary); statErr != nil {
		t.Fatalf("expected site.addsitedir to process the .pth file and create the canary, got: %v", statErr)
	}

	// Fixed path: under -S (Evaluate's actual launch flag), `site` is
	// never imported, so site.addsitedir is never even reachable -- no
	// .pth file anywhere, including this hostile one, can ever be
	// processed during a real evaluation.
	assertSiteNeverImportedUnderDashS(t, snap)
}

// assertSiteNeverImportedUnderDashS confirms, through the same held handle
// and the same leading "-S" argument evaluateArguments always returns, that
// Python's `site` module -- the sole mechanism that imports
// sitecustomize.py/usercustomize.py and processes any `.pth` file -- is
// never present in sys.modules. This is the one fact both case 25 and case
// 26 ultimately rest on.
func assertSiteNeverImportedUnderDashS(t *testing.T, snap *Snapshot) {
	t.Helper()
	if got := evaluateArguments(snap, "coding-output-v1"); len(got) == 0 || got[0] != "-S" {
		t.Fatalf("expected evaluateArguments to lead with -S, got %v", got)
	}
	cmd, err := snap.Python.Command(context.Background(), "-S", "-c",
		"import sys; sys.exit(0 if 'site' not in sys.modules else 1)\n")
	if err != nil {
		t.Fatalf("construct site-import probe: %v", err)
	}
	cmd.Env = controllerenv.Base()
	if err := cmd.Run(); err != nil {
		t.Fatalf("expected 'site' to never be imported under -S, probe reported it was imported: %v", err)
	}
}

// TestV10Case27InstalledDependencyChangeWithoutLockfileChangeInvalidatesReplay
// proves DependencyHash's underlying mechanism -- hashPathTree over the
// resolved site-packages roots -- changes the moment installed bytes
// change, with no lockfile involved at all, so a later replay comparison
// against an earlier transaction's ledgered identity misses rather than
// silently matching stale installed bytes.
//
// This drives hashPathTree directly against a throwaway fixture directory
// standing in for a real purelib/platlib root, rather than this host's
// actual installed site-packages (which may not be writable, and mutating
// it would leak a side effect into shared host state for the run's
// duration) -- hashPathTree is exactly and only what buildRuntimeManifest
// calls to produce DependencyHash, so this is a faithful, direct proof of
// the real mechanism, not a stand-in for it.
func TestV10Case27InstalledDependencyChangeWithoutLockfileChangeInvalidatesReplay(t *testing.T) {
	siteRoot := t.TempDir()
	distInfo := filepath.Join(siteRoot, "somepkg-1.2.3.dist-info")
	if err := os.MkdirAll(distInfo, 0o755); err != nil {
		t.Fatal(err)
	}
	pkgFile := filepath.Join(siteRoot, "somepkg", "__init__.py")
	if err := os.MkdirAll(filepath.Dir(pkgFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pkgFile, []byte("VALUE = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	before, err := hashPathTree([]string{siteRoot})
	if err != nil {
		t.Fatalf("hash installed dependency tree before tamper: %v", err)
	}
	if before == "" {
		t.Fatal("expected a non-empty dependency hash for a non-empty site-packages fixture")
	}

	// Simulate a same-UID or supply-chain tamper of the installed package
	// bytes -- deliberately touching nothing that looks like a lockfile.
	if err := os.WriteFile(pkgFile, []byte("VALUE = 2  # tampered, no lockfile touched\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	after, err := hashPathTree([]string{siteRoot})
	if err != nil {
		t.Fatalf("hash installed dependency tree after tamper: %v", err)
	}
	if after == before {
		t.Fatal("expected the installed-dependency hash to change when installed bytes change, even with no lockfile change -- replay would silently match stale bytes")
	}
}

// TestV10Case28StdlibModuleChangeWithoutExecutableChangeInvalidatesReplay is
// case 27's exact counterpart for RuntimeHash/StdlibReadRoots: a stdlib
// module's bytes changing, with the python executable itself untouched,
// must change the frozen runtime identity. Same rationale as case 27 for
// using a fixture root instead of this host's real stdlib directory.
func TestV10Case28StdlibModuleChangeWithoutExecutableChangeInvalidatesReplay(t *testing.T) {
	stdlibRoot := t.TempDir()
	modFile := filepath.Join(stdlibRoot, "os.py")
	if err := os.WriteFile(modFile, []byte("SENTINEL = 'original'\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	before, err := hashPathTree([]string{stdlibRoot})
	if err != nil {
		t.Fatalf("hash stdlib tree before tamper: %v", err)
	}
	if before == "" {
		t.Fatal("expected a non-empty runtime hash for a non-empty stdlib fixture")
	}

	if err := os.WriteFile(modFile, []byte("SENTINEL = 'tampered'\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	after, err := hashPathTree([]string{stdlibRoot})
	if err != nil {
		t.Fatalf("hash stdlib tree after tamper: %v", err)
	}
	if after == before {
		t.Fatal("expected the stdlib runtime hash to change when a stdlib module's bytes change, even with the interpreter itself untouched -- replay would silently match a hybrid environment")
	}
}
