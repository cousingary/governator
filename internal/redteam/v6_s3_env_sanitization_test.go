//go:build redteam

// v6_s3_env_sanitization_test.go is the Sol redteam v6 Permanent Regression
// Corpus, cases 6-7, owned by Session 3 (Phase 3: build every controller
// launch environment from an allowlist, never os.Environ()). See
// agents/governator-sol-upgrade6-plan.md Session 3 and
// agents/governator-sol-upgrade6.md P0-4. Every test here is scaffolding
// only (Session 0): t.Skip(...) is the literal first statement, before any
// fixture construction.
package redteam

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// lookPathAny returns the first of names found on PATH, or an error naming
// every candidate tried.
func lookPathAny(names ...string) (string, error) {
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("none of %v found on PATH", names)
}

// buildLDPreloadFixture compiles src into a shared object at soPath using
// whichever C compiler is available, failing the test on error.
func buildLDPreloadFixture(t *testing.T, srcPath, soPath string) {
	t.Helper()
	cc, err := lookPathAny("cc", "gcc")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cc, "-shared", "-fPIC", "-o", soPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build LD_PRELOAD fixture: %v: %s", err, out)
	}
}

// TestV6Case6BashEnvControllerInjectionNeverExecutes is corpus case 6
// (report P0-4): a supplied BASH_ENV environment variable points at a
// hostile script. Noninteractive Bash sources BASH_ENV on every
// invocation, and every governed controller shell command (success
// validators run through bash -lc, per toolregistry_test.go's
// TestAttack26) currently inherits the parent process's environment
// wholesale rather than an explicit allowlist -- so BASH_ENV is a live
// code-execution mechanism today. This test supplies a BASH_ENV script
// that appends to an external marker file on every Bash init, and asserts
// it never executed even though the run's own validator commands ran
// correctly (the run still reaches APPROVED).
func TestV6Case6BashEnvControllerInjectionNeverExecutes(t *testing.T) {

	root := fixtureRepo(t)
	marker := filepath.Join(t.TempDir(), "bash-env-ran.txt")
	bashEnvScript := filepath.Join(t.TempDir(), "bash-env-hostile.sh")
	// Appends one byte per Bash init, mirroring the report's own fixture
	// ("appended one byte to an external marker every time Bash
	// initialized... executed 16 times during the run").
	if err := os.WriteFile(bashEnvScript, []byte("#!/bin/sh\nprintf x >> "+marker+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BASH_ENV", bashEnvScript)
	// S3 exercises controller environment sanitization, not host descendant
	// primitive availability. Keep this corpus case runnable on hosts without
	// writable cgroup/systemd scopes.
	t.Setenv("GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING", "off")
	t.Setenv("GOV_CONTAINMENT_FORCE_DEGRADED", "1")

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))
	rec := runGoverned(t, t.TempDir(), bin, c)

	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED (the well-behaved backend/validator must still succeed once BASH_ENV is stripped), got status=%s message=%s", rec.Status, rec.Message)
	}
	if data, err := os.ReadFile(marker); err == nil {
		t.Fatalf("BASH_ENV-injected script executed %d time(s) during a governed run -- controller shell environments must be built from an allowlist, never inherit BASH_ENV", len(data))
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

// TestV6Case7LDPreloadControllerInjectionNeverExecutes is corpus case 7
// (report P0-4): the same class of injection via LD_PRELOAD, which the
// dynamic loader honors for every ELF executable that isn't statically
// linked or otherwise hardened against it -- including git, bash, and any
// other controller-tool invocation a governed run makes. This test builds
// a real hostile shared object (via cc/gcc, available on this host) whose
// constructor leaves a marker file the instant it is loaded, points
// LD_PRELOAD at it for the duration of the run, and asserts the marker
// never appears even though the run's own controller-tool invocations
// (git, bash) succeed normally.
func TestV6Case7LDPreloadControllerInjectionNeverExecutes(t *testing.T) {

	if _, err := lookPathAny("cc", "gcc"); err != nil {
		t.Skipf("no C compiler available to build the LD_PRELOAD fixture: %v", err)
	}

	root := fixtureRepo(t)
	marker := filepath.Join(t.TempDir(), "ld-preload-ran.txt")
	srcPath := filepath.Join(t.TempDir(), "ld_preload_marker.c")
	soPath := filepath.Join(t.TempDir(), "ld_preload_marker.so")
	src := `#include <stdio.h>
__attribute__((constructor))
static void governator_redteam_ld_preload_marker(void) {
    FILE *f = fopen("` + marker + `", "a");
    if (f) { fputc('x', f); fclose(f); }
}
`
	if err := os.WriteFile(srcPath, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	buildLDPreloadFixture(t, srcPath, soPath)
	t.Setenv("LD_PRELOAD", soPath)
	// S3 exercises controller environment sanitization, not host descendant
	// primitive availability. Keep this corpus case runnable on hosts without
	// writable cgroup/systemd scopes.
	t.Setenv("GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING", "off")
	t.Setenv("GOV_CONTAINMENT_FORCE_DEGRADED", "1")

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))
	rec := runGoverned(t, t.TempDir(), bin, c)

	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED (the well-behaved backend/validator must still succeed once LD_PRELOAD is stripped from controller-tool launches), got status=%s message=%s", rec.Status, rec.Message)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("LD_PRELOAD-injected shared object's constructor ran during a governed run's controller-tool invocations -- controller-tool environments must be built from an allowlist, never inherit LD_PRELOAD")
	}
}
