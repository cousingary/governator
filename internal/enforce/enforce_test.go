package enforce

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWrapUsesRegistryResolvedUnsharePath is Session 2 (post-v4 hardening
// plan item C): Wrap used to return the bare literal "unshare" as the argv0
// for the network-denial launch, letting os/exec's own ambient PATH lookup
// resolve it -- a hostile "unshare" placed earlier on Governator's own
// process PATH would run with full authority instead of the real
// unshare(1). NewPlan now resolves+verifies unshare through the
// trusted-tool registry once and binds the canonical path into the Plan;
// this test constructs a Plan directly (bypassing NewPlan's Landlock/
// Supported() dependency, which this host may not have) and asserts Wrap
// returns that bound path, never a bare "unshare" string that could still
// be redirected by PATH.
func TestWrapUsesRegistryResolvedUnsharePath(t *testing.T) {
	pinnedUnshare := filepath.Join(t.TempDir(), "unshare")
	if err := os.WriteFile(pinnedUnshare, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	p := Plan{
		Active:       true,
		Workspace:    t.TempDir(),
		AllowNetwork: false,
		selfExe:      "/fake/gov",
		unsharePath:  pinnedUnshare,
	}

	bin, args := p.Wrap("some-backend", []string{"--flag"})
	if bin != pinnedUnshare {
		t.Fatalf("Wrap returned bin=%q, want the registry-resolved path %q (a bare \"unshare\" would let ambient PATH redirect it)", bin, pinnedUnshare)
	}
	if len(args) == 0 || args[len(args)-2] != "some-backend" {
		t.Fatalf("Wrap args malformed, backend not found where expected: %v", args)
	}
}

// TestNewPlanFailsClosedWhenUnshareUnresolvable proves Supported() (and
// therefore NewPlan, which gates on it) now incorporates the trusted-tool
// registry's own verdict, not just "is a file named unshare somewhere on
// PATH": pinning unshare to a path that does not exist must make
// Supported() false and, for a high-risk request, make NewPlan refuse
// outright -- exactly as if unshare were entirely absent from the host --
// rather than the old bare exec.LookPath("unshare") existence check, which
// this same setup would have satisfied.
func TestNewPlanFailsClosedWhenUnshareUnresolvable(t *testing.T) {
	if !Supported() {
		t.Skip("host cannot provide external enforcement (no Landlock/unshare) -- nothing to prove here")
	}
	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	// A registry entry that pins unshare to a path that does not exist:
	// Resolve must fail (stat/open error), and NewPlan must propagate that
	// failure rather than falling back to an unverified ambient lookup.
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	yaml := "tools:\n  - name: unshare\n    kind: trusted_controller\n    path: " + missing + "\n"
	if err := os.WriteFile(registryFile, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	// highRisk=true: NewPlan's documented contract is to refuse outright
	// when this host cannot actually provide external enforcement, rather
	// than silently returning an inactive Plan a high-risk contract would
	// then launch unconfined by.
	if _, err := NewPlan(true, t.TempDir(), false, false, true); err == nil {
		t.Fatal("expected NewPlan to fail closed when unshare cannot be resolved through the trusted-tool registry")
	}
}
