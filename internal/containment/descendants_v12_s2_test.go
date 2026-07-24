package containment

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/toolregistry"
)

// descendants_v12_s2_test.go holds the Sol v12 rc5 Session 2 containment-level
// corpus case (agents/governator-sol-upgrade12-rc5-plan.md Session 2, report
// P0-1). It lives in package containment (untagged, like its sibling
// TestV10Case12/13) because it exercises the unexported newSystemdUserScope
// selection path and the /proc/self/fd leak counter directly. Enrolled by
// exact name in internal/redteam/manifest.yaml (case 206).

// TestV12Case8DeterministicSystemdUnavailableFailurePath proves the
// determinism correction at the heart of P0-1's mutually-exclusive-cases
// defect. Before Session 2, TestV10Case12 (report case 12) could only run
// where the host genuinely LACKED a systemd --user manager -- so on a host
// that had one (this project's own dev box), case 12 always skipped while its
// partner case 13 (the real live-systemd launch) ran, making a correct
// single-host zero-skip red-team run structurally impossible. The
// ScopeSelectionForceUnavailableForTesting seam injects the selection failure
// deterministically, so this case proves the absent-systemd fallback's
// zero-descriptor-leak invariant on EVERY host -- including one with a live
// systemd --user bus present, the exact condition that previously forced a
// skip. It deliberately does NOT skip on /run/user/<uid>/bus presence.
func TestV12Case8DeterministicSystemdUnavailableFailurePath(t *testing.T) {
	// Record the host's real systemd --user state and assert the outcome is
	// identical either way: this is the determinism guarantee (the previous
	// test skipped precisely when busPresent was true).
	busPresent := false
	if _, err := os.Stat(fmt.Sprintf("/run/user/%d/bus", os.Getuid())); err == nil {
		busPresent = true
	}

	ScopeSelectionForceUnavailableForTesting.Store(true)
	t.Cleanup(func() { ScopeSelectionForceUnavailableForTesting.Store(false) })

	t.Setenv("GOV_TOOLREGISTRY_FILE", t.TempDir()+"/tools.yaml")
	v10s2EnrollTamperableScript(t, "systemd-run", "#!/bin/sh\nexit 0\n")
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ResolveEnvironment(registry)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	if env.SystemdRun == nil {
		t.Fatal("expected systemd-run to resolve into the frozen environment (the borrowed handle this failure path must not leak)")
	}

	before := v10s2CountOpenFDs(t)
	for i := 0; i < 20; i++ {
		s, err := newSystemdUserScope("v12-case8", env.SystemdRun)
		if err == nil {
			t.Fatalf("newSystemdUserScope succeeded with the forced-unavailable seam set (host busPresent=%v); the selection failure must be deterministic", busPresent)
		}
		if s != nil {
			t.Fatalf("newSystemdUserScope returned a non-nil scope alongside an error")
		}
		if !strings.Contains(err.Error(), "test-forced scope-selection failure") {
			t.Fatalf("expected the deterministic forced-failure error, got: %v", err)
		}
	}
	after := v10s2CountOpenFDs(t)
	if after > before {
		t.Fatalf("20 forced scope-selection failures leaked descriptors on a host with busPresent=%v: before=%d after=%d", busPresent, before, after)
	}
}
