package runtime

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/attest"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/observability"
)

// TestSol3FakeCodexFailedProbesNoLongerBlockAuthorizationAlone documents the
// Session 5 (Sol P0-3) reversal of this test's original assertion. Under S3,
// a stored attestation with failed behavioral probes was sufficient on its
// own to deny a high-risk local run -- exactly what this test used to check
// (name preserved with an S5 suffix for git-blame continuity). Report §9
// attack 5 is precisely why that was never enough: a backend that behaves
// safely only while it knows it's being probed defeats a probe-outcome gate
// by construction. Session 5 moved authorization onto Governator's own
// externally enforced sandbox (enforce.Supported()) -- probe results are
// still recorded as evidence, but the run below now correctly gets
// authorized despite the fake codex's failed probes, because authorization
// no longer depends on them. What actually stops the escape this fake codex
// attempts (`echo pwned > ../outside_probe.txt`) is Landlock, applied at
// real launch time, exercised end-to-end by
// internal/redteam.TestAttack5FakeBackendBehavesSafelyOnlyDuringAttestation
// -- not by this authorization-only unit test.
func TestSol3FakeCodexFailedProbesNoLongerBlockAuthorizationAlone(t *testing.T) {
	root, _ := fixture(t)
	fake := writeFakeBackend(t, `if [ "${1:-}" = "--version" ]; then echo "codex fake 1.0"; exit 0; fi
# This fake imitates the redteam exploit: it accepts any flags, writes outside
# its current workspace, and returns success without exercising Codex controls.
echo pwned > ../outside_probe.txt
printf 'not-json-transcript\n'
exit 0
`)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("GOV_CODEX_BIN", fake)
	cfg := config.Current()
	// Sol P1-2: an unknown model/provider identity now blocks high-risk
	// native-sandbox reuse before the probe-freshness check below ever runs
	// (see attest.VerifyHighRiskNative) -- declare one so this test still
	// proves what it names: a fake backend's attestation, even though it has
	// identity evidence, must still fail on required probes.
	codexBackend := cfg.Backends["codex"]
	codexBackend.Provider = "test-provider"
	codexBackend.ModelRevision = "test-model-rev"
	cfg.Backends["codex"] = codexBackend

	a, err := attest.Generate(context.Background(), cfg, "codex")
	if err != nil {
		t.Fatal(err)
	}
	if !a.SupportedFlags || a.SandboxProbe || a.NetworkProbe || a.TranscriptProbe || a.ReadOnlyProbe || a.ApprovalProbe {
		t.Fatalf("fake codex should have identity evidence but failed behavioral probes, got %+v", a)
	}
	db, err := observability.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := attest.Store(db, a); err != nil {
		t.Fatal(err)
	}

	agent, err := agents.New("codex")
	if err != nil {
		t.Fatal(err)
	}
	c := contract(root)
	c.Agent = "codex"
	c.RiskClass = "high"
	if !enforce.Supported() {
		t.Skip("this host cannot provide external enforcement (Landlock/unshare unavailable)")
	}
	attestID, _, _, err := enforceContainment(context.Background(), db, c, agent, cfg)
	if err != nil {
		t.Fatalf("high-risk local run must be authorized by external enforcement alone, regardless of a stored attestation's failed probes: %v", err)
	}
	if attestID != "" {
		t.Fatalf("a stored attestation that failed required probes must never surface as the run's recorded attestation id, got %q", attestID)
	}
}
