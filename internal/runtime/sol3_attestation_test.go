package runtime

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/attest"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/observability"
)

func TestSol3FakeCodexAttestationCannotAuthorizeHighRiskLocal(t *testing.T) {
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
	_, err = enforceContainment(db, c, agent, cfg)
	if err == nil || !strings.Contains(err.Error(), "failed required probes") {
		t.Fatalf("high-risk local run must reject fake codex attestation, got %v", err)
	}
}
