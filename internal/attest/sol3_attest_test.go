package attest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/config"
)

func writeSol3FakeBackend(t *testing.T, body string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fake-backend")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nset -eu\n"+body), 0755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestSol3FakeCodexVersionStringDoesNotAttestCapabilities(t *testing.T) {
	fake := writeSol3FakeBackend(t, `if [ "${1:-}" = "--version" ]; then echo "codex fake 1.0"; exit 0; fi
# Simulate the audit exploit: ignore Governator/Codex flags and write outside
# the scratch workspace. A version string containing "codex" must not convert
# static adapter declarations into successful behavioral probes.
echo pwned > ../outside_probe.txt
printf 'not-json-transcript\n'
exit 0
`)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("GOV_CODEX_BIN", fake)

	cfg := config.Current()
	agent, err := agents.New("codex")
	if err != nil {
		t.Fatal(err)
	}
	res, err := agents.Resolve(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	a, err := GenerateFromResolution(context.Background(), cfg, agent, res)
	if err != nil {
		t.Fatal(err)
	}
	if !a.SupportedFlags {
		t.Fatalf("version identity evidence should be recorded as supported_flags for this fake; got %+v", a)
	}
	if a.SandboxProbe || a.NetworkProbe || a.TranscriptProbe || a.ReadOnlyProbe || a.ApprovalProbe {
		t.Fatalf("version string must not synthesize behavioral probe success: %+v", a)
	}
	if a.ProbeSuiteVersion != ProbeSuiteVersion || a.ExecutableFileIdentity == "" || a.BackendConfigHash == "" {
		t.Fatalf("attestation missing binding fields: %+v", a)
	}
	if !strings.Contains(a.ProbeNotes, "sibling write") || !strings.Contains(a.ProbeNotes, "transcript") {
		t.Fatalf("probe notes should explain failed behavioral evidence, got %q", a.ProbeNotes)
	}
}

// A probe that never returns a verdict — the backend hangs past the budget —
// must fail CLOSED (capability not assumed present) AND be recorded as
// UNOBSERVED, not as a denial. Before attest.probe_timeout_seconds existed, the
// budget was a hardcoded 30s that no real multi-step agent turn could meet, so
// every real backend recorded sandbox/network/transcript as unattested and no
// operator could tell a slow probe harness from an uncontained backend.
func TestSol3ProbeTimeoutRecordsUnobservedNotDenial(t *testing.T) {
	fake := writeSol3FakeBackend(t, `if [ "${1:-}" = "--version" ]; then echo "codex fake 1.0"; exit 0; fi
sleep 30
exit 0
`)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("GOV_CODEX_BIN", fake)

	cfg := config.Current()
	cfg.Attest.ProbeTimeoutSeconds = 1 // force the hang to exceed the budget
	agent, err := agents.New("codex")
	if err != nil {
		t.Fatal(err)
	}
	res, err := agents.Resolve(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	a, err := GenerateFromResolution(context.Background(), cfg, agent, res)
	if err != nil {
		t.Fatal(err)
	}
	if a.SandboxProbe || a.NetworkProbe || a.TranscriptProbe {
		t.Fatalf("a probe that never completed must not be attested: %+v", a)
	}
	if !strings.Contains(a.ProbeNotes, "UNOBSERVED") {
		t.Fatalf("timeout must record UNOBSERVED, not a denial; notes=%q", a.ProbeNotes)
	}
}

// The configured budget must actually reach the probe: a generous budget lets a
// slow-but-honest backend finish, which is the whole point of making it tunable.
func TestSol3ProbeTimeoutIsConfigurable(t *testing.T) {
	if got := probeTimeoutFor(config.Config{}); got != defaultProbeTimeout {
		t.Fatalf("zero-value config must fall back to %v, got %v", defaultProbeTimeout, got)
	}
	cfg := config.Config{}
	cfg.Attest.ProbeTimeoutSeconds = 600
	if got := probeTimeoutFor(cfg); got != 600*time.Second {
		t.Fatalf("configured budget must be honored, got %v", got)
	}
	if built := config.BuiltIn(); built.Attest.ProbeTimeoutSeconds != 300 {
		t.Fatalf("default probe budget must cover a real agent turn, got %d", built.Attest.ProbeTimeoutSeconds)
	}
}
