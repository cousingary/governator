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

// TestSol3TotalProbeDeadlineIsConfigurable is the P1-17 counterpart to
// TestSol3ProbeTimeoutIsConfigurable: the whole suite's ceiling must default
// to something sane (today's actual 3-probe worst case, now enforced) and
// honor an explicit operator override.
func TestSol3TotalProbeDeadlineIsConfigurable(t *testing.T) {
	if got := totalProbeDeadlineFor(config.Config{}); got != defaultTotalProbeDeadline {
		t.Fatalf("zero-value config must fall back to %v, got %v", defaultTotalProbeDeadline, got)
	}
	if defaultTotalProbeDeadline != 3*defaultProbeTimeout {
		t.Fatalf("default total deadline should preserve today's actual 3-probe worst case, got %v (3x probe timeout = %v)", defaultTotalProbeDeadline, 3*defaultProbeTimeout)
	}
	cfg := config.Config{}
	cfg.Attest.TotalDeadlineSeconds = 120
	if got := totalProbeDeadlineFor(cfg); got != 120*time.Second {
		t.Fatalf("configured total deadline must be honored, got %v", got)
	}
	if built := config.BuiltIn(); built.Attest.TotalDeadlineSeconds != 900 {
		t.Fatalf("default total deadline must be 900s (3x the 300s per-probe default), got %d", built.Attest.TotalDeadlineSeconds)
	}
}

// TestSol3TotalProbeDeadlineBoundsWholeSuite proves the total deadline
// actually caps the SUM of probe time, not just each probe individually: a
// per-probe budget generous enough for any one probe (10s) but a total
// deadline too small for all three probes in sequence (1s) must still bound
// the whole Generate call to roughly the total, not 3x the per-probe value.
func TestSol3TotalProbeDeadlineBoundsWholeSuite(t *testing.T) {
	fake := writeSol3FakeBackend(t, `if [ "${1:-}" = "--version" ]; then echo "codex fake 1.0"; exit 0; fi
sleep 10
exit 0
`)
	t.Setenv("GOV_HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("GOV_CODEX_BIN", fake)

	cfg := config.Current()
	cfg.Attest.ProbeTimeoutSeconds = 10 // generous per-probe -- would let all 3 probes hang up to 30s combined without a total ceiling
	cfg.Attest.TotalDeadlineSeconds = 1 // but the whole suite gets only 1s
	agent, err := agents.New("codex")
	if err != nil {
		t.Fatal(err)
	}
	res, err := agents.Resolve(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	a, err := GenerateFromResolution(context.Background(), cfg, agent, res)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed > 8*time.Second {
		t.Fatalf("total deadline did not bound the suite: elapsed=%v (per-probe alone could have allowed up to ~30s)", elapsed)
	}
	if a.SandboxProbe || a.NetworkProbe || a.TranscriptProbe {
		t.Fatalf("a probe cut short by the total deadline must not be attested: %+v", a)
	}
	if a.ProbeSuiteTotalMS <= 0 {
		t.Fatalf("expected a recorded total suite duration, got %d", a.ProbeSuiteTotalMS)
	}
}
