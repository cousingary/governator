package attest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
