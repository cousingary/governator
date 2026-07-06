package contracts

import (
	"strings"
	"testing"
)

func TestCompilePromptIsModeAware(t *testing.T) {
	c := Contract{Task: "repair one defect", Mode: ModeSurgeon}
	prompt, err := CompilePrompt(c, "/tmp/worktree")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"smallest targeted change", "repair one defect", "/tmp/worktree", "RESULT.json", "files_changed"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %q", want)
		}
	}
}

func TestContractHashIsStable(t *testing.T) {
	c := Contract{JobID: "x", Mode: ModeVerifier}
	a, err := ContractHash(c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ContractHash(c)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || len(a) != 64 {
		t.Fatalf("unstable hash %q %q", a, b)
	}
}

func TestCompilePromptTerseOutputPolicy(t *testing.T) {
	c := Contract{
		Task:   "repair one defect",
		Mode:   ModeSurgeon,
		Output: &OutputPolicy{Style: "terse", MaxFinalWords: 80},
	}
	prompt, err := CompilePrompt(c, "/tmp/worktree")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Output discipline: terse", "under 80 words", "Never omit evidence"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %q", want)
		}
	}
}

// TestCompilePromptNetworkAnnotationOnlyWhenForbidden asserts the prompt-level
// network nudge fires only when the contract forbids network, and that it names
// the concrete verbs a compensated backend (Claude/GLM/OpenCode/Pi) otherwise
// learns the hard way from a post-hoc quarantine.
func TestCompilePromptNetworkAnnotationOnlyWhenForbidden(t *testing.T) {
	allowed := Contract{Task: "t", Mode: ModeSurgeon}
	prompt, err := CompilePrompt(allowed, "/tmp/w")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, "Network discipline") {
		t.Fatalf("network annotation leaked into a contract that does not forbid network")
	}

	forbidden := Contract{Task: "t", Mode: ModeSurgeon, Forbidden: Forbidden{Behaviors: []string{"network"}}}
	prompt, err = CompilePrompt(forbidden, "/tmp/w")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Network discipline", "curl", "npm/pnpm/yarn install", "pip install", "git push", "quarantines the run"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("network annotation missing %q", want)
		}
	}
}
