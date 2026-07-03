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
