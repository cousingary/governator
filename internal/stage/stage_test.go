package stage

import (
	"context"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/controllerenv"
)

func TestExecutorUsesOnlyFrozenEnvironment(t *testing.T) {
	executable, err := HashExecutable("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	frozen := controllerenv.Frozen{Values: []string{"HOME=/frozen/home", "PATH=/frozen/bin"}}
	frozen.Hash = controllerenv.Hash(frozen.Values)
	t.Setenv("PATH", "/attacker/bin")
	t.Setenv("HOME", "/attacker/home")

	result, err := NewExecutor().Run(context.Background(), StageSpec{
		RunID: "s3-test", StageID: "frozen-env", Executable: executable,
		Arguments:        []string{"-c", `printf '%s|%s' "$PATH" "$HOME"`},
		Environment:      FrozenEnvironment{Values: frozen.Values, Hash: frozen.Hash},
		DescendantPolicy: DescendantPolicy{RequireStrong: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(result.Output); got != "/frozen/bin|/frozen/home" {
		t.Fatalf("stage environment = %q", got)
	}
	if result.EnvironmentHash != frozen.Hash {
		t.Fatalf("evidence hash = %q, want %q", result.EnvironmentHash, frozen.Hash)
	}
}

func TestExecutorRejectsMissingOrMismatchedFrozenEnvironment(t *testing.T) {
	executable, err := HashExecutable("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	base := StageSpec{RunID: "s3-test", StageID: "missing-env", Executable: executable}
	if _, err := NewExecutor().Run(context.Background(), base); err == nil || !strings.Contains(err.Error(), "missing frozen environment") {
		t.Fatalf("missing environment error = %v", err)
	}
	base.Environment = FrozenEnvironment{Values: []string{"PATH=/trusted"}, Hash: "wrong"}
	if _, err := NewExecutor().Run(context.Background(), base); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("mismatched environment error = %v", err)
	}
}
