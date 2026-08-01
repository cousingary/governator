package stage

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/enforce"
)

func truePath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("true")
	if err != nil {
		t.Fatalf("locate true: %v", err)
	}
	return p
}

func TestExecutorUsesOnlyFrozenEnvironment(t *testing.T) {
	// This test asserts the child environment, not host scope selection.
	// Keep a hosted runner's ambient systemd-run from turning that unrelated
	// capability into a fixture dependency.
	containment.ForceDegradedScopeForTesting.Store(true)
	t.Cleanup(func() { containment.ForceDegradedScopeForTesting.Store(false) })

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
		OutputLimit:      1 << 20,
		OutputCapture:    CaptureRequiredComplete,
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
	executable, err := HashExecutable(truePath(t))
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

func TestExecutorRequiresOutputLimitForCapturedStages(t *testing.T) {
	executable, err := HashExecutable(truePath(t))
	if err != nil {
		t.Fatal(err)
	}
	env := controllerenv.Base()
	_, err = NewExecutor().Run(context.Background(), StageSpec{
		RunID: "phase3", StageID: "no-limit", Executable: executable,
		Environment: FrozenEnvironment{Values: env, Hash: controllerenv.Hash(env)},
	})
	if err == nil || !strings.Contains(err.Error(), "output limit required") {
		t.Fatalf("missing output limit error = %v", err)
	}
}

func TestExecutorUsesOneAggregateOutputBudget(t *testing.T) {
	executable, err := HashExecutable("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	env := controllerenv.Base()
	res, err := NewExecutor().Run(context.Background(), StageSpec{
		RunID: "phase3", StageID: "aggregate-limit", Executable: executable,
		Arguments:     []string{"-c", "printf 12345; printf 67890 >&2"},
		Environment:   FrozenEnvironment{Values: env, Hash: controllerenv.Hash(env)},
		OutputLimit:   7,
		OutputCapture: CaptureBounded,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OutputTruncated {
		t.Fatal("aggregate cap did not report truncation")
	}
	if got := len(res.Output); got != 7 {
		t.Fatalf("captured bytes = %d, want shared cap 7; output %q", got, res.Output)
	}
}

func TestExecutorRequiredCompleteOutputLimitTerminatesStage(t *testing.T) {
	executable, err := HashExecutable("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	env := controllerenv.Base()
	start := time.Now()
	res, err := NewExecutor().Run(context.Background(), StageSpec{
		RunID: "phase3", StageID: "limit-kills", Executable: executable,
		Arguments:     []string{"-c", "while :; do printf 0123456789; done"},
		Environment:   FrozenEnvironment{Values: env, Hash: controllerenv.Hash(env)},
		OutputLimit:   64,
		OutputCapture: CaptureRequiredComplete,
		Timeout:       5 * time.Second,
	})
	if !errors.Is(err, ErrOutputLimitExceeded) {
		t.Fatalf("error = %v, want ErrOutputLimitExceeded", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("stage kept running after required-complete output cap")
	}
	if !res.OutputTruncated {
		t.Fatal("limit kill did not report truncation")
	}
	if got := len(res.Output); got != 64 {
		t.Fatalf("captured bytes = %d, want 64", got)
	}
}

func TestExecutorCaptureNoneDoesNotRetainStreamedOutput(t *testing.T) {
	executable, err := HashExecutable("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	env := controllerenv.Base()
	var streamed strings.Builder
	res, err := NewExecutor().Run(context.Background(), StageSpec{
		RunID: "phase3", StageID: "capture-none", Executable: executable,
		Arguments:     []string{"-c", "printf streamed"},
		Environment:   FrozenEnvironment{Values: env, Hash: controllerenv.Hash(env)},
		OutputCapture: CaptureNone,
		Stdout:        &streamed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if streamed.String() != "streamed" {
		t.Fatalf("streamed output = %q", streamed.String())
	}
	if res.Output != "" {
		t.Fatalf("capture-none retained output %q", res.Output)
	}
}

func TestExecutorRejectsAuthorityThatNeedsSandboxWithoutSupport(t *testing.T) {
	executable, err := HashExecutable(truePath(t))
	if err != nil {
		t.Fatal(err)
	}
	enforce.ForceUnsupported = true
	defer func() { enforce.ForceUnsupported = false }()
	env := controllerenv.Base()
	_, err = NewExecutor().Run(context.Background(), StageSpec{
		RunID: "phase3", StageID: "authority-no-plan", Executable: executable,
		Environment:      FrozenEnvironment{Values: env, Hash: controllerenv.Hash(env)},
		OutputCapture:    CaptureNone,
		DescendantPolicy: DescendantPolicy{RequireStrong: true},
		Authority:        StageAuthority{ReadRoots: []string{"."}, Network: NetworkPolicyDenied, Credentials: CredentialPolicyNone, RequireStrongScope: true},
		CommandFactory: func(context.Context, *containment.Scope, enforce.Plan, string, []string, string) (*exec.Cmd, error) {
			return nil, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "construct authority plan") {
		t.Fatalf("missing sandbox error = %v", err)
	}
}

func TestExecutorRejectsAuthorityStrongScopeMismatch(t *testing.T) {
	executable, err := HashExecutable(truePath(t))
	if err != nil {
		t.Fatal(err)
	}
	env := controllerenv.Base()
	_, err = NewExecutor().Run(context.Background(), StageSpec{
		RunID: "phase3", StageID: "scope-mismatch", Executable: executable,
		Environment:   FrozenEnvironment{Values: env, Hash: controllerenv.Hash(env)},
		OutputCapture: CaptureNone,
		Authority:     StageAuthority{RequireStrongScope: true},
	})
	if err == nil || !strings.Contains(err.Error(), "requires strong descendant scope") {
		t.Fatalf("scope mismatch error = %v", err)
	}
}

func TestExecutorRejectsAuthorityPlanContradiction(t *testing.T) {
	if !enforce.Supported() {
		t.Skip("host containment (Landlock + unshare) not available")
	}
	executable, err := HashExecutable(truePath(t))
	if err != nil {
		t.Fatal(err)
	}
	env := controllerenv.Base()
	_, err = NewExecutor().Run(context.Background(), StageSpec{
		RunID: "phase3", StageID: "plan-contradiction", Executable: executable,
		Environment:      FrozenEnvironment{Values: env, Hash: controllerenv.Hash(env)},
		OutputCapture:    CaptureNone,
		DescendantPolicy: DescendantPolicy{RequireStrong: true},
		Authority:        StageAuthority{ReadRoots: []string{"."}, Network: NetworkPolicyDenied, Credentials: CredentialPolicyNone, RequireStrongScope: true},
		EnforcementPlan:  enforce.Plan{Active: true, ReadOnly: true, AllowNetwork: true},
		CommandFactory: func(context.Context, *containment.Scope, enforce.Plan, string, []string, string) (*exec.Cmd, error) {
			return nil, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "authority denies network but plan allows it") {
		t.Fatalf("plan contradiction error = %v", err)
	}
}
