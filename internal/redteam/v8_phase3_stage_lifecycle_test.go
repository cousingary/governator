//go:build redteam

package redteam

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/controllerenv"
	stageexec "github.com/cousingary/governator/internal/stage"
)

func runV8Stage(t *testing.T, stageID string, command string, limit int64, mode stageexec.OutputCaptureMode, timeout time.Duration) (stageexec.StageResult, error) {
	t.Helper()
	executable, err := stageexec.HashExecutable("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	env := controllerenv.Base()
	return stageexec.NewExecutor().Run(context.Background(), stageexec.StageSpec{
		RunID: "v8-phase3", StageID: stageID, Executable: executable,
		Arguments:     []string{"-c", command},
		Environment:   stageexec.FrozenEnvironment{Values: env, Hash: controllerenv.Hash(env)},
		OutputLimit:   limit,
		OutputCapture: mode,
		Timeout:       timeout,
	})
}

// TestV8Case1BackendUnlimitedStdoutHitsStageOutputLimit proves a stage that
// emits an unbounded stream cannot fill Governator memory: evidence-critical
// capture has a mandatory finite cap and crossing it terminates the stage.
func TestV8Case1BackendUnlimitedStdoutHitsStageOutputLimit(t *testing.T) {
	res, err := runV8Stage(t, "unlimited-stdout", "while :; do printf 0123456789; done", 128, stageexec.CaptureRequiredComplete, 5*time.Second)
	if !errors.Is(err, stageexec.ErrOutputLimitExceeded) {
		t.Fatalf("error = %v, want STAGE_OUTPUT_LIMIT_EXCEEDED", err)
	}
	if !res.OutputTruncated || len(res.Output) != 128 {
		t.Fatalf("limit evidence = truncated:%v len:%d", res.OutputTruncated, len(res.Output))
	}
}

// TestV8Case2StdoutAndStderrShareAggregateStageOutputCap prevents the old
// split-budget bug where stdout and stderr each received the nominal cap.
func TestV8Case2StdoutAndStderrShareAggregateStageOutputCap(t *testing.T) {
	res, err := runV8Stage(t, "aggregate-cap", "printf 12345; printf 67890 >&2", 7, stageexec.CaptureBounded, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OutputTruncated {
		t.Fatal("aggregate cap did not report truncation")
	}
	if got := len(res.Output); got != 7 {
		t.Fatalf("captured bytes = %d, want one shared cap of 7; output %q", got, res.Output)
	}
}

// TestV8Case9StageWrapperTimeoutBoundsWaitAndExtinguishes covers timeout
// lifecycle hardening: timeout handling must not wait forever on cmd.Wait,
// and descendant extinction must be proven before the caller can proceed.
func TestV8Case9StageWrapperTimeoutBoundsWaitAndExtinguishes(t *testing.T) {
	start := time.Now()
	res, err := runV8Stage(t, "timeout-wrapper", `trap "" TERM; while :; do :; done`, 0, stageexec.CaptureNone, 100*time.Millisecond)
	if err == nil || (!errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "signal: killed")) {
		t.Fatalf("timeout error = %v, want deadline/kill", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("timeout handling was not bounded; elapsed %s", time.Since(start))
	}
	if !res.DescendantsGone {
		t.Fatalf("descendant extinction not proven after timeout: %#v", res)
	}
}
