package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/contracts"
)

func TestParseTokenUsageBackendShapes(t *testing.T) {
	tests := []struct {
		name       string
		values     map[string]any
		total      int64
		cached     int64
		cacheWrite int64
	}{
		{name: "claude", values: map[string]any{"input_tokens": float64(10), "output_tokens": float64(5), "cache_read_input_tokens": float64(20), "cache_creation_input_tokens": float64(3)}, total: 38, cached: 20, cacheWrite: 3},
		{name: "codex", values: map[string]any{"input_tokens": float64(100), "cached_input_tokens": float64(70), "output_tokens": float64(25), "reasoning_output_tokens": float64(5)}, total: 130, cached: 70},
		{name: "opencode", values: map[string]any{"input": float64(8), "output": float64(2), "reasoning": float64(1), "cacheRead": float64(4), "cacheWrite": float64(3)}, total: 18, cached: 4, cacheWrite: 3},
		{name: "pi", values: map[string]any{"input": float64(8), "output": float64(2), "cacheRead": float64(4), "cacheWrite": float64(3), "totalTokens": float64(17)}, total: 17, cached: 4, cacheWrite: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usage, ok := parseTokenUsage(tt.values)
			if !ok || !usage.Available {
				t.Fatal("usage not detected")
			}
			if usage.TotalTokens != tt.total || usage.CachedInputTokens != tt.cached || usage.CacheCreationTokens != tt.cacheWrite {
				t.Fatalf("unexpected usage: %+v", usage)
			}
		})
	}
}

func TestUsageAccumulatorSumsDistinctMessages(t *testing.T) {
	acc := newUsageAccumulator()
	acc.walk(agents.TranscriptPi, map[string]any{"id": "a", "usage": map[string]any{"input": float64(10), "output": float64(2), "totalTokens": float64(12)}})
	acc.walk(agents.TranscriptPi, map[string]any{"id": "b", "usage": map[string]any{"input": float64(4), "output": float64(1), "totalTokens": float64(5)}})
	acc.walk(agents.TranscriptPi, map[string]any{"id": "a", "usage": map[string]any{"input": float64(11), "output": float64(2), "totalTokens": float64(13)}})
	usage, _ := acc.result()
	if usage.TotalTokens != 18 || usage.InputTokens != 15 {
		t.Fatalf("unexpected accumulated usage: %+v", usage)
	}
}

func TestAuditTranscriptEnforcesMaxTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transcript.jsonl")
	line := `{"type":"result","usage":{"input_tokens":90,"output_tokens":20}}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	contract := contracts.Contract{}
	contract.Budget.MaxTokens = 100
	contract.Budget.MaxCommands = 10
	audit := auditTranscript(path, agents.TranscriptClaude, "", contract, nil, "")
	if audit.Usage.TotalTokens != 110 || audit.TranscriptBytes != int64(len(line)) {
		t.Fatalf("unexpected audit telemetry: %+v", audit)
	}
	if len(audit.Violations) != 1 || !strings.Contains(audit.Violations[0], "max_tokens exceeded: 110 > 100") {
		t.Fatalf("expected token violation, got %v", audit.Violations)
	}
}

func TestTelemetryModesHandleUnavailableUsage(t *testing.T) {
	strict := contracts.Contract{Budget: contracts.Budget{MaxTokens: 100}}
	got := telemetryViolations(strict, transcriptAudit{})
	if len(got) != 1 || !strings.Contains(got[0], "strict telemetry unavailable") {
		t.Fatalf("strict max_tokens contract must fail closed on unavailable usage, got %v", got)
	}

	for _, mode := range []string{"estimated", "advisory"} {
		c := contracts.Contract{TelemetryMode: mode, Budget: contracts.Budget{MaxTokens: 100}}
		if got := telemetryViolations(c, transcriptAudit{}); len(got) != 0 {
			t.Fatalf("%s telemetry should not block unavailable usage, got %v", mode, got)
		}
	}
}

func TestStageTimeoutFailsWhenRunBudgetExpired(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	stageCtx, stageCancel, err := stageTimeout(ctx, "validator")
	defer stageCancel()
	if err == nil || !strings.Contains(err.Error(), "run deadline exceeded before validator") {
		t.Fatalf("expected expired run budget error, got %v", err)
	}
	if stageCtx.Err() == nil {
		t.Fatal("expected returned stage context to already be canceled")
	}
}
