package runtime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contextgraph"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

func TestBuildHandoffIsBoundedAndExcludesBulkContext(t *testing.T) {
	long := strings.Repeat("x", 2000)
	record := RunRecord{
		ID: "run-1", JobID: "job-1", Status: "APPROVED", Message: long,
		Diff:       "diff --git a/internal/a.go b/internal/a.go\n" + long,
		Transcript: long, ToolCalls: 7, TranscriptBytes: 2000,
		Usage: observability.TokenUsage{InputTokens: 100, OutputTokens: 20, TotalTokens: 120, Available: true},
		Graph: contextgraph.Snapshot{Provider: "codegraph", Version: "0.24.0", Fingerprint: strings.Repeat("a", 64), FileCount: 51, NodeCount: 689, EdgeCount: 1579},
		SelfReview: &contracts.ResultDocument{
			FilesChanged: []string{"internal/a.go"}, Blockers: []string{long},
			NextRecommendedAction: long,
		},
	}
	handoff := BuildHandoff(record)
	if handoff.RunID != "run-1" || handoff.Usage.TotalTokens != 120 || handoff.Graph.Fingerprint != record.Graph.Fingerprint {
		t.Fatalf("handoff=%+v", handoff)
	}
	if len([]rune(handoff.Summary)) > handoffMaxSummaryRunes || len([]rune(handoff.Blockers[0])) > handoffMaxItemRunes || len([]rune(handoff.NextRecommendedAction)) > handoffMaxActionRunes {
		t.Fatalf("handoff fields were not bounded: %+v", handoff)
	}
	encoded, err := json.Marshal(handoff)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "Transcript") || len(encoded) >= 4096 {
		t.Fatalf("handoff is not compact: bytes=%d payload=%s", len(encoded), encoded)
	}
}

func TestBuildHandoffDerivesFilesFromDiff(t *testing.T) {
	record := RunRecord{Diff: "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\ndiff --git a/b.go b/b.go\n"}
	handoff := BuildHandoff(record)
	if strings.Join(handoff.FilesChanged, ",") != "a.go,b.go" {
		t.Fatalf("files=%v", handoff.FilesChanged)
	}
}
