package runtime

import (
	"strings"

	"github.com/cousingary/governator/internal/observability"
)

const (
	handoffMaxSummaryRunes = 500
	handoffMaxActionRunes  = 500
	handoffMaxItemRunes    = 300
	handoffMaxFiles        = 50
	handoffMaxBlockers     = 10
)

type HandoffGraph struct {
	Provider    string `json:"provider,omitempty"`
	Version     string `json:"version,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	FileCount   int    `json:"file_count,omitempty"`
	NodeCount   int    `json:"node_count,omitempty"`
	EdgeCount   int    `json:"edge_count,omitempty"`
}

type Handoff struct {
	RunID                 string                   `json:"run_id"`
	JobID                 string                   `json:"job_id"`
	JobType               string                   `json:"job_type,omitempty"`
	Agent                 string                   `json:"agent,omitempty"`
	Mode                  string                   `json:"mode,omitempty"`
	Status                string                   `json:"status"`
	Summary               string                   `json:"summary"`
	Commit                string                   `json:"commit,omitempty"`
	Created               string                   `json:"created"`
	FailureTaxonomy       string                   `json:"failure_taxonomy,omitempty"`
	FilesChanged          []string                 `json:"files_changed,omitempty"`
	Blockers              []string                 `json:"blockers,omitempty"`
	NextRecommendedAction string                   `json:"next_recommended_action,omitempty"`
	ValidOutput           bool                     `json:"valid_output"`
	Usage                 observability.TokenUsage `json:"usage"`
	ToolCalls             int                      `json:"tool_calls"`
	TranscriptBytes       int64                    `json:"transcript_bytes"`
	Graph                 HandoffGraph             `json:"graph"`
	PromptVersion         string                   `json:"prompt_version,omitempty"`
}

func HandoffFor(id string) (Handoff, error) {
	record, err := Last(id)
	if err != nil {
		return Handoff{}, err
	}
	return BuildHandoff(record), nil
}

func BuildHandoff(record RunRecord) Handoff {
	handoff := Handoff{
		RunID: record.ID, JobID: record.JobID, JobType: record.JobType,
		Agent: record.Agent, Mode: record.Mode, Status: record.Status,
		Summary: boundedText(record.Message, handoffMaxSummaryRunes),
		Commit:  record.Commit, Created: record.Created,
		FailureTaxonomy: record.FailureTaxonomy, ValidOutput: record.ValidOutput,
		Usage: record.Usage, ToolCalls: record.ToolCalls, TranscriptBytes: record.TranscriptBytes,
		PromptVersion: record.PromptVersion,
		Graph: HandoffGraph{
			Provider: record.Graph.Provider, Version: record.Graph.Version,
			Fingerprint: record.Graph.Fingerprint, FileCount: record.Graph.FileCount,
			NodeCount: record.Graph.NodeCount, EdgeCount: record.Graph.EdgeCount,
		},
	}
	if record.SelfReview != nil {
		handoff.FilesChanged = boundedItems(record.SelfReview.FilesChanged, handoffMaxFiles, handoffMaxItemRunes)
		handoff.Blockers = boundedItems(record.SelfReview.Blockers, handoffMaxBlockers, handoffMaxItemRunes)
		handoff.NextRecommendedAction = boundedText(record.SelfReview.NextRecommendedAction, handoffMaxActionRunes)
	}
	if len(handoff.FilesChanged) == 0 {
		handoff.FilesChanged = boundedItems(diffFiles(record.Diff), handoffMaxFiles, handoffMaxItemRunes)
	}
	return handoff
}

func boundedText(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes-1]) + "…"
}

func boundedItems(values []string, maxItems, maxRunes int) []string {
	if len(values) > maxItems {
		values = values[:maxItems]
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = boundedText(value, maxRunes); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func diffFiles(diff string) []string {
	seen := map[string]bool{}
	var files []string
	for _, line := range strings.Split(diff, "\n") {
		if !strings.HasPrefix(line, "diff --git a/") {
			continue
		}
		parts := strings.SplitN(line, " b/", 2)
		if len(parts) != 2 {
			continue
		}
		path := strings.TrimSpace(parts[1])
		if path != "" && !seen[path] {
			seen[path] = true
			files = append(files, path)
		}
	}
	return files
}
