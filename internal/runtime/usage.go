package runtime

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/observability"
)

type usageAccumulator struct {
	byID     map[string]observability.TokenUsage
	fallback observability.TokenUsage
	tools    map[string]bool
}

func newUsageAccumulator() *usageAccumulator {
	return &usageAccumulator{byID: map[string]observability.TokenUsage{}, tools: map[string]bool{}}
}

func integer(value any) (int64, bool) {
	switch v := value.(type) {
	case float64:
		return int64(v), v >= 0
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		return n, err == nil && n >= 0
	case int:
		return int64(v), v >= 0
	case int64:
		return v, v >= 0
	}
	return 0, false
}

func firstInteger(values map[string]any, keys ...string) (int64, string, bool) {
	for _, key := range keys {
		if n, ok := integer(values[key]); ok {
			return n, key, true
		}
	}
	return 0, "", false
}

func parseTokenUsage(values map[string]any) (observability.TokenUsage, bool) {
	var usage observability.TokenUsage
	var found, foundOutput, foundCache, foundWrite, foundReasoning bool
	var cacheKey string
	usage.InputTokens, _, found = firstInteger(values, "input_tokens", "inputTokens", "input")
	usage.OutputTokens, _, foundOutput = firstInteger(values, "output_tokens", "outputTokens", "output")
	usage.CachedInputTokens, cacheKey, foundCache = firstInteger(values, "cached_input_tokens", "cache_read_input_tokens", "cacheRead", "cache_read")
	usage.CacheCreationTokens, _, foundWrite = firstInteger(values, "cache_creation_input_tokens", "cacheCreationInputTokens", "cacheWrite", "cache_write")
	usage.ReasoningTokens, _, foundReasoning = firstInteger(values, "reasoning_output_tokens", "reasoning_tokens", "reasoningTokens", "reasoning")
	explicitTotal, _, foundTotal := firstInteger(values, "total_tokens", "totalTokens")
	found = found || foundOutput || foundCache || foundWrite || foundReasoning || foundTotal
	if !found {
		return observability.TokenUsage{}, false
	}
	usage.TotalTokens = explicitTotal
	if !foundTotal {
		usage.TotalTokens = usage.InputTokens + usage.OutputTokens + usage.ReasoningTokens + usage.CacheCreationTokens
		// Codex cached_input_tokens is a subset of input_tokens. Other backends
		// report cache reads separately from uncached input.
		if cacheKey != "cached_input_tokens" {
			usage.TotalTokens += usage.CachedInputTokens
		}
	}
	usage.Available = true
	return usage, true
}

func usageRecordID(parent map[string]any) string {
	for _, key := range []string{"id", "message_id", "messageID", "call_id", "callID"} {
		if value, ok := parent[key].(string); ok && value != "" {
			return key + ":" + value
		}
	}
	if value, ok := parent["timestamp"]; ok {
		return "timestamp:" + fmt.Sprint(value)
	}
	return ""
}

func isToolCall(format string, value map[string]any) bool {
	typeName, _ := value["type"].(string)
	switch format {
	case agents.TranscriptClaude, agents.TranscriptGLM:
		return typeName == "tool_use"
	case agents.TranscriptCodex:
		return typeName == "command_execution" || strings.Contains(typeName, "tool_call")
	case agents.TranscriptOpenCode:
		_, hasTool := value["tool"]
		_, hasState := value["state"].(map[string]any)
		return hasTool && (hasState || typeName == "tool")
	case agents.TranscriptPi:
		_, camel := value["toolName"]
		_, snake := value["tool_name"]
		return camel || snake || typeName == "toolCall" || typeName == "tool_call"
	}
	return false
}

func (a *usageAccumulator) walk(format string, value any) {
	switch x := value.(type) {
	case []any:
		for _, item := range x {
			a.walk(format, item)
		}
	case map[string]any:
		if isToolCall(format, x) {
			encoded, _ := json.Marshal(x)
			a.tools[string(encoded)] = true
		}
		for _, key := range []string{"usage", "tokens"} {
			if values, ok := x[key].(map[string]any); ok {
				if usage, ok := parseTokenUsage(values); ok {
					if id := usageRecordID(x); id != "" {
						a.byID[id] = usage
					} else if usage.TotalTokens >= a.fallback.TotalTokens {
						a.fallback = usage
					}
				}
			}
		}
		for _, item := range x {
			a.walk(format, item)
		}
	}
}

func addUsage(total *observability.TokenUsage, usage observability.TokenUsage) {
	total.InputTokens += usage.InputTokens
	total.OutputTokens += usage.OutputTokens
	total.CachedInputTokens += usage.CachedInputTokens
	total.CacheCreationTokens += usage.CacheCreationTokens
	total.ReasoningTokens += usage.ReasoningTokens
	total.TotalTokens += usage.TotalTokens
	total.Available = total.Available || usage.Available
}

func (a *usageAccumulator) result() (observability.TokenUsage, int) {
	var total observability.TokenUsage
	for _, usage := range a.byID {
		addUsage(&total, usage)
	}
	if len(a.byID) == 0 {
		addUsage(&total, a.fallback)
	}
	return total, len(a.tools)
}
