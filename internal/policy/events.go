package policy

import (
	"regexp"
	"strings"
)

// EventKind classifies one governance-relevant action in a run's event
// graph — narrow by design, matching what the existing capture surfaces
// (the PreToolUse hook_events audit trail, agent transcript tool_use/
// tool_result blocks) can actually observe today.
type EventKind string

const (
	EventRead       EventKind = "read"
	EventWrite      EventKind = "write"
	EventExec       EventKind = "exec"
	EventNetwork    EventKind = "network"
	EventToolOutput EventKind = "tool_output"
	EventOther      EventKind = "other"
)

// Event is one node in a run's event graph, in the order it occurred.
// Subject is the governance-relevant payload for the kind: a file path for
// read/write, a command for exec, a URL (or best-effort target) for network,
// and free text for tool_output (the rule engine scans it for injection
// markers, never executes or interprets it).
type Event struct {
	Sequence int
	Kind     EventKind
	Tool     string
	Subject  string
}

var (
	writeTools   = map[string]bool{"write": true, "edit": true, "multiedit": true, "multi_edit": true, "notebookedit": true, "notebook_edit": true}
	readTools    = map[string]bool{"read": true, "grep": true, "glob": true}
	networkTools = map[string]bool{"webfetch": true, "web_fetch": true, "websearch": true, "web_search": true}

	networkCommandRE = regexp.MustCompile(`(?i)\b(curl|wget|nc|ncat|telnet|scp|http\.client|requests\.(get|post))\b`)
)

// ClassifyEvent turns one tool call (name + input fields, already decoded
// from either the PreToolUse hook payload or an agent transcript's tool_use
// block) into a typed Event. Unknown tools fall back to EventOther rather
// than being dropped, so the event graph stays complete even for tools the
// classifier doesn't specifically recognize.
func ClassifyEvent(sequence int, tool string, input map[string]any) Event {
	lowTool := strings.ToLower(strings.TrimSpace(tool))
	e := Event{Sequence: sequence, Tool: tool}
	switch {
	case writeTools[lowTool]:
		e.Kind = EventWrite
		e.Subject = stringField(input, "file_path", "notebook_path")
	case readTools[lowTool]:
		e.Kind = EventRead
		e.Subject = stringField(input, "file_path", "path", "pattern")
	case networkTools[lowTool]:
		e.Kind = EventNetwork
		e.Subject = stringField(input, "url", "query")
	case lowTool == "bash" || lowTool == "shell":
		cmd := stringField(input, "command")
		e.Subject = cmd
		if networkCommandRE.MatchString(cmd) {
			e.Kind = EventNetwork
		} else {
			e.Kind = EventExec
		}
	default:
		e.Kind = EventOther
		e.Subject = stringField(input, "file_path", "command", "url")
	}
	return e
}

// ToolOutputEvent builds the tool_output half of the graph: the text a tool
// call returned, scanned (never executed) for suspected prompt-injection
// markers by the starter rule set.
func ToolOutputEvent(sequence int, tool, text string) Event {
	return Event{Sequence: sequence, Kind: EventToolOutput, Tool: tool, Subject: text}
}

func stringField(input map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := input[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
