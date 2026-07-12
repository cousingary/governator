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

// Transcript format identifiers, mirroring internal/agents' Transcript*
// constants (claude-stream-json, codex-json, glm-stream-json, opencode-json,
// pi-json). Duplicated as plain strings rather than imported for the same
// reason internal/contracts mirrors policy's own Verdict/op constants
// (policyRuleVerdicts/policyRuleOps): internal/config already imports this
// package (PolicyRules), and internal/agents imports internal/config, so
// policy -> agents would close an import cycle (policy -> agents -> config
// -> policy). Session 6 (Sol High 12) is the one place this package needs to
// reason about transcript formats at all, so the values are named here
// rather than left as scattered literals.
const (
	formatClaude   = "claude-stream-json"
	formatCodex    = "codex-json"
	formatGLM      = "glm-stream-json"
	formatOpenCode = "opencode-json"
	formatPi       = "pi-json"
)

// formatEventCoverage declares, per transcript format, which EventKinds that
// format's parser (internal/runtime's transcriptEvent) can structurally
// produce. Session 6 (Sol High 12): "the source explicitly notes that Claude
// and GLM receive rich tool events, while Codex, OpenCode and Pi generally
// receive only shell-command events... create a normalized backend event
// protocol... do not advertise a temporal rule as cross-backend until every
// supported adapter supplies its required event types." This is that
// declaration — the ground truth UnenforceableRules checks against.
//
//   - Claude/GLM transcripts carry generic Anthropic-style tool_use/
//     tool_result content blocks, so every event kind classifies.
//   - Codex's JSON stream exposes only command_execution (shell); it has no
//     generic tool-call schema this codebase parses, so only EventExec is
//     available.
//   - OpenCode/Pi expose a generic tool-name+input shape (previously mined
//     only for bash extraction; Session 6 generalizes it via
//     policy.ClassifyEvent) that lets read/write/exec/network classify
//     whenever the backend's own tool names match the classifier's maps.
//     Neither format exposes tool-result *text* the way Claude/GLM's
//     tool_result blocks do, so EventToolOutput stays unavailable for them.
var formatEventCoverage = map[string]map[EventKind]bool{
	formatClaude:   {EventRead: true, EventWrite: true, EventExec: true, EventNetwork: true, EventToolOutput: true},
	formatGLM:      {EventRead: true, EventWrite: true, EventExec: true, EventNetwork: true, EventToolOutput: true},
	formatCodex:    {EventExec: true},
	formatOpenCode: {EventRead: true, EventWrite: true, EventExec: true, EventNetwork: true},
	formatPi:       {EventRead: true, EventWrite: true, EventExec: true, EventNetwork: true},
}

// SupportsEventKind reports whether format's parser can structurally
// produce events of kind. An unrecognized format supports nothing (fail
// closed: an unknown backend gets no free pass on cross-backend rules).
func SupportsEventKind(format string, kind EventKind) bool {
	return formatEventCoverage[format][kind]
}

// ruleRequiredKinds maps each starter temporal rule (rules.go) to the
// EventKinds its cause/trigger events depend on. Kept next to
// formatEventCoverage (not in rules.go) so the two stay reviewable
// together — this table is the "backend coverage" half of a rule's
// definition, EvaluateTemporalRules is the "logic" half.
var ruleRequiredKinds = map[string][]EventKind{
	RuleSecretPrecedesNetwork:       {EventRead, EventNetwork},
	RuleOutOfScopeReadPrecedesWrite: {EventRead, EventWrite},
	RuleInjectionPrecedesExec:       {EventToolOutput, EventExec},
}

// starterRuleNames is every rule ruleRequiredKinds declares, in a stable
// order, so UnenforceableRules' output order never depends on map iteration.
var starterRuleNames = []string{RuleSecretPrecedesNetwork, RuleOutOfScopeReadPrecedesWrite, RuleInjectionPrecedesExec}

// UnenforceableRules returns the starter rule names that cannot possibly
// fire for a transcript of the given format, because the format's parser
// doesn't supply one or more of the event kinds the rule depends on (Sol
// High 12). Callers (internal/runtime's auditTranscript) use this to FLAG or
// block per policy config instead of leaving the coverage gap silent, which
// is what happened before Session 6: a rule requiring events an adapter
// never supplies simply never fired, with nothing recorded anywhere.
func UnenforceableRules(format string) []string {
	var out []string
	for _, name := range starterRuleNames {
		for _, kind := range ruleRequiredKinds[name] {
			if !SupportsEventKind(format, kind) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}
