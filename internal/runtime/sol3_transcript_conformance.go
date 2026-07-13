package runtime

import (
	"fmt"
	"sort"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/policy"
)

// Sol redteam v3 P1.8 (audit finding #15): "transcript integrity remains
// based on self-report" — the pre-fix bar for a declared-JSON transcript was
// "at least one valid JSON line, and at least one line whose type belongs to
// a broad per-format allowlist" (recognizedTranscriptEvent, unchanged by
// this file). The audit's own reproduction: a malicious or incompatible
// wrapper can perform hidden operations entirely outside the JSON stream and
// still satisfy that bar by emitting a single benign recognizable event
// (e.g. any Codex item.* line, or a Pi line naming a tool).
//
// This file adds a second, independent layer on top: does the transcript
// look like one complete, internally consistent session, not just one
// matching line? It is deliberately versioned (transcriptConformanceSchemaVersion)
// so a future backend CLI output change is a schema-version bump, not a
// silent behavior change — the "protocol version" the audit's correction
// asks for is Governator's own schema declaration, not a field read out of
// the (adversarial) transcript and trusted at face value; a self-reported
// "version" field could be spoofed as trivially as everything else finding
// #15 describes.
const transcriptConformanceSchemaVersion = "sol3-transcript-v1"

const (
	ruleTranscriptSessionStartMissing  = "transcript-session-start-missing"
	ruleTranscriptCompletionMissing    = "transcript-completion-missing"
	ruleTranscriptToolPairingMismatch  = "transcript-tool-pairing-mismatch"
	ruleTranscriptSessionIdentityMixed = "transcript-session-identity-mixed"
	ruleTranscriptDuplicateEventID     = "transcript-duplicate-event-id"
	ruleTranscriptTurnCountShort       = "transcript-turn-count-short"
)

// transcriptConformanceCapability records, per adapter, which of the checks
// below are grounded in real evidence for that format:
//
//   - Claude: 13 real governed-run transcripts captured on this machine
//     under ~/.governator/transcripts/ (actual `claude` CLI stream-json
//     output from real `gov run` invocations, not a synthetic fixture).
//     Every line on every one of those transcripts carries a session_id
//     matching the leading system/init event and a globally unique uuid;
//     every run ends in a "result" event; every tool_use content block's id
//     has exactly one matching tool_result content block's tool_use_id.
//   - GLM: docs/backends.md declares glm-cli's command surface as
//     "the headless Claude-compatible surface", and the pre-existing golden
//     fixture (testdata/glm_stream.jsonl, TestAuditGLMGoldenTranscript,
//     predates this session) already independently exercises the same
//     system/init + tool_use/tool_result-by-id + trailing result shape —
//     just without a uuid on every line, so session-identity/pairing are
//     verified but tolerant of uuid absence (see transcriptConformanceState
//     below).
//   - Codex, OpenCode, Pi: no real transcript was available to verify
//     against (none captured on this machine, and generating one requires
//     spending API budget this session was not authorized to spend). Their
//     session-start/pairing/identity shape is therefore unattested — marked
//     false here rather than guessed, per this session's standing
//     instruction not to weaken a check by inventing an untested pass
//     condition. Their pre-existing recognizedTranscriptEvent vocabulary
//     (item.*/command_execution/turn.completed for Codex; tool/result for
//     OpenCode; tool_execution*/result/done for Pi) was established by an
//     earlier session and is trusted here only for the one dimension that
//     vocabulary actually names unambiguously: which event is the
//     completion event.
type transcriptConformanceCapability struct {
	SessionStart       bool
	Completion         bool
	ToolPairing        bool
	SessionIdentity    bool
	TurnReconciliation bool
}

var transcriptConformanceCapabilities = map[string]transcriptConformanceCapability{
	agents.TranscriptClaude:   {SessionStart: true, Completion: true, ToolPairing: true, SessionIdentity: true, TurnReconciliation: true},
	agents.TranscriptGLM:      {SessionStart: true, Completion: true, ToolPairing: true, SessionIdentity: true, TurnReconciliation: true},
	agents.TranscriptCodex:    {Completion: true},
	agents.TranscriptOpenCode: {Completion: true},
	agents.TranscriptPi:       {Completion: true},
}

func transcriptIsSessionStart(format string, m map[string]any) bool {
	switch format {
	case agents.TranscriptClaude, agents.TranscriptGLM:
		typeName, _ := m["type"].(string)
		subtype, _ := m["subtype"].(string)
		return typeName == "system" && subtype == "init"
	}
	return false
}

func transcriptIsCompletion(format string, m map[string]any) bool {
	typeName, _ := m["type"].(string)
	switch format {
	case agents.TranscriptClaude, agents.TranscriptGLM:
		return typeName == "result"
	case agents.TranscriptCodex:
		return typeName == "turn.completed" || typeName == "result"
	case agents.TranscriptOpenCode:
		return typeName == "result"
	case agents.TranscriptPi:
		return typeName == "result" || typeName == "done"
	}
	return false
}

// transcriptConformanceState accumulates evidence across one transcript:
// observeLine sees every top-level JSONL line once (session_id/uuid/type/
// num_turns are always top-level fields in every real sample this session
// examined); observeNode sees every map node auditTranscript's existing
// recursive walk reaches, at any nesting depth — which is where Claude/GLM's
// tool_use/tool_result content blocks actually live, one level inside each
// assistant/user message's content array, the same nodes transcriptEvent and
// transcriptCommand already inspect.
type transcriptConformanceState struct {
	format string

	sawSessionStart bool
	sawCompletion   bool

	sessionID      string
	sessionIDSet   bool
	sessionIDMixed bool

	seenUUIDs     map[string]bool
	duplicateUUID string

	toolUseIDs       map[string]int
	toolResultIDs    map[string]int
	toolUseOrder     []string
	outOfOrderResult string

	numTurns    int64
	sawNumTurns bool
}

func newTranscriptConformanceState(format string) *transcriptConformanceState {
	return &transcriptConformanceState{
		format:        format,
		seenUUIDs:     map[string]bool{},
		toolUseIDs:    map[string]int{},
		toolResultIDs: map[string]int{},
	}
}

func (s *transcriptConformanceState) observeLine(m map[string]any) {
	if transcriptIsSessionStart(s.format, m) {
		s.sawSessionStart = true
	}
	if transcriptIsCompletion(s.format, m) {
		s.sawCompletion = true
		if n, ok := integer(m["num_turns"]); ok {
			s.numTurns = n
			s.sawNumTurns = true
		}
	}
	// Tolerant of absence, not just of mismatch: GLM's existing golden
	// fixture only stamps session_id on its system/init line, and neither
	// golden fixture stamps a uuid on every line the way real Claude Code
	// output does. A field's absence is not evidence of tampering — a
	// field's *contradiction* (a second, different value appearing after
	// the first) is. This preserves every pre-existing conforming fixture
	// while still catching a spliced/mixed-session transcript.
	if sid, ok := m["session_id"].(string); ok && sid != "" {
		if !s.sessionIDSet {
			s.sessionID = sid
			s.sessionIDSet = true
		} else if sid != s.sessionID {
			s.sessionIDMixed = true
		}
	}
	if uuid, ok := m["uuid"].(string); ok && uuid != "" {
		if s.seenUUIDs[uuid] && s.duplicateUUID == "" {
			s.duplicateUUID = uuid
		}
		s.seenUUIDs[uuid] = true
	}
}

func (s *transcriptConformanceState) observeNode(m map[string]any) {
	if s.format != agents.TranscriptClaude && s.format != agents.TranscriptGLM {
		return
	}
	typeName, _ := m["type"].(string)
	switch typeName {
	case "tool_use":
		id, ok := m["id"].(string)
		if !ok || id == "" {
			return
		}
		if s.toolUseIDs[id] == 0 {
			s.toolUseOrder = append(s.toolUseOrder, id)
		}
		s.toolUseIDs[id]++
	case "tool_result":
		id, ok := m["tool_use_id"].(string)
		if !ok || id == "" {
			return
		}
		if s.toolUseIDs[id] == 0 && s.outOfOrderResult == "" {
			s.outOfOrderResult = id
		}
		s.toolResultIDs[id]++
	}
}

// violations finalizes accumulated evidence into policy.RuleViolation
// entries at the given verdict (RuleFlag advisory by default, RuleDeny when
// doctrine.transcript_conformance_action is "block" — same two-tier posture
// Session 6 already established for policy.UnenforceableRules, and folded
// into audit.Violations by the exact same existing loop at the end of
// auditTranscript). A format with no known capability profile (should not
// happen; every declared TranscriptFormat constant is registered above)
// yields no findings rather than a false positive.
func (s *transcriptConformanceState) violations(verdict policy.RuleVerdict) []policy.RuleViolation {
	cap, known := transcriptConformanceCapabilities[s.format]
	if !known {
		return nil
	}
	var out []policy.RuleViolation
	add := func(rule, detail string) {
		out = append(out, policy.RuleViolation{Rule: rule, Verdict: verdict, CauseSeq: -1, TriggerSeq: -1, Detail: detail})
	}
	if cap.SessionStart && !s.sawSessionStart {
		add(ruleTranscriptSessionStartMissing, "no recognized session-start event for format "+s.format)
	}
	if cap.Completion && !s.sawCompletion {
		add(ruleTranscriptCompletionMissing, "no recognized completion event for format "+s.format)
	}
	if cap.SessionIdentity {
		if s.sessionIDMixed {
			add(ruleTranscriptSessionIdentityMixed, "transcript contains more than one distinct session_id")
		}
		if s.duplicateUUID != "" {
			add(ruleTranscriptDuplicateEventID, "duplicate event uuid: "+s.duplicateUUID)
		}
	}
	if cap.ToolPairing {
		for _, id := range s.toolUseOrder {
			if s.toolResultIDs[id] == 0 {
				add(ruleTranscriptToolPairingMismatch, "tool_use "+id+" has no matching tool_result")
			}
		}
		var orphanResults []string
		for id := range s.toolResultIDs {
			if s.toolUseIDs[id] == 0 {
				orphanResults = append(orphanResults, id)
			}
		}
		sort.Strings(orphanResults)
		for _, id := range orphanResults {
			add(ruleTranscriptToolPairingMismatch, "tool_result references unknown tool_use_id "+id)
		}
		if s.outOfOrderResult != "" {
			add(ruleTranscriptToolPairingMismatch, "tool_result for "+s.outOfOrderResult+" appears before its tool_use in transcript order")
		}
	}
	if cap.TurnReconciliation && s.sawNumTurns {
		toolStarts := int64(len(s.toolUseOrder))
		if s.numTurns < toolStarts {
			add(ruleTranscriptTurnCountShort, fmt.Sprintf("declared num_turns=%d is less than observed tool calls=%d", s.numTurns, toolStarts))
		}
	}
	return out
}
