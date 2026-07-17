package runtime

import (
	"regexp"
	"strings"
)

// applyPatchFileRE matches OpenAI's apply_patch envelope file-operation
// headers: "*** Add File: <path>", "*** Update File: <path>",
// "*** Delete File: <path>", and "*** Move to: <path>" (the rename target
// inside an Update block). Codex's PreToolUse hook reports tool_name
// "apply_patch" (never "Write"/"Edit", regardless of which matcher alias a
// hooks.json config uses) with the raw patch envelope in
// tool_input.command — unlike Claude Code, there is no clean file_path
// field, so protected-path enforcement has to parse it out of the patch
// text itself.
var applyPatchFileRE = regexp.MustCompile(`(?m)^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s*(.+?)\s*$|^\*\*\*\s+Move\s+to:\s*(.+?)\s*$`)

// ExtractApplyPatchPaths returns every file path an apply_patch envelope
// touches (add/update/delete/move targets), in first-seen order, deduplicated.
func ExtractApplyPatchPaths(patch string) []string {
	seen := map[string]bool{}
	var paths []string
	for _, m := range applyPatchFileRE.FindAllStringSubmatch(patch, -1) {
		p := strings.TrimSpace(m[1])
		if p == "" {
			p = strings.TrimSpace(m[2])
		}
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
	}
	return paths
}

// GateDecideApplyPatch gives Codex's apply_patch tool the same F2
// protected-path enforcement Claude Code's Write/Edit/MultiEdit already get.
// It evaluates every touched path through the unmodified GateDecide core (as
// a synthetic Write call, so the F2 branch and its provenance/unlock logic
// run unchanged) — first deny wins, matching GateDecide's single-verdict
// contract. A patch with no extractable file headers (malformed or empty)
// allows, same as GateDecide's default-allow for unrecognized shapes.
func GateDecideApplyPatch(cwd, patch string) GateDecision {
	paths := ExtractApplyPatchPaths(patch)
	if len(paths) == 0 {
		return attachProvenance(GateDecision{Allow: true, Finding: "F2_APPLY_PATCH"})
	}
	for _, p := range paths {
		if d := GateDecide(GateInput{ToolName: "Write", ToolInput: map[string]any{"file_path": p}, CWD: cwd}); !d.Allow {
			return d
		}
	}
	return attachProvenance(GateDecision{Allow: true, Finding: "F2_APPLY_PATCH"})
}
