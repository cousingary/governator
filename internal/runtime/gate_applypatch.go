package runtime

import (
	"fmt"
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
var applyPatchDirectiveRE = regexp.MustCompile(`^\*\*\*\s+(.+?)\s*$`)

// ExtractApplyPatchPaths returns every file path an apply_patch envelope
// touches (add/update/delete/move targets), in first-seen order, deduplicated.
func ExtractApplyPatchPaths(patch string) []string {
	paths, _ := ParseApplyPatchPaths(patch)
	return paths
}

// ParseApplyPatchPaths validates an apply_patch envelope and returns every
// touched path. Empty input, missing file directives, malformed file headers,
// and unknown future directives are protocol errors.
func ParseApplyPatchPaths(patch string) ([]string, error) {
	if strings.TrimSpace(patch) == "" {
		return nil, fmt.Errorf("missing apply_patch command")
	}
	seen := map[string]bool{}
	var paths []string
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "***") {
			continue
		}
		m := applyPatchDirectiveRE.FindStringSubmatch(line)
		if len(m) != 2 {
			return nil, fmt.Errorf("malformed apply_patch directive %q", line)
		}
		directive := strings.TrimSpace(m[1])
		switch {
		case directive == "Begin Patch", directive == "End Patch":
			continue
		case strings.HasPrefix(directive, "Add File:"), strings.HasPrefix(directive, "Update File:"), strings.HasPrefix(directive, "Delete File:"), strings.HasPrefix(directive, "Move to:"):
			mm := applyPatchFileRE.FindStringSubmatch(line)
			if len(mm) == 0 {
				return nil, fmt.Errorf("malformed apply_patch file directive %q", line)
			}
			p := strings.TrimSpace(mm[1])
			if p == "" {
				p = strings.TrimSpace(mm[2])
			}
			if p == "" {
				return nil, fmt.Errorf("empty apply_patch path in %q", line)
			}
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		default:
			return nil, fmt.Errorf("unsupported apply_patch directive %q", directive)
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no extractable apply_patch paths")
	}
	return paths, nil
}

// GateDecideApplyPatch gives Codex's apply_patch tool the same F2
// protected-path enforcement Claude Code's Write/Edit/MultiEdit already get.
// It evaluates every touched path through the unmodified GateDecide core (as
// a synthetic Write call, so the F2 branch and its provenance/unlock logic
// run unchanged) — first deny wins, matching GateDecide's single-verdict
// contract. Malformed envelopes fail closed with a dedicated structured
// finding instead of silently default-allowing.
func GateDecideApplyPatch(cwd, patch string) GateDecision {
	paths, err := ParseApplyPatchPaths(patch)
	if err != nil {
		return attachProvenance(GateDecision{Allow: false, Reason: err.Error(), Finding: "F2_APPLY_PATCH_PROTOCOL_ERROR"})
	}
	for _, p := range paths {
		if d := GateDecide(GateInput{ToolName: "Write", ToolInput: map[string]any{"file_path": p}, CWD: cwd}); !d.Allow {
			return d
		}
	}
	return attachProvenance(GateDecision{Allow: true, Finding: "F2_APPLY_PATCH"})
}
