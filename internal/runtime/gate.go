package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/policy"
	"github.com/cousingary/governator/internal/protectedpaths"
	"github.com/cousingary/governator/internal/snapshots"
)

// GateDecision is the output of the Phase 5 parity gate. It mirrors the JSON
// shape Claude Code's PreToolUse hook protocol expects so `gov hook pre-tool-use`
// can emit it directly. Allow=false + Reason produces a deny decision.
type GateDecision struct {
	Allow    bool   `json:"allow"`
	Reason   string `json:"reason,omitempty"`
	Degraded bool   `json:"degraded,omitempty"`
	Finding  string `json:"finding,omitempty"` // which F1-F7 axis decided
}

// GateInput is the PreToolUse payload. ToolName/tool_input mirror Claude Code;
// CWD resolves relative paths for the F4 Bash-plane protected-path check.
type GateInput struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	CWD       string         `json:"cwd,omitempty"`
}

type NeutralGateInput struct {
	Tool    string `json:"tool"`
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
	CWD     string `json:"cwd,omitempty"`
}

// NeutralGateDecide translates a harness-neutral tool call into the shared
// F1-F7 decision core.
func NeutralGateDecide(in NeutralGateInput) GateDecision {
	tool := strings.ToLower(strings.TrimSpace(in.Tool))
	name := in.Tool
	switch tool {
	case "bash", "shell", "execute", "command":
		name = "Bash"
	case "write":
		name = "Write"
	case "edit":
		name = "Edit"
	case "multiedit", "multi_edit":
		name = "MultiEdit"
	case "notebookedit", "notebook_edit":
		name = "NotebookEdit"
	}
	input := map[string]any{}
	if in.Command != "" {
		input["command"] = in.Command
	}
	if in.Path != "" {
		input["file_path"] = in.Path
	}
	return GateDecide(GateInput{ToolName: name, ToolInput: input, CWD: in.CWD})
}

// fileMutatingTools are the tools F2 gates against the protected-paths manifest.
var fileMutatingTools = map[string]bool{
	"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true,
}

// --- F1: degraded-mode safety net (fail-closed denylist) --------------------
// Ports _FALLBACK_DANGER from harness_gate.py verbatim. Fires when the gate
// cannot fully evaluate (F1 import-failure analogue: manifest unreadable, or
// any unexpected error — F5). NARROW by design: routine commands still pass so
// the session can repair itself.
var fallbackDanger = []struct {
	re  *regexp.Regexp
	why string
}{
	{regexp.MustCompile(`(?i)\brm\b[^|&;\n]*\s-{1,2}[a-zA-Z]*r`), "recursive remove (rm -r / -rf)"},
	{regexp.MustCompile(`(?i)\brm\b[^|&;\n]*\s--recursive`), "recursive remove (rm --recursive)"},
	{regexp.MustCompile(`(?i)\brm\b[^|&;\n]*\s(?:/|~|\$HOME)\s*$`), "remove targeting / or home"},
	{regexp.MustCompile(`(?i)\bshred\b`), "shred (secure delete)"},
	{regexp.MustCompile(`(?i)\bfind\b[^|&;\n]*-delete\b`), "find -delete"},
	{regexp.MustCompile(`(?i)\bfind\b[^|&;\n]*-exec\s+rm\b`), "find -exec rm"},
	{regexp.MustCompile(`(?i)\bgit\s+push\b[^|&;\n]*(?:--force\b|--force-with-lease\b|\s-f\b)`), "git force push"},
	{regexp.MustCompile(`(?i)\bmkfs\b`), "mkfs (format filesystem)"},
	{regexp.MustCompile(`(?i)\bdd\b[^|&;\n]*\bof=/dev/`), "dd writing to a device"},
	{regexp.MustCompile(`(?i)>\s*/dev/(?:sd|nvme|vd|hd|mapper)`), "redirect to block device"},
	{regexp.MustCompile(`(?i)\b(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA)\b`), "destructive SQL (DROP/TRUNCATE)"},
}

func fallbackDangerHit(cmd string) string {
	for _, d := range fallbackDanger {
		if d.re.MatchString(cmd) {
			return d.why
		}
	}
	return ""
}

// --- F2/F4: shared protected-paths manifest --------------------------------
// Same manifest path the Python plane and runtime.protectedFingerprint use, so
// the three enforcers (CC gate, OS locks, Governator runtime) never disagree.

func protectedManifestPath() string { return protectedpaths.Manifest() }

func loadProtectedPatterns() []string {
	patterns, _ := protectedpaths.Patterns()
	return patterns
}

func matchProtected(abspath, pattern string) bool { return protectedpaths.Match(abspath, pattern) }

func expandPath(path string) string { return protectedpaths.Expand(path) }

func protectedReasonForPath(path string) string {
	if path == "" {
		return ""
	}
	absolute, err := filepath.Abs(expandPath(path))
	if err != nil {
		return ""
	}
	unlock := strings.TrimSpace(config.Env("HARNESS_UNLOCK"))
	for _, pattern := range loadProtectedPatterns() {
		if matchProtected(absolute, pattern) {
			if unlock != "" && (unlock == "all" || strings.Contains(absolute, unlock)) {
				return ""
			}
			return absolute + " is a PROTECTED path (matched '" + pattern + "')" + remediationHint()
		}
	}
	return ""
}

// --- F4: Bash-plane protected-path enforcement ------------------------------
// A Bash command that *references* a protected path (argument or redirect
// target) is blocked, even if the classifier can't read an opaque script. This
// is the actual 86-file class: the incident command named the dir it destroyed.
var readonlyCmds = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "less": true, "more": true,
	"bat": true, "grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true,
	"stat": true, "file": true, "wc": true, "du": true, "df": true, "tree": true,
	"diff": true, "cmp": true, "tac": true, "md5sum": true, "sha1sum": true,
	"sha256sum": true, "cksum": true, "sort": true, "uniq": true, "cut": true,
	"column": true, "jq": true, "yq": true, "xxd": true, "hexdump": true, "od": true,
	"readlink": true, "realpath": true, "basename": true, "dirname": true, "echo": true,
	"printf": true, "pwd": true, "which": true, "type": true, "date": true, "true": true,
	"false": true, "man": true, "info": true, "nl": true, "fold": true, "comm": true,
	"look": true,
}

var (
	findMutatingRE = regexp.MustCompile(`-delete\b|-exec(?:dir)?\b`)
	sedInPlaceRE   = regexp.MustCompile(`(?:^|\s)-i\b|(?:^|\s)--in-place\b`)
	wrapperRE      = regexp.MustCompile(`^(?:sudo|nohup|time|env|exec|command|builtin)\s+`)
	assignmentRE   = regexp.MustCompile(`^(?:\w+=\S+\s+)+`)
	redirectRE     = regexp.MustCompile(`>>?\s*([^\s;|&>]+)`)
	tokenSplitRE   = regexp.MustCompile(`[\s;|&]+`)
	bashPathRE     = regexp.MustCompile(`^\S*/`)
)

func cmdIsReadonly(first, lowCmd string) bool {
	if first == "find" {
		return !findMutatingRE.MatchString(lowCmd)
	}
	if first == "sed" {
		return !sedInPlaceRE.MatchString(lowCmd)
	}
	return readonlyCmds[first]
}

func resolveArg(tok, cwd string) string {
	tok = strings.TrimSpace(strings.Trim(tok, "'\""))
	if strings.HasPrefix(tok, "-") && strings.Contains(tok, "=") {
		tok = strings.SplitN(tok, "=", 2)[1]
		tok = strings.Trim(tok, "'\"")
	}
	if tok == "" || strings.HasPrefix(tok, "-") {
		return ""
	}
	tok = expandPath(tok)
	p := os.ExpandEnv(tok)
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return ""
	}
	return abs
}

// bashProtectedReason blocks a Bash command touching a protected path. Empty
// patterns → zero friction (matches the Python default until paths are marked).
func bashProtectedReason(cmd, cwd string) string {
	patterns := loadProtectedPatterns()
	if len(patterns) == 0 {
		return ""
	}
	unlock := strings.TrimSpace(config.Env("HARNESS_UNLOCK"))
	cwdResolved := cwd
	if cwdResolved == "" {
		cwdResolved, _ = os.Getwd()
	}

	match := func(tok string) (string, string) {
		ap := resolveArg(tok, cwdResolved)
		if ap == "" {
			return "", ""
		}
		for _, raw := range patterns {
			if matchProtected(ap, raw) {
				return ap, raw
			}
		}
		return "", ""
	}

	var redirectHit, argHit string
	for _, t := range redirectRE.FindAllStringSubmatch(cmd, -1) {
		ap, raw := match(t[1])
		if ap != "" {
			redirectHit = ap + "|" + raw
			break
		}
	}
	for _, tok := range tokenSplitRE.Split(cmd, -1) {
		ap, raw := match(tok)
		if ap != "" {
			argHit = ap + "|" + raw
			break
		}
	}
	hit := redirectHit
	if hit == "" {
		hit = argHit
	}
	if hit == "" {
		return ""
	}
	// normalized first token for the read-only allowance
	s := wrapperRE.ReplaceAllString(strings.TrimSpace(cmd), "")
	s = assignmentRE.ReplaceAllString(s, "")
	parts := strings.Fields(s)
	first := ""
	if len(parts) > 0 {
		first = strings.ToLower(bashPathRE.ReplaceAllString(parts[0], ""))
	}
	if redirectHit == "" && cmdIsReadonly(first, strings.ToLower(cmd)) {
		return ""
	}
	ap := strings.SplitN(hit, "|", 2)[0]
	if unlock != "" && (unlock == "all" || strings.Contains(ap, unlock)) {
		return ""
	}
	return "command touches PROTECTED path " + ap + remediationHint()
}

// remediationHint tells the operator how to proceed deliberately, mirroring
// Python's F2/F4 block messages: comment the manifest line, or set
// HARNESS_UNLOCK to bypass intentionally.
func remediationHint() string {
	return " (to proceed: comment the path out of " + protectedManifestPath() + ", or set HARNESS_UNLOCK=all / a path substring)"
}

// GateDecide is the Phase 5 parity entry point. It reproduces the Python gate's
// F1-F7 decision matrix. F5: any unexpected panic fails CLOSED via the degraded
// denylist — never fail open.
func GateDecide(in GateInput) (decision GateDecision) {
	defer func() {
		if r := recover(); r != nil {
			// F5: an unexpected panic must not fail open. Fall back to the
			// degraded denylist so irreversible ops stay blocked.
			decision = GateDegradedDecide(in, fmt.Sprintf("gate internal error (%v)", r))
		}
	}()

	cwd := in.CWD
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	// F2: protected-path check for file-mutating tools (independent of authority).
	if fileMutatingTools[in.ToolName] {
		path, _ := in.ToolInput["file_path"].(string)
		if path == "" {
			path, _ = in.ToolInput["notebook_path"].(string)
		}
		if reason := protectedReasonForPath(path); reason != "" {
			return GateDecision{Allow: false, Reason: reason, Finding: "F2"}
		}
		return GateDecision{Allow: true, Finding: "F2"}
	}

	// Non-Bash, non-mutating tools (Read, Grep, …) carry no free-form string.
	if in.ToolName != "Bash" {
		return GateDecision{Allow: true, Finding: "default"}
	}

	cmd, _ := in.ToolInput["command"].(string)

	// F4: Bash-plane protected-path enforcement runs for EVERY Bash command
	// before classification. Catches opaque scripts the classifier can't read.
	if reason := bashProtectedReason(cmd, cwd); reason != "" {
		return GateDecision{Allow: false, Reason: reason, Finding: "F4"}
	}

	// F3: hardened classify_shell_command (high_danger_only — block
	// irreversible/bulk: rm -rf/-r, shred, find -delete, force/main push, DROP).
	class := policy.ClassifyShellCommand(cmd, true)
	if class == nil {
		return GateDecision{Allow: true, Finding: "F3"}
	}
	// DELIBERATE DIVERGENCE from harness_gate.py: Python consults
	// authority.check(verb, resource) and can allow a classified command the
	// manifest permits. The Go gate denies every classified (delete/push-main/
	// drop) command unconditionally on the interactive plane — stricter than
	// Python by design, not a parity gap. There is no allow path for these
	// verbs here.
	return GateDecision{
		Allow: false, Finding: "F3",
		Reason: class.Verb + " " + class.Resource + " forbidden by authority manifest",
	}
}

// GateDegradedDecide is the F1 path: the gate cannot fully evaluate (manifest
// unreadable here would still allow F4 with empty patterns, so this is reserved
// for caller-detected degradation). Blocks irreversible Bash via the denylist
// and still honours F2/F4 path protection; allows the rest with a warning.
func GateDegradedDecide(in GateInput, why string) GateDecision {
	if fileMutatingTools[in.ToolName] {
		path, _ := in.ToolInput["file_path"].(string)
		if path == "" {
			path, _ = in.ToolInput["notebook_path"].(string)
		}
		if reason := protectedReasonForPath(path); reason != "" {
			return GateDecision{Allow: false, Reason: reason, Degraded: true, Finding: "F2"}
		}
		return GateDecision{Allow: true, Degraded: true, Finding: "F1"}
	}
	if in.ToolName == "Bash" {
		cmd, _ := in.ToolInput["command"].(string)
		cwd := in.CWD
		if cwd == "" {
			cwd, _ = os.Getwd()
		}
		if reason := bashProtectedReason(cmd, cwd); reason != "" {
			return GateDecision{Allow: false, Reason: reason, Degraded: true, Finding: "F4"}
		}
		if hit := fallbackDangerHit(cmd); hit != "" {
			return GateDecision{
				Allow: false, Degraded: true, Finding: "F1",
				Reason: why + " — blocked by degraded-mode safety net: " + hit,
			}
		}
	}
	return GateDecision{Allow: true, Degraded: true, Finding: "F1"}
}

// hookJSON computes the stdout payload for a hook decision. An explicit
// "allow" in Claude Code's PreToolUse protocol bypasses the ENTIRE permission
// system for that call, so on allow we must emit nothing — matching
// harness_gate.py's _emit_block, which only ever writes JSON on deny and
// exits 0 silently on allow, leaving normal permission prompts intact. Only
// "deny" carries an explicit hookSpecificOutput payload. Split out from
// EmitHookJSON so the payload logic is unit-testable without capturing stdout.
func hookJSON(d GateDecision) []byte {
	if d.Allow {
		return nil
	}
	out := map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "deny",
		"permissionDecisionReason": "GOVERNATOR GATE — " + d.Reason,
	}}
	b, _ := json.Marshal(out)
	return b
}

// EmitHookJSON writes a Claude Code PreToolUse decision to stdout (deny only;
// nothing on allow, see hookJSON) and returns the exit code the hook should
// use (always 0 — the decision is carried by the presence/absence of JSON, not
// the exit code, matching harness_gate.py). A degraded-but-allowed decision
// still writes no stdout JSON, but prints a loud warning to stderr (parity
// with Python's _degraded_guard warning) so the operator knows the full
// evaluation was unavailable and only the denylist net was in effect.
// HookPayload returns the exact stdout bytes for a Claude Code hook decision.
func HookPayload(d GateDecision) []byte { return hookJSON(d) }

func EmitHookJSON(d GateDecision) int {
	if d.Degraded && d.Allow {
		fmt.Fprintln(os.Stderr, "GOVERNATOR GATE — running in degraded denylist-only mode; full evaluation unavailable, only known-dangerous commands are blocked")
	}
	if b := hookJSON(d); b != nil {
		os.Stdout.Write(b)
	}
	return 0
}

// --- Pre-delete recovery snapshot -------------------------------------------
// Ports harness_gate.py's best-effort snapshot: when the high-danger gate
// ALLOWS a command but full classification says it's a delete (single-file
// rm/rmdir/unlink/glob), take a recovery snapshot before the command runs.
// Throttled, time-boxed, and NEVER blocks or changes the decision — call this
// only on the interactive hook plane, only AFTER GateDecide has allowed.

func snapshotStoreDir() string { return snapshots.StoreDir() }

// snapshotThrottled reports whether a snapshot was already taken within the
// last 120s (newest subdirectory mtime under the store), so a burst of
// deletes doesn't spawn a subprocess per command.
func snapshotThrottled(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	cutoff := time.Now().Add(-120 * time.Second)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			return true
		}
	}
	return false
}

// PreflightSnapshotIfDelete takes a best-effort pre-delete recovery snapshot.
// Call ONLY on the interactive hook plane, and only after GateDecide has
// already allowed the command — a snapshot failure must NEVER change the
// decision, so all errors here are swallowed (with an optional stderr note).
func PreflightSnapshotIfDelete(cmd string) {
	full := policy.ClassifyShellCommand(cmd, false)
	if full == nil || full.Verb != "delete" {
		return
	}
	if policy.ClassifyShellCommand(cmd, true) != nil {
		// Already blocked by the high-danger gate — nothing was allowed to run.
		return
	}
	if snapshotThrottled(snapshotStoreDir()) {
		return
	}
	if script := strings.TrimSpace(config.Env("GOV_RECALL_SCRIPT")); script != "" {
		script = expandPath(script)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "python3", script, "snapshot", "pre-delete").Run(); err != nil {
			fmt.Fprintln(os.Stderr, "GOVERNATOR GATE — pre-delete snapshot failed (non-blocking):", err)
		}
		return
	}
	if _, err := snapshots.Create("pre-delete"); err != nil {
		fmt.Fprintln(os.Stderr, "GOVERNATOR GATE — pre-delete snapshot failed (non-blocking):", err)
	}
}
