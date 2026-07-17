# Codex integration

Codex CLI >=0.144 ships a real hook surface (`developers.openai.com/codex/hooks`)
that mirrors Claude Code's `PreToolUse` contract closely enough that
`gov hook pre-tool-use` works against it with zero changes for `Bash` calls —
same `tool_name`/`tool_input.command`/`cwd` field names, same
`hookSpecificOutput.permissionDecision` deny shape. The one real gap is
`apply_patch` (Codex's file-edit tool): it reports `tool_name: "apply_patch"`
with the raw patch envelope in `tool_input.command`, not a clean `file_path`
field the way Claude's Write/Edit/MultiEdit do — `internal/runtime/gate_applypatch.go`
extracts every `Add/Update/Delete File:` / `Move to:` path out of the patch
envelope and runs each through the same F2 protected-path check, via
`GateDecideApplyPatch`.

Deploy `hooks.json` to `~/.codex/hooks.json` (global, same scope as Claude
Code's `~/.claude/settings.json` PreToolUse hook). Codex applies it
automatically to every invocation once trusted — run `/hooks` inside the
Codex TUI once to review and trust it (hash-pinned; a changed hook definition
needs re-trust). No worktree isolation and no job-contract/task-text-upfront
step, matching how Claude Code and opencode are wired — this gates every
Bash/apply_patch call live, in place, during a normal interactive session.

**Known coverage gap** (from OpenAI's own docs, not specific to this
integration): `PreToolUse` doesn't fully cover Codex's newer `unified_exec`
streaming shell mechanism yet, and doesn't cover `WebSearch` or other
non-shell/non-MCP tool calls at all. This is a guardrail, not a complete
enforcement boundary — comparable in spirit to Claude Code's own PreToolUse
matcher (`Bash|Write|Edit|MultiEdit`), which also doesn't cover every tool.

`codex-gov-wrap.sh` (the `codex` alias, `/home/lam/bin/codex-gov-wrap.sh`)
passes flag-first invocations (`codex --yolo`, `--model`, ...) through with
Codex's own `--disable hooks` (equivalent to `-c features.hooks=false`) so a
deliberate escape hatch stays a real, complete bypass — not just a
wrapper-level illusion, since `~/.codex/hooks.json` is a global file Codex
would otherwise apply to every invocation regardless of which wrapper called
it. `codex-v` (`codex_wrap.sh`) does the same for its fully-vanilla path.

The old non-interactive `gov run <job.yaml> --agent codex` job-contract path
(worktree isolation, budget caps, mandatory fingerprint scan) is untouched
and still the right tool for batch/unattended Codex work — this integration
only changes how *interactive* `codex` sessions get governed.

See `agents/codex-pretooluse-hook-findings.md` in the main downloads tree for
the full investigation.
