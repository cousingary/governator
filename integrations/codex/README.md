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
keeps the gate active for every invocation EXCEPT when the user explicitly
passes one of `--disable hooks`, `--disable=hooks`, `-c features.hooks=false`
(or its quoted variants). `--yolo` is NOT a hook escape — it aliases
`--dangerously-bypass-approvals-and-sandbox`, which removes approvals and
the sandbox but leaves hooks (and therefore the gate) active. Benign
flag-first invocations
(`codex --model X`, `codex -s workspace-write`, `codex --reasoning-effort
high`, ...) KEEP THE GATE ACTIVE — the wrapper does NOT inject
`--disable hooks` for them. The earlier "any flag-first invocation runs
vanilla" behavior was too aggressive and silently shed the gate for
`codex --model ...` calls; the current wrapper scans all args for explicit
hook-disabling flags and only honors bypass when the user asked for it.
The wrapper is now a pure pass-through (with ctxledger reporting); the
global `~/.codex/hooks.json` is what actually enforces the gate, and it
fires whenever Codex hasn't been told `--disable hooks`. Use `codex
--disable hooks` when a real, deliberate escape hatch is needed
(`approval_policy = "never"` is NOT an escape — it only removes user
approval prompts; hooks still fire).

The old non-interactive `gov run <job.yaml> --agent codex` job-contract path
(worktree isolation, budget caps, mandatory fingerprint scan) is untouched
and still the right tool for batch/unattended Codex work — this integration
only changes how *interactive* `codex` sessions get governed.

See `agents/codex-pretooluse-hook-findings.md` in the main downloads tree for
the full investigation.
