# Pi integration

Pi (mariozechner/pi-coding-agent) gates via its `tool_call` extension event,
which fires on every tool invocation regardless of any approval/permission
mode — the same architectural shape as Claude Code's `PreToolUse`. This
means the gate stays active even when Pi is run with no approval prompts,
which is the working configuration Jeremy wants across all four CLIs.

`gov-gate.ts` registers a `tool_call` listener that pipes `{tool,
command, path, cwd}` to `gov gate check` and returns
`{block: true, reason: "Governator <finding>: <reason>"}` when Governator
denies. The decision API is stateless (`gov gate check` does not touch the
ledger); only `gov hook pre-tool-use` (Claude Code/Codex PreToolUse path)
writes to `hook_events`.

## Install

```bash
pi install /mnt/e/downloads/governator/integrations/pi/gov-gate.ts
```

This copies the file into `~/.pi/agent/extensions/gov-gate.ts` (Pi's
auto-discovered extension directory). No `settings.json` edit is needed —
Pi loads every `.ts` under `~/.pi/agent/extensions/` on startup. `pi list`
only shows extensions registered in `settings.json`, so the installed
gate will NOT appear there even though it is loaded; verify by listing
the directory directly, or by triggering a deny (e.g. ask Pi to run
`git push origin main --force` and look for
`Governator F3: push main forbidden by authority manifest`).

Run `/reload` inside an active Pi session, or restart Pi, to activate.

## Why this works where the OpenCode plugin didn't

OpenCode's plugin API only allows deny from the `permission.ask` event,
which fires exclusively when the configured permission policy is `ask`.
Setting `permission.X = "allow"` short-circuits the entire permission
flow, so the OpenCode plugin never runs. Pi's `tool_call` event is a
tool-execution lifecycle hook (like Claude Code's PreToolUse) — it fires
on every call independently of any permission system, so the gate
enforces unconditionally.
