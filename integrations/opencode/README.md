# OpenCode integration

The adapter writes the equivalent of `opencode.read-only.json` into its disposable
worktree during read-only runs and restores any prior file afterward. This is
configuration-level enforcement, not a kernel sandbox; Governator's fingerprint
scan remains authoritative.

**Live status (2026-07-28): the gate WORKS on opencode 1.18.7 via
`tool.execute.before`. Keep `permission` at `"allow"`/`"allow"`.**

The plugin gates on `tool.execute.before`, which fires on every tool call
*regardless of the configured permission policy*. It calls `gov gate check` and
throws on a deny, which OpenCode surfaces as a failed tool call — the command
never executes. Because it does not depend on the permission system, the old
bypass trap does not apply and no interactive prompts are introduced.

Verified 2026-07-28 on 1.18.7, isolated config via `OPENCODE_CONFIG`, with
`permission.bash = "allow"`:

- allow path — `echo govgate-probe-ok` → gate consulted, `allow=true`, command ran.
- deny path — same command with `gov` off `PATH` (forces fail-closed) → tool
  status `error`, `Governator denied: governator gate unavailable`, command did
  not run.

Not directly proven: a *policy* deny (e.g. `git push origin main`) blocked
end-to-end through the model. Every gov-forbidden command is also refused by the
model from `AGENTS.md` prose before it ever emits a tool call, and forcing one
through would mean actually running a destructive command if the gate failed.
The deny branch is shared with the fail-closed path proven above, and
`gov gate check` returns `{"allow":false,"reason":"push main forbidden by
authority manifest"}` for that command standalone.

**Superseded history (do not re-litigate).** The prior finding — "the plugin
never loads at all on 1.18.3, regardless of permission policy" — is stale. On
1.18.7 the plugin module evaluates and its factory runs. The real defect was the
hook name: `permission.ask` **no longer exists in the 1.18.7 runtime** (it now
exposes `permission.asked` / `permission.replied` / `permission.respond`), so the
old hook was silently inert and OpenCode fell through to an interactive prompt.
`permission.ask` is retained in the plugin only for runtimes older than 1.18.7.

The scoped `opencode.read-only.json` permission config remains the primary
read-only mechanism for adapter runs.

Load the plugin using OpenCode's normal project plugin configuration. Governator
invokes OpenCode with `--pure`, so plugins are intentionally disabled for
hermetic contract runs; use the plugin for interactive OpenCode sessions.
