# OpenCode integration

The adapter writes the equivalent of `opencode.read-only.json` into its disposable
worktree during read-only runs and restores any prior file afterward. This is
configuration-level enforcement, not a kernel sandbox; Governator's fingerprint
scan remains authoritative.

Current OpenCode's `permission.ask` plugin hook can set the permission result to
`deny`. The example plugin calls `gov gate check` and denies when Governator
does. The scoped permission config remains the primary read-only mechanism because
permission hooks only run for actions whose configured policy is `ask`.

**The bypass trap (architectural):** OpenCode's `permission.ask` is the only
plugin hook that can deny a call, but it only runs for actions whose configured
policy is `"ask"`. When the policy is `"allow"`, OpenCode short-circuits the
entire permission decision flow, so the hook never runs and the gate is
silently bypassed. In theory, setting the policy to `"ask"` with this plugin
loaded yields zero prompts and full enforcement (the plugin pre-decides every
call; on `gov gate check` failure or 2s timeout it fails closed with deny).

**Live status (2026-07-19): the gate does NOT work in OpenCode — do not set
`"ask"`.** Live-tested 2026-07-18 on opencode 1.18.3: the plugin never loads
at all, regardless of permission policy (zero plugin log lines, hook never
invoked). With the plugin not loading, `permission.bash/edit = "ask"` degrades
to real interactive prompts on every call — normal usage breaks with zero
Governator benefit. The live `~/.config/opencode/opencode.jsonc` therefore
stays at `"allow"`/`"allow"` until the plugin-loading failure is root-caused
in a dedicated debugging session. Until then, interactive OpenCode sessions
are UNGOVERNED; the theory in the paragraph above only becomes operative once
the plugin demonstrably loads (verify: a `GovernatorGate` deny on
`git push origin main --force`).

Load the plugin using OpenCode's normal project plugin configuration. Governator
invokes OpenCode with `--pure`, so plugins are intentionally disabled for
hermetic contract runs; use the plugin for interactive OpenCode sessions.
