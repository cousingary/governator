# OpenCode integration

The adapter writes the equivalent of `opencode.read-only.json` into its disposable
worktree during read-only runs and restores any prior file afterward. This is
configuration-level enforcement, not a kernel sandbox; Governator's fingerprint
scan remains authoritative.

Current OpenCode's `permission.ask` plugin hook can set the permission result to
`deny`. The example plugin calls `gov gate check` and denies when Governator
does. The scoped permission config remains the primary read-only mechanism because
permission hooks only run for actions whose configured policy is `ask`.

Load the plugin using OpenCode's normal project plugin configuration. Governator
invokes OpenCode with `--pure`, so plugins are intentionally disabled for
hermetic contract runs; use the plugin for interactive OpenCode sessions.
