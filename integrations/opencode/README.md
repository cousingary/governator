# OpenCode integration

The adapter writes the equivalent of `opencode.read-only.json` into its disposable
worktree during read-only runs and restores any prior file afterward. This is
configuration-level enforcement, not a kernel sandbox; Governator's fingerprint
scan remains authoritative.

Current OpenCode's `permission.ask` plugin hook can set the permission result to
`deny`. The example plugin calls `gov gate check` and denies when Governator
does. The scoped permission config remains the primary read-only mechanism because
permission hooks only run for actions whose configured policy is `ask`.

**Critical configuration requirement (the bypass trap):** for the gate to fire
on bash/edit calls, the live `opencode.jsonc` MUST set both `permission.bash`
and `permission.edit` to `"ask"` — never `"allow"`. When the policy is
`"allow"`, OpenCode short-circuits the entire permission decision flow, so the
`permission.ask` hook never runs and the gate is silently bypassed. This is the
architectural mismatch with OpenCode's plugin API: `permission.ask` is the only
hook that can deny a call, but it is also the only hook that depends on the
permission policy being non-`allow`. Setting policy to `"ask"` does NOT surface
user prompts in practice, because the plugin returns a definitive `allow` or
`deny` for every call — the gate pre-decides, so OpenCode never needs to ask the
human. Net effect with the correct config: zero prompts, full enforcement. If
`gov gate check` ever fails or times out (2s), the plugin fails closed (deny),
matching Governator's containment philosophy.

Load the plugin using OpenCode's normal project plugin configuration. Governator
invokes OpenCode with `--pure`, so plugins are intentionally disabled for
hermetic contract runs; use the plugin for interactive OpenCode sessions.
