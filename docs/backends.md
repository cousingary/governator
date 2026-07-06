# Backend projections

All adapters receive the same abstract spec: work directory, sandbox mode, approval policy, network policy, timeout, prompt, and transcript path. `gov doctor` detects installed binaries and checks the flags Governator depends on.

## Claude Code

- Command shape: `claude -p --output-format stream-json --verbose --no-session-persistence --safe-mode ...`.
- Write mode: `--permission-mode acceptEdits --add-dir WORKTREE`.
- Read-only mode: `--permission-mode plan`.
- Native sandbox, read-only, and approval controls; no declared native network control.
- Override: `GOV_CLAUDE_BIN` or `backends.claude-code.bin`.

## Codex

- Command shape: `codex --ask-for-approval POLICY -c sandbox_workspace_write.network_access=false exec --json --ephemeral --sandbox MODE -C WORKTREE PROMPT`.
- Native `read-only` and `workspace-write` sandboxes.
- Native approval and workspace-write network configuration.
- Codex exposes no PreToolUse hook, so Governator relies on sandboxing, transcript audit, and the fingerprint floor.
- Override: `GOV_CODEX_BIN` or `backends.codex.bin`.

## GLM

- Command shape follows the headless Claude-compatible surface: `glm -p --output-format stream-json --verbose --no-session-persistence --safe-mode --permission-mode MODE --add-dir=WORKTREE PROMPT`.
- Write mode: `--permission-mode acceptEdits`; read-only mode: `--permission-mode plan`.
- `--no-session-persistence` keeps contract runs hermetic (no leftover session state between governed runs); `--safe-mode` enables Claude Code's additional tool guards. Both rely on glm-cli's Claude-Code-compatible flag surface; doctor's backend flag-drift probe is the tripwire if a future glm-cli drops one.
- Approval is native, but sandbox, read-only, and network guarantees are compensated.
- Override: `GOV_GLM_BIN` or `backends.glm.bin`.

## OpenCode

- Command shape: `opencode run --pure --format json --dir WORKTREE PROMPT`.
- OpenCode has no read-only CLI flag. Governator temporarily writes a worktree-scoped `opencode.json` denying edits and shell by default, with a small read-only command allowlist, then restores any prior file.
- This is configuration-level enforcement, not kernel containment. `--pure` disables external plugins during hermetic contract runs.
- The example permission plugin can veto `permission.ask` events, but it cannot govern actions already configured as allow. The scoped permission configuration is the primary mechanism.
- Override: `GOV_OPENCODE_BIN` or `backends.opencode.bin`.

## Pi

- Command shape: `pi --print --mode json --no-session --no-extensions --no-skills PROMPT`.
- Read-only mode natively shrinks the tool surface with `--tools read,grep,find,ls`; bash, edit, and write are absent.
- Pi runs in the worktree through the process working directory. It does not declare native sandbox, approval, or network controls.
- Interactive use can load `integrations/pi/gov-gate.ts`; governed contract runs disable extensions for hermeticity.
- Override: `GOV_PI_BIN` or `backends.pi.bin`.

## Universal floor

Every run records which controls were native and which were compensated. Governator fingerprints the live repository before and after execution regardless of backend. A change outside the approved worktree or declared contract fails the run even when a backend claimed native confinement.

If a transcript format lacks cost data, the ledger stores cost zero together with the explicit note `cost_unavailable`; zero must not be interpreted as a free model call.
