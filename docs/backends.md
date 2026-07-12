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

## Capability attestation

A static `NativeSandbox`/`NetworkControl` declaration on a backend adapter is an *expected* capability, never sufficient evidence that the configured executable actually has it — any binary pointed at by `backends.<name>.bin` inherits that adapter's declared capabilities by name alone unless it has been attested. `gov attest <backend>` (`internal/attest`) generates and stores an attestation binding: the adapter name/version, the executable's canonicalized path (`filepath.Abs` + `EvalSymlinks`) and SHA-256, its `--version` output, the effective model ID, the effective config hash, and probe results for supported flags, sandbox, network control, and transcript format — plus a creation time and a 24-hour expiry. The attestation ID is a SHA-256 over all of the above, stored in the ledger's `capability_attestations` table.

A `runner: local` job on `risk_class: high` requires a **current** attestation matching the live executable's exact path, hash, config hash, and model before launch (`attest.VerifyHighRiskNative`, called from `enforceContainment`). It fails closed when: the backend doesn't declare a native sandbox at all; no stored attestation matches the current executable (an unattested binary, or one that has been swapped since the last `gov attest` run — same error either way, "capability attestation required, run `gov attest <backend>`"); the matched attestation has expired; or any of its probes (supported flags, sandbox, transcript, and network control when the backend claims it) came back false. Re-run `gov attest <backend>` after upgrading a backend CLI or repointing `backends.<name>.bin` — an unattested or stale swap fails the run rather than silently trusting the new binary's name.

## JSON transcript integrity

For every backend with a declared JSON transcript format (`claude-stream-json`, `codex-json`, `glm-stream-json`, `opencode-json`, `pi-json`), `auditTranscript` enforces the format rather than treating "produced some output" as sufficient: any non-JSON line before the first valid JSON line is tolerated only as a narrow, per-adapter allowlisted startup notice (currently just Codex's literal `"Reading additional input from stdin..."`), capped at 3 lines / 512 bytes total; a malformed JSON line appearing after JSON parsing has started is rejected outright; and the transcript must contain at least one recognized event type from that format's own allowlist (e.g. Claude/GLM's `tool_use`/`tool_result`/`result`/`message_start`/`message_stop`; Codex's `item.*`/`command_execution`/`result`/`agent_message`/`turn.completed`; OpenCode's `tool`/`result`/`message`; Pi's `tool_execution*`/`result`/`done`). Any violation — excess startup noise, schema drift, or zero recognized events — produces `TRANSCRIPT_FORMAT_INVALID` and quarantines the run; an all-plaintext transcript on a declared-JSON backend can no longer pass silently. Parsers are versioned per adapter (`transcriptEvent`, one switch arm per format), so a future backend CLI output change is a parser update, not a silent audit gap.

Output byte caps (`docker.output_cap_bytes` / `local.output_cap_bytes`, both default 20MiB) apply to both runners: `internal/runner/docker.go`'s `cappedWriter` bounds a container's stdout/stderr, and `internal/runner/runner.go`'s `LocalWorktreeRunner.executor` bounds a host subprocess's the same way (Sol High 11, closed). Both report accepted/discarded bytes through `Runner.Observe`, and both honor `require_complete_transcript` (`docker.*` / `local.*` respectively) to quarantine a run on a capped transcript. See [docs/security.md](security.md) — High 11.

## Telemetry modes

A contract's `telemetry_mode` (`strict` | `estimated` | `advisory`, `internal/contracts/schema.go`) controls what happens when a backend's transcript doesn't expose token usage but the contract declares a hard `budget.max_tokens` ceiling. Unset defaults to `strict` when `budget.max_tokens > 0`, otherwise `advisory`. `strict` treats unavailable usage as a blocking violation — the run quarantines rather than being approved against an unverifiable budget. `estimated` allows the run through, relying on the conservative reservation already made against `budget.max_tokens` at quota-check time. `advisory` records the gap in run notes and never blocks. See [docs/contracts.md](contracts.md#telemetry_mode) for the field and [docs/ledger.md](ledger.md#global-wall-clock-budget) for how this interacts with the run-level deadline.

## Normalized backend event coverage

Governator's temporal policy-rule engine reasons over a normalized event schema (`internal/policy.EventKind`: `read`, `write`, `exec`, `network`, `tool_output`, `other`) rather than each backend's raw transcript shape. Each transcript format declares which kinds it can actually supply (`formatEventCoverage`): Claude and GLM cover all five; Codex currently supplies only `exec`; OpenCode and Pi supply `read`/`write`/`exec`/`network` but not `tool_output`. When a temporal policy rule requires an event kind a backend's parser can't produce, that rule is **unenforceable for that backend** — it is never silently treated as "didn't fire, so it's fine." It is reported (`policy.UnenforceableRules`) and, per `doctrine.unenforceable_rule_action` (default `flag`, advisory-only), either recorded as an advisory `RuleFlag` violation or promoted to a blocking `RuleDeny` violation under `unenforceable_rule_action: block`. OpenCode and Pi transcript parsing was generalized from bash-only exec extraction to a generic tool-call classifier specifically to widen their real (not just declared) `read`/`write`/`network` coverage.
