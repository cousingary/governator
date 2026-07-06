# Migrating to Governator

Keep the existing gate authoritative while Governator runs in shadow. Do not remove the legacy hook until at least 200 real events over at least seven days produce zero mismatches in `gov parity report`.

## 1. Initialize

```sh
gov init
gov doctor
```

Move protected-path entries into `$HOME/.governator/protected-paths.txt`, configure snapshot roots in `$HOME/.governator/config.yaml`, and run `gov protect apply`. Keep normal backups throughout migration.

## 2. Shadow the interactive gate

Install the Claude Code `PreToolUse` shadow command from `integrations/claude-code/settings-snippet.json`, replacing placeholders with absolute executable paths:

```text
/absolute/path/to/gov hook pre-tool-use --shadow /absolute/path/to/legacy_gate.py
```

The legacy hook's stdout remains authoritative. Governator records its own decision, the legacy decision, payload hash, match state, and availability. Review `gov parity report` until the cutover threshold is met.

For Pi, load `integrations/pi/gov-gate.ts` interactively. For OpenCode, install the scoped permission configuration first; its example plugin can deny permission-ask events but cannot veto actions already configured as allow. Codex has no interactive hook surface.

## 3. Cut over

Replace the shadow hook with:

```text
/absolute/path/to/gov hook pre-tool-use
```

Keep legacy files installed but disarmed for rollback. Replace legacy protection and snapshot automation with `gov protect ...` and `gov snap ...`. Begin new automated agent work through reviewed job contracts and `gov run`.

## 4. Roll back

Restore the legacy hook command and stop launching new Governator jobs. Existing SQLite evidence and snapshots need not be deleted. If required, restore files with `gov snap restore ID --dry-run` followed by an operator-approved restore.

## Deliberate divergences

| Area | Governator behavior | Legacy Python plane | Reason |
|---|---|---|---|
| Classified destructive commands | Interactive gate denies every classified delete, main push, and database drop | Authority entries could permit some destructive verb/resource pairs | Interactive safety is intentionally stricter |
| Execution isolation | Contract jobs run in disposable Git worktrees through a backend capability envelope | General actions ran directly through a Python wrapper | Separate proposal from approval and merge |
| Universal write check | Pre/post repository fingerprints run for every backend | Protection depended primarily on hook classification and manifests | Detect writes missed by backend or lexical controls |
| Snapshot default store | `$HOME/.governator/snapshots` | Machine-specific storage path | Publishable neutral default |
| Snapshot implementation | Native Go; `GOV_RECALL_SCRIPT` remains a transition override | Python subprocess | Remove the runtime dependency while preserving rollback |
| Protected-path location | `$HOME/.governator/protected-paths.txt` after `gov init` | Harness-specific state directory | One neutral, configurable location |
| Protected lock verbs | `apply` and explicit `release PATH` | `lock` and `unlock` | Make the affected path explicit |
| Configuration | One strict YAML loader with environment overrides | Settings were distributed across environment and harness files | One precedence model and publishable defaults |
| Backend policy | Native guarantees and compensations are recorded per run | Claude-focused hook plane | Support five replaceable backends without overstating enforcement |
| OpenCode read-only | Scoped permission config plus fingerprint detection | No equivalent backend | OpenCode has no native read-only flag |
| Pi read-only | Mutating tools are removed from the tool surface | No equivalent backend | Use Pi's strongest native control |
| Cost gaps | Store zero with `cost_unavailable` note | Missing data could appear as zero | Avoid claiming an unknown call was free |
| Interactive integration | Claude dialect plus neutral `gov gate check` | Claude-specific hook payload | Reuse one decision core across harnesses |
| Evidence | Run, hook, parity, eval, routing, and repair data share one SQLite schema | Multiple logs and ledgers | Make audit and routing evidence queryable |
| Failure handling | Contract violations quarantine the run; unsupported actions fail contract validation | Wrapper circuit breaker governed arbitrary action retries | Governator governs bounded jobs, not every shell action on a workstation |
