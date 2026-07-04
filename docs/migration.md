# Migrating to Governator

The existing gate remains authoritative during shadowing. Do not remove it until at least 200 real hook events over at least seven days produce zero mismatches in `gov parity report`.

## 1. Shadow phase

Install the following Claude Code `PreToolUse` hook, replacing paths with absolute paths for your installation:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "/absolute/path/to/gov hook pre-tool-use --shadow /absolute/path/to/harness_gate.py"
      }]
    }]
  }
}
```

The Python hook's stdout is authoritative. Governator records the Go decision, Python decision, payload hash, payload, match status, and Python availability in `parity_events`.

Run `gov parity report` regularly. A Python error or two-second timeout is recorded as unavailable and the Go decision is emitted as the safety fallback.

## 2. Cutover

After the criterion holds, switch to the direct hook:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "/absolute/path/to/gov hook pre-tool-use"
      }]
    }]
  }
}
```

Keep the Python files installed but disarmed. Replace snapshot automation with `gov snap create scheduled`. Configure snapshot roots in `$HOME/.governed-harness/recall_roots.txt` during transition, or with `GOV_SNAPSHOT_ROOTS`; set `GOV_SNAPSHOT_DIR` when the neutral `$HOME/.governator/snapshots` default is unsuitable.

Use `gov protect apply`, `gov protect status`, and `gov protect release <path>` for filesystem locks. All gate, runtime, doctor, and protection commands read the same protected-path manifest.

## 3. Rollback

Restore the shadow or Python-only command in the same settings file. No database migration or Python file restoration is required.

## Deliberate divergences

| Area | Governator behavior | Legacy behavior | Reason |
|---|---|---|---|
| Classified destructive commands | Interactive Go gate denies every classified delete, main push, and database drop | Python may permit a verb/resource explicitly granted by its authority manifest | Governator's interactive plane is intentionally stricter |
| Snapshot default store | `$HOME/.governator/snapshots` | A machine-specific drive path | Publishable neutral default; override with `GOV_SNAPSHOT_DIR` |
| Snapshot implementation | Native Go by default; `GOV_RECALL_SCRIPT` preserves transitional Python override | Python subprocess | Removes the runtime dependency while retaining rollback |
| Protected lock verbs | `apply` and explicit `release <path>` | `lock` and `unlock` | Clear operator-facing terminology; file and directory modes remain compatible |
