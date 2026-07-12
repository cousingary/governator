# Interactive gate

Governator exposes one decision core through a Claude Code dialect and a harness-neutral dialect. The gate complements, but does not replace, the contract runtime's worktree, fingerprint, budget, and validator checks.

The runtime underneath the gate is transactional: live-root merges progress through durable `MERGE_INTENT → MERGE_APPLIED → ROOT_COMMITTED → LEDGER_FINALIZING → COMPLETE` stages (with a distinct `MERGED_LEDGER_PENDING` recovery status), workspace creation is guarded so a mid-run crash can never leak a worktree or branch, and workspace locks are held on the canonical (symlink- and device/inode-resolved) identity of the repository rather than a raw path string. See [docs/ledger.md](ledger.md#merge-transaction-and-workspace-lifecycle) for the state machine and [docs/containment.md](containment.md) for how lock/merge safety relates (and does not amount) to host containment.

## F1-F7 model

| Finding | Governator control |
|---|---|
| F1 | Gate failures fall back to a narrow degraded denylist instead of silently allowing destructive operations. |
| F2 | Write/Edit-style tools are checked against the shared protected-path manifest. |
| F3 | Shell commands are lexically classified; destructive deletes, pushes to the main branch, and database drops are denied. |
| F4 | Bash arguments and redirect targets are independently checked against protected paths, including opaque script invocations. |
| F5 | Unexpected decision errors recover through the degraded F1 path rather than fail open. |
| F6 | Hook decisions and contract runs share Governator's gate semantics and SQLite audit plane. |
| F7 | Integration wiring is explicit, probeable, and shipped under `integrations/` to reduce silent backend drift. |

Classification is deliberately conservative and lexical. A native sandbox and the runtime's post-run fingerprint remain necessary.

## Policy decision provenance

Every decision also carries `Sources` and `PolicyHash` (`internal/policy.PolicyDecision`, attached by `internal/runtime.attachProvenance`): `Sources` names which policy layer the finding represents — F2/F4 (protected paths) are `project_doctrine`, F1/F3 (the hardcoded denylist and command classifier) are `org_policy`, and a hard filter raised by the job's own contract (preflight risk flags) is `job_contract`. `PolicyHash` fingerprints the exact protected-path manifest and rule-set version consulted, so two decisions sharing a hash are provably comparing the same policy. `--run ID` persists both into `hook_events.sources`/`hook_events.policy_hash`.

A separate, compact temporal rule engine (`internal/policy.EvaluateTemporalRules`) runs over a run's event graph (derived from its agent transcript's tool-call blocks) rather than a single tool call in isolation, looking for sequences the single-call F1-F7 checks can't see: a protected/secret-path read followed by a network request (deny), a read outside the contract's `allowed.read` scope followed by a write (deny), and tool output containing a suspected prompt-injection marker followed by a shell command (advisory flag only — never blocking). Deny-verdict hits fold into the run's audit violations; every hit (deny and flag) is ledgered to `policy_rule_events` via `RecordPolicyRuleEvents`.

## Claude Code hook dialect

`gov hook pre-tool-use` accepts Claude's hook object on stdin:

```json
{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/workspace"}
```

Allowed actions produce no output. Denials emit Claude-compatible decision JSON. `--run ID` records the decision against a run. See `integrations/claude-code/settings-snippet.json` for direct and shadow configurations.

## Neutral dialect

Any harness can call:

```sh
printf '%s' '{"tool":"bash","command":"git status","path":"","cwd":"/workspace"}' \
  | gov gate check
```

A valid request always exits zero and returns:

```json
{"allow":true,"reason":"","finding":"F3"}
```

Malformed input exits zero with no output so a caller can distinguish “no decision” from an explicit allow. Integration shims should choose and document their own failure policy; the Pi and OpenCode examples fail closed when the `gov` process does not return a decision.

## Shadow parity

During migration, keep the old Python gate authoritative:

```sh
gov hook pre-tool-use --shadow /absolute/path/to/legacy_gate.py
gov parity report
```

Governator records the input, both outputs, match state, and legacy-gate availability. Cut over only after at least 200 events over at least seven days with zero mismatches. A legacy timeout or crash is recorded as unavailable and Governator's decision is used as the safety fallback.
