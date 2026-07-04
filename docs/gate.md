# Interactive gate

Governator exposes one decision core through a Claude Code dialect and a harness-neutral dialect. The gate complements, but does not replace, the contract runtime's worktree, fingerprint, budget, and validator checks.

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
