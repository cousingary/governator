# Job contracts

A job contract is strict YAML: unknown fields, multiple documents, malformed path patterns, and literal credentials are rejected. Run `gov validate job.yaml` before `gov preflight` or `gov run`.

## Fields

| Field | Meaning |
|---|---|
| `task` | Human-readable instruction compiled into the agent prompt. |
| `job_id` | Stable alphanumeric, dot, underscore, or hyphen identifier. |
| `job_type` | Operator-defined category used by scoring and routing. |
| `agent` | `claude-code`, `codex`, `glm`, `opencode`, or `pi`. |
| `mode` | `scout`, `surgeon`, `batch_worker`, `verifier`, `repair`, or `architect`. |
| `workspace.root` | Absolute path to the source Git repository. |
| `workspace.worktree` | `auto`; every run uses a disposable Git worktree. |
| `allowed.read` | Nonempty repository-relative path patterns the agent may inspect. |
| `allowed.write` | Repository-relative write patterns; empty for read-only modes. |
| `allowed.execute` | Shell-command patterns allowed by preflight and transcript audit. |
| `forbidden.paths` | Repository-relative paths that must never be touched. |
| `forbidden.commands` | Command patterns that must never run. |
| `forbidden.behaviors` | Semantic prohibitions carried into policy and prompt context. |
| `budget.max_minutes` | Positive wall-clock deadline. |
| `budget.max_commands` | Positive audited command limit. |
| `budget.max_files_changed` | Positive changed-file limit. |
| `budget.max_lines_changed` | Positive added-plus-deleted line limit. |
| `budget.max_new_files` | Nonnegative new-file limit, not above changed files. |
| `budget.max_deleted` | Nonnegative deleted-file limit. |
| `budget.max_tokens` | Optional nonnegative token ceiling. Exceeding reported usage quarantines the run; unavailable usage is recorded without guessing. |
| `preflight.intended_writes` | Declared write patterns; required in write modes and empty in read-only modes. |
| `preflight.scout_completed` | Records that reconnaissance preceded a high-risk write. |
| `preflight.approve_high_risk` | Explicit operator approval for policy-classified high-risk work. |
| `success.required_files` | Files that must exist after a write-capable run. |
| `success.validators` | Nonempty deterministic shell validators, run outside the model. |
| `output.style` | Optional. `terse` or `normal`. Omit the field for the existing unrestricted prompt. |
| `output.max_final_words` | Optional, `terse` only. 20-1000; defaults to 120 when omitted. |
| `repair.auto` | Optional, default `false`. When `true`, a quarantined run of this contract triggers the auto-repair loop (see `docs/ledger.md`). |
| `repair.max_attempts` | Optional, nonnegative. Defaults to 1 when unset; hard-clamped to 2 regardless of what is requested. |
| `repair.backend` | Optional. Overrides `agent` for compiled repair attempts only. |
| `on_violation` | `quarantine`; unsupported actions are rejected during validation. |

All path patterns are repository-relative and may not escape with `..`. Read-only modes are `scout`, `verifier`, and `architect`. Governator rejects direct-root execution and unimplemented violation actions rather than accepting policy it cannot enforce.

## Minimal read-only example

```yaml
task: Verify the repository.
job_id: verify
job_type: verification
agent: codex
mode: verifier
workspace: {root: /absolute/path/to/repository, worktree: auto}
allowed:
  read: ["**"]
  write: []
  execute: ["go test ./..."]
forbidden:
  paths: [".git/**"]
  commands: ["rm -rf", "git push"]
  behaviors: [write_files]
budget: {max_minutes: 10, max_commands: 20, max_files_changed: 1, max_lines_changed: 1, max_new_files: 0, max_deleted: 0}
preflight: {intended_writes: []}
success:
  required_files: []
  validators: ["go test ./..."]
on_violation: quarantine
```

## `RESULT.json`

Write-capable agents are instructed to create `RESULT.json` in the worktree:

```json
{
  "status": "complete",
  "files_changed": ["internal/example.go"],
  "commands_run": 3,
  "validation": {"go test ./...": "passed"},
  "violations": [],
  "blockers": [],
  "next_recommended_action": "none"
}
```

The document is advisory. Governator independently computes the diff, command count, budgets, forbidden-path checks, required files, and validator results before approving a merge.

## Output policy

```yaml
output:
  style: terse
  max_final_words: 80
```

Setting `output.style: terse` appends prompt guidance capping the agent's final response at `max_final_words` (default 120). The guidance suppresses task restatement, routine progress narration, and generic advice; it never permits omitting evidence or `RESULT.json`. Leave `output` unset for the unrestricted prompt. `max_final_words` is invalid under `style: normal`.
