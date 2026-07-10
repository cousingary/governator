# Job contracts

A job contract is strict YAML: unknown fields, multiple documents, malformed path patterns, and literal credentials are rejected. Run `gov validate job.yaml` before `gov preflight` or `gov run`.

## Fields

| Field | Meaning |
|---|---|
| `task` | Human-readable instruction compiled into the agent prompt. |
| `job_id` | Stable alphanumeric, dot, underscore, or hyphen identifier. |
| `job_type` | Operator-defined category used by scoring and routing. |
| `agent` | `claude-code`, `codex`, `glm`, `opencode`, or `pi`. |
| `mode` | `scout`, `surgeon`, `batch_worker`, `verifier`, `repair`, `architect`, or `planner`. |
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
| `cleanup.required` | Optional, default `false`. `true` makes a failing `cleanup.validators` entry block the merge like a failed `success.validators` entry; `false` records the result without gating. |
| `cleanup.validators` | Nonempty when `cleanup` is present. Shell commands run as a distinct post-approval stage after every `success.validators` entry passes (see `docs/ledger.md`). |
| `depends_on` | Optional, plan-authoring only. Names sibling `job_id`s within a `gov plan` manifest that must complete first. |
| `risk_class` | Optional, plan-authoring only. `low`, `medium`, or `high` — a coarse tier `gov plan --show` renders per job. |
| `on_violation` | `quarantine`; unsupported actions are rejected during validation. |

All path patterns are repository-relative and may not escape with `..`. Read-only modes are `scout`, `verifier`, and `architect`. `planner` writes only inside its own `gov plan --out` directory, never the target repository. Governator rejects direct-root execution and unimplemented violation actions rather than accepting policy it cannot enforce.

## Task decomposition (`gov plan`)

`gov plan <intent.md> --out jobs/<slug>/` compiles a `mode: planner` job whose task is the intent file plus repository context from `internal/contextgraph`. The planner is a normal governed run — read-only against the target repository, write-capable only inside `--out` — and must produce a `PLAN.yaml` manifest: an ordered list of sub-contracts, each with its own `budget`, `success.validators`, `risk_class`, and `depends_on`.

Before anything merges, an in-process post-run gate (`contracts.ValidatePlan`, run via `Contract.PostRunValidate`) checks the manifest deterministically: every sub-contract passes `Contract.Validate()`, `job_id`s are unique, `workspace.root` matches the intent's declared root, every `risk_class` is set and `budget.max_tokens` is nonzero, the sum of sub-budgets doesn't exceed `--max-total-tokens`, every write pattern stays inside the intent's declared envelope, and `depends_on` has no dangling references or cycles. Any failure quarantines the planner run exactly like a failed shell validator — a malformed plan never reaches disk as a runnable job.

`gov plan --show jobs/<slug>/` renders the dependency DAG with per-job budget and risk. Nothing in a validated plan runs automatically: `gov batch run jobs/<slug>/ --ordered` executes it, honoring `depends_on` as topological levels (serial across dependency edges, parallel within a level) via the same worker pool `gov batch run` uses for independent jobs.

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

## Cleanup stage and doctrine

```yaml
cleanup:
  required: false
  validators:
    - test -z "$(gofmt -l .)"
```

Once every `success.validators` entry passes, `cleanup.validators` run as a distinct pre-merge stage, recorded in the ledger's `validators` table with `stage='cleanup'` instead of the default `'success'`. `cleanup.required: false` (the default) records the result for visibility without gating the merge — useful for observing a new lint pass before enforcing it; `true` blocks the merge on a failing cleanup validator exactly like a failed success validator. Absent `cleanup` runs no cleanup stage at all — every contract predating this feature validates and runs unchanged.

`gov validate` separately checks doctrine: a `surgeon`, `batch_worker`, or `repair` contract with neither a `cleanup` block nor a validator that looks like a lint/format check (a `success.validators` entry containing `lint`, `fmt`, `format`, `vet`, or a known tool name such as `eslint`/`black`/`prettier`) prints a `DOCTRINE WARNING` naming the job but still exits 0. Setting `doctrine.require_cleanup: true` in `~/.governator/config.yaml` (or `GOV_DOCTRINE_REQUIRE_CLEANUP=true`) upgrades that to a `DOCTRINE ERROR` and a nonzero exit — off by default so every existing job YAML keeps validating unchanged. `scout`, `verifier`, `architect`, and `planner` contracts are exempt: they never write to the target repository.
