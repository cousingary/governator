# Job contracts

A job contract is strict YAML: unknown fields, multiple documents, malformed path patterns, and literal credentials are rejected. Run `gov validate job.yaml` before `gov preflight` or `gov run`.

## Fields

| Field | Meaning |
|---|---|
| `task` | Human-readable instruction compiled into the agent prompt. |
| `job_id` | Stable alphanumeric, dot, underscore, or hyphen identifier. |
| `job_type` | Operator-defined category used by scoring and routing. |
| `agent` | `claude-code`, `codex`, `glm`, `opencode`, `pi`, or `auto` (route broker). |
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
| `produces` | Optional typed handoff artifacts: `{name, path, schema, max_bytes}`. Paths must be under `.governator/artifacts/`; artifacts are copied to the ledger store and never merged. |
| `consumes` | Optional artifact names this job requires from `depends_on` ancestors in a validated plan. |
| `depends_on` | Optional, plan-authoring only. Names sibling `job_id`s within a `gov plan` manifest that must complete first. |
| `risk_class` | Optional. `low`, `medium`, or `high` — a coarse tier `gov plan --show` renders per job, and (paired with `agent: auto`) the route broker reads too, nudging scoring toward reliability over cost. See [docs/routing.md](routing.md#risk_class-scoring). |
| `on_violation` | `quarantine`; unsupported actions are rejected during validation. |

All path patterns are repository-relative and may not escape with `..`. Read-only modes are `scout`, `verifier`, and `architect`. `planner` writes only inside its own `gov plan --out` directory, never the target repository. Governator rejects direct-root execution and unimplemented violation actions rather than accepting policy it cannot enforce.

## Task decomposition (`gov plan`)

`gov plan <intent.md> --out jobs/<slug>/` compiles a `mode: planner` job whose task is the intent file plus repository context from `internal/contextgraph`. The planner is a normal governed run — read-only against the target repository, write-capable only inside `--out` — and must produce a `PLAN.yaml` manifest: an ordered list of sub-contracts, each with its own `budget`, `success.validators`, `risk_class`, and `depends_on`.

Before anything merges, an in-process post-run gate (`contracts.ValidatePlan`, run via `Contract.PostRunValidate`) checks the manifest deterministically: every sub-contract passes `Contract.Validate()`, `job_id`s are unique, `workspace.root` matches the intent's declared root, every `risk_class` is set and `budget.max_tokens` is nonzero, the sum of sub-budgets doesn't exceed `--max-total-tokens`, every write pattern stays inside the intent's declared envelope, `depends_on` has no dangling references or cycles, and every `consumes` artifact is produced by a `depends_on` ancestor. Any failure quarantines the planner run exactly like a failed shell validator — a malformed plan never reaches disk as a runnable job.

`gov plan --show jobs/<slug>/` renders the dependency DAG with per-job budget and risk. Nothing in a validated plan runs automatically: `gov batch run jobs/<slug>/ --ordered` executes it, honoring `depends_on` as topological levels (serial across dependency edges, parallel within a level) via the same worker pool `gov batch run` uses for independent jobs.

## Typed handoff artifacts

Jobs can make handoffs explicit instead of communicating only through source diffs:

```yaml
produces:
  - name: reconnaissance
    path: .governator/artifacts/scout.json
    schema: schemas/scout.schema.json
    max_bytes: 262144
consumes:
  - reconnaissance
```

A produced artifact path must be relative and under `.governator/artifacts/`. At job end Governator checks that each declared artifact exists, is within `max_bytes`, and optionally validates it against a deterministic in-process JSON Schema subset (`type`, `required`, `properties`, `items`, `enum`, and `additionalProperties: false`). Missing, oversized, or schema-invalid artifacts quarantine as `VALIDATION_FAILED`. Valid and invalid existing artifacts are sha256-hashed, copied to `<ledger_dir>/artifacts/<run_id>/...`, and recorded in the `artifacts` table with `schema_ok`. The `.governator/` tree is excluded from source merge and source-change budgeting.

A consuming job must be part of a validated plan: `ValidatePlan` resolves each `consumes` name to a producing `depends_on` ancestor and fails closed when no ancestor produces it. Runtime stages consumed artifacts read-only at `.governator/consumed/<name>` inside the consumer worktree and lists those paths in the prompt preamble.

## Panel plans

`gov plan --panel <n> <intent.md> --out jobs/<slug> --envelope <pattern>... --max-total-tokens <n> [--min-success <n>] [--member-timeout-seconds <n>] [--hard-timeout-seconds <n>] [--diversity-key backend|model_family] [--diversity-min-unique <n>] [--diversity-fallback-key backend|model_family]` writes a proposal-only panel template: read-only member contracts (executed serially — see `docs/routing.md`'s Phase 2 section), a verifier comparison contract that runs `gov panel compare`, and an advisory architect judge. The resulting `PLAN.yaml` includes a top-level `panel:` block mapping members, comparison job, judge, and (Phase 2) the `min_success`/`member_timeout_seconds`/`hard_timeout_seconds`/`diversity` quorum and backend-plurality policy; `ValidatePlanManifest` applies the normal plan checks plus panel-specific hard prohibitions: no write-capable panel members, no shared/concrete worktrees, no write-capable judge, schema'd artifacts for every panel handoff, and (Phase 2) `min_success >= 2` when set, `hard_timeout_seconds >= member_timeout_seconds` when both are set, and a known `diversity.group_by`/`fallback_group_by`.

Panel artifacts are typed handoff artifacts, so the Session 5 artifact rules still apply. The comparison command anonymizes provider/model identity before judge context and bundles the anonymous panel outputs for the judge; the ledger-side `panel_members` mapping is for audit only. `gov batch run --ordered <dir>` runs a panel plan through `internal/runtime.RunPanel` automatically whenever `<dir>/PLAN.yaml` carries a `panel:` block — no separate panel-run subcommand.

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

## Route broker (`agent: auto`)

```yaml
agent: auto
routing:
  objective: balanced          # balanced | cheapest | most_reliable
  candidates: [claude-code, codex, glm]
  max_attempts: 2
  fallback: infrastructure_only
  requirements:
    native_sandbox: true
    # read_only_mode, vision, tool_calling, local_only, min_context_tokens,
    # min_output_tokens are also available — see docs/routing.md.
risk_class: low                 # low | medium | high; optional, shifts scoring toward
                                 # reliability when paired with agent: auto
```

`agent: auto` defers backend selection to the route broker (`internal/router`):
instead of naming a backend, the contract declares what it needs and the broker
scores every registered backend against ledger evidence and selects one
deterministically. An explicit `agent:` is unchanged — the broker never
overrides an operator's explicit choice. A `routing:` block is only valid with
`agent: auto`; pairing the two is a validation error (ambiguity).

`requirements` are **hard capability filters**: if no healthy candidate
satisfies them the job refuses to run rather than silently widening the pool.
`native_sandbox`, `network_control`, and `read_only_mode` check the backend's
CLI wrapper; `vision`, `tool_calling`, `local_only`, `min_context_tokens`, and
`min_output_tokens` check the model the operator has configured for that
backend (`config.yaml` `backends.<name>`) and default to unsupported/zero
until declared. `objective` and `risk_class` both shift score weights but
neither ever bypasses a hard exclusion. `max_attempts` caps the
infrastructure-only fallback chain (0 defaults to 2; values above 3 are
rejected); fallback only retries when the failed attempt left the worktree
unchanged and executed no tools. See [docs/routing.md](routing.md) for the
score components, weight tables, `risk_class` scoring, the policy hash, and
the session/phase roadmap. `gov route --explain <contract.yaml>` previews the
scored decision (including its policy hash) without launching.

## Cleanup stage and doctrine

```yaml
cleanup:
  required: false
  validators:
    - test -z "$(gofmt -l .)"
```

Once every `success.validators` entry passes, `cleanup.validators` run as a distinct pre-merge stage, recorded in the ledger's `validators` table with `stage='cleanup'` instead of the default `'success'`. `cleanup.required: false` (the default) records the result for visibility without gating the merge — useful for observing a new lint pass before enforcing it; `true` blocks the merge on a failing cleanup validator exactly like a failed success validator. Absent `cleanup` runs no cleanup stage at all — every contract predating this feature validates and runs unchanged.

`gov validate` separately checks doctrine: a `surgeon`, `batch_worker`, or `repair` contract with neither a `cleanup` block nor a validator that looks like a lint/format check (a `success.validators` entry containing `lint`, `fmt`, `format`, `vet`, or a known tool name such as `eslint`/`black`/`prettier`) prints a `DOCTRINE WARNING` naming the job but still exits 0. Setting `doctrine.require_cleanup: true` in `~/.governator/config.yaml` (or `GOV_DOCTRINE_REQUIRE_CLEANUP=true`) upgrades that to a `DOCTRINE ERROR` and a nonzero exit — off by default so every existing job YAML keeps validating unchanged. `scout`, `verifier`, `architect`, and `planner` contracts are exempt: they never write to the target repository.
