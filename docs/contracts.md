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
| `telemetry_mode` | Optional. `strict`, `estimated`, or `advisory` — governs what happens when `budget.max_tokens` is set but the backend's transcript doesn't expose usage. Defaults to `strict` when `budget.max_tokens > 0`, else `advisory`. See [Telemetry modes](#telemetry-modes) below. |
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
| `risk_class` | Optional. `low`, `medium`, or `high` — a coarse tier `gov plan --show` renders per job, and (paired with `agent: auto`) the route broker reads too, nudging scoring toward reliability over cost. **`high` also gates containment (Session 3):** a high-risk job must run under hardened Docker, a backend with a verified native sandbox, or a signed operator override (`containment.*`) — otherwise it fails before launch. See [docs/routing.md](routing.md#risk_class-scoring) and [Containment](#containment-and-risk-class) below. |
| `runner` | Optional, `local` (default) or `docker`. Selects host-level containment (Phase 5): `local` runs the agent as a direct host subprocess against the worktree; `docker` runs it inside a container bind-mounting the same worktree. A `docker` request Governator can't satisfy (binary/daemon unavailable) fails closed — it never silently falls back to `local`. |
| `docker.image` | Required when `runner: docker`. Container image the agent process runs in. Hardened configs (`docker.*` controls below) require a digest-pinned reference (`image@sha256:…`) unless `allow_mutable_tag` is set. |
| `docker.cpu_limit` / `docker.memory_limit` / `docker.pids_limit` | Optional resource limits (`--cpus`, `--memory`, `--pids-limit`). Unset means Docker's own default (no limit). |
| `docker.network` | Optional, `deny` (default) or `allow`. Network access is default-deny (`--network none`); a contract must opt in to `allow`. |
| `docker.credential_mounts` | Optional list of absolute host paths mounted read-only into the container (canonicalized before launch). Empty by default — no credentials are exposed unless explicitly allowlisted. |
| `docker.output_cap_bytes` | Optional, defaults to 20MiB. Caps how much of the container's stdout/stderr is persisted to the transcript. Truncation past the cap is **loud** (Session 3a): bytes accepted/discarded are recorded, an `OUTPUT_TRUNCATED` ledger stage is emitted, and when `require_complete_transcript` is set the run is quarantined rather than approved on an incomplete trail. |
| `docker.user` | Optional. Runs the container as a non-root user (`--user`). Required for a hardened config. |
| `docker.read_only_rootfs` | Optional. Mounts the root filesystem read-only (`--read-only`). Required for a hardened config; pair with `tmpfs` for dirs the backend must write. |
| `docker.cap_drop_all` | Optional. Drops every Linux capability (`--cap-drop=ALL`). Required for a hardened config. |
| `docker.no_new_privileges` | Optional. Sets `--security-opt no-new-privileges`. Required for a hardened config. |
| `docker.seccomp_profile` / `docker.apparmor_profile` | Optional absolute-path seccomp profile / named AppArmor profile (`--security-opt seccomp=…` / `apparmor=…`). |
| `docker.tmpfs` | Optional list of controlled `--tmpfs` mounts (e.g. `/tmp`, `/run`) — needed under `read_only_rootfs`. |
| `docker.allow_mutable_tag` | Optional. The documented exception to the digest requirement; records the choice in provenance. Without it, a hardened config's image must be `image@sha256:…`. |
| `docker.egress_allowlist` | **Rejected by validation when non-empty (fail-closed).** The docker runner has no mechanism that actually restricts egress to a `host:port` list, and an unenforced allowlist that reads as a restriction is a silently-broken security control. Use `network: deny` (the default), or an explicit `network: allow` with `deny_metadata_and_local_net: true`. The field is reserved for a future runner that can enforce it. |
| `docker.deny_metadata_and_local_net` | Optional. Under `network: allow`, redirects cloud-metadata hostnames to loopback via `--add-host`. The safe default remains `network: deny`. |
| `docker.require_complete_transcript` | Optional. Makes output truncation a blocking violation — a run whose transcript was capped (or whose runner observation failed, leaving completeness unprovable) is quarantined. Defaults false (truncation recorded but non-blocking) **except** for blocking-assay runs, which are evidence-bearing by definition and always require a complete transcript regardless of this flag. High-risk hardened contracts should set it true. |
| `local.output_cap_bytes` | Optional, defaults to 20MiB. The `runner: local` equivalent of `docker.output_cap_bytes` (Sol High 11): caps how much of the host subprocess's stdout/stderr is persisted to the transcript, with the same loud accept/discard accounting and `OUTPUT_TRUNCATED` ledger stage. Must be absent when `runner: docker` (use `docker.output_cap_bytes` there instead). |
| `local.require_complete_transcript` | Optional. The `runner: local` equivalent of `docker.require_complete_transcript`: a local run whose transcript was capped is quarantined rather than approved on an incomplete trail. Same blocking-assay-always-requires-complete-transcript override applies regardless of this flag. |
| `containment.override_reason` / `containment.override_signature` | Optional. A signed operator escape hatch for `risk_class: high` jobs that can't meet hardened Docker or a native sandbox. The signature is ed25519 (hex) over `<job_id>:<contract_hash>:<override_reason>` where `contract_hash` is the contract's SHA-256 with the containment block cleared — print the exact bytes with `gov containment message <job.yaml> --reason "..."`. Verified against `containment.override_public_key` in config. Both fields must appear together or not at all; with no key configured, no override is ever accepted (fail-closed). |
| `on_violation` | `quarantine`; unsupported actions are rejected during validation. |
| `policy.rules` | Optional (Session 5). Job-contract-layer declarative policy rules — see [Layered policy engine and checkpointed ASK](#layered-policy-engine-and-checkpointed-ask). |

All path patterns are repository-relative and may not escape with `..`. Read-only modes are `scout`, `verifier`, and `architect`. `planner` writes only inside its own `gov plan --out` directory, never the target repository. Governator rejects direct-root execution and unimplemented violation actions rather than accepting policy it cannot enforce.

## Global wall-clock budget

`budget.max_minutes` is a single deadline for the whole run, not a per-stage allowance: at launch, Governator derives a run context bounded by `context.WithTimeout(ctx, max_minutes)` anchored to the run's start time, and every later stage draws only the **remaining** time from that same deadline rather than getting a fresh clock. The agent launch itself receives whatever is left when it starts (an already-exhausted budget fails closed before launching); each success validator and each cleanup validator gets `stageTimeout(ctx, stage)`, which fails immediately if no time remains; the Assayer bridge inherits the same deadline-bearing context, so its own `timeout_seconds` and the run's remaining budget both apply, whichever is shorter. Total wall time and remaining budget at completion are recorded in the run's notes so a deadline exhausted mid-validator is distinguishable after the fact from one exhausted mid-agent-run.

## Telemetry modes

See [docs/backends.md#telemetry-modes](backends.md#telemetry-modes) for the full behavior of `strict`/`estimated`/`advisory`. In short: a contract with a hard `budget.max_tokens` ceiling defaults to `strict`, which quarantines the run if the backend's transcript format doesn't expose token usage — an unmeasurable budget is never silently treated as "under budget."

## Local-runner symlink containment

Regardless of `risk_class`, any `runner: local` job rejects the run outright if the worktree contains **any** symlink (or, on Windows, a junction) anywhere under the tree, excluding `.git/` and `.codegraph/`. This is a whole-tree check, not scoped to the declared write envelope — a tracked symlink pointing outside the worktree, or a symlinked parent directory of a declared write path, both fail the same way, before any quota reservation or workspace side effect. This closes the path a "read-only" verifier or a scoped writer could otherwise use to write through a symlink to an arbitrary host path while the fingerprint diff still looked clean. See [docs/containment.md](containment.md) for why this is repository-level hygiene, not host containment, and does not substitute for hardened Docker or a verified native sandbox on `risk_class: high` work.

## Containment and risk-class

A `risk_class: high` contract must not silently resolve to local execution (Session 3, Phase 2). At run time — after the route broker resolves the agent (native sandbox is a verified backend capability, never a contract claim) and before any quota or workspace side effect — Governator requires one of:

- **Hardened Docker** (`runner: docker` with `docker.user`, `docker.read_only_rootfs`, `docker.cap_drop_all`, `docker.no_new_privileges`, a digest-pinned `docker.image`, and `network: deny` — i.e. `IsHardened()`). Network deny is part of hardened because unrestricted egress is a data-exfiltration path no filesystem or capability control compensates for; a high-risk job that genuinely needs the network goes through the signed operator override. These map to real `docker run` flags; credential mounts and the workspace bind are canonicalized before launch, and image provenance is recorded.
- **A verified native sandbox** for a `runner: local` job — the resolved backend declares `NativeSandbox` (e.g. Claude Code's `--safe-mode`, Codex's sandbox).
- **A signed operator override** (`containment.override_signature`), verified against `containment.override_public_key` in config (or `GOV_CONTAINMENT_OVERRIDE_PUBLIC_KEY`). With no key configured, no override is accepted — high-risk local jobs without qualifying containment simply fail before launch.

Everything else passes through untouched: `low`/`medium`/unset risk classes are scoring-only and never containment-gated, and a non-hardened docker config is still valid for ordinary jobs. To sign an override, the operator runs `gov containment message <job.yaml> --reason "..."` and signs the printed bytes (`<job_id>:<contract_hash>:<override_reason>`, where the hash is computed with the containment block cleared) with their ed25519 private key. Binding `job_id` prevents an override minted for one high-risk job being replayed against another; binding the contract hash prevents the sharper replay where the same job's contract body is edited after signing (widened scope, network enablement, a different image) while the old signature keeps verifying — any content edit invalidates the signature, and the operator re-signs after reviewing the new body.

## Layered policy engine and checkpointed ASK

Session 5 extends `internal/policy` from a single boolean allow/deny gate into four verdicts — **ALLOW**, **DENY**, **ASK**, **FLAG** — evaluated across four layers, in this fixed precedence order:

1. **Organization** — `policy_rules` in `~/.governator/config.yaml` (or `GOV_CONFIG`). Most authoritative: no lower layer can loosen a DENY an org rule produces.
2. **Project doctrine** — `policy_rules` in a `.governator-doctrine.yaml` file at the job's `workspace.root`. Missing is not an error; an unconfigured project contributes no rules.
3. **Job contract** — this contract's own `policy.rules` block (see the Fields table above).
4. **Session/operator override** — durable, expiring rows an operator creates while resolving a checkpoint (`gov ask approve --rule`), scoped to one `job_id` and one rule id.

All three data-driven layers share the same rule shape:

```yaml
policy_rules:
  - id: network-enablement        # required, referenced by checkpoints/overrides
    when:                          # AND of conditions; a rule with no "when" never fires
      - field: network_enabled    # a well-known fact name (see below)
        op: eq                    # eq, ne, gt, gte, lt, lte, contains, matches_any
        value: "true"
    verdict: ASK                   # DENY, ASK, or FLAG — never ALLOW (nothing firing already means allow)
    reason: network access needs operator review
```

There is no in-process rule-evaluator escape hatch: rules stay plain data (field/op/value/verdict/reason), matching Sol's non-goal "no arbitrary in-process Go/Python policy code."

**Facts** a rule's `when` can reference (`internal/policy.Fact*` constants): `risk_class`, `mode`, `backend`, `network_enabled` (a docker `network: allow` or an `allowed.execute` entry that looks like a network command), `write_out_of_scope` (an intended write outside `allowed.read`), `estimated_cost_usd` / `daily_cap_usd` (a pre-launch worst-case cost estimate vs. the operator's `spend.daily_cap_usd`), and `unusual_infra_retry` / `infra_failure_kind` (set only when deciding whether to auto-launch a fallback attempt after a `BINARY_MISSING`/`FLAG_DRIFT`/`TRANSIENT_UPSTREAM` infra failure — routine `RATE_LIMIT`/`QUOTA_EXHAUSTED`/`AUTH_EXPIRED` never consult the policy gate, so unattended fallback for those is unchanged).

**Verdicts and blocking:** DENY is terminal — fail-closed, no operator escape hatch within one evaluation. ASK pauses the run at a durable checkpoint. FLAG never blocks (same advisory posture as the Phase 6 temporal-rule engine's `flag` verdict) — it is recorded but the run proceeds. A run is quarantined (`FailureTaxonomy: POLICY_DENIED` or `POLICY_ASK_PENDING`) *before* quota reservation or workspace creation — nothing expensive has happened yet, so "resolve and resume" just means running the job again.

**Checkpointed ASK:** every rule that fires ASK (after any active override resolves it) gets a `policy_checkpoints` ledger row recording the reason, contributing sources, policy hash, and (when relevant) the cost estimate. Resolve it with:

```
gov ask list
gov ask show <id>
gov ask approve <id> [--rule] [--ttl 24h] [--by <name>] [--note "..."]
gov ask deny    <id> [--rule] [--ttl 24h] [--by <name>] [--note "..."]
```

`--rule` persists a durable `policy_overrides` row scoped to that job and rule id — an expiring (`--ttl`) or permanent temporary rule, so every subsequent run of the same job resolves the same ASK automatically. Without `--rule`, the approval/denial is **one-shot but real**: a single-use override row that authorizes exactly one subsequent evaluation of that job+rule, then is marked consumed. An ALLOW one-shot is spent only when the whole gate stops blocking (if another rule still ASKs, the approval survives for the retry that actually proceeds); a DENY one-shot is spent the moment it denies its one run. After consumption the job ASKs again. One mechanism (`gov ask`) works identically regardless of which layer or candidate target produced the ASK, and regardless of backend.

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
