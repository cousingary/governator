# Changelog

All notable changes to Governator are documented here.

## v1.4-session1-validator-test

Deterministic-validator-quarantine test: a deliberately-unsatisfiable
`success.validators` entry (`ZZZ_THIS_STRING_DELIBERATELY_NEVER_EXISTS_ZZZ`)
exercises the fail-closed quarantine path against this v1.4 Session 1
worktree. No code changed; this entry is the sole mutation.

## v1.4-session1

Merge + release-evidence proof landed on commit `2051e9b7`.

## [Unreleased] — v1.3 hardening (branch `v1.3-hardening`)

Closing gaps a benchmark audit found in the v1.2 routing spine. See
`agents/governator_hardening_plan.md` for the full phased plan; this section
grows per phase.

### Phase 0 — Release hygiene

Replaced `SECURITY.md`'s placeholder contact; synced `README.md`'s command
list to exactly match `gov --help`; corrected router/docs comments that still
called the breaker/quota `HealthSource` a Session 2/4 "stub" when
`breaker.Store` (the real ledger-backed implementation) has been live in both
`runtime.Run` and `gov route --explain` since those sessions shipped.

### Phase 1 — Router contract repair

- `RoutingRequirements` expanded from two fields to eight: `read_only_mode`,
  `vision`, `tool_calling`, `local_only`, `min_context_tokens`, and
  `min_output_tokens` join `native_sandbox`/`network_control`, all fail-closed.
  The first three check `agents.Capability`'s static CLI-wrapper fields; the
  model-dependent ones (`vision`/`tool_calling`/`local_only`/
  `min_context_tokens`/`min_output_tokens`) are satisfied only by an explicit
  `config.yaml` `backends.<name>` declaration (new `agents.WithConfiguredModel`
  overlay) — Governator never guesses model facts from a binary name.
- `Contract.RiskClass` (previously plan-authoring-only, feeding `gov plan
  --show`'s risk tier) now also feeds the route broker when paired with
  `agent: auto`: `internal/router.riskAdjustedWeights` shifts a bounded slice
  of the objective's cost weight onto valid-rate/severity/breaker for
  `medium`/`high` risk jobs. Unset stays a no-op, so no pre-existing contract
  routes differently.
- Every route decision now carries a `PolicyHash` (`internal/router.policyHash`,
  a SHA-256 digest of the effective scoring weights + requirement set),
  printed by `gov route --explain` and persisted in a new `route_decisions.
  policy_hash` column (additive migration, empty default on pre-existing rows).
- Confirmed and documented that `Mode` is not a router scoring signal (it
  never was); `docs/routing.md` no longer claims otherwise.
- Per-candidate exclusion reasons were already ledgered since Session 1; the
  new hard requirements simply add more callers of the existing mechanism.

See [docs/routing.md](docs/routing.md) for the score-components table,
`risk_class` scoring, and the policy hash.

### Phase 2 — Panel plurality + quorum

`panel:` gains `min_success`, `member_timeout_seconds`, `hard_timeout_seconds`,
and a `diversity: {group_by, min_unique, fallback_group_by}` block. Auto
members route with earlier members' backends hard-excluded
(`router.Request.ExcludeAgents`); an unsatisfiable diversity requirement
degrades the panel explicitly (`insufficient_diversity`), never silently.
Quorum stops launching members once `min_success` are APPROVED (rest SKIPPED)
or the level's hard timeout elapses (rest TIMEOUT, panel degraded); the
comparison job's consumes are trimmed to the members that actually succeeded.
Also fixed a pre-existing bug: panel member contracts' `max_new_files: 0`
budget-excluded every real member run (RESULT.json is always a new file).

### Phase 3A — Governator↔Assayer synchronous bridge

New `internal/assay` invokes Assayer's `cli.py evaluate --profile` as a local
subprocess (JSON on stdin/stdout, no network) with pre- AND post-evaluation
artifact sha256 re-checks (TOCTOU ⇒ ERROR). Contracts gain
`assay: {profile, enforcement: blocking|advisory|telemetry}`; config gains
`assay.repo/.python/.timeout_seconds`. New `assay_evaluations` ledger table;
blocking FAIL/ERROR reuses the existing violations→quarantine machinery; new
`ASSAY_FAILED` taxonomy (quality evidence only — never touches the breaker).

### Phase 4 — Durable run recovery

New `run_stages` checkpoint table (PARSED → … → APPROVED, idempotent per
run_id+stage) and `gov run inspect|resume|abandon|recover --stale`.
Recovery rule: pre-AGENT_RUNNING discards safely; AGENT_RUNNING-or-later
compares the worktree fingerprint recorded at launch (unchanged ⇒ safe,
changed/missing ⇒ fail-closed quarantine). Quota reservations are always
released and leftover worktrees destroyed. Also fixed a pre-existing
NULL-scan crash in `Last()`/`Quarantines()` on genuinely-interrupted runs.

### Phase 5 — Runner interface + Docker runner

`internal/runner` extracts Prepare/Launch/Observe/Stop/Destroy;
`LocalWorktreeRunner` is the pre-Phase-5 behavior moved verbatim.
`DockerRunner` (contract `runner: docker` + `docker:` block) adds
`--memory/--cpus/--pids-limit`, default-deny network, allowlisted read-only
credential mounts, an output-size cap, and docker-inspect-verified limits.
Docker unavailable + `runner: docker` fails closed — never silent local.

### Phase 6 — Policy provenance + temporal event rules

`internal/policy.PolicyDecision` (Allowed/Reasons/Sources/PolicyHash) routes
the F1-F7 gate; `hook_events` gains `sources`/`policy_hash`. A transcript
event graph + temporal rule engine ships 3 starter rules (secret-read →
network = deny; out-of-scope read → write = deny; suspected injection →
exec = advisory flag), ledgered to new `policy_rule_events`.

### Phase 7 — Analytical projection

`gov analytics summary|export` derives backend valid-output rate, failure
type by backend, fallback frequency, quota utilization, repair depth,
validator/assay failure clusters, panel disagreement, and cost by outcome
from the ledger (read-only; JSONL export; SQLite stays authoritative).

### Review pass (Fable, 2026-07-11) — 4 findings fixed

1. **`assay.Blocks` failed open on unrecognized verdicts**: under blocking
   enforcement, any verdict string other than the literal `fail`/`error`
   (empty, wrong-case, future/foreign values) cleared the gate. Now only
   known-good `pass`/`advisory` clear it — unrecognized means "not
   verified," and blocks.
2. **Blocking assay on an unconfigured Governator silently skipped and
   merged**: a contract explicitly demanding `enforcement: blocking` now
   quarantines when no assayer is configured (same fail-closed principle as
   `runner: docker` without Docker); advisory/telemetry keep the
   skip-and-record behavior.
3. **Bare-path `docker.credential_mounts` entries could never mount**:
   validation blesses a bare absolute host path, but `runArgs` appended
   `:ro` directly, handing Docker `ro` as the container path — every such
   mount failed at launch. Bare paths now mount at the same container path.
4. **`panel_members` was written by nothing** (Phase 7 flagged it):
   `RunPanel` now records one row per member, so the panel-disagreement
   metric has data. Plus gofmt cleanup in two test files that shipped
   unformatted despite commit messages claiming `gofmt -l` clean.

## [Unreleased] — v1.2 routing (branch `v1.2-routing`)

The route broker closes the loop the evidence substrate always supported but
nothing wired: `agent: auto` contracts defer backend selection to a
deterministic broker that scores every candidate against ledger evidence,
ledgering the full decision. See [docs/routing.md](docs/routing.md) for the
session roadmap and standing rules; this section grows per session.

### Added

- Route broker (`internal/router`): a new package that resolves an `agent: auto` contract to a concrete backend between contract validation and workspace creation. The broker scores every candidate on six recorded components — historical valid-output rate per `(agent, job_type)` from `agent_profiles`, quality-failure-taxonomy severity from the `runs` table, normalized estimated cost from `internal/spend/estimate.go`, capability fit, circuit-breaker state, and quota headroom — plus repair-lineage affinity for repair jobs. Hard exclusions (unsatisfiable `routing.requirements`, a missing backend binary, an OPEN breaker) fail closed: if no candidate qualifies the job refuses to run rather than silently widening the pool. The `routing.objective` (`balanced`/`cheapest`/`most_reliable`) shifts score weights but never bypasses a hard exclusion. Ties break by ascending name for reproducibility. No LLM calls; plain Go + SQLite; tests run offline. A `HealthSource` interface (breaker + quota) is stubbed healthy now and implemented in Sessions 2 and 4.
- Contract surface for `agent: auto`: a new `routing:` block (`objective`, `candidates`, `max_attempts`, `fallback`, `requirements: {native_sandbox, network_control}`) paired with the `agent: auto` sentinel. Validation rejects a `routing:` block with an explicit agent (ambiguity = error, not warning), validates the objective/fallback enums and candidate names against the known backend set, and enforces `max_attempts` in `[0,3]` (0 defaults to 2; Session 3 wires the fallback chain). An explicit agent now must name a known backend or `auto` (every prior job YAML uses valid names, so existing contracts keep validating unchanged).
- Routing ledger: a new additive `route_decisions` table records one row per candidate per decision (excluded candidates included with their reason), carrying every score component, the total, the selection, and a `preview` flag — so every routing decision is fully explainable and replayable from the ledger alone. `observability.RecordRouteDecision` writes a decision transactionally (all-or-nothing). Real launches record `preview=0`; the dry-run CLI records nothing.
- `gov route --explain <contract.yaml>`: a dry-run preview of the broker against an `agent: auto` contract — it resolves and prints the full scored candidate table without launching anything and without writing a decision row (print-only keeps the ledger clean of previews). Exits non-zero when the decision fail-closes, so `gov route --explain job.yaml && gov run job.yaml` stops before a launch that would refuse. The existing `gov route --job-type <type>` ranking is unchanged.
- Infrastructure circuit breakers (`internal/breaker`): backend health now persists in `breaker_state` (`CLOSED→DEGRADED→OPEN→HALF_OPEN`) with immutable `breaker_events`. Runtime classifies infra failures (`RATE_LIMIT`, `QUOTA_EXHAUSTED`, `AUTH_EXPIRED`, `BINARY_MISSING`, `FLAG_DRIFT`, `TRANSIENT_UPSTREAM`) from adapter-owned stderr/transcript matchers, records them on the run, and updates the breaker without polluting quality scores. OPEN backends are hard-excluded from `agent: auto`; DEGRADED backends take a score penalty; explicit-agent runs warn but still execute as operator overrides. `gov health` displays the table, auto-closes doctor-gated breakers once doctor passes, and supports `gov health reset <backend>` with an audit row.
- Safe pre-mutation fallback: `agent: auto` chains now retry the next routed backend only for infrastructure failures that prove no work happened (unchanged worktree fingerprint, zero `files_touched`, and zero transcript tool calls). Qualifying attempts are linked in the new `fallback_attempts` ledger table with `fallback_reason`; failed backends are excluded before re-routing into a fresh worktree. Any mutation or quality failure blocks fallback and leaves the existing quarantine/repair-packet path untouched.
- Quota-window ledger (`internal/quota`): provider-plan headroom now lives beside spend accounting without replacing it. New additive `quota_windows` and `quota_reservations` tables track configured reset windows, measured usage, in-flight reservations, confidence, and reset hints; `config.yaml` accepts a top-level `quotas:` seed block; runtime reserves quota before worktree creation and settles with measured `total_tokens`; stale reservations expire; the router reads live headroom through `HealthSource.Quota`; `QUOTA_EXHAUSTED` breakers use the next quota `reset_at` when present; and `gov quota` renders the current headroom table. Missing telemetry remains neutral rather than a penalty.
- Typed handoff artifacts: contracts now accept `produces` (`name`, `.governator/artifacts/...` path, optional schema, `max_bytes`) and `consumes` names. `ValidatePlan` requires every consumed artifact to be produced by a `depends_on` ancestor and annotates runtime sources; runs stage consumed artifacts read-only under `.governator/consumed/`, validate/copy/hash produced artifacts into the ledger-adjacent store, record them in the new `artifacts` table, exclude `.governator/` from merges, quarantine missing/oversized/schema-invalid artifacts as `VALIDATION_FAILED`, and include artifact summaries in repair packets.
- Panel mode: `gov plan --panel <n>` now emits a proposal-only cognition panel plan with read-only member jobs, a deterministic `gov panel compare` artifact, an advisory architect judge, panel-specific validation prohibiting write-capable members/judges/shared worktrees, anonymized panelist outputs, schema files, and a ledger `panel_members` mapping for audit.

### Fixed (Sessions 1–6 review pass, 2026-07-11)

- `gov batch run` never populated `ArtifactSources` (it is `yaml:"-"` and was only computed inside `ValidatePlan`), so every `consumes:` job refused to stage its inputs — the typed-handoff and panel pipelines could not execute end-to-end. Extracted `contracts.ResolveArtifactSources` and wired it into the batch path, failing closed when a consumed artifact has no producing `depends_on` ancestor in the batch.
- Breaker RATE_LIMIT exponential backoff overflowed int64 near 26 consecutive failures, yielding a negative cooldown (the breaker read as instantly admissible); the exponent now clamps at the 2 h cap.
- `breaker.RecordSuccess` audit rows recorded an empty `failure_kind` (cleared before the event was written); they now record the kind the backend recovered from.
- Router severity scoring gave failure taxonomies missing from its table a weight of 0, flattering the failing backend; unknown taxonomies now count as medium (0.7).
- `gov run --agent <name>` overrode the agent after parse-time validation, letting an explicit agent silently pair with a `routing:` block (the ambiguity the schema rejects); the contract is re-validated after the override.
- Removed the fallback loop's unreachable trailing `runOnce`, which — if ever reached — would have launched an extra attempt outside the `fallback_attempts` ledger chain.

## [Unreleased]

### Added

- Aggregate daily spend cap and kill switch (`internal/spend`): `spend.daily_cap_usd` (default `0`, unlimited) and `spend.halt_file` (default `~/.governator/HALT`) bound cross-run spend on top of the existing per-job `budget.max_tokens` quarantine. `gov run` checks the cap before launching a backend and refuses with a `QUARANTINED`/`SPEND_CAP` run (no workspace created, no backend launched) when the halt file is present or today's recorded cost meets or exceeds the cap; a post-run hook writes the halt file once a completed run crosses the cap so the next run refuses. New `gov spend` reports today's total/cap/remaining/run counts/halt status; `gov spend --halt` / `--resume` toggle the halt file directly.
- Minimalism prompt optimizer: a YAGNI-first ruleset adapted from ponytail (github.com/DietrichGebert/ponytail, MIT) is injected into every governed prompt (`minimalism.mode`: `off`/`lite`/`full`/`ultra`, default `full`), aimed at smaller diffs and lower per-run cost, with no external binary required. `gov doctor` reports the active mode.
- Auto-triggered repair loop: an optional `repair: {auto, max_attempts, backend}` contract block (default `auto: false`, existing job YAML unaffected). `gov run` now calls `RunWithAutoRepair`, which — when a run quarantines and `repair.auto` is set — compiles a follow-up job from that run's repair packet (the same evidence `gov repair-packet` gathers) and runs it as a normal governed job, stopping as soon as an attempt is approved. `max_attempts` defaults to 1 and hard-clamps to 2 regardless of YAML; a run refused purely by the spend cap is never retried. Every attempt in a lineage is linked via a new additive `runs.repair_of` column; `gov failures` gains a `repair_lineage` column and `gov handoff` reports `repair_attempted: n`.
- Batch runner: `gov batch run <job.yaml|dir|glob>... [--parallel N] [--halt-on-first-quarantine]` fans a set of independently-valid contracts out across a worker pool (default 2, clamped to 4). Every job goes through the unmodified single-run path (`RunWithAutoRepair`) — its own lock, spend check, gate, and validators apply exactly as `gov run` today. All contracts are parsed and validated up front; the whole batch refuses if any one is invalid, before anything launches. A new in-process `spend.Accountant` (`internal/spend/accountant.go`) closes the gap `CheckBudget` alone leaves for concurrent workers: `TodaySpend`'s ledger query excludes `RUNNING` rows, so two workers launched back to back would otherwise both pass the check before either's cost has landed; the accountant reserves a conservative per-job estimate (`spend.EstimateCostUSD`: `budget.max_tokens` × a per-backend $/1M-token table, or a flat $0.25 when a job sets no token ceiling) before launch and settles it against the real reported cost after. A worker that can't reserve exits `SKIPPED`/`SPEND_CAP` without ever calling `Run`; later jobs keep draining, they just skip too once the cap is exhausted. `--halt-on-first-quarantine` stops launching new jobs once any job quarantines (jobs already in flight finish). Batch summaries are written to a new additive `batches` ledger table (batch_id, started, finished, jobs, quarantined, total_cost_usd) and printed as a run_id/status/cost/worktree table plus an aggregate line. `internal/observability.Open` now sets WAL journal mode and a 5s `busy_timeout`, since batch workers each open their own `*sql.DB` against the same ledger file and need WAL to avoid `SQLITE_BUSY` under concurrent writes.
- Task decomposition: `gov plan <intent.md> --out jobs/<slug>/` compiles a new `mode: planner` contract (read-only against the target repository, write-capable only inside `--out`) whose required output is a `PLAN.yaml` manifest — an ordered list of sub-contracts with their own budgets, validators, `risk_class`, and `depends_on`. A new in-process post-run gate, `contracts.ValidatePlan` (run via a `Contract.PostRunValidate` hook that fires after shell validators pass and before merge), deterministically checks the manifest: every sub-contract passes `Validate()`, `job_id`s are unique, `workspace.root` matches the intent, every job declares `risk_class` and a nonzero `budget.max_tokens`, the sub-budget sum stays under `--max-total-tokens`, every write pattern stays inside the intent's declared envelope, and `depends_on` has no dangling refs or cycles — any failure quarantines the planner run like any other job, so a malformed plan never reaches disk. `gov plan --show <dir>` renders the dependency DAG with per-job budget/risk. Nothing in a validated plan runs on its own: `gov batch run <dir> --ordered` executes it, reusing Session 3's worker pool per topological level (serial across `depends_on` edges, parallel within a level). Contract gains two additive, optional fields (`depends_on`, `risk_class`) — every existing job YAML validates unchanged.
- Doctrine-enforced cleanup pass: an optional `cleanup: {required, validators}` contract block runs its `validators` as a distinct pre-merge stage once every `success.validators` entry passes, recorded in the ledger with a new additive `validators.stage` column (`'success'` or `'cleanup'`; every existing row defaults to `'success'`). `cleanup.required: false` (the default) records a failing cleanup validator without gating the merge; `true` blocks it exactly like a failed success validator. Separately, `gov validate` now applies the actual doctrine check (gap #5): a `surgeon`, `batch_worker`, or `repair` contract with neither a `cleanup` block nor a lint/format-looking `success.validators` entry (`internal/policy.CleanupDoctrineIssue`) prints a `DOCTRINE WARNING` naming the job but still exits 0; a new `doctrine.require_cleanup` config key (default `false`, `GOV_DOCTRINE_REQUIRE_CLEANUP` overrides) upgrades that to a `DOCTRINE ERROR` and exit 1. `scout`/`verifier`/`architect`/`planner` contracts are exempt — they never write to the target repository. `gov init`'s scaffolded config and example contract document both features; every existing job YAML and config file keeps validating unchanged under the warn-only default.

### Fixed

- Spend/routing evidence: a `SPEND_CAP` refusal no longer books a run/failure against the named agent in `agent_profiles` — the backend was never launched, so counting it corrupted the valid-output rates `gov score agents`/`gov route` rank by (a halted day would have piled fake failures onto whatever agent the refused jobs named). The refusal's run and violation rows are unchanged.
- Batch cost accounting: when auto-repair fires inside a batch, the worker now settles (and reports) the whole repair lineage's ledger cost — original run plus every attempt — instead of only the final attempt's, which under-counted the accountant and `batches.total_cost_usd` exactly when a job was most expensive.
- Plan envelope gate: `ValidatePlan` write patterns are path-cleaned before the envelope comparison, so a candidate like `src/../secrets/**` (inside the workspace root, so `Validate()` accepts it) can no longer prefix-match a declared `src/**` and smuggle a write target outside the declared envelope; `preflight.intended_writes` is now envelope-checked alongside `allowed.write`, as the planner prompt already promised.
- Halt file follows the ledger home: when `GOV_LEDGER_DIR`/`GOV_HOME`/`GOVERNATOR_HOME` overrides the home and no explicit `spend.halt_file` is configured, the halt file now defaults to `<home>/HALT` instead of always `~/.governator/HALT` — a real operator halt no longer bleeds into every isolated environment (the test suite especially), and `gov spend --halt` under an overridden home no longer writes to the real user home.
- `gov batch run` fails closed on `depends_on` it can't honor: contracts declaring dependencies refuse to run without `--ordered` (they would silently run in parallel), and an `--ordered` batch refuses a `depends_on` referencing a job not in the batch (`TopologicalLevels` would silently drop it and run the job without its prerequisite).
- Workspace lock: read the correct `/proc/<pid>/stat` field for process start time (field 22, index 19 after the comm parenthesis). The prior off-by-one read `itrealvalue` (always 0), which silently disabled recycled-PID detection and kept the staleness fallback from ever running on Linux. Regression test pins the field.
- Codex adapter: root-level flags (`--ask-for-approval`, `-c sandbox_workspace_write.network_access=false`) now precede the `exec` subcommand; `--ephemeral` added so Governator owns the sole durable transcript. Dedicated doctor probe verifies root-vs-exec flag placement against the installed binary.
- Protect: directory chmod failures during lock/release now propagate and verify instead of silently reporting a hollow lock; filtered release scopes to the target chain instead of releasing sibling paths.
- Snapshots: mtime comparison at nanosecond precision (whole-second compare could hardlink stale same-size content); exact snapshot-ID lookup wins over prefix ambiguity.
- Runtime: transcript audit treats malformed JSON lines as violations instead of skipping them; agent timeouts report one violation instead of three; context propagated through contextgraph subprocess calls; contextgraph index hashing streams instead of slurping.
- GLM adapter: `--no-session-persistence` and `--safe-mode` keep governed runs hermetic.

### Changed

- Contract schema is fail-closed on unenforceable policy: `workspace.worktree` must be `auto` (direct-root execution removed) and `on_violation` must be `quarantine` (halt/rollback were accepted but ignored). Scaffold, docs, and examples updated to match.
- Prompt compiler appends an explicit network-discipline annotation when a contract forbids `network`, naming the concrete command families the transcript audit will flag.

## [1.0.0-rc1] - 2026-07-04

### Added

- Phase 8: unified YAML configuration, idempotent `gov init`, release documentation, CI, fuzzing, and cross-platform release metadata.
- Phase 7: five-backend capability model, OpenCode and Pi adapters, neutral gate integrations, and per-format transcript audit.
- Phase 6: native protection and snapshots, parity reporting, and staged legacy-harness migration.
- Phase 5: replaceable Claude Code, Codex, and GLM adapters plus the F1-F7 interactive gate.
- Phase 4: evidence-based routing and deterministic harness evaluation.
- Phase 3: ledger intelligence, failure taxonomy, repair packets, and cost-per-valid-output reporting.
- Phase 2: policy hardening, preflight enforcement, command classification, and secret rejection.
- Phase 1: strict contracts, worktree execution, deterministic validation, quarantine, merge, and rollback.
- Phase 0: initial CLI and repository scaffold.

## v1.4-session1-fallback-test

Safe-pre-mutation-fallback test: the first routed candidate (a stubbed
backend simulating a real RATE_LIMIT infra failure) failed before touching
the worktree, exactly matching fallbackEligible's preconditions (infra
taxonomy, zero tool calls, unchanged worktree); the runtime's fallback loop
retried the next candidate, which completed this write and was approved.
