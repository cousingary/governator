# Route broker

Governator has always gathered routing *evidence* — per-`(agent, job_type)`
valid-output rates, a failure taxonomy, a doctor, a capability matrix, a spend
accountant — but the loop was open: `gov route` only printed a ranking, every
contract hard-coded `agent:`, and the runtime called `agents.New` directly.
Nothing about *current* backend health, quota headroom, or verified output
quality influenced which backend ran a job.

The route broker (`internal/router`) closes that loop. A contract can now defer
backend selection to the broker with `agent: auto`; the broker scores every
candidate against the ledger and selects one deterministically, ledgering the
full decision. This is the v1.2 routing spine; this document grows per session.

## Standing rules

These govern every routing decision and every future session of the plan:

1. **Fail closed.** If a contract requires a capability (sandbox, network
   control, vision) and no healthy candidate satisfies it, the job refuses to
   run with a clear error. The pool is never silently widened.
2. **Structured signals only.** The broker routes on `job_type`, `risk_class`,
   budgets, capability requirements, and ledger evidence. It never sniffs task
   text. `mode` is carried on every `Request` for downstream context (e.g.
   `gov route --explain` display) but is deliberately score-neutral: it is not
   one of the "structured signals" above. `risk_class` is the intended lever
   for "route this one more conservatively" — see [RiskClass
   scoring](#risk_class-scoring) — so a second, implicit mode-based nudge would
   just make decisions harder to explain from the ledger alone (rule 4).
3. **Infrastructure failures and quality failures are separate metrics.** A
   provider outage must never lower an agent's quality score; bad output must
   never open a circuit breaker.
4. **Every routing decision is explainable and ledgered** — all candidates,
   every score component, every exclusion reason, the selection, and why.
5. **Determinism.** No LLM calls inside the broker. Plain Go + SQLite; tests
   run offline. No paid API calls.
6. **Backward compatible.** Explicit `agent: claude-code` contracts behave
   exactly as before — the broker validates health but never overrides an
   explicit choice (it may warn). All ledger migrations are idempotent.

## Session 1 — RouteBroker core + `agent: auto`

### Contract surface

```yaml
agent: auto            # defers selection to the broker; explicit names still work
routing:               # optional; only valid with agent: auto
  objective: balanced  # balanced | cheapest | most_reliable
  candidates: [claude-code, codex, glm]   # optional allowlist; default = all registered
  max_attempts: 2      # 0 defaults to 2; >3 rejected (Session 3 wires the chain)
  fallback: infrastructure_only           # reserved enum (Session 3)
  requirements:                           # HARD capability filters — fail closed
    native_sandbox: true
    network_control: false
    read_only_mode: false     # requires agents.Capability.NativeReadOnly
    vision: false              # requires config.yaml backends.<name>.vision
    tool_calling: false        # requires config.yaml backends.<name>.tool_calling
    local_only: false          # requires config.yaml backends.<name>.local_only
    min_context_tokens: 0      # requires config.yaml backends.<name>.context_tokens >= N
    min_output_tokens: 0       # requires config.yaml backends.<name>.output_tokens >= N
risk_class: low         # low | medium | high; optional, see risk_class scoring below
```

A `routing:` block paired with an explicit agent is an **error**, not a warning
— an explicit agent is the operator overriding the broker, so the combination
is ambiguous. `agent: auto` without a `routing:` block routes over every
registered backend under the balanced default.

`requirements` splits into two kinds. `native_sandbox`, `network_control`, and
`read_only_mode` check fixed properties of the backend's CLI wrapper
(`agents.Capability`'s static fields, set once per adapter in
`internal/agents`). `vision`, `tool_calling`, `local_only`,
`min_context_tokens`, and `min_output_tokens` check the underlying *model* the
operator has pointed the backend at — Governator never guesses these from a
binary name, since the same CLI wrapper can run different models over time.
They default to unsupported/zero and are satisfied only by an explicit
`backends.<name>` declaration in `config.yaml` (`gov init` scaffolds a
commented example under each backend's block); an unmet requirement fails
closed exactly like a missing native capability.

### Score components

Each is recorded separately in the decision, so a decision is fully explainable
from the ledger alone:

| Component | Source | Hard/soft |
|---|---|---|
| valid-output rate | `agent_profiles(agent, job_type)` | soft |
| failure-taxonomy severity | `runs` failure taxonomy (quality kinds only) | soft |
| estimated cost | `internal/spend/estimate.go` (`max_tokens` × $/1M-tok) | soft, normalized across the pool |
| capability fit (`native_sandbox`, `network_control`, `read_only_mode`) | `agents.Capability`'s static fields vs `requirements` | **hard exclusion** |
| model fit (`vision`, `tool_calling`, `local_only`, `min_context_tokens`, `min_output_tokens`) | `config.yaml` `backends.<name>` vs `requirements` | **hard exclusion** |
| binary health | `config.BackendBin` + PATH presence (S1 floor) | **hard exclusion** |
| breaker state | `HealthSource.Breaker` (live via `breaker.Store`) | OPEN = exclusion, DEGRADED = penalty |
| quota headroom | `HealthSource.Quota` from `quota_windows` | soft when telemetry available |
| repair-lineage affinity | the backend that ran the root of the lineage | soft (repair jobs only) |
| `risk_class` | `Contract.RiskClass` (also `gov plan --show`'s risk tier) | soft — shifts weights, see below |
| assay quality | blend of assay/validator/repair/panel evidence (`internal/router.assayEvidenceFor`) | soft, see [Assayer quality evidence](#assayer-quality-evidence-into-routing-v14-session-2) below |

`mode` is **not** a score component: it is carried on `Request` for context
(e.g. `gov route --explain` display) but never read by `evaluate` or any
weight function. See standing rule 2.

Cost is min-max normalized across the **non-excluded** candidates: cheapest
survivor scores 1.0, most expensive 0.0. A single survivor has no peer and
scores 1.0.

The `objective` shifts weights but **never bypasses a hard exclusion**:

| Objective | valid | severity | cost | breaker | quota | affinity | assay_quality |
|---|---|---|---|---|---|---|---|
| balanced | 0.27 | 0.15 | 0.22 | 0.10 | 0.05 | 0.15 | 0.06 |
| cheapest | 0.18 | 0.10 | 0.50 | 0.05 | 0.05 | 0.05 | 0.07 |
| most_reliable | 0.30 | 0.28 | 0.05 | 0.18 | 0.05 | 0.05 | 0.09 |

(v1.4 Session 2 took the `assay_quality` slice mainly from `valid`/`cost` so
every preset still sums to exactly 1.0; see [Assayer quality
evidence](#assayer-quality-evidence-into-routing-v14-session-2) below.)

The breaker and quota weights are live when their telemetry exists; missing
quota telemetry stays neutral rather than penalizing a backend.

A backend with **no ledger evidence** is treated as neutral (0.5 valid rate,
1.0 severity): a brand-new backend is neither penalized for being unproven nor
rewarded over a proven one. Ties break by ascending name for reproducibility.

### `risk_class` scoring

`risk_class` (`low`, `medium`, `high`) is optional on every contract —
`gov plan --show` has always rendered it as a plan-authoring tier, and the
route broker (`internal/router.riskAdjustedWeights`) now reads it too when
paired with `agent: auto`. It moves a bounded slice of the objective's cost
weight onto the four reliability components — valid rate, failure severity,
breaker state, and (since v1.4 Session 2) assay quality — split 40/25/20/15
so the total always still sums to 1.0. It never touches quota or affinity
(rule 3 keeps infra/quality signals separate from anything risk-flavored) and
never bypasses a hard exclusion — only soft scores among survivors move.

| `risk_class` | cost shift | applied to (validRate / severity / breaker / assay_quality) |
|---|---|---|
| unset or `low` | none (no-op) | — |
| `medium` | up to 0.05 | 40% / 25% / 20% / 15% of the shift |
| `high` | up to 0.15 | 40% / 25% / 20% / 15% of the shift |

The shift clamps to whatever cost weight the chosen `objective` actually has
(e.g. `most_reliable`'s cost weight is already 0.05, so `high` there clamps to
a 0.05 shift, not the nominal 0.15). An unset `risk_class` is a deliberate
no-op: every `agent: auto` contract that predates this field routes exactly as
it did before.

### Policy hash

Every decision carries a `PolicyHash` — a 16-hex-character SHA-256 digest
(`internal/router.policyHash`) over the exact post-risk-adjustment scoring
weights and the requirement set used to produce it. Two decisions with the
same hash used the identical policy even if the ledger evidence they scored
differed; a changed hash between two otherwise-similar decisions is the
tripwire for an unnoticed weight or requirement change. `gov route --explain`
prints it in the header line (`policy_hash=...`), and it is recorded on every
`route_decisions` row (see Ledger below).

### Wiring

The broker runs inside `runtime.Run`, between contract validation and workspace
creation. Resolving **before** the workspace is built means a fail-closed
decision refuses with no orphan worktree or canary left behind. The resolved
agent feeds the prompt registry, `agents.New`, identity, and the run record, so
the run reports what actually ran — while the contract hash (computed from the
authored contract) still keys the replay cache on `agent: auto`.

### Ledger

A new additive `route_decisions` table records one row per candidate per
decision:

```
run_id, job_id, job_type, objective, policy_hash, candidate,
valid_rate_score, failure_severity_score, cost_score,
breaker_score, quota_score, repair_affinity_score, assay_quality_score, total,
excluded, exclusion_reason, selected, preview, created
```

`assay_quality_score` (v1.4 Session 2) is the only piece of the new Assayer
evidence persisted here — it is the blended component `totalScore` folds into
`total`. The raw per-metric evidence it blends (assay pass rate, validator
pass rate, repair success rate, panel agreement rate, cost per accepted
result) is *not* duplicated into `route_decisions`; it lives in, and stays
queryable from, the tables that are already its source of truth
(`assay_evaluations`, `validators`, `runs`, `panel_members`) — the same
reason `agent_profiles`' raw run/valid counts were never duplicated into
`route_decisions` either. `gov route --explain`'s printed table still shows
the raw per-metric numbers (see [Assayer quality
evidence](#assayer-quality-evidence-into-routing-v14-session-2)) even though
only the blend is ledgered.

Excluded candidates are included with their reason. `preview=1` marks dry-run
decisions; real launches always record `preview=0`.

### CLI

`gov route --explain <contract.yaml>` is a dry run: it resolves and prints the
full scored candidate table **without launching anything and without writing a
decision row** (print-only keeps the ledger clean of previews). It exits
non-zero when the decision fail-closes, so `gov route --explain job.yaml && gov
run job.yaml` stops before a launch that would refuse.

The existing `gov route --job-type <type>` ranking is unchanged.

## Session 2 — Infrastructure circuit breakers

Infrastructure health is now persisted separately from output quality. The
`breaker_state` table tracks each backend as `CLOSED`, `DEGRADED`, `OPEN`, or
virtual `HALF_OPEN`; `breaker_events` records every transition and manual
reset. The router hard-excludes `OPEN`, penalizes `DEGRADED`, and treats
cooled-down `HALF_OPEN` as an admissible real-job probe.

Infra classifications are the only inputs that move the breaker:
`RATE_LIMIT`, `QUOTA_EXHAUSTED`, `AUTH_EXPIRED`, `BINARY_MISSING`,
`FLAG_DRIFT`, and `TRANSIENT_UPSTREAM`. Quality failures such as
`VALIDATION_FAILED`, `SCOPE_DRIFT`, `POLICY_VIOLATION`, destructive commands,
or bad output never open a breaker and still feed only quality evidence.
Backend-owned matchers in `internal/agents` classify stderr/transcript tails;
unknown nonzero exits remain non-infra so they cannot trip the circuit by
accident.

`gov health` prints the breaker table. `gov health reset <backend>` manually
closes a breaker with an audit row. Doctor-gated kinds (`AUTH_EXPIRED`,
`BINARY_MISSING`, `FLAG_DRIFT`) stay open until `gov health` sees the backend
doctor check pass or the operator resets them; time-based kinds cool down
without a background probe daemon. Explicit-agent contracts still run as an
operator override, but print a warning when the chosen backend is degraded or
open.

## Session 3 — Safe pre-mutation fallback

`agent: auto` jobs may retry the next ranked candidate only when the failed
attempt proves no work happened. Fallback is allowed only when the routing
chain permits more than one attempt, the failure taxonomy is one of the infra
kinds above, the worktree fingerprint is unchanged, `files_touched` has no
rows for the failed run, and the audited transcript has no tool calls.

A qualifying failure records a `fallback_attempts` row with the root run id,
attempt number, backend, and `fallback_reason`, updates the breaker through the
normal Session 2 feedback path, excludes the failed backend, and re-enters the
router for a fresh worktree. Non-qualifying failures return the original
quarantine unchanged, so mutation still flows through the existing quarantine
and repair-packet path. The chain is capped by `routing.max_attempts`; no
mid-run provider swap is ever attempted.


## Session 4 — Quota-window ledger

Subscription headroom is now tracked separately from dollar spend. Spend caps
still bound paid usage; quota windows model provider-plan reset windows for a
single operator/account. The additive `quota_windows` table stores backend,
account, window type (`5h`, `daily`, `weekly`, `monthly`), reset time,
estimated limit, measured usage, reserved usage, confidence, and source. A
small `quota_reservations` table tracks in-flight reservations so crashed runs
can expire without leaving permanent reserved usage.

Quotas are seeded from the existing Governator config package via a top-level
`quotas:` block. Units are tokens by convention: launch reserves
`budget.max_tokens` (or a conservative no-ceiling token floor from
`internal/spend/estimate.go`), and completion replaces the reservation with the
backend's measured `total_tokens` when available. If no quota telemetry exists
for a backend, the router treats quota as unavailable rather than penalizing
it.

The route broker's `HealthSource.Quota` is live: configured low headroom lowers
the candidate's quota score, and existing hard exclusions (capability, missing
binary, OPEN breaker) remain separate. Runtime reserves before creating the
worktree; a selected backend with configured but insufficient headroom refuses
as `QUOTA_EXHAUSTED` before any mutation. `RATE_LIMIT`/`QUOTA_EXHAUSTED` reset
hints from backend stderr/transcript tails update quota reset windows with
`source=error_hint`, and the breaker now uses the next quota `reset_at` as the
`QUOTA_EXHAUSTED` cooldown when available.

`gov quota` prints the quota-window table with measured/reserved usage,
headroom, reset time, confidence, and source. It also seeds config windows and
expires stale reservations before rendering.

## Session 5 — Typed handoff artifacts

Contracts now support typed handoff artifacts with `produces` and `consumes`. Produced artifacts are controller-owned files under `.governator/artifacts/` in the disposable worktree; they are size-bounded, sha256-hashed, optionally JSON-Schema-validated without model calls, copied to the ledger-adjacent artifact store, and recorded in the additive `artifacts` table (`run_id`, `name`, `path`, `sha256`, `bytes`, `schema_ok`). The `.governator/` tree is excluded from merge and source-change accounting so artifacts never land in the source repository.

`ValidatePlan` fails closed unless every consumed artifact is produced by a `depends_on` ancestor. For ordered plan execution, the validator annotates each consuming sub-contract with the resolved producer job id; runtime then stages the latest approved artifact from that producer read-only at `.governator/consumed/<name>` and lists the staged paths in the prompt preamble. Missing, oversized, or schema-invalid produced artifacts quarantine as `VALIDATION_FAILED`; repair packets include the artifact list so repair jobs see the handoff evidence.

## Session 6 — Panel mode

Panel mode is cognition-only and plan-level. `gov plan --panel <n>` emits a validated proposal plan with `n` read-only member jobs, one deterministic comparison job, and one advisory architect judge. Members may only use `scout`, `architect`, or `verifier`; the judge must be `architect`; all panel jobs use isolated `workspace.worktree: auto`; no panel verdict can auto-merge or override validators.

Each member produces a schema'd typed artifact. The comparison job consumes those artifacts and runs `gov panel compare`, a deterministic local command that strips provider identity fields (`agent`, `backend`, `model`, `provider`, etc.), labels outputs as `panelist_1...N`, hashes the original inputs, and emits a JSON comparison artifact. The ledger has a `panel_members` table for mapping anonymous labels back to job ids/backends outside model context. The judge consumes only the anonymized comparison bundle and writes an advisory schema'd judgment artifact; normal validators and artifact checks remain sovereign.

Good uses: architecture review, failure diagnosis, security inspection, plan criticism, and ambiguous root-cause hunts. Bad uses: source editing, auto-fixing, or using a judge verdict to bypass quarantine.

## Phase 2 — Panel plurality + quorum

Members execute one at a time, in `panel.members` order, not concurrently: every governed run holds an exclusive per-workspace-root lock for its whole lifetime (`internal/runtime.lock`, keyed on `workspace.root`), and every panel member targets the same root, so concurrent launches would just race for that lock. `internal/runtime.RunPanel` is the panel-aware entry point `gov batch run --ordered <dir>` switches to automatically whenever a `PLAN.yaml` with a `panel:` block sits alongside the job files it's running (no separate `gov panel run` subcommand).

**Backend diversity.** `PanelSpec.Diversity` (`gov plan --panel`'s `--diversity-key`, `--diversity-min-unique`, `--diversity-fallback-key` flags) drives the router's `Request.ExcludeAgents` hard-exclusion set: each `agent: auto` member is resolved with every backend (or, with `group_by: model_family`, every backend in the same coarse vendor grouping — see `internal/runtime.diversityGroup`) already claimed by an earlier member excluded from its candidate pool, so distinct members land on distinct backends whenever the live candidate pool allows it. `min_unique` (default: every member gets a different backend) is enforced after assignment, not before: if the pool is too small, the panel proceeds with a reused backend rather than fail closed, and reports `degraded: insufficient_diversity` — diversity can degrade a panel, it never blocks one. An operator-set explicit `agent:` on a member is never re-routed, but its backend still counts toward the exclusion set for later members.

*Field-naming note:* `PanelDiversity`'s YAML tags are `group_by`/`fallback_group_by`, not `key`/`fallback_key` — `contracts.ParsePlan`'s literal-secret scan flags any `<word>KEY: <8+ char value>` pattern in a manifest (catching an accidentally-committed API key), and `key: model_family` would false-positive on it every time.

**Quorum.** `PanelSpec.MinSuccess` (default: every member) is how many members must reach `APPROVED` before the comparison job is allowed to run — `CompareArtifacts` needs at least two, so an explicit `min_success` below 2 fails validation. `RunPanel` stops launching further members the moment quorum is met (the rest are recorded `SKIPPED`, not run at all — the intended fast path, not a degradation) or once the level's cumulative wall-clock passes `HardTimeoutSeconds` (default 180s; the rest are recorded `TIMEOUT` and the panel is marked degraded — this ceiling exists specifically because the per-job `budget.max_minutes` gate can't bound below one full minute, while `MemberTimeoutSeconds`, default 120s, converts to that per-member budget at second granularity via `ceil(seconds/60)`). Fewer than 2 successful members fails the whole panel: comparison and judge are marked `SKIPPED` and no error is returned (a degraded result, not a Go error). The comparison job's `consumes`/`artifact_sources` are trimmed post hoc to whichever members actually succeeded (`internal/runtime.adjustComparisonConsumes`), so a skipped or timed-out member's missing artifact never hard-fails the comparison job's artifact-staging step.

## Review pass (2026-07-11, post-S6)

The plan's mandated Fable review over Sessions 1–6 found and fixed six defects,
each with a regression test:

1. **Consuming jobs could never execute** — `ArtifactSources` is `yaml:"-"`
   and was only populated inside `ValidatePlan`, so `gov batch run` (which
   re-parses exploded job files) launched every `consumes:` job with an empty
   mapping and it refused to stage inputs. Extracted
   `contracts.ResolveArtifactSources` and wired it into the batch path
   (fail-closed when a consumed artifact has no producing ancestor in the
   batch).
2. **RATE_LIMIT backoff overflow** — `base << (consecutive-1)` overflows int64
   near 26 consecutive failures, producing a *negative* cooldown (an instantly
   admissible breaker on the most rate-limited backend). Exponent now clamps
   to the 2 h cap.
3. **Lost audit context** — `RecordSuccess` cleared `FailureKind` before
   writing the close/probe_success event; the audit row now records the kind
   the backend recovered from.
4. **Zero-weight unknown taxonomies** — a failure taxonomy missing from the
   router's severity table weighed 0 (flattering the failing backend);
   unknowns now count as medium (0.7).
5. **`gov run --agent` validation bypass** — the override landed after
   `ParseFile` validation, so an explicit agent could silently pair with a
   `routing:` block (the exact ambiguity the schema rejects). The contract is
   re-validated after the override.
6. **Hazardous dead tail** — the fallback loop's unreachable trailing
   `runOnce` would, if ever reached, have launched an extra unledgered
   attempt; the loop now provably returns from inside.

## Phase 1 — Router contract repair (`v1.3-hardening`, 2026-07-11)

The v1.3 hardening plan's Phase 1 closed a set of doc/implementation gaps a
benchmark audit found in the v1.2 routing spine (see
`agents/governator_hardening_plan.md`):

1. **`RoutingRequirements` expanded** from two fields (`native_sandbox`,
   `network_control`) to eight: `read_only_mode`, `vision`, `tool_calling`,
   `local_only`, `min_context_tokens`, `min_output_tokens` join them, all
   fail-closed. See the contract-surface example and score-components table
   above for the split between CLI-wrapper facts (checked against
   `agents.Capability`) and model facts (checked against `config.yaml`
   `backends.<name>`, via the new `agents.WithConfiguredModel` overlay).
2. **`RiskClass` now feeds scoring.** Previously plan-authoring-only
   (`gov plan --show`'s risk tier), `Contract.RiskClass` is now also read by
   the router when paired with `agent: auto` — see [`risk_class`
   scoring](#risk_class-scoring) above. Unset stays a no-op, so no prior
   contract routes differently.
3. **`Mode` confirmed score-neutral**, not wired into scoring. Standing rule 2
   above and the score-components table now say so explicitly instead of
   claiming `mode` as a routing signal it never was.
4. **Policy hash** — every decision now carries `PolicyHash` (see [Policy
   hash](#policy-hash) above), persisted as a new `policy_hash` column on
   `route_decisions` (migration: `ALTER TABLE ... ADD COLUMN`, empty-string
   default on pre-existing rows, since those decisions were never actually
   fingerprinted).
5. **Per-candidate exclusion reasons** were already persisted in
   `route_decisions.exclusion_reason` since Session 1 — the new hard
   requirements simply add more `excluded(...)` call sites, which flow through
   the same existing plumbing.

## Assayer quality evidence into routing (v1.4 Session 2)

Closes the gap `internal/observability/phase7.go`'s own package doc left
explicitly open ("Nothing here feeds back into routing, the breaker, or
quota... that boundary is Phase 3C's job") — the Assayer bridge (Phase 3A)
now feeds a quality-evidence component into the same router Phase 3A never
touched.

`internal/router.assayEvidenceFor(db, agent, jobType)` reads five read-only
queries, each scoped to `(agent, job_type)` via a join through `runs` (the
same scoping `evidenceFor` already uses for valid rate/severity):

| Evidence | Source | No-evidence default |
|---|---|---|
| assay pass rate | `assay_evaluations` (verdict `pass`/`advisory` over non-`skipped` rows) | 0.5 |
| validator pass rate | `validators` (`exit_code=0`) | 0.5 |
| repair success rate | `runs` where `repair_of<>''`, `status='APPROVED'` | 0.5 |
| panel agreement rate | `panel_members` joined to `runs.status` (the per-agent analog of `observability.PanelDisagreementRate`, inverted) | 0.5 |
| cost per accepted result | `AVG(cost_usd)` over `status='APPROVED'` | 0 |

`assayQualityComponent` blends the first four (equal-weighted mean) into
`ScoredCandidate.AssayQualityScore`, the only one of the five `totalScore`
folds into `Total` — a new `assay_quality` slot in `weightSet`, populated in
every `objectiveWeights` preset and included in `riskAdjustedWeights`'
reliability shift (see the updated tables above) and in `policyHash`'s
fingerprint material. `CostPerAcceptedUSD` is deliberately excluded from the
blend: cost preference already has its own estimate-based `CostScore`
component, so folding actual cost in again would double-count it. All five
raw values are still recorded on `ScoredCandidate` and printed by
`Decision.Format()` (`gov route --explain`) for full explainability (rule
4), even though only the blend is persisted to `route_decisions` (see
Ledger above).

A candidate with none of this evidence yet scores exactly 0.5 — identical to
how `ValidRateScore` already treats an unproven backend — so a ledger with no
assay/validator/repair/panel history routes exactly as it did before this
component existed.

Every evaluation's ledger row (`assay_evaluations`) also gained four
provenance columns this session: `assayer_commit`, `profile_hash`,
`validators_hash`, `python_version` (`internal/assay.DescribeEnvironment`,
computed once per `runAssayStep` call and stamped onto every verdict —
pass, fail, error, *and* skipped alike). `assayer_commit` is `git rev-parse
HEAD` inside the configured Assayer checkout when it owns a `.git` of its
own, or the checked-in fixture's `PINNED_COMMIT` marker when it doesn't —
never a naive `git -C <repo>`, which would silently walk up to and report
*governator's own* commit for a fixture nested inside this repo.

Quality and infrastructure evidence remain separate metrics (rule 3,
unchanged): `assayEvidenceFor`/`AssayQualityScore` never touch
`internal/breaker`, and a blocking assay FAIL/ERROR quarantine — a
quality-only failure — never opens or degrades the breaker for the backend
that produced it (`internal/runtime`'s
`TestAssayBlockingFailNeverOpensBreaker`/`TestAssayBlockingErrorNeverOpensBreaker`
regression-test this end to end).

## Roadmap (subsequent sessions)

Explicit anti-goals: no OmniRoute fork, no fail-open capability filtering, no
keyword task classification, no mid-run agent swapping, no lossy validator
compression.
