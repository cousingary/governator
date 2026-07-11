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
2. **Structured signals only.** The broker routes on `job_type`, `mode`,
   `risk_class`, budgets, capability requirements, and ledger evidence. It
   never sniffs task text.
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
```

A `routing:` block paired with an explicit agent is an **error**, not a warning
— an explicit agent is the operator overriding the broker, so the combination
is ambiguous. `agent: auto` without a `routing:` block routes over every
registered backend under the balanced default.

### Score components

Each is recorded separately in the decision, so a decision is fully explainable
from the ledger alone:

| Component | Source | Hard/soft |
|---|---|---|
| valid-output rate | `agent_profiles(agent, job_type)` | soft |
| failure-taxonomy severity | `runs` failure taxonomy (quality kinds only) | soft |
| estimated cost | `internal/spend/estimate.go` (`max_tokens` × $/1M-tok) | soft, normalized across the pool |
| capability fit | `agents.Capability` vs `requirements` | **hard exclusion** |
| binary health | `config.BackendBin` + PATH presence (S1 floor) | **hard exclusion** |
| breaker state | `HealthSource.Breaker` (Session 2; stubbed CLOSED) | OPEN = exclusion, DEGRADED = penalty |
| quota headroom | `HealthSource.Quota` from `quota_windows` | soft when telemetry available |
| repair-lineage affinity | the backend that ran the root of the lineage | soft (repair jobs only) |

Cost is min-max normalized across the **non-excluded** candidates: cheapest
survivor scores 1.0, most expensive 0.0. A single survivor has no peer and
scores 1.0.

The `objective` shifts weights but **never bypasses a hard exclusion**:

| Objective | valid | severity | cost | breaker | quota | affinity |
|---|---|---|---|---|---|---|
| balanced | 0.30 | 0.15 | 0.25 | 0.10 | 0.05 | 0.15 |
| cheapest | 0.20 | 0.10 | 0.55 | 0.05 | 0.05 | 0.05 |
| most_reliable | 0.35 | 0.30 | 0.05 | 0.20 | 0.05 | 0.05 |

In v1.2 the breaker and quota weights are live when their telemetry exists;
missing quota telemetry stays neutral rather than penalizing a backend.

A backend with **no ledger evidence** is treated as neutral (0.5 valid rate,
1.0 severity): a brand-new backend is neither penalized for being unproven nor
rewarded over a proven one. Ties break by ascending name for reproducibility.

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
run_id, job_id, job_type, objective, candidate,
valid_rate_score, failure_severity_score, cost_score,
breaker_score, quota_score, repair_affinity_score, total,
excluded, exclusion_reason, selected, preview, created
```

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

Panel mode is cognition-only and plan-level. `gov plan --panel <n>` emits a validated proposal plan with `n` parallel read-only member jobs, one deterministic comparison job, and one advisory architect judge. Members may only use `scout`, `architect`, or `verifier`; the judge must be `architect`; all panel jobs use isolated `workspace.worktree: auto`; no panel verdict can auto-merge or override validators.

Each member produces a schema'd typed artifact. The comparison job consumes those artifacts and runs `gov panel compare`, a deterministic local command that strips provider identity fields (`agent`, `backend`, `model`, `provider`, etc.), labels outputs as `panelist_1...N`, hashes the original inputs, and emits a JSON comparison artifact. The ledger has a `panel_members` table for mapping anonymous labels back to job ids/backends outside model context. The judge consumes only the anonymized comparison bundle and writes an advisory schema'd judgment artifact; normal validators and artifact checks remain sovereign.

Good uses: architecture review, failure diagnosis, security inspection, plan criticism, and ambiguous root-cause hunts. Bad uses: source editing, auto-fixing, or using a judge verdict to bypass quarantine.

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

## Roadmap (subsequent sessions)

- **Session 7** — Assayer quality feedback loop (gated on Assayer acceptance).

Explicit anti-goals: no OmniRoute fork, no fail-open capability filtering, no
keyword task classification, no mid-run agent swapping, no lossy validator
compression.
