# Ledger and evidence

Governator stores an SQLite WAL database in `ledger_dir` (default `$HOME/.governator`). The schema migrates forward on open; do not manually truncate or edit it while runs are active.

## Tables

| Table | Evidence |
|---|---|
| `runs` | Contract identity, worktree, status, diff, transcript, cost, token usage, tool calls, transcript bytes, graph provider/version/fingerprint/stats, result, prompt version, enforcement envelope, notes, and repair lineage (`repair_of`). |
| `jobs` | Last-seen timestamp and job type. |
| `agents` | First and last observed run per backend. |
| `agent_profiles` | Runs, valid outputs, failures, and total cost by agent and job type. |
| `files_touched` | Path and change type per run. |
| `commands_run` | Audited shell command and classification. |
| `validators` | Validator command, exit code, bounded output, and `stage` (`success` or `cleanup`; see `docs/contracts.md`). |
| `violations` | Policy, budget, transcript, and validation failures. |
| `repair_packets` | Generated failure packet JSON and taxonomy. |
| `eval_runs` | Hermetic harness-evaluation outcomes. |
| `hook_events` | Interactive tool decision, finding, detail, and (Phase 6) `sources`/`policy_hash` provenance — see `docs/gate.md`. |
| `parity_events` | Go/Python shadow decisions and availability. |
| `batches` | One row per `gov batch run` invocation: batch id, started/finished timestamps, job count, quarantined count, and aggregate cost. |
| `run_stages` | Durable stage checkpoints for one run (`PARSED`, `PREFLIGHTED`, `ROUTED`, `QUOTA_RESERVED`, `WORKSPACE_READY`, `AGENT_RUNNING`, `AUDITED`, `VALIDATING`, `ASSAYING`, `MERGED`, plus the terminal `APPROVED`/`QUARANTINED`/`ROLLED_BACK`/`ABANDONED`), one row per `(run_id, stage)`. `AGENT_RUNNING`'s detail carries the pre-launch worktree digest recovery compares against. See "Run recovery" below. |
| `policy_rule_events` | Phase 6 temporal rule engine hits: rule name, verdict (`deny`/`flag`), detail, and the cause/trigger event sequence numbers, one row per violation, append-only per run. See `docs/gate.md`. |

## Operations

```sh
gov batch run JOBS_DIR --parallel 2
gov handoff last
gov diff last
gov quarantine list
gov failures
gov cost --per-valid-output
gov spend
gov spend --halt
gov spend --resume
gov usage summary
gov usage RUN_ID
gov graph status
gov graph query SYMBOL --limit 5
gov score agents --job-type code_change
gov route --job-type code_change
gov repair-packet RUN_ID
gov eval harness harness_eval
gov eval scorecard
```

Scoring reports valid-output rate and cost per valid output. Routing orders agents using recorded failure evidence for the requested job type; it does not invent a recommendation when no evidence exists.

## Run recovery

A crash (or `kill -9`) mid-`gov run` leaves a `runs` row stuck at `status='RUNNING'` — the process died before reaching a terminal status update — plus, potentially, an open quota reservation and a worktree still on disk. `run_stages` records how far the run actually got, so recovery does not have to guess:

```sh
gov run inspect <run_id>     # run record + full stage checkpoint history
gov run resume <run_id>      # recover one interrupted run
gov run abandon <run_id>     # force-cleanup one interrupted run regardless of stage
gov run recover --stale      # apply the resume rule to every RUNNING run
```

The recovery rule: if the last recorded checkpoint is before `AGENT_RUNNING`, no agent work happened, so the run is safe to discard as a fresh attempt (`status='ABANDONED'`). If it reached `AGENT_RUNNING` or later, the current worktree fingerprint is compared against the digest recorded at that checkpoint — byte-identical means safe (`ABANDONED`), anything else (changed, missing, or no baseline recorded) fails closed to `status='QUARANTINED'`. Either way, any open quota reservation for the run is released and any leftover worktree/branch is destroyed. `gov run resume`/`recover --stale` both refuse to touch a run whose workspace lock is still held by a live process (reported as `still_running`); `gov run abandon` is the same rule but treats every case as safe, for an operator who has already made the call. All three are safe to re-run: an already-terminal run is reported as `already_terminal` and left untouched.

## Handoffs

`gov handoff [last|run_id]` emits a bounded JSON summary of one run from ledger evidence: run identity and status, files changed, blockers, next recommended action, token usage, graph fingerprint/stats, and prompt version. It excludes the transcript and diff bodies entirely, falling back to file paths parsed from the diff header when `RESULT.json` reported no file list. Use it to brief the next session or agent without paying for the full transcript context.

## Repair packets

`gov repair-packet RUN_ID` gathers the original run identity, classified failure, diff, touched files, commands, validator outcomes, and violations into a bounded JSON packet. Use that packet as the input to a separate `repair` contract rather than asking an agent to rediscover an unbounded history.

## Auto-triggered repair loop

A contract that sets `repair.auto: true` opts into automatic repair: `gov run` (via `RunWithAutoRepair`) compiles a follow-up job from the quarantined run's repair packet — the same evidence `gov repair-packet` gathers — and runs it as a normal governed job, going through the same lock, spend check, gate, and validators as any other run. It stops as soon as an attempt is approved, is refused by the spend cap, or `repair.max_attempts` (default 1, hard-clamped to 2 regardless of YAML) is reached. Every run in a failure lineage — the original and every repair attempt, including a repair of a repair — records `runs.repair_of` as the lineage's original run id, so counting attempts-so-far is a flat query rather than a chain walk. `gov failures` prints a `repair_lineage` column from this data, and `gov handoff` reports `repair_attempted: n` for the lineage the queried run belongs to. Repair is skipped for read-only modes (`scout`, `verifier`, `architect`) and for a run that was itself refused purely by the spend cap.

## Evaluation

`harness_eval/` contains deterministic, failure-shaped fixtures that exercise governance without calling a model. `gov eval harness harness_eval` records case outcomes, and `gov eval scorecard` summarizes pass rate and cost by agent and mode.

## Structural context evidence

When graph integration is active, every run records the CodeGraph provider version, SHA-256 database fingerprint, file/node/edge counts, and database size. Runtime indexes live only in the disposable worktree and are not merged into source. The fingerprint identifies the exact context database presented to the agent; it is evidence, not a substitute for source verification.

## Usage and cost caveats

`gov usage summary` aggregates measured tokens, cache activity, tool calls, and transcript bytes; `gov usage RUN_ID` reports one run. Token totals are parsed from Claude, Codex, GLM, OpenCode, and Pi transcript shapes. Runs without reported usage store zero plus `usage_unavailable`; zero must not be interpreted as measured usage.

Cost is parsed from backend transcript formats when exposed. Unsupported or cost-free formats store `0` plus the run note `cost_unavailable`; consumers must distinguish that state from a reported zero-dollar call.

## Aggregate spend cap and halt switch

`spend.daily_cap_usd` (default `0`, unlimited) and `spend.halt_file` (default `~/.governator/HALT`) bound cross-run spend on top of the existing per-job `budget.max_tokens` quarantine. Before launching a backend, `gov run` sums today's (UTC) recorded `cost_usd` via `internal/spend` and refuses with a `QUARANTINED` run whose `failure_taxonomy` is `SPEND_CAP` and `message` starts with `SPEND_CAP:` if the halt file is present or the cap is met or exceeded — no workspace is created and no backend is launched, so a refusal costs nothing. Unknown-cost runs (`cost_unavailable`) count as `$0` toward the cap but are reported separately so the cap stays honest about its blind spots.

After a run completes, a post-run hook writes the halt file if that run pushed today's total to or past the cap, so the *next* run refuses; a live mid-run abort is out of scope. `gov spend` reports today's total, cap, remaining budget, run and unknown-cost-run counts, and halt status. `gov spend --halt` / `gov spend --resume` write or remove the halt file directly. Both `spend.daily_cap_usd` and `spend.halt_file` can be overridden per-invocation with `GOV_SPEND_DAILY_CAP_USD` and `GOV_SPEND_HALT_FILE`.

This cap is enforced at `gov run`, including every attempt the auto-triggered repair loop (`repair.auto`, see below) fires — each is a normal `Run` call and checks the cap independently. `gov batch run` (below) also honors it, plus an additional in-process reservation layer for the concurrency the ledger-only check can't see.

## Batch runner

`gov batch run <job.yaml|dir|glob>... [--parallel N] [--halt-on-first-quarantine]` runs a set of independent contracts through a worker pool (default 2, max 4). Every path argument may be a single job file, a directory (every `*.yaml` file directly inside it), or a quoted glob. All contracts are parsed and validated up front; if any one fails validation the whole batch refuses before anything launches.

Each job goes through the same single-run path as `gov run` (including any `repair.auto` loop) — its own lock, spend check, gate, and validators apply unmodified. On top of that, a batch run seeds an in-process `spend.Accountant` from today's ledger total: before launching, each worker reserves a conservative per-job cost estimate (`budget.max_tokens` × a per-backend $/1M-token table, or a flat $0.25 estimate when a job sets no token ceiling) and settles it against the real reported cost once the job finishes. This closes a gap the ledger-only `CheckBudget` check can't: `TodaySpend` excludes `RUNNING` rows, so without the accountant, two workers launched close together could both pass the check before either's cost had landed. A worker that can't reserve exits with status `SKIPPED` / taxonomy `SPEND_CAP` without ever calling `Run`; later jobs keep draining the queue, they just skip too once the cap is exhausted.

`--halt-on-first-quarantine` stops launching new jobs as soon as any job in the batch quarantines; jobs already in flight run to completion, and jobs not yet started are marked `SKIPPED`.

Each `gov batch run` writes one row to the `batches` table (batch id, started/finished timestamps, job count, quarantined count, aggregate cost) and prints a `job_id / run_id / status / failure_taxonomy / cost_usd / worktree` table plus an aggregate summary line. Exit code is non-zero if any job did not end `APPROVED`.


## Typed handoff artifacts

The additive `artifacts` table records typed handoff files copied out of run worktrees: `run_id`, `name`, ledger-store `path`, `sha256`, `bytes`, `schema_ok`, and `created`. Runtime stores artifact bytes under `<ledger_dir>/artifacts/<run_id>/...`; source merges exclude `.governator/`, so these files remain ledger evidence rather than repository content. Repair packets include artifact summaries (`name:sha256:bytes`) for the failed run.


## Panel label mapping

Panel mode anonymizes member outputs before judge context. The additive `panel_members` table maps `(panel_id, member_label)` to the real `job_id`, backend, and artifact name for operator audit, while model-facing comparison artifacts use only `panelist_N` labels.

Note: as of Phase 7, `observability.RecordPanelMembers` has no caller in the actual panel run path (`internal/runtime/panel.go` tracks `PanelMemberOutcome` in memory but never persists it to `panel_members`). The table and its downstream consumer (`gov analytics summary`'s panel-disagreement metric, below) are wired and tested, but read real data only once a future session adds the `RecordPanelMembers` call to the panel runtime. Until then `gov analytics` correctly reports zero panels rather than fabricating a rate from empty evidence.

## Analytics projection (Phase 7)

SQLite stays authoritative; `gov analytics` is a read-only derived view over the tables above, never a write path:

```sh
gov analytics summary
gov analytics export [--out <path>]
```

`summary` prints tab-separated tables (backend valid-output rate, failure type by backend, fallback frequency, quota utilization, repair depth, validator and assay failure clusters, panel disagreement, cost by outcome). `export` writes the same snapshot as line-delimited JSON, one object per metric row tagged with a `metric` field — the format any external system (a spreadsheet, `jq`, an OpenTelemetry or Langfuse adapter) can consume. There is no outbox or Supabase replication behind this yet: Phase 3A's assay bridge stays deliberately network-free, so JSONL export (to a file or stdout) is the whole shipping mechanism for now. An export failure never affects a run outcome — it runs after the fact, outside any governed job's lifecycle.
