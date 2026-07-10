# Ledger and evidence

Governator stores an SQLite WAL database in `ledger_dir` (default `$HOME/.governator`). The schema migrates forward on open; do not manually truncate or edit it while runs are active.

## Tables

| Table | Evidence |
|---|---|
| `runs` | Contract identity, worktree, status, diff, transcript, cost, token usage, tool calls, transcript bytes, graph provider/version/fingerprint/stats, result, prompt version, enforcement envelope, and notes. |
| `jobs` | Last-seen timestamp and job type. |
| `agents` | First and last observed run per backend. |
| `agent_profiles` | Runs, valid outputs, failures, and total cost by agent and job type. |
| `files_touched` | Path and change type per run. |
| `commands_run` | Audited shell command and classification. |
| `validators` | Validator command, exit code, and bounded output. |
| `violations` | Policy, budget, transcript, and validation failures. |
| `repair_packets` | Generated failure packet JSON and taxonomy. |
| `eval_runs` | Hermetic harness-evaluation outcomes. |
| `hook_events` | Interactive tool decision, finding, and detail. |
| `parity_events` | Go/Python shadow decisions and availability. |

## Operations

```sh
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

## Handoffs

`gov handoff [last|run_id]` emits a bounded JSON summary of one run from ledger evidence: run identity and status, files changed, blockers, next recommended action, token usage, graph fingerprint/stats, and prompt version. It excludes the transcript and diff bodies entirely, falling back to file paths parsed from the diff header when `RESULT.json` reported no file list. Use it to brief the next session or agent without paying for the full transcript context.

## Repair packets

`gov repair-packet RUN_ID` gathers the original run identity, classified failure, diff, touched files, commands, validator outcomes, and violations into a bounded JSON packet. Use that packet as the input to a separate `repair` contract rather than asking an agent to rediscover an unbounded history.

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

This cap is enforced only at `gov run`; it does not yet cover `gov batch` or `gov repair --auto` (planned for later sessions).
