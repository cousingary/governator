# Changelog

All notable changes to Governator are documented here.

## [Unreleased]

### Added

- Aggregate daily spend cap and kill switch (`internal/spend`): `spend.daily_cap_usd` (default `0`, unlimited) and `spend.halt_file` (default `~/.governator/HALT`) bound cross-run spend on top of the existing per-job `budget.max_tokens` quarantine. `gov run` checks the cap before launching a backend and refuses with a `QUARANTINED`/`SPEND_CAP` run (no workspace created, no backend launched) when the halt file is present or today's recorded cost meets or exceeds the cap; a post-run hook writes the halt file once a completed run crosses the cap so the next run refuses. New `gov spend` reports today's total/cap/remaining/run counts/halt status; `gov spend --halt` / `--resume` toggle the halt file directly.
- Minimalism prompt optimizer: a YAGNI-first ruleset adapted from ponytail (github.com/DietrichGebert/ponytail, MIT) is injected into every governed prompt (`minimalism.mode`: `off`/`lite`/`full`/`ultra`, default `full`), aimed at smaller diffs and lower per-run cost, with no external binary required. `gov doctor` reports the active mode.
- Auto-triggered repair loop: an optional `repair: {auto, max_attempts, backend}` contract block (default `auto: false`, existing job YAML unaffected). `gov run` now calls `RunWithAutoRepair`, which — when a run quarantines and `repair.auto` is set — compiles a follow-up job from that run's repair packet (the same evidence `gov repair-packet` gathers) and runs it as a normal governed job, stopping as soon as an attempt is approved. `max_attempts` defaults to 1 and hard-clamps to 2 regardless of YAML; a run refused purely by the spend cap is never retried. Every attempt in a lineage is linked via a new additive `runs.repair_of` column; `gov failures` gains a `repair_lineage` column and `gov handoff` reports `repair_attempted: n`.

### Fixed

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
