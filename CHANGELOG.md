# Changelog

All notable changes to Governator are documented here.

## [Unreleased]

### Added

- Minimalism prompt optimizer: a YAGNI-first ruleset adapted from ponytail (github.com/DietrichGebert/ponytail, MIT) is injected into every governed prompt (`minimalism.mode`: `off`/`lite`/`full`/`ultra`, default `full`), aimed at smaller diffs and lower per-run cost, with no external binary required. `gov doctor` reports the active mode.

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
