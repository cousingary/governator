# Governator

Governator is a contract-first runtime for replaceable coding-agent backends. It turns file scope, command authority, budgets, and success criteria into deterministic checks around an isolated agent run. Models can propose changes, but only validators and the merge gate can approve them.

> *The model proposes. The governor disposes. The validator decides. The ledger remembers.*

## Quickstart

Requires Go 1.26 or newer and Git 2.30 or newer.

```sh
go install github.com/cousingary/governator/cmd/gov@latest
gov init
gov validate "$HOME/.governator/jobs/example.yaml"
gov doctor
```

`gov init` is safe to run repeatedly: it creates a commented configuration, a valid example contract, and an empty protected-path manifest without overwriting existing files. Edit the generated contract's absolute workspace path and validator before a real `gov run`; running an agent may consume a paid subscription or API quota.

For a source checkout:

```sh
go test ./...
go build -trimpath -o bin/gov ./cmd/gov
bin/gov validate examples/jobs/code_surgical_fix.yaml
```

## Architecture

```text
job.yaml -> strict parser -> preflight policy -> disposable Git worktree
                                                  |
                                           backend adapter
                                      (Claude/Codex/GLM/
                                         OpenCode/Pi)
                                                  |
          protected paths <- F1-F7 gate <- tool calls/transcript
                                                  |
             fingerprint diff -> budgets -> deterministic validators
                                                  |
                              approve + merge OR quarantine/rollback
                                                  |
                                         SQLite WAL ledger
```

Every backend implements one abstract execution specification. Native controls are used when available; missing guarantees are compensated by the runtime and recorded in each run's enforcement envelope.

## Backend capabilities

| Backend | Sandbox | Read-only | Approval policy | Network control | Transcript |
|---|---:|---:|---:|---:|---|
| Claude Code | native | native | native | compensated | `claude-stream-json` |
| Codex | native | native | native | native (explicitly disabled by default) | `codex-json` |
| GLM | compensated | compensated | native | compensated | `glm-stream-json` |
| OpenCode | compensated | config projection | native | compensated | `opencode-json` |
| Pi | compensated | native tool reduction | compensated | compensated | `pi-json` |

Run `gov doctor` to probe installed backend flags and print the live matrix. See [backend details](docs/backends.md) for exact projections and limitations.

## Threat model

Governator governs **cooperative coding agents**. A native sandbox is containment; a pre/post fingerprint scan is detection and remains the universal floor for every backend. Config and prompt restrictions are weaker than kernel enforcement, and transcript audit can only inspect events a backend emits.

Governator does not stop a malicious human, a compromised process with equivalent shell access, or an agent that escapes the operating-system boundary. Protected files still need normal host permissions, backups, credential isolation, and least-privilege execution. Never treat an approved run as proof that arbitrary third-party code is safe.

## Configuration

Configuration defaults to `$HOME/.governator/config.yaml`; `GOV_CONFIG` selects another file. Environment values take precedence over the file, which takes precedence over neutral built-ins. Supported settings cover the protected manifest, snapshots, ledger directory, backend binaries, RTK, structural context graphs, the minimalism ruleset, default agent, and default time limit. Existing runtime overrides such as `GOV_HOME`, `GOV_PROTECTED_PATHS`, `GOV_SNAPSHOT_DIR`, `GOV_SNAPSHOT_ROOTS`, and `GOV_<BACKEND>_BIN` remain supported.

RTK (Rust Token Killer) integration defaults to `rtk.mode: auto`: when an `rtk` binary is on `PATH`, Governator adds token-saving command guidance to the backend prompt and normalizes RTK-wrapped commands before all command-policy checks. Use `off` to disable it or `required` to fail before an agent run when RTK is unavailable. `GOV_RTK_MODE` and `GOV_RTK_BIN` override those settings; `gov doctor` reports whether optimization is active. Install RTK from the [official project](https://github.com/rtk-ai/rtk).

Structural context defaults to `graph.mode: auto` with the `codegraph` provider. When the binary is available, `gov doctor` reports its version and the current repository's index statistics; otherwise auto mode remains an optional warning. Use `graph.mode: required` to make a missing provider a hard preflight failure, or `off` to disable graph integration. `GOV_GRAPH_MODE`, `GOV_GRAPH_PROVIDER`, and `GOV_GRAPH_BIN` override the YAML settings. The first supported adapter is [CodeGraph-Rust](https://github.com/sunerpy/codegraph-rust), selected after a compatibility spike confirmed Go type, method, and relationship indexing.

Minimalism defaults to `minimalism.mode: full`: Governator appends a YAGNI-first ruleset (adapted from the [ponytail](https://github.com/DietrichGebert/ponytail) project, MIT-licensed) to every governed prompt, biasing backends toward reuse, stdlib, and the smallest diff over new abstractions and dependencies. Use `lite` for a condensed version, `ultra` for a stricter "delete over add" framing, or `off` to disable. `GOV_MINIMALISM_MODE` overrides the YAML setting; `gov doctor` reports the active mode. Unlike RTK and the context graph, this optimizer has no external binary and is always available.

For each governed run, the controller builds or refreshes the graph inside the disposable worktree before baseline fingerprints, injects bounded read-only query forms into the runtime prompt, and excludes the controller-owned `.codegraph` index from source commits. The ledger records provider version, SHA-256 index fingerprint, file/node/edge counts, and database size. Operators can inspect or explicitly manage an index with `gov graph status [path]`, `gov graph refresh [path]`, and `gov graph query <search> [--path <path>] [--limit <n>]`.

`doctrine.require_cleanup` (default `false`) governs whether `gov validate` treats a missing cleanup pass as advisory or fatal: a `surgeon`, `batch_worker`, or `repair` contract with neither a `cleanup` block nor a lint/format `success.validators` entry always prints a `DOCTRINE WARNING`; setting this to `true` (or `GOV_DOCTRINE_REQUIRE_CLEANUP=true`) upgrades it to a `DOCTRINE ERROR` and a nonzero exit. See [`docs/contracts.md`](docs/contracts.md) for the `cleanup` block itself.

## Commands

```text
gov init
gov validate <job.yaml>
gov preflight <job.yaml>
gov run <job.yaml> [--agent <name>]
gov batch run <job.yaml|dir|glob>... [--parallel N] [--halt-on-first-quarantine] [--ordered]
gov plan <intent.md> --out <dir> --envelope <pattern>... --max-total-tokens <n> [--backend <name>]
gov plan --panel <n> <intent.md> --out <dir> --envelope <pattern>... --max-total-tokens <n> [--backend <name>]
    [--min-success <n>] [--member-timeout-seconds <n>] [--hard-timeout-seconds <n>]
    [--diversity-key backend|model_family] [--diversity-min-unique <n>] [--diversity-fallback-key backend|model_family]
gov plan --show <dir>
gov handoff [last|run_id]
gov diff [last|run_id]
gov rollback <run_id>
gov quarantine list|show <id>|diff <id>
gov score agents --job-type <type>
gov failures
gov cost --per-valid-output
gov spend [--halt|--resume]
gov quota
gov usage summary|<run_id>
gov route --job-type <type>
gov route --explain <contract.yaml>
gov repair-packet <run_id>
gov eval harness <case-dir>
gov eval scorecard
gov protect status|apply|release <path>
gov snap create [label]|list|diff <id>|restore <id> [--dry-run]
gov graph status|refresh [path]
gov graph query <search> [--path <path>] [--limit <n>]
gov hook pre-tool-use [--run <id>] [--shadow <python-gate>]
gov panel compare --out <artifact.json> <input.json>...
gov gate check
gov parity report
gov doctor
gov health [reset <backend>]
gov version
```

## Documentation

- [Contracts and `RESULT.json`](docs/contracts.md)
- [F1-F7 gate and hook integration](docs/gate.md)
- [Backend projections](docs/backends.md)
- [Migration and deliberate divergences](docs/migration.md)
- [Ledger, routing, evaluation, and repair packets](docs/ledger.md)
- [Publishing checklist](docs/publishing.md)
- [Security policy](SECURITY.md) and [contributing guide](CONTRIBUTING.md)

Governator is licensed under the [MIT License](LICENSE).
