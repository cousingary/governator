# Governator

**Let coding agents do real work — without them touching the wrong file, running the wrong command, or shipping a change nothing verified.**

Governator is the supervisor that sits above [Claude Code](docs/backends.md), Codex, OpenCode, and Pi. You write a short contract that says what the agent may touch, what it may run, what "done" looks like, and what it may cost — and the operating system enforces it. The model proposes changes; validators and the merge gate decide whether they land.

> *The model proposes. The governor disposes. The validator decides. The ledger remembers.*

## Why you'd run it

Most agent harnesses trust the backend's own sandbox and its own definition of success. Governator doesn't — it's for the cases where "it worked" isn't good enough:

- **Unattended runs** — cron jobs, CI, overnight batch runs where a stray `rm`, an escaped sandbox, or a quietly edited protected file costs real money while you sleep.
- **Multi-agent / panel runs** — compare backends side by side and pick the winner on recorded evidence (pass rate, cost, tokens), not vibes.
- **Auditable changes** — every run writes to an append-only SQLite WAL ledger: what was scoped, what was enforced, what passed, what was quarantined. Never "trust me."

| Without Governator | With Governator |
|---|---|
| "It succeeded" — but it rewrote a file it shouldn't have. | File-scope contracts + a protected-path gate stop it at the kernel. |
| "The sandbox caught it." (the backend says so) | Containment is **enforced by the OS** — Landlock, a network namespace with no route, a cgroup v2 descendant kill before final-state capture. |
| "Which model is best?" — gut feel. | Scorecards, a route broker, and `gov cost --per-valid-output` from ledger data. |
| A run dies mid-task — lost work. | Crash recovery, quarantine, repair packets, resumable runs. |

## The stack: one unit, four allies

Governator supervises and verifies; it doesn't try to be everything. So it composes with four tools that each kill a different failure mode of an unattended agent run. Together they're the difference between *the model proposed* and *it shipped safely at 3am* — yet each one is independent and useful on its own.

| Tool | Role in the run | Made by |
|---|---|---|
| **Governator** | **Supervise** — scope, authority, OS-enforced containment, validators, merge gate, ledger. The hub. | this repo |
| **[Assayer](https://github.com/cousingary/assayer)** | **Verify output** — schema / boilerplate / placeholder / dedup checks, durable quarantine, traceable verdicts. | cousingary |
| **[Context Mode](https://github.com/mksglu/context-mode)** | **Protect the context window** — keep raw bytes out, session continuity across compaction, "think in code" sandbox tools. | mksglu (third-party) |
| **[RTK](https://github.com/rtk-ai/rtk)** | **Filter before it lands** — a token-saving CLI proxy on `PATH` that compacts command output before it reaches the model. | rtk-ai (third-party) |
| **Ponytail ruleset** | **Smallest diff** — a YAGNI-first discipline injected into every prompt, biasing toward reuse, stdlib, and the smallest change over new abstractions. | adapted from [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail) (MIT) — see [NOTICE](NOTICE) |

Governator auto-detects Context Mode and RTK when they're on `PATH` and wires them in (`rtk.mode: auto`, graph `auto`). The Ponytail-derived minimalism ruleset ships inside Governator itself (`minimalism.mode: full`) as a prompt annotation Governator's own compiler adds to every `gov run`/`gov batch run` execution — no external binary needed for that path. It does not reach interactive or hook-only sessions (a Claude Code session gated by `gov hook pre-tool-use` without going through `gov run`, or any use of these CLIs outside Governator entirely) — nothing in that path calls Governator's prompt compiler. Install [ponytail](https://github.com/DietrichGebert/ponytail) directly if you want the same discipline there too; it hooks into Claude Code, Codex, and other CLIs through their own plugin systems, so it isn't limited to governed runs. Toggle any of them under [Configuration](#configuration); `gov doctor` reports which are active.

### What it does, technically

Governator is a contract-first runtime for replaceable coding-agent backends. It turns file scope, command authority, budgets, and success criteria into deterministic checks around an isolated agent run. Models can propose changes, but only validators and the merge gate can approve them.

## Quickstart

Requires Go 1.26 or newer and Git 2.30 or newer.

```sh
go install github.com/cousingary/governator/cmd/gov@latest
gov init
gov validate "$HOME/.governator/jobs/example.yaml"
gov doctor
```

`gov init` is safe to run repeatedly: it creates a commented configuration, a valid example contract, and an empty protected-path manifest without overwriting existing files. Edit the generated contract's absolute workspace path and validator before a real `gov run`; running an agent may consume a paid subscription or API quota.

### Platform support

Published release archives are built for three platforms, but "built" is not the same claim as "approving." An archive is **approving** only when it carries *executed* native acceptance evidence (the archive was actually extracted and run on that architecture, not merely cross-compiled for it) — see [docs/containment.md](docs/containment.md) for what approval gates in a governed run.

| Platform | Status | Notes |
|---|---|---|
| `linux_amd64` | **Approving** | Built and acceptance-tested natively on this platform. |
| `linux_arm64` | **Approving with evidence** | Native acceptance evidence is available from CI and is consumed by release labeling. |
| `darwin_arm64` | **Approving with evidence** | Native acceptance, unit, race, Sol3, red-team, and red-team-race tiers passed on Apple silicon in CI run `30688682689`. Linux-only primitives remain explicit fail-closed capabilities. |

`darwin/amd64` is intentionally not published: GitHub's free macOS runners are Apple-silicon only, so no free native host can ever attest it, and Rosetta 2 runs the `darwin/arm64` archive on Intel Macs.

Approval is attached to the exact published archive and its executed native evidence; a locally cross-compiled or `go install ... @latest` binary does not inherit another artifact's evidence. Governed operations that require unavailable Linux-only primitives still refuse safely on Darwin rather than silently degrading.

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
                                  enforce.Plan (Landlock + netns,        ┐
                                                applied via              │ S5
                                                gov __sandbox_exec)      │
                            containment.Scope (cgroup v2 descendants)    ┘ ┐ S2
                                                  |                       ┘
                                  BackendExecutionHandle (one fd,         ┐
                                          re-verified pre-launch)        │ S3
                                                  |                       ┘
                                           backend adapter
                                      (Claude/Codex/
                                         OpenCode/Pi)
                                                  |
                          toolregistry gates every controller tool      ┐ S4
                          (git self-pins on first gov doctor run)        ┘
                                                  |
           protected paths <- F1-F7 gate <- tool calls/transcript
                                                  |
              fingerprint diff -> budgets -> deterministic validators
                                                  |
                              DESCENDANTS_TERMINATED lifecycle stage     ┐ S2/S9
                              (cgroup freeze+kill+extinction proof)      ┘
                                                  |
                       final-state capture (worktree diff,              ┐
                          transcript-effect cross-check)                 │ S1/S5
                                                  |                       ┘
             gitplumb: isolated index + commit-tree + update-ref CAS,   ┐
                       no shell, no hooks, literal pathspecs only        │ S1
                                                  |                       ┘
                               approve + merge OR quarantine/rollback
                                                  |
                                  lifecycle.Record validates every      ┐ S9
                                  stage transition (state machine)        ┘
                                                  |
                                          SQLite WAL ledger
                            (runs, run_stages, effect_events,
                             enforcement_events, capability_attestations)
```

Every backend implements one abstract execution specification. Native controls are used when available; missing guarantees are compensated by the runtime and recorded in each run's enforcement envelope. As of v1.0.0 (Sol redteam v4), the load-bearing containment/identity/sovereignty invariants are **enforced by the operating system rather than promised by the backend**: Landlock LSM confines filesystem writes; a network namespace with no route removes egress at the kernel level; a cgroup v2 scope owns the whole process tree through a `DESCENDANTS_TERMINATED` stage before final-state capture; an immutable `BackendExecutionHandle` resolves the executable exactly once from a single open file descriptor; a trusted-tool registry gates every controller-invoked external process; and `internal/gitplumb` performs merge/commit with no shell, no hooks, and literal pathspecs only. See [docs/containment.md](docs/containment.md) for the full containment model.

## Backend capabilities

| Backend | Sandbox | Read-only | Approval policy | Network control | Transcript |
|---|---:|---:|---:|---:|---|
| Claude Code | native | native | native | compensated | `claude-stream-json` |
| Codex | native | native | native | native (explicitly disabled by default) | `codex-json` |
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

Minimalism defaults to `minimalism.mode: full`: Governator appends a YAGNI-first ruleset (adapted from the [ponytail](https://github.com/DietrichGebert/ponytail) project, MIT-licensed — see [NOTICE](NOTICE) for the full copyright and permission notice) to every governed prompt, biasing backends toward reuse, stdlib, and the smallest diff over new abstractions and dependencies. Use `lite` for a condensed version, `ultra` for a stricter "delete over add" framing, or `off` to disable. `GOV_MINIMALISM_MODE` overrides the YAML setting; `gov doctor` reports the active mode.

For each governed run, the controller builds or refreshes the graph inside the disposable worktree before baseline fingerprints, injects bounded read-only query forms into the runtime prompt, and excludes the controller-owned `.codegraph` index from source commits. The ledger records provider version, SHA-256 index fingerprint, file/node/edge counts, and database size. Operators can inspect or explicitly manage an index with `gov graph status [path]`, `gov graph refresh [path]`, and `gov graph query <search> [--path <path>] [--limit <n>]`.

`doctrine.require_cleanup` (default `false`) governs whether `gov validate` treats a missing cleanup pass as advisory or fatal: a `surgeon`, `batch_worker`, or `repair` contract with neither a `cleanup` block nor a lint/format `success.validators` entry always prints a `DOCTRINE WARNING`; setting this to `true` (or `GOV_DOCTRINE_REQUIRE_CLEANUP=true`) upgrades it to a `DOCTRINE ERROR` and a nonzero exit. See [`docs/contracts.md`](docs/contracts.md) for the `cleanup` block itself.

## Commands

```text
gov init
gov validate <job.yaml>
gov preflight <job.yaml>
gov run <job.yaml> [--agent <name>]
gov run inspect <run_id>
gov run resume <run_id>
gov run abandon <run_id>
gov run recover --stale
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
gov analytics summary
gov analytics export [--out <path>]
gov route --job-type <type>
gov route --explain <contract.yaml>
gov repair-packet <run_id>
gov eval harness <case-dir>
gov eval scorecard
gov protect status|apply|release <path>
gov snap create [label]|list|diff <id>|restore <id> [--dry-run]|prune [--keep N]
gov graph status|refresh [path]
gov graph query <search> [--path <path>] [--limit <n>]
gov hook pre-tool-use [--run <id>] [--shadow <python-gate>]
gov panel compare --out <artifact.json> <input.json>...
gov gate check
gov parity report
gov reconcile
gov cleanup --stale [--max-attempts N]
gov ask list|show <id>|approve <id>|deny <id> [--rule] [--ttl <duration>] [--by <name>] [--note <text>]
gov containment message <job.yaml> [--reason <text>]
gov attest <backend>
gov tools enroll <name> <absolute-path>|verify <name>|status|rotate <name> <absolute-path>
gov doctor
gov health [reset <backend>]
gov claims verify [--file <path>] [--repo <path>] [--artifact <path>] [--manifest <path>] [--release]
gov redteam-gate verify --manifest <path> --log <path> [--capabilities <json>] [--inventory <path>] [--exact-manifest <path>...]
    [--attestations <dir> --attestation-trust <path> --attestation-governator-commit <commit>
    --attestation-assayer-commit <commit> --attestation-release-version <version>
    --attestation-source-identity <path> --attestation-toolchain-hash <sha256>
    --attestation-release-time <rfc3339> --attestation-max-age <duration>] [--require-zero-skips]
gov integration-gate verify --log <path> --expected-names <path>
    [--harness-evidence <dir> --governator-binary <path> --expected-packages <path> --assayer-commit <commit>]
gov version
```

## Documentation

- [Contracts and `RESULT.json`](docs/contracts.md)
- [F1-F7 gate and hook integration](docs/gate.md)
- [Backend projections](docs/backends.md)
- [Containment model](docs/containment.md)
- [Migration and deliberate divergences](docs/migration.md)
- [Ledger, routing, evaluation, and repair packets](docs/ledger.md)
- [Route broker](docs/routing.md)
- [Machine-verified documentation claims](docs/claims.md)
- [Sol redteam findings register](docs/security.md)
- [Publishing checklist](docs/publishing.md)
- [Security policy](SECURITY.md) and [contributing guide](CONTRIBUTING.md)

## v1.0.2 — current release (first public distribution)

`v1.0.2` (commit `130e22d`, cut 2026-08-02) is Governator's first publicly distributed release: `github.com/cousingary/governator` and `github.com/cousingary/assayer` are now public, GitHub Actions builds and tests every push, and all three published platforms — `linux_amd64`, `linux_arm64`, `darwin_arm64` — carry *executed* native acceptance evidence (`known_degraded_modes: []`) rather than a cross-compiled claim; `darwin/amd64` stays unpublished since no free native Apple-silicon-only runner can attest it. The release is Minisign-signed against the out-of-band-published key `B5CBEE8BBA8826A7`, `gov claims verify --release` confirms all 62 documentation claims, and a clean-room checkout on a separate machine rebuilds a byte-identical `linux_amd64` binary and independently verifies the published bundle end to end — the reproducibility claim CI's release workflow has asserted since Sol11 and had never actually been tested until this cut. See [CHANGELOG.md](CHANGELOG.md) for the full distribution-cycle summary.

> Versioning note: `v1.0.0` was Governator's first *released* version — the v1.1–v1.5 numbers that appear in the changelog, branch names, and internal planning documents were pre-release development milestones of the initial build that were never themselves released. `v1.0.2` is the first version a stranger, on a different machine, can obtain, verify, and independently confirm.

### Sol redteam repair program (through v1.0.0)

The Sol redteam repair program that produced `v1.0.0` ran in three rounds against this codebase:

- **Round 1 (v2)** reproduced eight Critical and twelve High-severity gaps in v1.4.1 (replay bypasses, symlink escapes, unattested backend trust, non-atomic live-root merges, and more). All were repaired across seven sessions, plus a documentation pass (S8) and one follow-up session that closed the single gap S8's own cross-check found (High 11's local-runner output capping).
- **Round 2 (v3)** reproduced twenty further findings against the v1.0.0 binary round 1 shipped — mostly transaction/concurrency, identity, and containment gaps the first pass's fixes didn't reach. All twenty were repaired across fifteen sessions (S1–S15) plus one standalone flake fix.
- **Round 3 (v4)** reproduced a 25-item black-box attack corpus against the binary round 2 shipped — git-tree sovereignty, descendant/process containment, executable identity, externally enforced (not self-reported) capability attestation, and release/supply-chain integrity. All twenty-five were repaired across ten sessions (S0–S9).

The defining v4 change, still load-bearing today, is that the core invariants are **enforced by the operating system rather than promised by the backend**: Landlock LSM confines filesystem writes; a network namespace with no route removes egress at the kernel level; a cgroup v2 scope owns the whole process tree through a `DESCENDANTS_TERMINATED` stage before final-state capture; an immutable `BackendExecutionHandle` resolves the executable exactly once from a single open file descriptor; a trusted-tool registry gates every controller-invoked external process; and `internal/gitplumb` performs merge/commit with no shell, no hooks, and literal pathspecs only. Three further rc cycles (rc6 through rc8) then hardened the release *ceremony* itself — trust chain, boundary correctness, provenance — closing with a mandatory red-team corpus that runs clean, zero unexpected skips, both plain and `-race`, on every tagged cut. See [docs/security.md](docs/security.md) for the full finding-by-finding register, [docs/containment.md](docs/containment.md) for the containment model, [docs/claims.md](docs/claims.md) for how `docs/claims.yaml` mechanically re-derives many of these fixes from the repository, and [CHANGELOG.md](CHANGELOG.md) for the per-release summary. `gov version` reports the build's real semantic version, source commit, and claims hash, embedded at build time by `scripts/release.sh` — there is exactly one version story now, not the source/archive/repo-claim divergence Sol found.

## Roadmap (not built)

These items from the Sol audit's strategic-enhancements list (§9/P3) are deliberately out of scope for the repair program and are not implemented:

- An external backend adapter protocol (adapters beyond the four built-in CLIs).
- A versioned harness profile registry (today's harness/eval fixtures are not versioned as a registry).
- Panel independence across provider, account, model lineage, prompt, and policy (today's panel mode anonymizes labels but doesn't enforce cross-panelist independence on these axes).
- An offline Governator Evolver Lab.
- Profile drift detection with champion/challenger promotion.

Governator is licensed under the [MIT License](LICENSE).
