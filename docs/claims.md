# Claims ledger

`docs/claims.yaml` is the v1.4 Session 6 (Sol Phase 11) machine-verified
documentation ledger: each entry maps one feature claim to the concrete,
checkable facts that back it, and `gov claims verify` (`internal/claims`)
re-derives every fact from the repository on every CI run. Nothing here is
trusted from a hand-written status field except `claimed_maturity` itself —
and CI fails the moment the computed maturity falls short of what's claimed.

This is what makes "implemented," "tested," "accepted," and "shipped"
mechanically distinct instead of overlapping English words: each is a gate
that requires the one below it, plus its own additional evidence.

The ledger also now carries the Sol redteam repair program's claims (`sol-s1-*`
through `sol-s7-*`), added by each repair session as its fixes landed. Those
entries are deliberately capped at `claimed_maturity: tested` rather than
`shipped` — none of them yet has a `binary_build_evidence` entry pointing at a
rebuilt-and-verified artifact for the v1.0.0 release; see [docs/security.md](security.md)
for the full Sol-finding-to-commit-to-test register, which is the audit-closure
artifact this ladder feeds.

## The maturity ladder

| Level | Requires | Additional check |
|---|---|---|
| `implemented` | — | Every `implementation[].symbols` entry actually exists as a top-level func/type/const/var in the named file (checked via `go/parser`, not a text match). If `cli` is declared, every word of the command is a reachable `case "..."` dispatch label somewhere under `cmd/gov`. |
| `tested` | implemented | Every `tests[].funcs` and `integration_tests[].funcs` entry exists as a `func Name(` in its named file. An `integration_tests[].build_tag` must appear as a `//go:build <tag>` line in that file. |
| `accepted` | tested | Every `acceptance_artifacts[].path` file exists; if it declares a `pointer`, that dot-path resolves to a real key in the file's parsed JSON. |
| `shipped` | accepted | `binary_build_evidence.commit` exists, is an ancestor of (or equal to) `HEAD`, is recorded in `evidence_file` alongside a real binary hash (via `git show <commit>:<file>`), every implementation symbol is present in the file **at that historical commit** — not just at `HEAD`. |

`gov claims verify` walks this ladder only as far as a claim's own
`claimed_maturity` requires — a claim that only asserts `tested` is never
penalized for lacking acceptance evidence it never promised.

## Adding or updating a claim

1. Pick real files and symbol names — copy them from the code, don't
   paraphrase. `gov claims verify` matches on exact identifiers.
2. Only claim `shipped` if a rebuilt-binary evidence report (like
   `evidence/release-v1.4.json`) actually exists for the commit that landed
   the feature. Code merged to `main` without a matching evidence entry is
   honestly `accepted` at most, not `shipped` — this is intentional; the
   ledger's whole point is to catch the gap between "merged" and "proven and
   shipped."
3. Run `go run ./cmd/gov claims verify` locally before committing. The
   `claims` CI job (`.github/workflows/ci.yml`) runs the same command against
   full git history (`fetch-depth: 0`, required for the ancestor/historical
   checks) and fails the build on any violation.

## Usage

```
gov claims verify [--file <path>] [--repo <path>] [--artifact <path>] [--manifest <path>] [--release] [--portable-release]
```

Defaults to `docs/claims.yaml` against the current directory. Exits non-zero
if any claim's computed maturity falls short of its claimed maturity.

`--release` (Sol redteam v4 S8 / P0-7) asserts this invocation is gating an
actual release, not a day-to-day source check: it refuses to run at all
unless both `--artifact` and `--manifest` are also given. The bare CI/local
pre-commit form (no `--release`, no artifact) is unaffected — it verifies
claim-to-source consistency and has nothing to do with a built binary.
`scripts/release_verify.sh` is the only caller that passes `--release`.
`--portable-release` is the third-party verification profile: it still
requires `--artifact` + `--manifest`, but resolves Git read-only from the
local environment instead of Governator's operational trusted-tool registry
and hashes the exact `--file` claims ledger rather than assuming
`docs/claims.yaml` under `--repo`.

## Release artifact provenance

`scripts/release.sh` is the canonical release builder. It refuses a dirty
tree, re-executes itself from a disposable detached checkout, re-checks
cleanliness before each platform build, runs the full test/fuzz/Assayer
matrix, builds every platform into `dist/`, writes
`dist/architecture-build-metadata.json`, then writes `dist/build-manifest.json`
— the one document every other release file's identity must agree with:
version, source commit, build timestamp, claims hash, adapter protocol
version, every platform artifact, plus (S8/S4) the host-platform archive
path/SHA-256, extracted binary SHA-256, Go buildinfo, `test_result`/
`test_run_id`, and `acceptance_result`/`acceptance_run_id`.
The manifest is written only after the acceptance smoke test (extract, check
the binary is exactly mode `0755`, hash-match, self-reported version/commit/
claims-hash match) has already run — never before both are known.

As the pipeline's last release-blocking gate, `scripts/release_verify.sh`
extracts the host archive fresh (independently of the acceptance step's own
extraction), re-asserts mode `0755`, and runs
`gov claims verify --release --artifact <path> --manifest <path>` against
it — full claims verification against the *exact archived artifact*, every
release, no exceptions. A binary that self-reports `1.0.0-rc1` while the
claim/manifest expects `v1.4.1`, or whose embedded `source_commit`/Go
buildinfo `vcs.revision` drifts from the manifest's, fails verification even
if every symbol and YAML key exists — this is what closes report attack 25
(a shipped binary two commits behind its submitted source). Report attack 24
(the archived binary shipping at mode `0777`) is closed by the exact-mode
assertion in both the acceptance step and `release_verify.sh`.

If `GOV_RELEASE_HMAC_KEY` is present, `scripts/release.sh` adds a
`manifest_hmac_sha256` over the unsigned manifest JSON. `checksums.txt.minisig`
is now mandatory for rc/production releases: if `GOV_RELEASE_MINISIGN_KEY`
(path to an unencrypted minisign secret key) or the `minisign` binary is
missing, the release fails. Only clearly marked local candidates may remain
unsigned.
