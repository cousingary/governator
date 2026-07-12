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
gov claims verify [--file <path>] [--repo <path>] [--artifact <path>] [--manifest <path>]
```

Defaults to `docs/claims.yaml` against the current directory. Exits non-zero
if any claim's computed maturity falls short of its claimed maturity.

## Release artifact provenance

Session 4 adds a canonical release builder:

```
scripts/release.sh
```

The script refuses a dirty tree, runs `go test ./...`, builds exactly one
artifact from the current commit with `-ldflags` embedding version, source
commit, build timestamp, claims hash, and adapter protocol version, then writes
`dist/build-manifest-<version>-<commit>.json`. The manifest records the
artifact path and SHA-256, Go version/build flags/buildinfo, the claims hash,
a concrete test run ID/result, and a concrete acceptance self-check ID/result
from running the built artifact's `gov version --json`.

`gov claims verify --artifact <path> --manifest <path>` uses that manifest to
inspect the exact binary. A binary that self-reports `1.0.0-rc1` while the
claim/manifest expects `v1.4.1` fails verification even if all symbols and YAML
keys exist.

If `GOV_RELEASE_HMAC_KEY` is present, `scripts/release.sh` adds a
`manifest_hmac_sha256` over the unsigned manifest JSON. That local environment
variable is the current trust root for CI summary signing until dedicated
signing infrastructure exists; do not commit the key.
