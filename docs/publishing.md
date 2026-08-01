# Publishing checklist

Publishing is operator-executed. Automation must not create the public repository, push `main`, or tag a release without explicit approval.

1. Run the complete local verification loop and confirm the working tree contains only the release commit. **Branch hygiene (v16 R1/R9):** `main` is the only branch that ships — confirm every `v*` release tag is reachable from `main` (`scripts/check_branch_topology.py` enforces this in `release.sh` and refuses a release while any release tag is unreachable), and delete any `gov/job/*` quarantine branches (governed-run detritus: `git branch -D $(git branch --list 'gov/job/*')`) so a naive `git push --all` cannot publish unreviewed agent workspace output. Historical feature branches (`rc7-upg14`, `rc8-upg15`, etc.) are real history and stay.
2. Create the public repository with `gh repo create governator --public`, add the remote, and push `main`.
3. Enable GitHub Actions and confirm `.github/workflows/ci.yml`'s Linux/macOS matrix (build, vet, unit + race tests, the black-box Sol3 security regression corpus, gofmt), lint, fuzz, and cross-compile smoke are green.
4. Confirm repository security settings and replace the placeholder private-report contact in `SECURITY.md`.
5. Tag `v<version>` and push the tag. `.github/workflows/release.yml` sets `REQUIRE_TAG=1` and `REQUIRE_ASYMMETRIC_SIGNATURE=1`, then runs `scripts/release.sh` — the single canonical release pipeline (Sol redteam v3 S14 / finding #20 retired the divergent `.goreleaser.yml` generation; Sol redteam v4 S8 / P0-7 added the hard assertions below; Sol v8 S4 adds the detached immutable checkout + mandatory asymmetric signature gate). It uploads `gov_<version>_<platform>.tar.gz` per platform, `checksums.txt`, `checksums.txt.minisig`, `build-manifest.json`, `architecture-build-metadata.json`, `sbom.json`, `claims.yaml`, `test-summary.json`, `acceptance-summary.json`, `claims-verify-report.txt`, and, only when `GOV_RELEASE_HMAC_KEY` is configured, `checksums.txt.hmac` (Sol9 P2-2: renamed from the ambiguous `signature`, and no longer written as an "UNSIGNED" placeholder when absent — its absence is the honest signal). Darwin archives are published as feature-limited/non-approving artifacts. To run it locally instead (or before tagging, to check the pipeline is clean): `VERSION=<version> scripts/release.sh` from a clean working tree — `REQUIRE_TAG` defaults off locally, but rc/production versions still require a minisign signature.

## Verifying a release's minisign signature

`checksums.txt.minisig` is an Ed25519 signature over `checksums.txt`, publicly verifiable with only the corresponding **public** key — no shared secret required. To verify a downloaded release:

1. Obtain the project's minisign public key. **Do not trust a public key or fingerprint bundled inside the release archive or repository itself** — a compromised release could ship a forged key alongside a forged signature. The trust root is published out-of-band (e.g. directly by the maintainer, on a separate channel from the release download) and must be cross-checked there before use. **External sourcing is the documented default for every verifier in this repo** (Sol15 P2-3): `scripts/audit_bundle_validate.py` fails closed with `NO_EXTERNAL_TRUST_ANCHOR` unless `--trusted-fingerprints-file` and `--trusted-public-keys-dir` are supplied from outside the bundle, and both it and `scripts/release_policy.py signature` reject trust material resolving inside the artifacts directory (`BUNDLE_LOCAL_TRUST_ANCHOR`) unless the explicit, warned-about `--allow-bundle-local-trust-anchor` opt-in is passed — a key that travels beside the payload proves integrity but not origin. `scripts/bundle_verify.py` accepts the same `--trusted-fingerprints-file` and cross-checks the bundle's signer fingerprint against it; without one it verifies integrity but warns `WEAK_ORIGIN_AUTHENTICATION`. The production fingerprint `B5CBEE8BBA8826A7` is published out-of-band in `agents/governator-signing-key-fingerprint.txt` (a separate nested repository) and mirrored to VPS `216.158.228.204` — see [signing_key.md](signing_key.md) for the full channel list and ceremony.

   **Primary out-of-band channel (v16 D4):** `https://jeremylamkin.com/governator-signing-key.txt` — served from Hostinger infrastructure independent of GitHub entirely, so a compromised GitHub account or repo cannot also forge this copy. `docs/signing_keys/B5CBEE8BBA8826A7.pub` in this repo is the **secondary** copy only — proves nothing about origin on its own; cross-check it against the primary URL before trusting it. Retrieval:

   ```
   curl -fsSL -A "Mozilla/5.0" https://jeremylamkin.com/governator-signing-key.txt -o governator.pub
   ```

   The `-A "Mozilla/5.0"` is required: the site's edge WAF returns `403` to requests with no `User-Agent` header (bare `curl`/`urllib` defaults included) but serves the file normally to a browser-shaped one — this is a hosting quirk, not a security gate, and does not change what is being trusted. The file's own `untrusted comment` line names the fingerprint; confirm it reads `B5CBEE8BBA8826A7` before use:

   ```
   grep -F 'B5CBEE8BBA8826A7' governator.pub
   ```
2. `minisign -V -p governator.pub -m checksums.txt -x checksums.txt.minisig`
3. Only after the signature verifies, cross-check `sha256sum -c checksums.txt` against the downloaded archives.

The production signing key was generated and anchored on 2026-07-22 (Sol10 rc4 Session 8): fingerprint `B5CBEE8BBA8826A7`, published out-of-band before anchoring per [signing_key.md](signing_key.md). A missing `.minisig` remains the honest signal for a release deliberately produced without one (candidate/local dry-runs); do treat a `.minisig` file with no published, independently-obtained public key to verify it against as unverifiable and untrusted. `scripts/release.sh` refuses (`scripts/release_policy.py signature --trusted-fingerprints-file docs/TRUSTED_SIGNING_KEYS.txt`) any REQUIRE_ASYMMETRIC_SIGNATURE=1 release whose signature was not produced by a fingerprint on that anchored list — a valid signature from an unanchored key is not sufficient — and, since rc8-upg15 S7 (Sol15 P2-3), that gate additionally rejects a trust anchor sourced from inside the release artifacts unless explicitly opted in.
6. Verify checksums, archive contents (executable bit preserved, mode exactly `0755`), `gov version --json` against `build-manifest.json`, `gov claims verify --release --artifact <path> --manifest build-manifest.json`, and one clean-home `gov init` from a downloaded artifact — `scripts/release.sh` already runs the acceptance smoke test once against the host platform's own archive (`acceptance-summary.json`) and, as its own separate release-blocking gate, full claims verification against that same exact archived artifact (`claims-verify-report.txt`, via `scripts/release_verify.sh`); step 6 here is the operator's independent re-check on a genuinely different machine.
7. **Install only from a signed platform archive.** Always extract the `gov` binary from the signed `gov_<version>_<platform>.tar.gz` for your platform — never from the loose file in the outer source ZIP. The outer ZIP flattens executable permissions; the signed platform tarball preserves mode `0755` and is covered by `checksums.txt` and its minisign signature. `scripts/install_evidence.py generate` requires `--source-archive` naming the exact tarball the binary was extracted from; it validates the archive against the build manifest's platform artifact (name and SHA-256), safely extracts the contained binary (rejecting symlinks, path traversal, duplicate members, unexpected members, and non-regular files), verifies the contained binary's SHA-256 and mode against the manifest's `executable_sha256`, and proves byte-for-byte equality between the installed binary and the extracted one. The signed installation evidence records both `source_archive_sha256` and `contained_binary_sha256`; the audit-bundle validator (`scripts/audit_bundle_validate.py`) cross-checks both against the manifest's `archive_sha256` and `executable_sha256`.
8. Run the legacy-gate shadow cutover described in [migration.md](migration.md).
9. After the live cutover has run clean for one month, prepare and tag `v1.0.0`.

## Two-layer signing contract (rc8-upg15 S5)

The release carries two independent signed layers with an explicit ordering:

1. **Layer 1 — `checksums.txt` + `checksums.txt.minisig`.** Produced during the
   release build, before installation. Covers platform archives, build manifest,
   test evidence, toolset, release environment, and the acceptance binary. Signed
   by Minisign (Ed25519).

2. **Layer 2 — `closure-manifest.json` + `closure-manifest.json.minisig`.**
   Produced after installation, by `scripts/closure_manifest.py generate`. Binds
   `checksums.txt`'s own SHA-256 plus the six closure objects that necessarily
   come into existence after layer 1 is signed:
   - `governator-source-<version>.tar.gz` + `.tree.json` (source closure)
   - `governator_architecture.md`
   - `install-evidence.json`
   - `assayer-source-<version>.tar.gz` + `.tree.json` (Assayer closure)

   The closure manifest also binds the trust anchor
   (`source/docs/TRUSTED_SIGNING_KEYS.txt`) so an attacker cannot replace both
   the evidence and its verification key.

**Ordering contract:** layer 1 is signed first (during the release build); layer
2 references layer 1's hash and is signed second (after installation). A
verifier must check both layers and confirm layer 2's `checksums_sha256` matches
the actual `checksums.txt` bytes.

## One-command offline verification

`scripts/bundle_verify.py --bundle-dir DIR` verifies the complete binding
offline in a clean room: source closure, architecture, install evidence,
checksums, closure manifest, trust anchor, and the portable Git bundle. It names
each specific unbound object on failure. This is the entry point Sol's next
audit pass will run. Pass `--trusted-fingerprints-file FILE` obtained through an
independent channel (the documented default, Sol15 P2-3) to cross-check the
bundle's signer fingerprint against the externally published anchor; without it
the verifier completes integrity checks but warns `WEAK_ORIGIN_AUTHENTICATION`,
because a trust anchor read from inside the bundle proves integrity only.

Do not publish generated databases, `.env` files, `PROGRESS.md`, local binaries, credentials, or machine-specific paths.
