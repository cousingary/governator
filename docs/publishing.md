# Publishing checklist

Publishing is operator-executed. Automation must not create the public repository, push `main`, or tag a release without explicit approval.

1. Run the complete local verification loop and confirm the working tree contains only the release commit.
2. Create the public repository with `gh repo create governator --public`, add the remote, and push `main`.
3. Enable GitHub Actions and confirm `.github/workflows/ci.yml`'s Linux/macOS matrix (build, vet, unit + race tests, the black-box Sol3 security regression corpus, gofmt), lint, fuzz, and cross-compile smoke are green.
4. Confirm repository security settings and replace the placeholder private-report contact in `SECURITY.md`.
5. Tag `v<version>` and push the tag. `.github/workflows/release.yml` sets `REQUIRE_TAG=1` and `REQUIRE_ASYMMETRIC_SIGNATURE=1`, then runs `scripts/release.sh` — the single canonical release pipeline (Sol redteam v3 S14 / finding #20 retired the divergent `.goreleaser.yml` generation; Sol redteam v4 S8 / P0-7 added the hard assertions below; Sol v8 S4 adds the detached immutable checkout + mandatory asymmetric signature gate). It uploads `gov_<version>_<platform>.tar.gz` per platform, `checksums.txt`, `checksums.txt.minisig`, `build-manifest.json`, `architecture-build-metadata.json`, `sbom.json`, `claims.yaml`, `test-summary.json`, `acceptance-summary.json`, `claims-verify-report.txt`, and `signature`. Darwin archives are published as feature-limited/non-approving artifacts. To run it locally instead (or before tagging, to check the pipeline is clean): `VERSION=<version> scripts/release.sh` from a clean working tree — `REQUIRE_TAG` defaults off locally, but rc/production versions still require a minisign signature.
6. Verify checksums, archive contents (executable bit preserved, mode exactly `0755`), `gov version --json` against `build-manifest.json`, `gov claims verify --release --artifact <path> --manifest build-manifest.json`, and one clean-home `gov init` from a downloaded artifact — `scripts/release.sh` already runs the acceptance smoke test once against the host platform's own archive (`acceptance-summary.json`) and, as its own separate release-blocking gate, full claims verification against that same exact archived artifact (`claims-verify-report.txt`, via `scripts/release_verify.sh`); step 6 here is the operator's independent re-check on a genuinely different machine.
7. Run the legacy-gate shadow cutover described in [migration.md](migration.md).
8. After the live cutover has run clean for one month, prepare and tag `v1.0.0`.

Do not publish generated databases, `.env` files, `PROGRESS.md`, local binaries, credentials, or machine-specific paths.
