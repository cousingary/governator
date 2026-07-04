# Publishing checklist

Publishing is operator-executed. Automation must not create the public repository, push `main`, or tag a release without explicit approval.

1. Run the complete local verification loop and confirm the working tree contains only the release commit.
2. Create the public repository with `gh repo create governator --public`, add the remote, and push `main`.
3. Enable GitHub Actions and confirm the Linux/macOS CI matrix (build, vet, race tests, gofmt), lint, fuzz, and cross-compile smoke are green.
4. Confirm repository security settings and replace the placeholder private-report contact in `SECURITY.md`.
5. Tag `v1.0.0-rc1` and push the tag. No release workflow runs automatically; the operator runs `goreleaser release --clean` locally (or in a manually triggered CI job) against `.goreleaser.yml` to build artifacts.
6. Verify checksums, archive contents, `gov version`, and one clean-home `gov init` from a downloaded artifact.
7. Run the legacy-gate shadow cutover described in [migration.md](migration.md).
8. After the live cutover has run clean for one month, prepare and tag `v1.0.0`.

Do not publish generated databases, `.env` files, `PROGRESS.md`, local binaries, credentials, or machine-specific paths.
