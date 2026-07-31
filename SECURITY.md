# Security policy

## Supported versions

Security fixes are applied to the latest tagged release candidate or stable release. The current release is `v1.0.2-rc8`.

## Reporting

Please report suspected vulnerabilities privately to **webmaster@jeremylamkin.com**. Do not open a public issue until maintainers confirm that disclosure is safe. Include the affected version, reproduction steps, impact, and any proposed mitigation; never send live credentials.

## Security boundary

Governator governs cooperative coding agents. Native sandboxes provide containment, while repository fingerprints detect unexpected writes. Permission configs, prompts, lexical command classification, transcripts, and protected-path manifests are defense-in-depth controls rather than a security boundary.

Governator does not defend against a malicious human, a compromised peer process, stolen host credentials, kernel escape, or an actor already holding equivalent shell access. Operators remain responsible for least privilege, secret isolation, backups, host patching, and reviewing contracts before real agent execution.

## Independent red-team findings

The Sol redteam program (2026-07 onward) has run across eight release-candidate cycles (`v1.0.2-rc1` through `v1.0.2-rc8`) and multiple audit rounds (Sol3 through Sol15), reproducing replay bypasses, symlink escapes, unattested backend capability trust, non-atomic live-root merges, and dozens of further identity, containment, and release-integrity gaps against each round's binary. See [docs/security.md](docs/security.md) for the finding-by-finding register (finding → fix commit → regression test) and [docs/containment.md](docs/containment.md) for the resulting containment model.

Every finding in that register is closed, including High 11 (local-runner output capping), closed by commit `629cb62`. Two residual containment limitations remain disclosed and open by design — accepted, not release blockers:

- **Same-UID Node dependency mutation** (Sol15 P2-1): a same-UID process can transiently modify and restore a Node backend's frozen dependency closure between the pre-run and post-run hash. Governator refuses production approval for any Node backend run on `runner: local`; approval requires a digest-pinned `runner: docker` image. See [docs/containment.md](docs/containment.md#node-dependency-closure-a-disclosed-residual-same-uid-window).
- **Landlock read-path scope**: the local external-enforcement sandbox (`gov __sandbox_exec`) confines filesystem *writes* to the workspace by default; every other host path stays readable. A high-risk `runner: local` job is not confined against reading the rest of the host filesystem. See [docs/containment.md](docs/containment.md#local-external-enforcement).

Both are recorded rc9+ candidates (immutable mount / separate UID / memfd execution for Node; a stricter read allowlist for Landlock), deliberately out of scope for the current release.
