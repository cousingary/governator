# Security policy

## Supported versions

Security fixes are applied to the latest tagged release candidate or stable release.

## Reporting

Please report suspected vulnerabilities privately to **webmaster@jeremylamkin.com**. Do not open a public issue until maintainers confirm that disclosure is safe. Include the affected version, reproduction steps, impact, and any proposed mitigation; never send live credentials.

## Security boundary

Governator governs cooperative coding agents. Native sandboxes provide containment, while repository fingerprints detect unexpected writes. Permission configs, prompts, lexical command classification, transcripts, and protected-path manifests are defense-in-depth controls rather than a security boundary.

Governator does not defend against a malicious human, a compromised peer process, stolen host credentials, kernel escape, or an actor already holding equivalent shell access. Operators remain responsible for least privilege, secret isolation, backups, host patching, and reviewing contracts before real agent execution.

## Independent red-team findings

The Sol redteam review (2026-07) reproduced eight Critical and twelve High-severity gaps against a prior release — replay bypasses, symlink escapes, unattested backend capability trust, non-atomic live-root merges, and more. All were repaired in a seven-session program; see [docs/security.md](docs/security.md) for the finding-by-finding register (finding → fix commit → regression test) and [docs/containment.md](docs/containment.md) for the resulting containment model. One item (local-runner output capping, High 11) remains open — see that register for status.
