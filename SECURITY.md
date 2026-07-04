# Security policy

## Supported versions

Security fixes are applied to the latest tagged release candidate or stable release.

## Reporting

Please report suspected vulnerabilities privately to **security-contact-placeholder@example.invalid**. Do not open a public issue until maintainers confirm that disclosure is safe. Include the affected version, reproduction steps, impact, and any proposed mitigation; never send live credentials.

## Security boundary

Governator governs cooperative coding agents. Native sandboxes provide containment, while repository fingerprints detect unexpected writes. Permission configs, prompts, lexical command classification, transcripts, and protected-path manifests are defense-in-depth controls rather than a security boundary.

Governator does not defend against a malicious human, a compromised peer process, stolen host credentials, kernel escape, or an actor already holding equivalent shell access. Operators remain responsible for least privilege, secret isolation, backups, host patching, and reviewing contracts before real agent execution.
