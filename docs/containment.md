# Containment model

This is the single place that states what "containment" means in Governator, after the Sol redteam repair program (v1.0.0, the first release). Related detail lives in [docs/contracts.md](contracts.md#containment-and-risk-class) (the contract-facing `risk_class`/`docker.*`/`containment.*` fields), [docs/backends.md](backends.md#capability-attestation) (attestation mechanics), and [docs/security.md](security.md) (the finding-by-finding register this model closes).

## The rule

**A local worktree is repository isolation. It is never host containment.** A disposable Git worktree keeps a run's changes out of the live branch until approved; it does nothing to stop a process running inside it from reading or writing anywhere else the host user can. Before the Sol repair, several code paths implicitly treated "runs in its own worktree" as if it were a security boundary — it is not, and no doc, contract field, or code comment should imply otherwise going forward.

What actually qualifies as host containment, for a `risk_class: high` job, is one of exactly three things:

1. **Hardened Docker** — `runner: docker` with `docker.user` (non-root), `docker.read_only_rootfs`, `docker.cap_drop_all`, `docker.no_new_privileges`, a digest-pinned `docker.image` (`@sha256:<64-hex>`, not a mutable tag), and `docker.network: deny`. See [Docker hardening](#docker-hardening) below for what's actually enforced and verified.
2. **A verified native sandbox** on `runner: local` — the resolved backend must have a *current capability attestation* proving the specific configured executable, not just the adapter name, actually has the sandbox it claims. See [Capability attestation](#capability-attestation-lifecycle).
3. **A signed operator override** (`containment.override_signature`), ed25519-verified against a configured public key, binding both the job ID and the contract's content hash so neither replay across jobs nor a post-signature contract edit can reuse it.

Everything else — an unattested local run, a non-hardened Docker config, an expired attestation, an unsigned override — fails closed before quota reservation or workspace creation for `risk_class: high` work. `low`/`medium`/unset risk classes are scoring-only and are never containment-gated.

## What local-worktree isolation actually does and doesn't stop

Local-worktree isolation (every risk class, not just `high`) now additionally enforces:

- **Whole-tree symlink rejection.** Any `runner: local` job refuses to launch if the worktree contains a symlink or junction anywhere outside `.git/`/`.codegraph/` — this closes the path where a tracked symlink (or a symlinked parent of a declared write target) let a nominally "read-only" or scope-limited run write through the link to an arbitrary host path while the post-run fingerprint diff still looked clean. See [docs/contracts.md#local-runner-symlink-containment](contracts.md#local-runner-symlink-containment).
- **Canonical lock identity.** The workspace lock keys on the repository's resolved device/inode identity, not a raw path string, so a symlinked alias to an already-running repository can't slip past the lock and run concurrently against the same tree. See [docs/ledger.md#canonical-workspace-lock-identity](ledger.md#canonical-workspace-lock-identity).
- **Git control-plane fingerprinting.** `.git/hooks` and `.git/config` (resolved to the shared git-common-dir for worktrees, not each worktree's private per-checkout view) are hashed before and after every run, independent of anything the contract declares. A backend process that modifies a hook or the repo config during a run is a blocking violation (`git control-plane mutation`) even though hooks/config live outside the worktree's own file tree and wouldn't otherwise appear in a source diff.

None of these make a local run *contained* — they make it honest about what changed. A process with host-user-equivalent shell access inside a local worktree can still read or write anything that user can; the symlink ban, lock identity, and control-plane fingerprint close specific detection/escape gaps, they don't add a security boundary. That boundary is Docker or a native sandbox, full stop.

## Capability attestation lifecycle

Backend adapters (`internal/agents`) declare *expected* capabilities per adapter name — e.g. "Claude Code has a native sandbox." Before the Sol repair, any executable configured at `backends.<name>.bin` silently inherited that adapter's declared capabilities regardless of what the executable actually was. `internal/attest` closes this:

- `gov attest <backend>` generates and stores an **attestation**: adapter name/version, the executable's canonicalized path and SHA-256, its `--version` output, the effective model ID, the effective config hash, and four probe results (supported flags, sandbox, network control, transcript format) — plus a 24-hour expiry. The attestation ID is a SHA-256 over all of that, stored in the ledger's `capability_attestations` table.
- A `risk_class: high` job on `runner: local` requires a **current** attestation exactly matching the live executable's path, hash, config hash, and model. It is rejected before launch if: the backend doesn't declare a native sandbox at all; no attestation matches the current executable (unattested, or swapped since the last `gov attest` run — both surface the same "capability attestation required" error); the matched attestation has expired; or any required probe failed.
- Re-attestation is required after any backend CLI upgrade or `backends.<name>.bin` repoint. A stale or silently-swapped executable fails the run rather than inheriting trust from the adapter name.
- The attestation ID feeds into `ExecutionIdentity` (see [docs/security.md](security.md), Critical 1), so a replay can't reuse an approval whose attestation has since changed or expired.

## Docker hardening

`IsHardened()` requires every one of: a validated non-root `docker.user` (empty, `root`, `0`, and `0:0` are all rejected); `read_only_rootfs`; `cap_drop_all`; `no_new_privileges`; a digest-pinned image (`@sha256:` plus a real 64-hex digest — `allow_mutable_tag` is an explicit, logged exception and never makes a config "hardened," it only silences the digest requirement); and `network: deny`.

Hardening is **verified against the running container**, not just the declared request: for a hardened config, `DockerRunner.Observe` runs `docker inspect` and checks the container's effective user, network mode, read-only rootfs, capability drops, `no-new-privileges`, seccomp/AppArmor security profiles, running image digest, resource limits, and mount set against what was declared. `docker inspect` failing, or any mismatch, blocks approval for a hardened run — it does not degrade to a note the way it still does for a non-hardened, low-risk run.

Credential mounts resolve symlinks (checking both the raw and resolved path against a hardcoded Docker/containerd/CRI-O socket list before allowing the mount), require the resolved path to fall under a configured credential root, and by default only permit regular files — a directory requires an explicit `docker.credential_mount_allow_dirs` entry, and sockets/devices/FIFOs are never permitted regardless of configuration. Mounts land read-only under `/run/governator-credentials/`.

## Output byte caps (local and Docker)

Output byte caps are enforced for both runners. `docker.output_cap_bytes` bounds a Docker run's container stdout/stderr (`internal/runner/docker.go`'s `cappedWriter`); `local.output_cap_bytes` bounds a local run's host subprocess the same way (`internal/runner/runner.go`'s `LocalWorktreeRunner.executor`, closing Sol High 11). Both default to 20MiB, report accepted/discarded bytes through `Runner.Observe`, emit a loud `OUTPUT_TRUNCATED` ledger stage, and honor their runner's `require_complete_transcript` flag to quarantine a run on a capped transcript rather than approve it on an incomplete trail. Neither field participates in Docker/local's "must be absent under the other runner" placement rule crossing over — `docker.*` stays Docker-only, `local.*` stays local-only. See [docs/security.md](security.md), High 11.
