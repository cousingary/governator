#!/usr/bin/env python3
"""scripts/release_checkpoint.py -- Sol11 rc5 Session 3 (P1-5): the atomic,
identity-scoped checkpoint primitive that makes scripts/release.sh's tier
pipeline (scripts/release_tier_pipeline.sh) crash-resumable.

The defect this closes: scripts/release.sh emptied its OUT_DIR at the start
of every invocation and ran every expensive tier (unit/race/integration/
corpus/redteam/redteam_race/fuzz) sequentially with no durable record of
partial progress. A crash (OOM, host contention, WSL restart) mid-pipeline
left whatever the current tier had written and forced a full restart of
every tier, including ones that had already passed cleanly.

Design:
  - "identity" fields (governator_commit, governator_tag, assayer_commit,
    go_sum_hash, toolchain_hash, environment_hash, go_test_parallelism)
    describe everything that must be IDENTICAL between the crashed attempt
    and the resuming one for a prior tier's result to still be trustworthy.
    Any one of these differing (a different commit, a different Go
    toolchain, a different Assayer checkout, ...) invalidates every
    existing checkpoint -- a fresh release_attempt_id is minted and no
    checkpoint from the old attempt is ever reused.
  - "peek" is a pure read: given a candidate identity, does the state dir's
    identity.json already describe the SAME attempt? Never writes.
  - "init" is called once per invocation, after the caller has decided
    (via peek, and possibly wiping OUT_DIR on a mismatch) which
    release_attempt_id this run uses; it atomically (re)writes
    identity.json.
  - "check" is called before running an individual tier: does an existing
    checkpoint for this tier belong to the SAME resolved identity (attempt
    id included) and the SAME exact command, and did it record PASS? If
    every one of those holds, the tier can be skipped (reused). Any
    mismatch is reported by name (not just "stale") so a human -- or a
    red-team test -- can see exactly which identity field diverged.
  - "write" is called after a tier actually runs, to durably record its
    outcome. The write is atomic: write to a temp file in the same
    directory, fsync the file, os.replace() it into place, then fsync the
    containing directory -- so a crash between "wrote bytes" and "renamed"
    can never leave a checkpoint that looks committed but is actually
    truncated or missing (corpus case 10: "crash after unit completion but
    before checkpoint rename").
  - "aggregate" is called once, right before build-manifest.json is
    finalized: every checkpoint named as required must exist, belong to
    the CURRENT resolved release_attempt_id (and every other identity
    field), and record PASS. Mixing evidence from two different release
    attempts (corpus case 16) is rejected here, by construction -- a
    checkpoint whose release_attempt_id doesn't match the identity file's
    is never aggregated, no matter how recently it was written.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import uuid

IDENTITY_FIELDS = (
    "governator_commit",
    "governator_tag",
    "assayer_commit",
    "go_sum_hash",
    "toolchain_hash",
    "environment_hash",
    "go_test_parallelism",
    "requested_version",
    "expected_exact_tag",
    "release_mode",
    "distribution_allowed",
)

# Fields (beyond the six pure-identity ones) that must ALSO match for a
# tier's checkpoint to be reused -- the exact command executed is part of
# what a checkpoint attests to, not just the environment it ran in.
CHECK_MATCH_FIELDS = ("release_attempt_id",) + IDENTITY_FIELDS


def atomic_write_json(path: pathlib.Path, data: dict, inject_delay_before_rename: float = 0.0) -> None:
    """temp file (same directory) -> fsync -> atomic rename -> parent-dir
    fsync. Every field of the P1-5 "atomic checkpoint" requirement.

    inject_delay_before_rename is a TEST-ONLY hook (default 0, a no-op in
    every production call site): it sleeps after the temp file is fully
    written+fsynced but before os.replace() commits it, giving a red-team
    test a wide, reliable window in which to SIGKILL this process and prove
    that a crash in that window leaves NO checkpoint at the final path --
    never a corrupt/partial one, and never one a resuming attempt could
    mistake for a completed tier (corpus case 10: "crash after unit
    completion but before checkpoint rename")."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    if inject_delay_before_rename > 0:
        import time

        time.sleep(inject_delay_before_rename)
    os.replace(tmp, path)
    dirfd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def load_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def cmd_identity(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    for field in IDENTITY_FIELDS:
        p.add_argument("--" + field.replace("_", "-"), required=True)
    args = p.parse_args(argv)
    data = {field: getattr(args, field) for field in IDENTITY_FIELDS}
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


def cmd_peek(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--state-dir", required=True)
    p.add_argument("--identity-file", required=True)
    args = p.parse_args(argv)

    state_dir = pathlib.Path(args.state_dir)
    candidate = load_json(pathlib.Path(args.identity_file))
    identity_path = state_dir / "identity.json"
    resumed = False
    attempt_id = None
    if identity_path.is_file():
        try:
            existing = load_json(identity_path)
        except (json.JSONDecodeError, OSError):
            existing = {}
        if all(existing.get(f) == candidate.get(f) for f in IDENTITY_FIELDS):
            resumed = True
            attempt_id = existing.get("release_attempt_id")
    print(json.dumps({"resumed": resumed, "attempt_id": attempt_id}))
    return 0


def cmd_init(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--state-dir", required=True)
    p.add_argument("--identity-file", required=True)
    p.add_argument("--attempt-id", required=True)
    args = p.parse_args(argv)

    identity = load_json(pathlib.Path(args.identity_file))
    data = {f: identity[f] for f in IDENTITY_FIELDS}
    data["release_attempt_id"] = args.attempt_id
    identity_path = pathlib.Path(args.state_dir) / "identity.json"
    atomic_write_json(identity_path, data)
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


def cmd_check(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--checkpoint", required=True)
    p.add_argument("--identity-file", required=True, help="resolved identity.json, includes release_attempt_id")
    p.add_argument("--command", required=True)
    args = p.parse_args(argv)

    ckpt_path = pathlib.Path(args.checkpoint)
    if not ckpt_path.is_file():
        print(f"MISSING: no checkpoint at {ckpt_path}", file=sys.stderr)
        return 2

    try:
        ckpt = load_json(ckpt_path)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"MISSING: checkpoint at {ckpt_path} is unreadable/corrupt ({exc}) -- treating as absent", file=sys.stderr)
        return 2

    current = load_json(pathlib.Path(args.identity_file))

    for field in CHECK_MATCH_FIELDS:
        if ckpt.get(field) != current.get(field):
            print(
                f"STALE: checkpoint field {field!r} differs -- checkpoint={ckpt.get(field)!r} current={current.get(field)!r}",
                file=sys.stderr,
            )
            return 3
    if ckpt.get("command") != args.command:
        print(
            f"STALE: checkpoint field 'command' differs -- checkpoint={ckpt.get('command')!r} current={args.command!r}",
            file=sys.stderr,
        )
        return 3
    if ckpt.get("result") != "PASS":
        print(f"NOT_REUSABLE: checkpoint recorded result={ckpt.get('result')!r}, not PASS", file=sys.stderr)
        return 4

    print(json.dumps(ckpt, indent=2, sort_keys=True))
    return 0


def cmd_write(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--checkpoint", required=True)
    p.add_argument("--identity-file", required=True)
    p.add_argument("--command", required=True)
    p.add_argument("--started", required=True)
    p.add_argument("--completed", required=True)
    p.add_argument("--exit-code", required=True, type=int)
    p.add_argument("--log-sha256", required=True)
    p.add_argument("--result", required=True, choices=["PASS", "FAIL"])
    p.add_argument("--duration-seconds", type=int, default=0)
    p.add_argument("--inject-delay-before-rename", type=float, default=0.0, help="TEST ONLY: sleep this many seconds between fsync and rename")
    args = p.parse_args(argv)

    identity = load_json(pathlib.Path(args.identity_file))
    data = {f: identity[f] for f in CHECK_MATCH_FIELDS}
    data.update(
        command=args.command,
        started=args.started,
        completed=args.completed,
        exit_code=args.exit_code,
        log_sha256=args.log_sha256,
        result=args.result,
        duration_seconds=args.duration_seconds,
    )
    atomic_write_json(pathlib.Path(args.checkpoint), data, inject_delay_before_rename=args.inject_delay_before_rename)
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


def cmd_aggregate(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--state-dir", required=True)
    p.add_argument("--identity-file", required=True)
    p.add_argument("--required", required=True, help="comma-separated tier names")
    args = p.parse_args(argv)

    current = load_json(pathlib.Path(args.identity_file))
    state_dir = pathlib.Path(args.state_dir)
    required = [t.strip() for t in args.required.split(",") if t.strip()]

    aggregated = {}
    for tier in required:
        ckpt_path = state_dir / f"{tier}.json"
        if not ckpt_path.is_file():
            print(f"INCOMPLETE_RELEASE_EVIDENCE: no checkpoint for required tier {tier!r} at {ckpt_path}", file=sys.stderr)
            return 1
        try:
            ckpt = load_json(ckpt_path)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"INCOMPLETE_RELEASE_EVIDENCE: checkpoint for tier {tier!r} is unreadable ({exc})", file=sys.stderr)
            return 1
        for field in CHECK_MATCH_FIELDS:
            if ckpt.get(field) != current.get(field):
                print(
                    f"MIXED_RELEASE_EVIDENCE: tier {tier!r} checkpoint field {field!r} "
                    f"({ckpt.get(field)!r}) does not match the current release attempt's "
                    f"({current.get(field)!r}) -- refusing to aggregate evidence from two "
                    "different release attempts",
                    file=sys.stderr,
                )
                return 1
        if ckpt.get("result") != "PASS":
            print(f"INCOMPLETE_RELEASE_EVIDENCE: tier {tier!r} checkpoint recorded result={ckpt.get('result')!r}, not PASS", file=sys.stderr)
            return 1
        aggregated[tier] = ckpt

    print(json.dumps(aggregated, indent=2, sort_keys=True))
    return 0


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: release_checkpoint.py <identity|peek|init|check|write|aggregate> ...", file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    handlers = {
        "identity": cmd_identity,
        "peek": cmd_peek,
        "init": cmd_init,
        "check": cmd_check,
        "write": cmd_write,
        "aggregate": cmd_aggregate,
    }
    handler = handlers.get(cmd)
    if handler is None:
        print(f"unknown command: {cmd}", file=sys.stderr)
        return 2
    return handler(rest)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
