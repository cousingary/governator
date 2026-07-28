#!/usr/bin/env python3
"""Reproduce Sol14 P0-3 by comparing rc6's fixture to Assayer v1.1.6."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


GOVERNATOR = Path(__file__).resolve().parents[3]
ASSAYER = GOVERNATOR.parent / "assayer"
FIXTURE = GOVERNATOR / "internal" / "assay" / "testdata" / "assayer_fixture"
RELEASED = "81fa57d7461321308e571dfcc5144913229ca985"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ASSAYER), *args], text=True
    ).strip()


def main() -> int:
    pinned = (FIXTURE / "PINNED_COMMIT").read_text(encoding="utf-8").strip()
    if pinned != "33bfde2bf32dd2b3089bcc09fd769d1f4b1e858a":
        raise SystemExit(f"unexpected fixture pin: {pinned}")
    if git("rev-parse", "HEAD") != RELEASED:
        raise SystemExit("Assayer checkout is not the released v1.1.6 commit")
    if git("status", "--porcelain"):
        raise SystemExit("Assayer checkout is dirty")

    fixture_files = sorted(
        path.relative_to(FIXTURE)
        for path in FIXTURE.rglob("*.py")
        if "__pycache__" not in path.parts
    )
    divergences = []
    for relative in fixture_files:
        released_path = ASSAYER / relative
        if not released_path.is_file():
            raise SystemExit(f"released Assayer path missing: {relative}")
        fixture_hash = sha256(FIXTURE / relative)
        released_hash = sha256(released_path)
        if fixture_hash == released_hash:
            raise SystemExit(f"fixture unexpectedly matches released Assayer: {relative}")
        divergences.append(
            {
                "path": str(relative),
                "fixture_sha256": fixture_hash,
                "released_sha256": released_hash,
            }
        )

    changed = git("diff", "--name-only", f"{pinned}..{RELEASED}").splitlines()
    if len(changed) != 23:
        raise SystemExit(f"changed-file count is {len(changed)}, expected 23")
    print(
        json.dumps(
            {
                "fixture_commit": pinned,
                "released_commit": RELEASED,
                "fixture_hash_divergences": divergences,
                "changed_files": changed,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
