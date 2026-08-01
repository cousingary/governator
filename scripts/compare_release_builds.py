#!/usr/bin/env python3
"""Require byte identity between local reviewed-bytes and CI release outputs."""
import argparse
import hashlib
import pathlib
import sys


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-dist", required=True)
    parser.add_argument("--ci-dist", required=True)
    args = parser.parse_args()
    local = pathlib.Path(args.local_dist)
    ci = pathlib.Path(args.ci_dist)
    failures = []
    names = sorted(
        path.name for path in local.glob("gov_*.tar.gz")
        if path.is_file()
    )
    if not names:
        failures.append("LOCAL_RELEASE_ARCHIVES_ABSENT")
    for name in names:
        other = ci / name
        if not other.is_file():
            failures.append(f"CI_RELEASE_ARCHIVE_ABSENT: {name}")
        elif digest(local / name) != digest(other):
            failures.append(f"CI_LOCAL_BYTE_IDENTITY_MISMATCH: {name}")
    extra = sorted(path.name for path in ci.glob("gov_*.tar.gz") if path.name not in names)
    failures.extend(f"CI_UNMATCHED_RELEASE_ARCHIVE: {name}" for name in extra)
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(f"compare_release_builds: OK — {len(names)} archives are byte-identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
