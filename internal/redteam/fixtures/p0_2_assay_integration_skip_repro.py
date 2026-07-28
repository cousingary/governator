#!/usr/bin/env python3
"""Reproduce Sol14 P0-2: rc6's mandatory Assayer integration test skips."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
TEST = "TestEvaluateAgainstRealCLIPassAndFail"


def main() -> int:
    proc = subprocess.run(
        [
            "go",
            "test",
            "-v",
            "-tags",
            "integration",
            "-p",
            "2",
            "-parallel",
            "2",
            "-count=1",
            "./internal/assay/...",
        ],
        cwd=REPO,
        check=False,
        capture_output=True,
        text=True,
    )
    output = proc.stdout + proc.stderr
    skip_line = f"--- SKIP: {TEST}"
    if proc.returncode != 0 or skip_line not in output:
        raise SystemExit(
            "mandatory integration skip did not reproduce "
            f"(exit={proc.returncode}, expected={skip_line!r})\n{output}"
        )
    print(json.dumps({"package_exit": 0, "skipped_test": TEST}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
