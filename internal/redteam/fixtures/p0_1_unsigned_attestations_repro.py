#!/usr/bin/env python3
"""Reproduce Sol13 P0-1 against the shipped rc5 gate.

This fixture intentionally supplies five unsigned, same-host attestations that
claim a skipped Docker-required test passed elsewhere. rc5 incorrectly accepts
the release because it aggregates covered tests without verifying signatures,
host capabilities, or category-specific coverage. S2/S3 must invert this
fixture into an enrolled regression case.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
GOV = REPO / "dist" / "gov"
CASE = "TestV13SyntheticSkippedDockerCase"
CATEGORIES = ("core", "systemd-enabled", "docker-enabled", "fallback-path", "darwin")


def main() -> int:
    if not GOV.is_file():
        raise SystemExit(f"packaged rc5 binary is missing: {GOV}")

    with tempfile.TemporaryDirectory(prefix="governator-p0-1-") as temp_dir:
        root = Path(temp_dir)
        (root / "manifest.yaml").write_text(
            """version: 1
cases:
  - case: 1
    name: TestV13SyntheticSkippedDockerCase
    session: S0
    required: true
    conditional: true
    allowed_skip:
      predicate: has_docker_daemon
      reason: docker unavailable
    status: implemented
exclusions: []
""",
            encoding="utf-8",
        )
        (root / "inventory.txt").write_text(f"{CASE}\n", encoding="utf-8")
        (root / "redteam.log").write_text(
            f"=== RUN   {CASE}\n    fixture_test.go:1: docker unavailable\n--- SKIP: {CASE} (0.00s)\nPASS\n",
            encoding="utf-8",
        )
        attestations = root / "attestations"
        attestations.mkdir()
        binding = {
            "governator_commit": "cfc6bb5734a732a97a20d3bf6fea0919fda97772",
            "assayer_commit": "1f9c28fc8d89bb0e6174959e10955a6d46fe7087",
            "test_source_hash": "synthetic-test-source",
            "toolchain_hash": "synthetic-toolchain",
            "release_version": "1.0.2-rc5",
            "host_identity": "same-unproven-host",
            "platform": "Linux/x86_64",
            "capabilities": {},
            "covered_tests": [CASE],
            "timestamp": "2026-07-26T00:00:00Z",
        }
        for category in CATEGORIES:
            (attestations / f"{category}.json").write_text(
                json.dumps({"category": category, **binding}, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        proc = subprocess.run(
            [
                str(GOV),
                "redteam-gate",
                "verify",
                "--manifest",
                str(root / "manifest.yaml"),
                "--log",
                str(root / "redteam.log"),
                "--capabilities",
                json.dumps({"has_docker_daemon": {"state": "present"}}),
                "--inventory",
                str(root / "inventory.txt"),
                "--attestations",
                str(attestations),
                "--require-zero-skips",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise SystemExit(f"rc5 rejected the known P0-1 exploit:\n{proc.stderr}{proc.stdout}")
        result = json.loads(proc.stdout)

    expected = {
        "ok": True,
        "discovered": 1,
        "run": 0,
        "skipped": 1,
        "failed": 0,
        "require_zero_skips": True,
        "inventory_supplied": True,
    }
    actual = {key: result.get(key) for key in expected}
    if actual != expected:
        raise SystemExit(f"rc5 P0-1 result differed from the audited exploit:\n{json.dumps(result, indent=2)}")
    print(json.dumps(actual, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
