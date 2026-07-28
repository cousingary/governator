#!/usr/bin/env python3
"""Reproduce Sol14 P1-1 against rc6's complete audit bundle."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
WORKSPACE = REPO.parent
COMMIT = "86c230629089536f75f7c570213fa6839ca0df10"


def main() -> int:
    command = [
        "python3",
        str(REPO / "scripts" / "audit_bundle_validate.py"),
        "--dist-dir",
        str(REPO / "dist"),
        "--repo",
        str(REPO),
        "--release-commit",
        COMMIT,
        "--architecture-doc",
        str(WORKSPACE / "agents" / "governator_architecture.md"),
        "--trusted-fingerprints-file",
        str(REPO / "docs" / "TRUSTED_SIGNING_KEYS.txt"),
        "--trusted-public-keys-dir",
        str(REPO / "docs" / "signing_keys"),
    ]
    proc = subprocess.run(command, check=False, capture_output=True, text=True)
    output = proc.stdout + proc.stderr
    if proc.returncode != 0 or "audit_bundle_validate: OK" not in output:
        raise SystemExit(
            "rc6 audit validator did not accept the unevidenced live-install claim "
            f"(exit={proc.returncode})\n{output}"
        )
    print(
        json.dumps(
            {
                "audit_bundle_validate": "OK",
                "architecture_contains_live_install_claim": True,
                "install_evidence_argument_supplied": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
