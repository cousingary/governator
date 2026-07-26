#!/usr/bin/env python3
"""Reproduce Sol13 P0-2 against rc5's release-policy verifier.

The fixture supplies a fake minisign that always exits successfully, a forged
packet with a trusted key ID and zero-filled signature, and the fake tool's own
hash as its claimed pin. rc5 accepts the circular trust chain. S4 must invert
this fixture into an enrolled regression case.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
POLICY = REPO / "scripts" / "release_policy.py"
FINGERPRINT = "B5CBEE8BBA8826A7"


def main() -> int:
    if not POLICY.is_file():
        raise SystemExit(f"release policy is missing: {POLICY}")

    with tempfile.TemporaryDirectory(prefix="governator-p0-2-") as temp_dir:
        root = Path(temp_dir)
        artifacts = root / "artifacts"
        artifacts.mkdir()
        artifact = artifacts / "gov"
        artifact.write_bytes(b"synthetic rc5 artifact\n")
        checksums = artifacts / "checksums.txt"
        checksums.write_text(
            f"{hashlib.sha256(artifact.read_bytes()).hexdigest()}  gov\n",
            encoding="utf-8",
        )

        key_id = bytes.fromhex(FINGERPRINT)[::-1]
        signature_packet = b"Ed" + key_id + bytes(64)
        minisig = artifacts / "checksums.txt.minisig"
        minisig.write_text(
            "untrusted comment: forged fixture signature\n"
            + base64.b64encode(signature_packet).decode("ascii")
            + "\ntrusted comment: not a signature\n",
            encoding="utf-8",
        )
        trusted = root / "trusted-fingerprints.txt"
        trusted.write_text(f"{FINGERPRINT}\n", encoding="utf-8")
        public_keys = root / "public-keys"
        public_keys.mkdir()
        public_key = b"Ed" + key_id + bytes(32)
        (public_keys / "fixture.pub").write_text(
            "untrusted comment: fixture public key\n"
            + base64.b64encode(public_key).decode("ascii")
            + "\n",
            encoding="utf-8",
        )
        fake_minisign = root / "minisign"
        fake_minisign.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_minisign.chmod(0o755)
        fake_hash = hashlib.sha256(fake_minisign.read_bytes()).hexdigest()

        proc = subprocess.run(
            [
                sys.executable,
                str(POLICY),
                "signature",
                "--version",
                "1.0.2-rc5",
                "--require",
                "1",
                "--minisig",
                str(minisig),
                "--trusted-fingerprints-file",
                str(trusted),
                "--checksums",
                str(checksums),
                "--trusted-public-keys-dir",
                str(public_keys),
                "--artifacts-dir",
                str(artifacts),
                "--minisign-bin",
                str(fake_minisign),
                "--minisign-bin-hash",
                fake_hash,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise SystemExit(f"rc5 rejected the known P0-2 exploit:\n{proc.stderr}{proc.stdout}")
        result = json.loads(proc.stdout)

    if result.get("signature_verified") is not True or result.get("minisign_hash_pinned") is not True:
        raise SystemExit(f"rc5 P0-2 result differed from the audited exploit:\n{json.dumps(result, indent=2)}")
    print(
        json.dumps(
            {
                "release_policy": result.get("release_policy"),
                "signature_verified": result.get("signature_verified"),
                "signer_fingerprint": result.get("signer_fingerprint"),
                "minisign_hash_pinned": result.get("minisign_hash_pinned"),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
