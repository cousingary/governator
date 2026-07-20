#!/usr/bin/env python3
"""Write checksums.txt.hmac -- HMAC-SHA256 over checksums.txt, keyed by
GOV_RELEASE_HMAC_KEY. Factored out of scripts/release.sh (Sol9 P2-2/case 41)
so the exact "omit entirely when no key is configured, never write a
placeholder" behavior is independently testable rather than only provable by
running the full release pipeline.

Usage: release_hmac_sign.py --checksums <path> --out <path>
Exits 0 whether or not a signature was written; writes the file to --out
only when GOV_RELEASE_HMAC_KEY is set in the environment. Never writes an
"UNSIGNED" placeholder -- absence of the output file IS the honest signal
that this release carries no HMAC signature.
"""
import argparse
import hashlib
import hmac
import os
import sys


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--checksums", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)

    key = os.environ.get("GOV_RELEASE_HMAC_KEY", "")
    if not key:
        # Deliberately no output file, no placeholder text. See module
        # docstring: absence is the signal.
        return 0

    data = open(args.checksums, "rb").read()
    signature = "hmac-sha256:" + hmac.new(key.encode(), data, hashlib.sha256).hexdigest()
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(signature + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
