#!/usr/bin/env python3
"""Sol9 P2-3 / case 42: assert the release docs actually tell an operator how
to verify a minisign signature and where the trust root (public key
fingerprint) is published -- "a HMAC/minisign signature with nowhere
documented to get the matching public key from" is unverifiable in practice
even though the file on disk is real.

This is a documentation-completeness check, not a live-key check: it does
not (and must not) require a real production signing key to exist yet --
the trust root is meant to be published out-of-band, never embedded in this
repo (a compromised release could otherwise ship a forged key next to a
forged signature). It only asserts the *procedure* is documented.

Usage: check_release_docs.py <path-to-publishing.md>
"""
import sys

REQUIRED_SUBSTRINGS = [
    "checksums.txt.minisig",
    "fingerprint",
    "out-of-band",
    "minisign -V",
    "signed platform archive",
    "source-archive",
]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_release_docs.py <path>", file=sys.stderr)
        return 2
    path = argv[1]
    text = open(path, encoding="utf-8").read()

    missing = [s for s in REQUIRED_SUBSTRINGS if s not in text]
    if missing:
        print(
            f"check_release_docs: FAIL -- {path} is missing required minisign "
            f"verification guidance: {missing}. An operator with only "
            "checksums.txt.minisig and no documented way to obtain/verify the "
            "matching public key fingerprint cannot actually verify a release.",
            file=sys.stderr,
        )
        return 1

    print(f"check_release_docs: OK -- {path} documents minisign verification and fingerprint sourcing", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
