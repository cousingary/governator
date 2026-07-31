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

v16 R3: a second mode covers SECURITY.md, the file GitHub surfaces in the
security tab -- the first thing a researcher opens. It went stale by roughly
nineteen release-candidate-cycles' worth of work (High 11 fixed in
`docs/security.md`, still described as open in `SECURITY.md`) because no
checker ever looked at it. This mode asserts SECURITY.md links to the real
register/containment docs, and -- the durable half -- that no finding
`docs/security.md` records as fixed (a table row with a backtick commit
hash) is described as open anywhere in SECURITY.md. It is a contradiction
assertion, not a fact checker: it does not know which of the two documents
is correct, only that they must not disagree.

Usage:
  check_release_docs.py <path-to-publishing.md>
  check_release_docs.py <path-to-SECURITY.md> <path-to-docs/security.md>
"""
import re
import sys

REQUIRED_SUBSTRINGS = [
    "checksums.txt.minisig",
    "fingerprint",
    "out-of-band",
    "minisign -V",
    "signed platform archive",
    "source-archive",
]

SECURITY_REQUIRED_SUBSTRINGS = [
    "docs/security.md",
    "docs/containment.md",
]

# Table rows in docs/security.md's Critical/High registers look like:
#   | High 11 | <description> | `629cb62` (S3/S6 follow-up) | <tests> |
# A row with a backtick commit hash in the fix-commit column is a finding
# the register considers fixed.
FIXED_FINDING_ROW = re.compile(
    r"^\|\s*(Critical|High)\s+(\d+)\s*\|.*?\|\s*`[0-9a-f]{7,40}`", re.MULTILINE
)

OPEN_MARKERS = (
    "remains open",
    "still open",
    "currently open",
    "is open",
    "not fixed",
    "not yet fixed",
    "unresolved",
    "unpatched",
)


def _fixed_finding_labels(register_text: str) -> set[str]:
    return {f"{m.group(1)} {m.group(2)}" for m in FIXED_FINDING_ROW.finditer(register_text)}


def _contradicting_labels(security_text: str, fixed_labels: set[str]) -> list[str]:
    sentences = re.split(r"(?<=[.:])\s+", security_text)
    contradictions = []
    for label in sorted(fixed_labels):
        # \b on both ends so "High 1" cannot match inside "High 11".
        label_re = re.compile(r"\b" + re.escape(label) + r"\b")
        for sentence in sentences:
            if label_re.search(sentence) and any(marker in sentence.lower() for marker in OPEN_MARKERS):
                contradictions.append(label)
                break
    return contradictions


def check_publishing(path: str) -> int:
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


def check_security(security_path: str, register_path: str) -> int:
    security_text = open(security_path, encoding="utf-8").read()
    register_text = open(register_path, encoding="utf-8").read()

    missing = [s for s in SECURITY_REQUIRED_SUBSTRINGS if s not in security_text]
    if missing:
        print(
            f"check_release_docs: FAIL -- {security_path} is missing required "
            f"references to the finding register/containment docs: {missing}.",
            file=sys.stderr,
        )
        return 1

    fixed_labels = _fixed_finding_labels(register_text)
    contradictions = _contradicting_labels(security_text, fixed_labels)
    if contradictions:
        print(
            f"check_release_docs: FAIL -- {security_path} describes "
            f"{contradictions} as open, but {register_path} records "
            f"each with a fix commit. A file GitHub surfaces as the security "
            f"contact point must never advertise an already-fixed vulnerability "
            f"as live.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check_release_docs: OK -- {security_path} agrees with {register_path} "
        f"on every finding's status ({len(fixed_labels)} fixed findings checked)",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 2:
        return check_publishing(argv[1])
    elif len(argv) == 3:
        return check_security(argv[1], argv[2])
    else:
        print(
            "usage: check_release_docs.py <publishing.md> | "
            "check_release_docs.py <SECURITY.md> <docs/security.md>",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
