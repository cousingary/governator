#!/usr/bin/env python3
"""Sol9 P2-3: assert the architecture doc's own narrative is internally
consistent -- specifically, that its "Remediation history" section (the
section that describes PRESENT-tense current/outstanding build status, not
a changelog of what shipped when) does not still name an older release as
though it were current. This is exactly the defect the audit found: the
Status header correctly said v1.0.2-rc2, but the Remediation history
section's last sentence still said the only outstanding task was
reinstalling a v1.0.2-rc1 build. A stale current-state claim next to an
accurate header reads as though the header lied. This deliberately does NOT
scan the whole document: sections like "Non-goals" or "Acceptance evidence"
legitimately cite older version numbers as historical fact ("shipped in
v1.5.0"), and flagging those would be a false positive on accurate content.

Usage: check_architecture_doc.py <path-to-architecture.md>
Exit 0 if consistent, exit 1 with a diagnostic message if the Remediation
history section names a version that differs from the Status header.
"""
import re
import sys

VERSION_RE = re.compile(r"v\d+\.\d+\.\d+(?:-rc\d+)?")
CURRENT_STATE_SECTION_HEADING = "remediation history"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_architecture_doc.py <path>", file=sys.stderr)
        return 2
    path = argv[1]
    text = open(path, encoding="utf-8").read()

    status_match = re.search(r"\*\*Status:\*\*.*?(" + VERSION_RE.pattern + r")", text)
    if not status_match:
        print(f"check_architecture_doc: no **Status:** line with a version found in {path}", file=sys.stderr)
        return 1
    status_version = status_match.group(1)

    sections = re.split(r"^## (.*)$", text, flags=re.MULTILINE)
    # re.split with a capturing group interleaves: [preamble, heading1, body1, heading2, body2, ...]
    headings_and_bodies = list(zip(sections[1::2], sections[2::2]))
    target_body = None
    for heading, body in headings_and_bodies:
        if heading.strip().lower() == CURRENT_STATE_SECTION_HEADING:
            target_body = body
            break
    if target_body is None:
        print(f"check_architecture_doc: OK -- {path} has no '## {CURRENT_STATE_SECTION_HEADING}' section to check (Status {status_version})", file=sys.stderr)
        return 0

    stale_versions = sorted({v for v in VERSION_RE.findall(target_body) if v != status_version})
    if stale_versions:
        print(
            f"check_architecture_doc: FAIL -- {path}'s '## {CURRENT_STATE_SECTION_HEADING}' section names "
            f"{stale_versions} but the Status header declares {status_version}. "
            "That section describes present-tense current/outstanding state; a "
            "different version there implies the doc is stale even though the "
            "header is accurate. Update the section or explicitly mark the "
            "reference as historical (e.g. 'as of v1.0.2-rc1, since superseded').",
            file=sys.stderr,
        )
        return 1

    print(f"check_architecture_doc: OK -- {path} (Status {status_version}, '{CURRENT_STATE_SECTION_HEADING}' section consistent)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
