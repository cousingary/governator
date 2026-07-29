#!/usr/bin/env python3
"""Sol9 P2-3 / Sol11 P1-7: assert the architecture doc's own narrative is
internally consistent with reality.

Two doc styles are supported, because the terminal rc5 Session 9 rewrite
(converting the live doc to machine-readable front matter) has not happened
yet, but this validator must already be able to prove the FUTURE style's
five contradiction categories are caught:

  1. PROSE style (today's live doc): a "## Remediation history" section
     (present-tense current/outstanding build status, not a changelog) must
     not still name an older release as though it were current -- the
     original Sol9 check, unchanged. This deliberately does NOT scan the
     whole document: sections like "Non-goals" legitimately cite older
     version numbers as historical fact.

  2. FRONT MATTER style (target schema, Sol11 report):
         ---
         governator_commit: <sha>
         governator_tag: v1.0.2-rc5
         assayer_commit: <sha>
         assayer_tag: v1.1.3
         release_state: pending   # or "complete"
         artifact_manifest_sha256: null   # or the real hash once complete
         ---
     A doc carrying this block is validated against FIVE contradiction
     categories a prose-only check cannot express:
       (a) TAG_COMMIT_MISMATCH     -- governator_tag does not resolve (via
           `git rev-parse`/`git tag --points-at`, --repo) to governator_commit.
       (b) INCOMPLETE_RELEASE_EVIDENCE -- release_state: complete claimed
           without the release artifacts existing (--dist-dir).
       (c) MANIFEST_HASH_MISMATCH  -- artifact_manifest_sha256 does not
           match the actual build-manifest.json's sha256 (--dist-dir).
       (d) STALE_RELEASE_CLAIM     -- the same prose staleness check as (1),
           run against the front-matter doc's body too (a doc can carry
           BOTH front matter and a Remediation-history section).
       (e) Live-install evidence is deliberately enforced only by
           audit_bundle_validate.py from the machine-readable
           ``live_install_claim`` front-matter field. Prose has no effect on
           enforcement, so this document checker does not inspect it.

Front matter absent -> only category (1)/(d)'s prose check runs (today's
exact behavior, byte-for-byte). Front matter present -> categories (a)-(d)
all run, IN ADDITION to the prose check.

Usage: check_architecture_doc.py <path> [--repo DIR] [--dist-dir DIR]
Exit 0 if consistent. Exit 1 with a diagnostic (prefixed by the category
tag above) on the first contradiction found.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

VERSION_RE = re.compile(r"v\d+\.\d+\.\d+(?:-rc\d+)?")
CURRENT_STATE_SECTION_HEADING = "remediation history"
FRONT_MATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)


def parse_front_matter(text: str) -> dict | None:
    """A tiny, dependency-free parser for the FLAT key: value front matter
    this doc style uses -- no lists/nesting, so a real YAML library is not
    worth adding as a new dependency for this one release-identity block."""
    m = FRONT_MATTER_RE.match(text)
    if not m:
        return None
    fm: dict = {}
    for line in m.group(1).splitlines():
        line = line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if value.lower() == "null" or value == "":
            fm[key] = None
        elif value.lower() in ("true", "false"):
            fm[key] = value.lower() == "true"
        elif len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            fm[key] = value[1:-1]
        else:
            fm[key] = value
    return fm


def check_prose_staleness(text: str) -> tuple[bool, str]:
    """The original Sol9 P2-3 check, unchanged: Status header version vs
    the Remediation-history section's cited version(s)."""
    status_match = re.search(r"\*\*Status:\*\*.*?(" + VERSION_RE.pattern + r")", text)
    if not status_match:
        return True, "no **Status:** line with a version found (skipping prose staleness check)"
    status_version = status_match.group(1)

    sections = re.split(r"^## (.*)$", text, flags=re.MULTILINE)
    headings_and_bodies = list(zip(sections[1::2], sections[2::2]))
    target_body = None
    for heading, body in headings_and_bodies:
        if heading.strip().lower() == CURRENT_STATE_SECTION_HEADING:
            target_body = body
            break
    if target_body is None:
        return True, f"no '## {CURRENT_STATE_SECTION_HEADING}' section to check (Status {status_version})"

    stale_versions = sorted({v for v in VERSION_RE.findall(target_body) if v != status_version})
    if stale_versions:
        return False, (
            f"STALE_RELEASE_CLAIM: '## {CURRENT_STATE_SECTION_HEADING}' section names "
            f"{stale_versions} but the Status header declares {status_version}. "
            "That section describes present-tense current/outstanding state; a "
            "different version there implies the doc is stale even though the "
            "header is accurate."
        )
    return True, f"Status {status_version}, '{CURRENT_STATE_SECTION_HEADING}' section consistent"


def resolve_git_commit(repo: str, ref: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", repo, "rev-parse", f"{ref}^{{commit}}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def check_conflicting_current_commits(fm: dict, body: str) -> list[str]:
    """A doc can carry front matter's governator_commit AND a legacy prose
    'Source HEAD `<sha>`' declaration in the same body (exactly the
    transitional shape this session's validator must already handle, since
    the terminal front-matter conversion is Session 9's job, not this
    one). If both are present and name DIFFERENT commits, the doc
    contradicts itself about what "current" even means -- independent of
    whether either one matches git (that's TAG_COMMIT_MISMATCH's job)."""
    gov_commit = fm.get("governator_commit")
    if not gov_commit:
        return []
    m = re.search(r"Source HEAD `([0-9a-f]{7,40})`", body)
    if not m:
        return []
    prose_commit = m.group(1)
    if gov_commit.startswith(prose_commit) or prose_commit.startswith(gov_commit):
        return []
    return [
        f"CONFLICTING_CURRENT_COMMITS: front matter declares governator_commit {gov_commit!r} but the "
        f"document body separately declares 'Source HEAD `{prose_commit}`' -- the doc names two different "
        "commits as the current one"
    ]


def check_front_matter(fm: dict, repo: str | None, dist_dir: str | None) -> list[str]:
    failures: list[str] = []

    gov_commit = fm.get("governator_commit")
    gov_tag = fm.get("governator_tag")
    if repo and gov_commit and gov_tag:
        resolved = resolve_git_commit(repo, gov_tag)
        if resolved is None:
            failures.append(
                f"TAG_COMMIT_MISMATCH: governator_tag {gov_tag!r} does not resolve to any commit in {repo} "
                "(tag missing, or repo unreachable) -- cannot confirm it names governator_commit"
            )
        elif not resolved.startswith(gov_commit) and not gov_commit.startswith(resolved):
            failures.append(
                f"TAG_COMMIT_MISMATCH: governator_tag {gov_tag!r} resolves to commit {resolved}, "
                f"but the doc declares governator_commit {gov_commit!r} -- the tag and the declared "
                "commit disagree"
            )

    release_state = fm.get("release_state")
    manifest_path = pathlib.Path(dist_dir) / "build-manifest.json" if dist_dir else None
    manifest_exists = manifest_path is not None and manifest_path.is_file()
    if release_state == "complete":
        missing = []
        if not dist_dir:
            missing.append("--dist-dir was not provided")
        elif not manifest_exists:
            missing.append(f"{manifest_path} does not exist")
        else:
            checksums = pathlib.Path(dist_dir) / "checksums.txt"
            if not checksums.is_file():
                missing.append(f"{checksums} does not exist")
        if missing:
            failures.append(
                "INCOMPLETE_RELEASE_EVIDENCE: architecture doc declares release_state: complete, "
                f"but the release artifacts do not verify: {'; '.join(missing)}"
            )
        elif fm.get("artifact_manifest_sha256") in (None, ""):
            failures.append(
                "INCOMPLETE_RELEASE_EVIDENCE: architecture doc declares release_state: complete "
                "but artifact_manifest_sha256 is null -- a complete release must name the exact "
                "manifest it shipped"
            )

    declared_hash = fm.get("artifact_manifest_sha256")
    if declared_hash and manifest_exists:
        actual_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        if actual_hash != declared_hash:
            failures.append(
                f"MANIFEST_HASH_MISMATCH: architecture doc declares artifact_manifest_sha256={declared_hash}, "
                f"but the actual {manifest_path} hashes to {actual_hash}"
            )

    return failures


def check_front_matter_prose_contradiction(fm: dict, body: str) -> list[str]:
    """Sol13 P1-3: front matter and status prose must not disagree about
    tag/release/live-gate state. The architecture doc is the unreliable
    narrator -- hand-editing prose is not a durable fix; this check makes
    the contradiction a hard failure so it cannot ship."""
    failures: list[str] = []

    gov_tag = fm.get("governator_tag")
    if gov_tag:
        no_tag_patterns = [
            re.compile(r"[Nn]o\s+`?" + re.escape(gov_tag) + r"`?\s+git tag currently exists"),
            re.compile(r"front matter\s+`governator_tag:\s*null`"),
            re.compile(r"governator_tag:\s*null"),
        ]
        for pat in no_tag_patterns:
            if pat.search(body):
                failures.append(
                    f"FRONT_MATTER_PROSE_CONTRADICTION: front matter declares governator_tag: {gov_tag!r} "
                    f"but the document body claims no such tag exists (matched: {pat.pattern!r}). "
                    "The front matter is authoritative; the prose is stale and must be corrected."
                )
                break

    release_state = fm.get("release_state")
    if release_state == "complete":
        incomplete_patterns = [
            re.compile(r"[Nn]o\s+v?\d+\.\d+\.\d+(?:-rc\d+)?\s+(?:git\s+)?tag currently exists"),
            re.compile(r"release[_ ]state[:\s]+pending", re.IGNORECASE),
            re.compile(r"the tag is cut.*as the final step", re.IGNORECASE),
        ]
        for pat in incomplete_patterns:
            if pat.search(body):
                failures.append(
                    f"FRONT_MATTER_PROSE_CONTRADICTION: front matter declares release_state: complete "
                    f"but the document body describes the release as still pending (matched: {pat.pattern!r}). "
                    "The front matter is authoritative; the prose is stale and must be corrected."
                )
                break

    return failures


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("path")
    p.add_argument("--repo", default=None, help="repo root for tag/commit resolution (front-matter docs)")
    p.add_argument("--dist-dir", default=None, help="release dist/ dir for artifact-existence + manifest-hash checks (front-matter docs)")
    args = p.parse_args(argv)

    text = pathlib.Path(args.path).read_text(encoding="utf-8")

    failures: list[str] = []

    fm = parse_front_matter(text)
    if fm is not None:
        failures.extend(check_front_matter(fm, args.repo, args.dist_dir))
        failures.extend(check_conflicting_current_commits(fm, text))
        failures.extend(check_front_matter_prose_contradiction(fm, text))

    prose_ok, prose_msg = check_prose_staleness(text)
    if not prose_ok:
        failures.append(prose_msg)

    if failures:
        for f in failures:
            print(f"check_architecture_doc: FAIL -- {args.path}: {f}", file=sys.stderr)
        return 1

    style = "front-matter" if fm is not None else "prose"
    print(f"check_architecture_doc: OK -- {args.path} ({style} style; {prose_msg})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
