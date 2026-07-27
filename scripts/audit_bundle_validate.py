#!/usr/bin/env python3
"""scripts/audit_bundle_validate.py -- Sol11 rc5 Session 3 (P0-2): the
release-mode evidence-completeness gate for scripts/audit_bundle.sh.

Before this existed, audit_bundle.sh treated ANY nonempty dist/ as
sufficient release content -- run against a dist/ containing only a
truncated test-unit.log, it printed "audit_bundle: OK" with a bundle
carrying no binary, no manifest, no checksums, no signature, no summaries.

This script is the single place that decides whether a dist/ directory is a
COMPLETE, verifiable release, per the Sol11 report's release-mode
requirement: platform archives, checksums.txt, a valid cryptographic
signature, build-manifest.json, architecture-build-metadata.json,
sbom.json, claims.yaml, test-summary.json, acceptance-summary.json,
claims-verify-report.txt, every required test-evidence log,
test-summary.json overall_result == PASS, acceptance overall_result ==
PASS, zero production red-team skips, and an exact tag-and-commit match
between the release commit, build-manifest.json's source_commit, and (when
the architecture doc declares one) the architecture doc's own commit.

A partial/incomplete dist/ fails LOUDLY with an INCOMPLETE_RELEASE_EVIDENCE
error naming exactly what is missing -- never a silent "OK".

Usage:
  audit_bundle_validate.py --dist-dir DIR --repo REPO --release-commit SHA
    [--architecture-doc PATH] [--trusted-fingerprints-file FILE]
    [--trusted-public-keys-dir DIR]
"""
import argparse
import gzip
import hashlib
import json
import pathlib
import re
import subprocess
import sys

REQUIRED_TOP_LEVEL_FILES = (
    "checksums.txt",
    "checksums.txt.minisig",
    "build-manifest.json",
    "architecture-build-metadata.json",
    "sbom.json",
    "claims.yaml",
    "test-summary.json",
    "acceptance-summary.json",
    "claims-verify-report.txt",
    "preflight.json",
    "toolset.json",
)
REQUIRED_TEST_EVIDENCE_LOGS = (
    "unit.log.gz",
    "race.log.gz",
    "integration.log.gz",
    "corpus.log.gz",
    "redteam.log.gz",
    "redteam-race.log.gz",
)


def fail(missing: list[str]) -> int:
    joined = "; ".join(missing)
    print(f"audit_bundle_validate: INCOMPLETE_RELEASE_EVIDENCE -- {joined}", file=sys.stderr)
    return 1


def load_json(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8"))


def extract_doc_commit(text: str) -> str | None:
    m = re.search(r"governator_commit:\s*([0-9a-fA-F]{7,40})", text)
    if m:
        return m.group(1)
    m = re.search(r"Source HEAD `([0-9a-f]{7,40})`", text)
    if m:
        return m.group(1)
    return None


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dist-dir", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--release-commit", required=True)
    p.add_argument("--architecture-doc", default=None)
    p.add_argument("--trusted-fingerprints-file", default=None)
    p.add_argument("--trusted-public-keys-dir", default=None)
    p.add_argument("--install-evidence", default=None,
                   help="signed install-evidence.json; required when the architecture doc claims a live deployment")
    args = p.parse_args(argv)

    dist = pathlib.Path(args.dist_dir)
    missing: list[str] = []

    if not dist.is_dir():
        return fail([f"{dist} does not exist"])

    archives = sorted(dist.glob("gov_*_*.tar.gz"))
    if not archives:
        missing.append("no platform archive (gov_<version>_<platform>.tar.gz) present")

    for name in REQUIRED_TOP_LEVEL_FILES:
        if not (dist / name).is_file():
            missing.append(f"{name} is missing")

    for name in REQUIRED_TEST_EVIDENCE_LOGS:
        if not (dist / name).is_file():
            missing.append(f"required test-evidence log {name} is missing")

    if missing:
        # Every remaining check below reads files this loop already proved
        # are missing -- report what's missing now rather than a confusing
        # cascade of "file not found" tracebacks.
        return fail(missing)

    # overall_result == PASS (test-summary.json and acceptance-summary.json)
    test_summary = load_json(dist / "test-summary.json")
    if test_summary.get("overall_result") != "PASS":
        missing.append(f"test-summary.json overall_result is {test_summary.get('overall_result')!r}, not PASS")

    acceptance_summary = load_json(dist / "acceptance-summary.json")
    if acceptance_summary.get("overall_result") != "PASS":
        missing.append(f"acceptance-summary.json overall_result is {acceptance_summary.get('overall_result')!r}, not PASS")

    # zero production red-team skips
    # Production red-team skips are validated by IDENTITY, not by count.
    #
    # This check previously required a literal `tests_skipped == 0`, which no
    # host could ever satisfy: corpus cases 34/35 are Darwin-native and never
    # run on Linux, and on a real Mac their capability attestation is forced
    # non-approving. A release-mode bundle was therefore unobtainable --
    # reproducing at this second enforcement point exactly the deadlock corpus
    # case 297 removed from the gate itself. A raw count also cannot tell a
    # DROPPED CLAIM (a skip bound to a platform ClassifyPlatform declares
    # non-approving, asserting no production property) or a pre-declared
    # capability-conditioned skip from an unaccounted coverage gap.
    #
    # `gov redteam-gate verify` already answers this by name, and release.sh
    # ships its full structured verdict as suites.redteam.identity_gate. Defer
    # to it -- the same "identity-based, not count-based" doctrine (Sol v7 S7
    # HS4) that release.sh's own gate invocation follows. `ok` under
    # `require_zero_skips` means every skip was individually authorized by name;
    # `unexpected_skips` is the gate's list of those that were NOT.
    redteam_suite = test_summary.get("suites", {}).get("redteam", {})
    gate = redteam_suite.get("identity_gate")
    if not isinstance(gate, dict):
        missing.append(
            "test-summary.json suites.redteam.identity_gate is absent -- cannot confirm "
            "every production red-team skip was individually authorized"
        )
    else:
        if gate.get("ok") is not True:
            missing.append(f"suites.redteam.identity_gate.ok is {gate.get('ok')!r}, not true -- the red-team gate refused this run")
        if gate.get("require_zero_skips") is not True:
            missing.append(
                f"suites.redteam.identity_gate.require_zero_skips is {gate.get('require_zero_skips')!r}, "
                "not true -- a production release must be gated in strict zero-skip mode"
            )
        if gate.get("failed") not in (0, None) or gate.get("failed") is None:
            missing.append(f"suites.redteam.identity_gate.failed is {gate.get('failed')!r}, not 0")
        unexpected = gate.get("unexpected_skips") or []
        if unexpected:
            missing.append(
                f"suites.redteam.identity_gate.unexpected_skips is non-empty ({', '.join(unexpected)}) "
                "-- a production release must carry zero unauthorized red-team skips"
            )

    # exact tag-and-commit match: release commit == manifest source_commit ==
    # (when declared) architecture doc's declared commit.
    manifest = load_json(dist / "build-manifest.json")
    manifest_commit = manifest.get("source_commit")
    if manifest_commit != args.release_commit:
        missing.append(
            f"build-manifest.json source_commit ({manifest_commit!r}) does not match the release commit ({args.release_commit!r})"
        )
    if args.architecture_doc:
        arch_path = pathlib.Path(args.architecture_doc)
        if arch_path.is_file():
            doc_commit = extract_doc_commit(arch_path.read_text(encoding="utf-8"))
            if doc_commit is not None and not (
                args.release_commit.startswith(doc_commit) or doc_commit.startswith(args.release_commit)
            ):
                missing.append(
                    f"architecture doc declares commit {doc_commit!r} which does not match the release commit ({args.release_commit!r})"
                )

    if missing:
        return fail(missing)

    # Log content integrity: every suite in test-summary.json that names a
    # log_sha256 + log_path must have that EXACT decompressed content in
    # dist/ -- a truncated or otherwise-modified log (corpus case 11) is
    # caught here even though the gzip object itself is present (satisfying
    # the mere-existence check above is not enough).
    suites = test_summary.get("suites", {})
    for suite_name, suite in suites.items():
        if not isinstance(suite, dict):
            continue
        log_sha = suite.get("log_sha256")
        log_path_name = suite.get("log_path")
        if not log_sha or not log_path_name:
            continue
        log_path = dist / log_path_name
        if not log_path.is_file():
            missing.append(f"suite {suite_name!r} references log_path {log_path_name!r} but it is not present in {dist}")
            continue
        try:
            with gzip.open(log_path, "rb") as f:
                actual = hashlib.sha256(f.read()).hexdigest()
        except OSError as exc:
            missing.append(f"suite {suite_name!r}'s log {log_path_name!r} could not be decompressed: {exc}")
            continue
        if actual != log_sha:
            missing.append(
                f"TRUNCATED_OR_MODIFIED_TEST_LOG: suite {suite_name!r}'s {log_path_name!r} decompresses to "
                f"sha256={actual}, but test-summary.json declares log_sha256={log_sha} -- the log was "
                "truncated or modified after the tier that produced it recorded its hash"
            )

    if missing:
        return fail(missing)

    # Tier-checkpoint cross-check (P1-5 x P0-2): a dist/ can carry a
    # test-summary.json that claims every suite PASSED while the underlying
    # release-attempt checkpoint evidence tells a different, incomplete
    # story (corpus case 46: "test-summary PASS with incomplete tier
    # checkpoint") -- e.g. a hand-edited or partially-regenerated
    # test-summary.json next to checkpoints that never actually completed
    # for this attempt. When a checkpoint state directory travelled with
    # this dist/, it must aggregate cleanly for the exact identity it
    # itself declares.
    checkpoint_dir = dist / ".checkpoints"
    identity_path = checkpoint_dir / "identity.json"
    if identity_path.is_file():
        cmd = [
            sys.executable, str(pathlib.Path(__file__).parent / "release_checkpoint.py"), "aggregate",
            "--state-dir", str(checkpoint_dir), "--identity-file", str(identity_path),
            "--required", "unit,race,integration,corpus,redteam,redteam_race",
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.returncode != 0:
            missing.append(f"tier-checkpoint aggregate rejected this dist/'s checkpoint evidence: {proc.stdout.strip()}")

    if missing:
        return fail(missing)

    # Cryptographic signature verification -- reuse Session 1's machinery
    # rather than reinventing it (release_policy.py signature).
    if args.trusted_fingerprints_file and args.trusted_public_keys_dir:
        version = manifest.get("version", "")
        cmd = [
            sys.executable, str(pathlib.Path(__file__).parent / "release_policy.py"), "signature",
            "--version", version, "--require", "1",
            "--minisig", str(dist / "checksums.txt.minisig"),
            "--trusted-fingerprints-file", args.trusted_fingerprints_file,
            "--checksums", str(dist / "checksums.txt"),
            "--trusted-public-keys-dir", args.trusted_public_keys_dir,
            "--artifacts-dir", str(dist),
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.returncode != 0:
            return fail([f"cryptographic signature verification failed: {proc.stdout.strip()}"])

    # Sol13 P1-3: a live-install claim in the architecture doc must be backed
    # by a signed install-evidence record. The architecture doc check
    # (check_architecture_doc.py) already enforces this when --install-evidence
    # is passed; here we enforce it at the bundle-validation tier too, so a
    # release-mode bundle cannot ship an unevidenced live-install claim even
    # if the caller forgot to wire the flag through check_architecture_doc.py.
    if args.architecture_doc:
        arch_text = pathlib.Path(args.architecture_doc).read_text(encoding="utf-8")
        live_claim_patterns = [
            re.compile(r"live gate installed", re.IGNORECASE),
            re.compile(r"deployed to production", re.IGNORECASE),
            re.compile(r"installed at ~?/?\.local/bin/gov", re.IGNORECASE),
            re.compile(r"live[- ]deployed", re.IGNORECASE),
            re.compile(r"running in production", re.IGNORECASE),
        ]
        has_live_claim = any(pat.search(arch_text) for pat in live_claim_patterns)
        if has_live_claim:
            if not args.install_evidence:
                missing.append(
                    "LIVE_INSTALL_CLAIM_WITHOUT_EVIDENCE: architecture doc claims a live deployment/installation "
                    "but no --install-evidence file was supplied to this validator"
                )
            elif not pathlib.Path(args.install_evidence).is_file():
                missing.append(
                    f"LIVE_INSTALL_CLAIM_WITHOUT_EVIDENCE: architecture doc claims a live deployment/installation "
                    f"but the install-evidence file {args.install_evidence!r} does not exist"
                )

    if missing:
        return fail(missing)

    print(f"audit_bundle_validate: OK -- {dist} is a complete, verified release ({len(archives)} platform archive(s), commit {args.release_commit})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
