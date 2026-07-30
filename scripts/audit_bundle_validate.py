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

from install_evidence import CANARY_FIELDS, PLATFORM_ARCHIVE_PATTERN, sha256_file, verify_record

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
    "release-environment.json",
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


def validate_live_install(fm: dict, evidence_path: pathlib.Path | None, manifest_path: pathlib.Path) -> list[str]:
    """Validate the S8 front-matter claim without inspecting prose."""
    if fm.get("live_install_claim") is not True:
        return []
    failures: list[str] = []
    required_fm = ("installed_binary_sha256", "hook_configuration_sha256", "install_evidence_sha256", "install_evidence_signer")
    absent = [field for field in required_fm if not isinstance(fm.get(field), str) or not fm[field]]
    if absent:
        failures.append("LIVE_INSTALL_METADATA_INCOMPLETE: " + ", ".join(absent))
    if evidence_path is None:
        return failures + ["LIVE_INSTALL_CLAIM_WITHOUT_EVIDENCE: live_install_claim is true but no --install-evidence file was supplied"]
    if not evidence_path.is_file():
        return failures + [f"LIVE_INSTALL_CLAIM_WITHOUT_EVIDENCE: {evidence_path} does not exist"]
    try:
        evidence = load_json(evidence_path)
    except (OSError, json.JSONDecodeError) as exc:
        return failures + [f"INSTALL_EVIDENCE_UNREADABLE: {exc}"]
    if sha256_file(str(evidence_path)) != fm.get("install_evidence_sha256"):
        failures.append("INSTALL_EVIDENCE_HASH_MISMATCH: install evidence does not match architecture metadata")
    if evidence.get("installed_sha256") != fm.get("installed_binary_sha256"):
        failures.append("INSTALLED_BINARY_HASH_MISMATCH: evidence does not match architecture metadata")
    if evidence.get("hook_configuration_sha256") != fm.get("hook_configuration_sha256"):
        failures.append("HOOK_CONFIGURATION_HASH_MISMATCH: evidence does not match architecture metadata")
    signer = fm.get("install_evidence_signer", "")
    prefix = "ed25519-public-key:"
    if not isinstance(signer, str) or not signer.startswith(prefix):
        failures.append("INSTALL_EVIDENCE_SIGNER_UNUSABLE: install_evidence_signer must be ed25519-public-key:<hex>")
        public_key = None
    else:
        public_key = signer[len(prefix):]
        try:
            ok, message = verify_record(evidence, public_key)
        except ValueError as exc:
            ok, message = False, str(exc)
        if not ok:
            failures.append(message)
    required_record = ("installed_path", "installed_sha256", "installed_mode", "source_archive", "source_archive_sha256", "hook_configuration_path", "hook_configuration_sha256", "release_manifest_sha256", *CANARY_FIELDS)
    absent_record = [field for field in required_record if evidence.get(field) in (None, "")]
    if absent_record:
        failures.append("INSTALL_EVIDENCE_MISSING_FIELDS: " + ", ".join(absent_record))
    if evidence.get("installed_mode") != "0o755":
        failures.append("INSTALLED_BINARY_MODE_MISMATCH: installed mode must be 0o755")
    source_archive = evidence.get("source_archive", "")
    if source_archive and not PLATFORM_ARCHIVE_PATTERN.match(source_archive):
        failures.append(
            f"LOOSE_FILE_INSTALL_REJECTED: source_archive {source_archive!r} does not match "
            "the signed platform archive pattern gov_<version>_<platform>.tar.gz"
        )
    if source_archive and PLATFORM_ARCHIVE_PATTERN.match(source_archive):
        archive_path = manifest_path.parent / source_archive
        if not archive_path.is_file():
            failures.append(f"SOURCE_ARCHIVE_NOT_IN_DIST: {source_archive} is not present in the release dist/")
        elif evidence.get("source_archive_sha256") != sha256_file(str(archive_path)):
            failures.append("SOURCE_ARCHIVE_HASH_MISMATCH: install evidence is not bound to the shipped platform archive")
    if evidence.get("release_manifest_sha256") != sha256_file(str(manifest_path)):
        failures.append("RELEASE_MANIFEST_MISMATCH: install evidence is not bound to this build manifest")
    if not failures and public_key is not None:
        proc = subprocess.run([
            sys.executable, str(pathlib.Path(__file__).parent / "install_evidence.py"), "verify",
            "--evidence", str(evidence_path), "--release-manifest", str(manifest_path),
            "--trusted-public-key", public_key, "--rerun-canaries",
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.returncode != 0:
            failures.append(f"INSTALL_EVIDENCE_VERIFICATION_FAILED: {proc.stdout.strip()}")
    return failures


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

    # S8 intentionally ignores live-install prose. Only machine-readable
    # front matter can assert the claim.
    if args.architecture_doc:
        arch_text = pathlib.Path(args.architecture_doc).read_text(encoding="utf-8")
        from check_architecture_doc import parse_front_matter
        fm = parse_front_matter(arch_text) or {}
        missing.extend(validate_live_install(
            fm,
            pathlib.Path(args.install_evidence) if args.install_evidence else None,
            dist / "build-manifest.json",
        ))

    if missing:
        return fail(missing)

    print(f"audit_bundle_validate: OK -- {dist} is a complete, verified release ({len(archives)} platform archive(s), commit {args.release_commit})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
