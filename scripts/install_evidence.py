#!/usr/bin/env python3
"""scripts/install_evidence.py — Sol13 P1-3 / P2: signed installation-evidence
record with a real four-check hook canary.

Before this script existed, the live gate reported a version string but nothing
bound the installed binary to the release binary, nothing recorded the hook
configuration, and the architecture document could contradict itself about
what was actually installed. This script produces a cryptographically signed,
machine-verifiable installation record that closes that gap.

The evidence record carries (Sol13 report's exact shape):
  installed_path, installed_sha256, installed_mode, source_archive,
  source_archive_sha256, version, source_commit, dirty,
  hook_configuration_path, hook_command, hook_configuration_sha256,
  installed_at, installer_identity, release_manifest_sha256, signature

Sol14 P2: source_archive and source_archive_sha256 bind the installed binary
to the exact signed platform tarball it was extracted from. Installation from
the loose file in the outer ZIP is rejected: the outer ZIP flattens executable
mode, and only the signed platform archive preserves 0755 and is covered by
checksums.txt and its minisign signature.

Signing uses the same Ed25519 scheme as the S2 capability attestations:
the signature covers the canonical sorted-key JSON of every field except
`signature` itself. The signing key ID is `ed25519:<hex(sha256(pubkey))>`.

The four-check hook canary runs at generate time and its results are embedded
in the record. Installation fails (exit 1) if any check fails:
  (a) benign action allows
  (b) protected-path action denies (against a manifest the canary seeds itself
      via GOV_PROTECTED_PATHS, plus a negative bound proving it is not denying
      everything -- the operator's own protected-path list is legitimately
      empty on a host that has not needed one, and testing it would test
      configuration rather than the gate)
  (c) malformed apply_patch denies
  (d) installed binary hash equals the release binary hash for THIS platform

Allow/deny is read from the hook's stdout JSON
(`hookSpecificOutput.permissionDecision`), never from its exit code: a
well-formed PreToolUse hook exits 0 whatever it decides, and an allow emits no
payload at all.

Usage:
  install_evidence.py generate \
    --installed-path PATH --release-manifest PATH \
    --hook-config PATH --signing-key HEXKEY \
    --source-archive PATH \
    [--installer-identity ID] [--out PATH]

  install_evidence.py verify \
    --evidence PATH --release-manifest PATH \
    --trusted-public-key HEXKEY

Exit 0 on success. Exit 1 with a diagnostic on any failure.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import platform
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

CANARY_FIELDS = (
    "canary_benign_allows",
    "canary_protected_denies",
    "canary_malformed_patch_denies",
    "canary_binary_hash_matches",
)

PLATFORM_ARCHIVE_PATTERN = re.compile(r"^gov_.+_.+\.tar\.gz$")


def current_platform_id() -> str:
    """Host platform in the release's `<goos>_<goarch>` form (e.g. linux_amd64)."""
    goos = {"linux": "linux", "darwin": "darwin"}.get(platform.system().lower(), platform.system().lower())
    machine = platform.machine().lower()
    goarch = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
    }.get(machine, machine)
    return f"{goos}_{goarch}"


def sha256_file(path: str) -> str:
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def canonical_payload(record: dict) -> bytes:
    payload = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def signing_key_id(public_key_bytes: bytes) -> str:
    return "ed25519:" + hashlib.sha256(public_key_bytes).hexdigest()


def sign_record(record: dict, private_key_hex: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_bytes = bytes.fromhex(private_key_hex.strip())
    if len(key_bytes) == 64:
        key_bytes = key_bytes[:32]
    if len(key_bytes) != 32:
        raise ValueError(f"expected a 32-byte (or 64-byte Go-format) hex Ed25519 private key, got {len(key_bytes)} bytes")
    private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    message = canonical_payload(record)
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode()


def verify_record(record: dict, public_key_hex: str) -> tuple[bool, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    key_bytes = bytes.fromhex(public_key_hex.strip())
    if len(key_bytes) != 32:
        return False, f"expected a 32-byte hex Ed25519 public key, got {len(key_bytes)} bytes"
    public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
    signature_b64 = record.get("signature", "")
    if not signature_b64:
        return False, "INSTALL_EVIDENCE_UNSIGNED: evidence record carries no signature"
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        return False, f"INSTALL_EVIDENCE_BAD_SIGNATURE_ENCODING: {exc}"
    message = canonical_payload(record)
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False, "INSTALL_EVIDENCE_INVALID_SIGNATURE: signature does not verify against the trusted public key"
    expected_kid = signing_key_id(key_bytes)
    if record.get("signing_key_id") != expected_kid:
        return False, (
            f"INSTALL_EVIDENCE_SIGNER_MISMATCH: evidence signing_key_id is {record.get('signing_key_id')!r} "
            f"but the trusted key's identity is {expected_kid!r}"
        )
    return True, ""


def hook_decision(gov_bin: str, env: dict, payload: dict) -> str:
    """Run one PreToolUse hook invocation and return its permission decision.

    The decision is carried in the hook's stdout JSON, NEVER in its exit code:
    internal/runtime/gate.go's EmitHookJSON unconditionally `return 0`, because
    the PreToolUse protocol expects a well-formed hook to exit 0 and express
    allow/deny in `hookSpecificOutput.permissionDecision`. An allow emits no
    payload at all. Earlier revisions of this canary asserted `returncode != 0`
    for the two deny checks, which could therefore never pass on any host
    regardless of gate behavior -- this script had never been run end to end
    against a real release until rc6 Session 9.
    """
    proc = subprocess.run(
        [gov_bin, "hook", "pre-tool-use"],
        input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=30,
    )
    if proc.returncode != 0:
        return "error"
    out = proc.stdout.strip()
    if not out:
        return "allow"
    try:
        decision = json.loads(out)
    except json.JSONDecodeError:
        return "error"
    return decision.get("hookSpecificOutput", {}).get("permissionDecision", "allow")


def run_hook_canary(gov_bin: str, hook_config: str) -> dict:
    results = {}
    env = dict(os.environ)
    env["GOV_HOOK_CONFIG"] = hook_config

    results["canary_benign_allows"] = hook_decision(gov_bin, env, {
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/benign-read-target.txt"},
    }) == "allow"

    # The protected-path canary seeds its OWN manifest via GOV_PROTECTED_PATHS
    # rather than assuming the operator's list contains any particular entry.
    # Protected paths are operator configuration and are legitimately empty on
    # a host that has not needed one yet; asserting that e.g. /etc/passwd is
    # protected tested the operator's config, not the gate. Seeding a pattern
    # proves the enforcement mechanism itself on every host, and the negative
    # bound below proves the canary is not simply denying everything.
    with tempfile.TemporaryDirectory(prefix="gov-install-canary-") as tmp:
        tmp_path = pathlib.Path(tmp)
        guarded = tmp_path / "guarded"
        guarded.mkdir()
        manifest = tmp_path / "protected_paths.txt"
        manifest.write_text(f"{guarded}/**\n")
        canary_env = dict(env)
        canary_env["GOV_PROTECTED_PATHS"] = str(manifest)
        canary_env.pop("HARNESS_UNLOCK", None)  # an unlock would void the check

        denied = hook_decision(gov_bin, canary_env, {
            "tool_name": "Write",
            "tool_input": {"file_path": str(guarded / "secret.txt"), "content": "pwned"},
        })
        allowed = hook_decision(gov_bin, canary_env, {
            "tool_name": "Write",
            "tool_input": {"file_path": str(tmp_path / "unguarded.txt"), "content": "ok"},
        })
        results["canary_protected_denies"] = denied == "deny" and allowed == "allow"

    results["canary_malformed_patch_denies"] = hook_decision(gov_bin, env, {
        "tool_name": "apply_patch",
        "tool_input": {"patch": "not a valid patch\x00\x01\x02"},
    }) == "deny"

    return results


def cmd_generate(args: argparse.Namespace) -> int:
    installed_path = pathlib.Path(args.installed_path)
    if not installed_path.is_file():
        print(f"install_evidence: installed binary not found at {installed_path}", file=sys.stderr)
        return 1

    installed_sha256 = sha256_file(str(installed_path))
    installed_mode = oct(stat.S_IMODE(installed_path.stat().st_mode))

    release_manifest = pathlib.Path(args.release_manifest)
    if not release_manifest.is_file():
        print(f"install_evidence: release manifest not found at {release_manifest}", file=sys.stderr)
        return 1
    release_manifest_sha256 = sha256_file(str(release_manifest))

    try:
        manifest = json.loads(release_manifest.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"install_evidence: cannot parse release manifest: {exc}", file=sys.stderr)
        return 1

    version = manifest.get("version", "")
    source_commit = manifest.get("source_commit", "")
    dirty = manifest.get("dirty", False)

    # Resolve the release binary hash for THIS host's platform. build-manifest
    # artifact entries are keyed by `platform` and carry `binary_sha256` /
    # `extracted_binary_sha256`; they have no `name` field. The previous lookup
    # matched on artifact["name"] and fell back to a checksums.txt line ending
    # in "/gov" -- the entry is the bare name "gov", so neither ever matched and
    # release_binary_sha256 was always None, hard-failing canary_binary_hash_matches
    # even when every hash agreed. Never executed until rc6 Session 9.
    release_binary_sha256 = None
    host_platform = current_platform_id()
    for artifact in manifest.get("artifacts", []):
        if artifact.get("platform") == host_platform:
            release_binary_sha256 = (
                artifact.get("binary_sha256")
                or artifact.get("extracted_binary_sha256")
                or artifact.get("sha256")
            )
            break
    if release_binary_sha256 is None:
        checksums_path = release_manifest.parent / "checksums.txt"
        if checksums_path.is_file():
            for line in checksums_path.read_text().splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1].rstrip("*").rsplit("/", 1)[-1] == "gov":
                    release_binary_sha256 = parts[0]
                    break
    if release_binary_sha256 is None:
        print(
            f"install_evidence: RELEASE_BINARY_HASH_UNRESOLVED: no artifact for platform "
            f"{host_platform!r} in {release_manifest} and no bare 'gov' entry in checksums.txt",
            file=sys.stderr,
        )
        return 1

    hook_config_path = pathlib.Path(args.hook_config)
    if not hook_config_path.is_file():
        print(f"install_evidence: hook configuration not found at {hook_config_path}", file=sys.stderr)
        return 1
    hook_config_sha256 = sha256_file(str(hook_config_path))
    hook_command = "gov hook pre-tool-use"

    if installed_mode != "0o755":
        print(
            f"install_evidence: WRONG_BINARY_MODE: installed binary mode is {installed_mode}, "
            "expected 0o755 (release tarballs preserve 0755; the outer source ZIP flattens it -- "
            "install from the tarball, not the ZIP)",
            file=sys.stderr,
        )
        return 1

    source_archive = pathlib.Path(args.source_archive)
    if not source_archive.is_file():
        print(f"install_evidence: SOURCE_ARCHIVE_NOT_FOUND: {source_archive}", file=sys.stderr)
        return 1
    archive_name = source_archive.name
    if not PLATFORM_ARCHIVE_PATTERN.match(archive_name):
        print(
            f"install_evidence: LOOSE_FILE_INSTALL_REJECTED: source archive {archive_name!r} does not match "
            "the signed platform archive pattern gov_<version>_<platform>.tar.gz -- installation must use "
            "a signed platform tarball, never the loose binary from the outer ZIP",
            file=sys.stderr,
        )
        return 1
    source_archive_sha256 = sha256_file(str(source_archive))

    canary = run_hook_canary(str(installed_path), str(hook_config_path))

    if release_binary_sha256 is not None:
        canary["canary_binary_hash_matches"] = installed_sha256 == release_binary_sha256
    else:
        canary["canary_binary_hash_matches"] = False

    failures = [k for k in CANARY_FIELDS if not canary.get(k)]
    if failures:
        print(f"install_evidence: hook canary FAILED: {failures}", file=sys.stderr)
        return 1

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_bytes = bytes.fromhex(args.signing_key.strip())
    if len(key_bytes) == 64:
        key_bytes = key_bytes[:32]
    private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    public_key = private_key.public_key()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = signing_key_id(pub_bytes)

    record = {
        "installed_path": str(installed_path),
        "installed_sha256": installed_sha256,
        "installed_mode": installed_mode,
        "source_archive": archive_name,
        "source_archive_sha256": source_archive_sha256,
        "version": version,
        "source_commit": source_commit,
        "dirty": dirty,
        "hook_configuration_path": str(hook_config_path),
        "hook_command": hook_command,
        "hook_configuration_sha256": hook_config_sha256,
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "installer_identity": args.installer_identity or os.environ.get("USER", "unknown"),
        "release_manifest_sha256": release_manifest_sha256,
        "signing_key_id": kid,
    }
    record.update(canary)
    record["signature"] = sign_record(record, args.signing_key)

    out_path = args.out or str(installed_path.parent / "install-evidence.json")
    pathlib.Path(out_path).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"install_evidence: OK -- signed evidence written to {out_path}", file=sys.stderr)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    evidence_path = pathlib.Path(args.evidence)
    if not evidence_path.is_file():
        print(f"install_evidence: LIVE_INSTALL_CLAIM_WITHOUT_EVIDENCE: {evidence_path} does not exist", file=sys.stderr)
        return 1

    try:
        record = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"install_evidence: cannot parse evidence: {exc}", file=sys.stderr)
        return 1

    ok, msg = verify_record(record, args.trusted_public_key)
    if not ok:
        print(f"install_evidence: {msg}", file=sys.stderr)
        return 1

    required = ("installed_path", "installed_sha256", "installed_mode", "source_archive", "source_archive_sha256", "hook_configuration_path", "hook_configuration_sha256", "release_manifest_sha256", "signing_key_id", *CANARY_FIELDS)
    absent = [field for field in required if record.get(field) in (None, "")]
    if absent:
        print(f"install_evidence: INSTALL_EVIDENCE_MISSING_FIELDS: {', '.join(absent)}", file=sys.stderr)
        return 1

    source_archive = record["source_archive"]
    if not PLATFORM_ARCHIVE_PATTERN.match(source_archive):
        print(
            f"install_evidence: LOOSE_FILE_INSTALL_REJECTED: source_archive {source_archive!r} does not match "
            "the signed platform archive pattern gov_<version>_<platform>.tar.gz -- installation must use "
            "a signed platform tarball, never the loose binary from the outer ZIP",
            file=sys.stderr,
        )
        return 1

    release_manifest = pathlib.Path(args.release_manifest)
    if release_manifest.is_file():
        actual_manifest_sha = sha256_file(str(release_manifest))
        if record.get("release_manifest_sha256") != actual_manifest_sha:
            print(
                f"install_evidence: RELEASE_MANIFEST_MISMATCH: evidence records release_manifest_sha256="
                f"{record.get('release_manifest_sha256')!r} but the supplied manifest hashes to {actual_manifest_sha}",
                file=sys.stderr,
            )
            return 1

    installed_path = record["installed_path"]
    if not pathlib.Path(installed_path).is_file():
        print(f"install_evidence: INSTALLED_BINARY_UNAVAILABLE: {installed_path}", file=sys.stderr)
        return 1
    else:
        actual_sha = sha256_file(installed_path)
        if record.get("installed_sha256") != actual_sha:
            print(
                f"install_evidence: INSTALLED_BINARY_CHANGED: evidence records installed_sha256="
                f"{record.get('installed_sha256')!r} but the binary at {installed_path} now hashes to {actual_sha}",
                file=sys.stderr,
            )
            return 1
        actual_mode = oct(stat.S_IMODE(pathlib.Path(installed_path).stat().st_mode))
        if record.get("installed_mode") != actual_mode:
            print(
                f"install_evidence: INSTALLED_BINARY_MODE_CHANGED: evidence records mode "
                f"{record.get('installed_mode')!r} but the binary now has mode {actual_mode}",
                file=sys.stderr,
            )
            return 1

    hook_config_path = record["hook_configuration_path"]
    if not pathlib.Path(hook_config_path).is_file():
        print(f"install_evidence: HOOK_CONFIGURATION_UNAVAILABLE: {hook_config_path}", file=sys.stderr)
        return 1
    else:
        actual_hook_sha = sha256_file(hook_config_path)
        if record.get("hook_configuration_sha256") != actual_hook_sha:
            print(
                f"install_evidence: HOOK_CONFIGURATION_CHANGED: evidence records hook_configuration_sha256="
                f"{record.get('hook_configuration_sha256')!r} but {hook_config_path} now hashes to {actual_hook_sha}",
                file=sys.stderr,
            )
            return 1

    for field in CANARY_FIELDS:
        if not record.get(field):
            print(f"install_evidence: CANARY_CHECK_FAILED: {field} is not true in the evidence record", file=sys.stderr)
            return 1

    if args.rerun_canaries:
        actual = run_hook_canary(installed_path, hook_config_path)
        actual["canary_binary_hash_matches"] = record["installed_sha256"] == sha256_file(installed_path)
        failed = [field for field in CANARY_FIELDS if actual.get(field) is not True]
        if failed:
            print(f"install_evidence: REPRODUCED_CANARY_FAILED: {', '.join(failed)}", file=sys.stderr)
            return 1

    print(f"install_evidence: OK -- {evidence_path} verifies (version={record.get('version')}, commit={record.get('source_commit')})", file=sys.stderr)
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Signed installation-evidence record (Sol13 P1-3)")
    sub = p.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="generate signed installation evidence")
    gen.add_argument("--installed-path", required=True, help="path to the installed gov binary")
    gen.add_argument("--release-manifest", required=True, help="path to build-manifest.json from the release")
    gen.add_argument("--hook-config", required=True, help="path to the hook configuration file")
    gen.add_argument("--signing-key", required=True, help="64-byte hex Ed25519 private key")
    gen.add_argument("--installer-identity", default=None, help="identity of the installer (defaults to $USER)")
    gen.add_argument("--source-archive", required=True,
                     help="path to the signed platform tarball (gov_<version>_<platform>.tar.gz) the binary was extracted from")
    gen.add_argument("--out", default=None, help="output path (defaults to <installed-dir>/install-evidence.json)")

    ver = sub.add_parser("verify", help="verify signed installation evidence")
    ver.add_argument("--evidence", required=True, help="path to install-evidence.json")
    ver.add_argument("--release-manifest", required=True, help="path to build-manifest.json to cross-check")
    ver.add_argument("--trusted-public-key", required=True, help="32-byte hex Ed25519 public key")
    ver.add_argument("--rerun-canaries", action="store_true", help="re-run hook canaries against the recorded installation")

    args = p.parse_args(argv)
    if args.command == "generate":
        return cmd_generate(args)
    return cmd_verify(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
