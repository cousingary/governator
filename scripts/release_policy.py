#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys


def minisig_signer_fingerprint(minisig_path: pathlib.Path) -> str:
    """Extracts the signer's key ID from a minisign .minisig file, formatted
    as the same uppercase-hex fingerprint minisign prints in a public key's
    own comment line (e.g. "minisign public key 7B2C4B5C968E3A59").

    A minisign signature file's second line (the untrusted, non-comment
    line) base64-decodes to: 2 bytes algorithm ("Ed"/"ED") + 8 bytes key ID
    + 64 bytes Ed25519 signature. The key ID bytes are little-endian
    relative to the display fingerprint, so this reverses them -- verified
    against `minisign -G`'s own printed pubkey comment for a freshly
    generated test key pair (P1-5 red-team fixture uses this same code
    path against an ephemeral, non-production key).
    """
    lines = minisig_path.read_text().splitlines()
    if len(lines) < 2:
        raise ValueError(f"{minisig_path}: not a valid minisig file (too few lines)")
    sig_blob = base64.b64decode(lines[1].strip())
    if len(sig_blob) < 10:
        raise ValueError(f"{minisig_path}: signature blob too short to contain a key ID")
    keyid = sig_blob[2:10]
    return keyid[::-1].hex().upper()


def minisign_pubkey_fingerprint(pub_path: pathlib.Path) -> str:
    """Extracts the fingerprint from a minisign public key file. A .pub
    file's non-comment line base64-decodes to: 2 bytes algorithm ("Ed") +
    8 bytes key ID + 32 bytes Ed25519 public key. The key ID is stored
    little-endian relative to the display fingerprint, matching
    minisig_signer_fingerprint's orientation."""
    lines = pub_path.read_text().splitlines()
    blob_line = None
    for line in lines:
        line = line.strip()
        if line and not line.startswith("untrusted"):
            blob_line = line
            break
    if blob_line is None:
        raise ValueError(f"{pub_path}: not a valid minisign public key file (no key blob)")
    blob = base64.b64decode(blob_line)
    if len(blob) < 10:
        raise ValueError(f"{pub_path}: public key blob too short to contain a key ID")
    return blob[2:10][::-1].hex().upper()


def load_trusted_fingerprints(path: pathlib.Path) -> set[str]:
    if not path.is_file():
        return set()
    out = set()
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line.upper())
    return out


def load_pinned_public_keys(dir_path: pathlib.Path) -> dict[str, pathlib.Path]:
    """Loads every *.pub minisign public key file in dir_path, returning a
    mapping from each key's fingerprint to its file path. These are the
    PINNED verification keys -- the release toolchain's own copy, never a
    key discovered beside a release or via PATH lookup."""
    pinned: dict[str, pathlib.Path] = {}
    if not dir_path.is_dir():
        return pinned
    for entry in sorted(dir_path.iterdir()):
        if entry.is_file() and entry.suffix == ".pub":
            pinned[minisign_pubkey_fingerprint(entry)] = entry
    return pinned


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_minisign(preferred: str) -> tuple[str | None, str]:
    """Resolves the minisign binary used for verification. --minisign-bin
    (an absolute, operator-pinned path) takes precedence; otherwise fall
    back to PATH lookup. Returns (path_or_None, sha256_of_binary_or_"")."""
    candidates: list[str] = []
    if preferred:
        candidates.append(preferred)
    candidates.append(shutil.which("minisign") or "")
    for cand in candidates:
        if cand and pathlib.Path(cand).is_file():
            return cand, sha256_file(pathlib.Path(cand))
    return None, ""


def verify_signature_cryptographically(
    minisign_bin: str, pub_path: pathlib.Path, checksums: pathlib.Path, minisig: pathlib.Path
) -> tuple[bool, str]:
    """Runs `minisign -V -p <pub> -m <checksums> -x <minisig>` -- the real
    Ed25519 verification over the exact checksums.txt bytes. A syntactically
    valid .minisig whose signature does not actually cover checksums.txt
    (a forged packet, a signature over a different file, or checksums.txt
    modified after signing) fails here. This is the gate Sol11 P0-1 found
    absent: previously the signer key ID was trusted without ever checking
    the signature itself."""
    proc = subprocess.run(
        [minisign_bin, "-V", "-p", str(pub_path), "-m", str(checksums), "-x", str(minisig)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if proc.returncode == 0:
        return True, proc.stdout.strip()
    detail = proc.stdout.strip()
    return False, (
        f"release_policy: cryptographic signature verification FAILED -- minisign -V rejected "
        f"{minisig} over {checksums} (exit {proc.returncode}){': ' + detail if detail else ''}"
    )


_CHECKSUM_LINE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(\S.+?)\s*$")


def parse_checksums(checksums_path: pathlib.Path) -> list[tuple[str, str]]:
    """Parses sha256sum output lines into (sha256, filename) pairs."""
    entries: list[tuple[str, str]] = []
    for line in checksums_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _CHECKSUM_LINE.match(line)
        if not m:
            continue
        entries.append((m.group(1).lower(), m.group(2)))
    return entries


def verify_checksums_self_consistent(
    checksums_path: pathlib.Path,
) -> tuple[bool, str, list[tuple[str, str]]]:
    """Re-hashes every file checksums.txt names and confirms each hash still
    matches. Catches a release artifact (e.g. a platform archive) modified
    AFTER checksums.txt was generated, which a signature over checksums.txt
    alone would not detect -- the signed checksums.txt is unchanged, but it
    no longer describes the bytes actually shipped (Sol11 corpus case 6)."""
    entries = parse_checksums(checksums_path)
    if not entries:
        return False, f"release_policy: {checksums_path} names no artifacts", entries
    base = checksums_path.parent
    for expected, name in entries:
        target = base / name
        if not target.is_file():
            return False, f"release_policy: {name} is listed in {checksums_path} but is absent from the release", entries
        actual = sha256_file(target)
        if actual != expected:
            return False, (
                f"release_policy: {name} no longer matches its checksum in {checksums_path} "
                f"(recorded {expected}, actual {actual}) -- a release artifact was modified after checksums were generated"
            ), entries
    return True, "", entries


def verify_checksum_coverage(
    artifacts_dir: pathlib.Path, entries: list[tuple[str, str]]
) -> tuple[bool, str]:
    """Confirms every file the release ships is covered by checksums.txt.
    Without this, checksums.txt could quietly omit an artifact (the audit's
    original finding: 'checksums covering the stale snapshot archives but
    not the current production binary'). Every regular file in the staging
    directory except checksums.txt and its own .minisig/.hmac sidecars must
    appear in checksums.txt (Sol11 P0-1: 'checksums cover exact release
    artifacts')."""
    listed = {name for _, name in entries}
    excluded = {"checksums.txt", "checksums.txt.minisig", "checksums.txt.hmac"}
    unlisted = []
    for entry in sorted(artifacts_dir.iterdir()):
        if not entry.is_file():
            continue
        if entry.name in excluded:
            continue
        if entry.name not in listed:
            unlisted.append(entry.name)
    if unlisted:
        return False, (
            f"release_policy: checksums.txt does not cover every release artifact -- "
            f"missing: {', '.join(unlisted)}"
        )
    return True, ""


def command_signature(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--version", required=True)
    p.add_argument("--require", default="")
    p.add_argument("--minisig", required=True)
    # P1-5 (Sol10 rc4 Session 8): "a public key shipped only beside its own
    # signature proves nothing... users still need an independently
    # trusted public-key fingerprint." When set, the signer's own key ID
    # (extracted from the .minisig file itself, not from any key shipped
    # alongside it) must appear in this file -- the out-of-band-published
    # trust root, never bundled inside the release archive.
    p.add_argument("--trusted-fingerprints-file", default="")
    # Sol11 P0-1: the signature gate previously accepted a forged .minisig
    # because it only checked the signer key ID against this trust root and
    # never verified the Ed25519 signature over checksums.txt. The three
    # arguments below close that gap: --checksums is the exact file the
    # signature must cover; --trusted-public-keys-dir is the release
    # toolchain's PINNED copy of the verification public key(s), never a key
    # discovered beside the release; --minisign-bin / --minisign-bin-hash
    # pin the verifier itself (Sol11: 'The release minisign executable
    # itself must be pinned by hash'), so a fake minisign on PATH cannot
    # mint or accept a forged packet.
    p.add_argument("--checksums", default="")
    p.add_argument("--trusted-public-keys-dir", default="")
    p.add_argument("--artifacts-dir", default="")
    p.add_argument("--minisign-bin", default="")
    p.add_argument("--minisign-bin-hash", default="")
    args = p.parse_args(argv)

    require = args.require.strip().lower()
    if require in {"", "auto"}:
        require = "1"
        for prefix in ("local-candidate-",):
            if args.version.startswith(prefix):
                require = "0"
                break
        if "-candidate" in args.version or "+" in args.version:
            require = "0"
    if require not in {"0", "1", "false", "true"}:
        print(f"release_policy: unsupported --require value {args.require!r}", file=sys.stderr)
        return 2
    must_have = require in {"1", "true"}
    has_minisig = pathlib.Path(args.minisig).is_file()
    if must_have and not has_minisig:
        print(
            f"release_policy: version {args.version} requires an asymmetric minisign signature; none was produced",
            file=sys.stderr,
        )
        return 1
    if not must_have:
        # Candidate/local dry-runs are not required to carry an asymmetric
        # signature; the cryptographic verification chain below is a
        # production gate.
        return 0

    # --- Production release: full cryptographic verification chain. ---
    if not args.trusted_fingerprints_file:
        print(
            "release_policy: a production release requires --trusted-fingerprints-file "
            "(the out-of-band-published trust root) so the signing key can be anchored",
            file=sys.stderr,
        )
        return 1
    trusted = load_trusted_fingerprints(pathlib.Path(args.trusted_fingerprints_file))
    if not trusted:
        print(
            f"release_policy: {args.trusted_fingerprints_file} names no trusted signing-key fingerprint yet "
            "-- no production signing key has been anchored (P1-5); a production release cannot be trusted "
            "until one is generated and its fingerprint published out-of-band",
            file=sys.stderr,
        )
        return 1
    try:
        actual = minisig_signer_fingerprint(pathlib.Path(args.minisig))
    except ValueError as exc:
        print(f"release_policy: {exc}", file=sys.stderr)
        return 1
    if actual not in trusted:
        print(
            f"release_policy: {args.minisig} was signed by key {actual}, which is not in "
            f"{args.trusted_fingerprints_file} -- refusing a release signed by a nonproduction/unknown key",
            file=sys.stderr,
        )
        return 1

    if not args.checksums:
        print(
            "release_policy: a production release requires --checksums (the exact file the signature covers) "
            "so the Ed25519 signature can be cryptographically verified (Sol11 P0-1)",
            file=sys.stderr,
        )
        return 1
    if not args.trusted_public_keys_dir:
        print(
            "release_policy: a production release requires --trusted-public-keys-dir (the release toolchain's "
            "pinned verification public key) -- a key ID alone cannot verify a signature (Sol11 P0-1)",
            file=sys.stderr,
        )
        return 1
    checksums_path = pathlib.Path(args.checksums)
    if not checksums_path.is_file():
        print(f"release_policy: checksums file {args.checksums} does not exist", file=sys.stderr)
        return 1

    pinned = load_pinned_public_keys(pathlib.Path(args.trusted_public_keys_dir))
    # The verification key is the PINNED public key whose fingerprint matches
    # the anchored signer -- not a key shipped beside the release, and not a
    # key whose fingerprint merely matches a directory listing without also
    # appearing in the out-of-band trust root.
    if actual not in pinned:
        print(
            f"release_policy: no pinned public key for anchored fingerprint {actual} in "
            f"{args.trusted_public_keys_dir} -- cannot verify the signature without the release toolchain's "
            "own copy of the verification key (Sol11 P0-1)",
            file=sys.stderr,
        )
        return 1
    # Belt-and-suspenders: confirm the pinned key's fingerprint is itself
    # anchored (load_pinned_public_keys already keyed by fingerprint, but
    # this guards against a future where the dir and trust root drift).
    pub_path = pinned[actual]

    minisign_bin, minisign_sha = resolve_minisign(args.minisign_bin)
    if minisign_bin is None:
        print(
            "release_policy: minisign binary is not available -- a production release cannot be "
            "cryptographically verified without it (Sol11 P0-1)",
            file=sys.stderr,
        )
        return 1
    if args.minisign_bin_hash and args.minisign_bin_hash.lower() != minisign_sha.lower():
        print(
            f"release_policy: minisign binary hash mismatch -- pinned {args.minisign_bin_hash} but "
            f"{minisign_bin} is {minisign_sha}; refusing to verify with a substituted verifier (Sol11 P0-1)",
            file=sys.stderr,
        )
        return 1

    ok, detail = verify_signature_cryptographically(minisign_bin, pub_path, checksums_path, pathlib.Path(args.minisig))
    if not ok:
        print(detail, file=sys.stderr)
        return 1

    ok, msg, entries = verify_checksums_self_consistent(checksums_path)
    if not ok:
        print(msg, file=sys.stderr)
        return 1

    coverage_verified = False
    if args.artifacts_dir:
        cov_ok, cov_msg = verify_checksum_coverage(pathlib.Path(args.artifacts_dir), entries)
        if not cov_ok:
            print(cov_msg, file=sys.stderr)
            return 1
        coverage_verified = True

    # Evidence: bind the verified signer, the pinned verifier, and the
    # checksum coverage into a single machine-readable record the release
    # pipeline can attach to build-manifest/test-summary identity.
    print(json.dumps({
        "release_policy": "signature",
        "version": args.version,
        "signer_fingerprint": actual,
        "verification_key": str(pub_path),
        "minisign_binary": minisign_bin,
        "minisign_sha256": minisign_sha,
        "minisign_hash_pinned": bool(args.minisign_bin_hash),
        "signature_verified": True,
        "checksum_entries": len(entries),
        "artifacts_dir": args.artifacts_dir,
        "coverage_verified": coverage_verified,
    }, sort_keys=True))
    return 0


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: release_policy.py signature ...", file=sys.stderr)
        return 2
    cmd, *rest = argv
    if cmd == "signature":
        return command_signature(rest)
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
