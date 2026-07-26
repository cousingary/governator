#!/usr/bin/env python3
import argparse
import base64
import binascii
import hashlib
import json
import os
import pathlib
import re
import stat as stat_mod
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


_ED25519_Q = 2**255 - 19
_ED25519_L = 2**252 + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, _ED25519_Q - 2, _ED25519_Q)) % _ED25519_Q
_ED25519_I = pow(2, (_ED25519_Q - 1) // 4, _ED25519_Q)


def _ed25519_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_ED25519_D * y * y + 1, _ED25519_Q - 2, _ED25519_Q) % _ED25519_Q
    x = pow(xx, (_ED25519_Q + 3) // 8, _ED25519_Q)
    if (x * x - xx) % _ED25519_Q:
        x = x * _ED25519_I % _ED25519_Q
    if (x * x - xx) % _ED25519_Q:
        raise ValueError("invalid Ed25519 point")
    return x


def _ed25519_decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("Ed25519 point must be 32 bytes")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _ED25519_Q:
        raise ValueError("non-canonical Ed25519 point")
    x = _ed25519_xrecover(y)
    if x == 0 and sign:
        raise ValueError("non-canonical Ed25519 point sign")
    if x & 1 != sign:
        x = _ED25519_Q - x
    return x, y


def _ed25519_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    denominator_x = pow(1 + _ED25519_D * x1 * x2 * y1 * y2 % _ED25519_Q, _ED25519_Q - 2, _ED25519_Q)
    denominator_y = pow(1 - _ED25519_D * x1 * x2 * y1 * y2 % _ED25519_Q, _ED25519_Q - 2, _ED25519_Q)
    return (
        ((x1 * y2 + x2 * y1) * denominator_x) % _ED25519_Q,
        ((y1 * y2 + x1 * x2) * denominator_y) % _ED25519_Q,
    )


def _ed25519_scalar_mul(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    while scalar:
        if scalar & 1:
            result = _ed25519_add(result, point)
        point = _ed25519_add(point, point)
        scalar >>= 1
    return result


def _ed25519_base_point() -> tuple[int, int]:
    y = 4 * pow(5, _ED25519_Q - 2, _ED25519_Q) % _ED25519_Q
    x = _ed25519_xrecover(y)
    # RFC 8032's base point has an even x coordinate. xrecover may choose
    # the other square root, which is the inverse point (-B).
    if x & 1:
        x = _ED25519_Q - x
    return x, y


def verify_ed25519_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature without executing an external verifier.

    Minisign's primary packet is a standard Ed25519 signature over the exact
    message bytes. Cofactor multiplication rejects small-order point tricks.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        point_r = _ed25519_decode_point(signature[:32])
        point_a = _ed25519_decode_point(public_key)
    except ValueError:
        return False
    scalar_s = int.from_bytes(signature[32:], "little")
    if scalar_s >= _ED25519_L:
        return False
    scalar_h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _ED25519_L
    left = _ed25519_scalar_mul(_ed25519_base_point(), scalar_s)
    right = _ed25519_add(point_r, _ed25519_scalar_mul(point_a, scalar_h))
    return _ed25519_scalar_mul(left, 8) == _ed25519_scalar_mul(right, 8)


def minisign_public_key(pub_path: pathlib.Path) -> tuple[bytes, bytes]:
    lines = pub_path.read_text().splitlines()
    for line in lines:
        line = line.strip()
        if line and not line.startswith("untrusted"):
            blob = base64.b64decode(line, validate=True)
            if len(blob) != 42 or blob[:2] != b"Ed":
                raise ValueError(f"{pub_path}: unsupported Minisign public-key packet")
            return blob[2:10], blob[10:]
    raise ValueError(f"{pub_path}: not a valid minisig public key")


def verify_signature_cryptographically(
    pub_path: pathlib.Path, checksums: pathlib.Path, minisig: pathlib.Path
) -> tuple[bool, str]:
    """Verify the Minisign primary packet in-process, never through PATH."""
    try:
        lines = minisig.read_text().splitlines()
        if len(lines) < 2:
            raise ValueError("signature file has too few lines")
        packet = base64.b64decode(lines[1].strip(), validate=True)
        key_id, public_key = minisign_public_key(pub_path)
        if len(packet) != 74 or packet[:2] not in {b"Ed", b"ED"}:
            raise ValueError("unsupported Minisign signature packet")
        if packet[2:10] != key_id:
            raise ValueError("signature packet key ID does not match pinned public key")
        message = checksums.read_bytes()
        # Minisign uses Ed for direct Ed25519 signatures and ED for the
        # documented BLAKE2b-512-prehashed variant emitted by current tools.
        if packet[:2] == b"ED":
            message = hashlib.blake2b(message, digest_size=64).digest()
        verified = verify_ed25519_signature(public_key, message, packet[10:])
    except (OSError, ValueError, binascii.Error) as exc:
        return False, f"release_policy: cryptographic signature verification FAILED -- {exc}"
    if not verified:
        return False, "release_policy: cryptographic signature verification FAILED -- in-process Ed25519 verification rejected the packet"
    return True, ""


_CHECKSUM_LINE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(\S.+?)\s*$")


def _validate_checksum_name(name: str, checksums_path: pathlib.Path) -> str | None:
    """Returns an error string if name is unsafe, else None (Sol12 P1-7)."""
    if not name:
        return f"release_policy: {checksums_path}: empty artifact name in checksum entry"
    if name.startswith("/"):
        return f"release_policy: {checksums_path}: absolute path in checksum entry: {name!r}"
    if ".." in name.split("/") or ".." in name.split("\\"):
        return f"release_policy: {checksums_path}: parent traversal in checksum entry: {name!r}"
    normalized = pathlib.PurePosixPath(name)
    if normalized != pathlib.PurePosixPath(*normalized.parts):
        return f"release_policy: {checksums_path}: non-normalized path in checksum entry: {name!r}"
    return None


def parse_checksums(checksums_path: pathlib.Path) -> list[tuple[str, str]]:
    """Parses sha256sum output lines into (sha256, filename) pairs.

    Sol12 P1-7: strict parsing. Every non-comment, non-empty line MUST match
    the checksum format. Rejects: absolute paths, parent traversal (../),
    empty names, duplicate entries, and malformed lines. A checksums file is
    a release security policy -- permissive parsing lets an attacker inject
    unsafe paths that escape the artifacts directory.
    """
    entries: list[tuple[str, str]] = []
    seen_names: set[str] = set()
    for lineno, line in enumerate(checksums_path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _CHECKSUM_LINE.match(line)
        if not m:
            raise ValueError(
                f"release_policy: {checksums_path}:{lineno}: malformed checksum line "
                f"(expected '<sha256> <filename>'): {line!r}"
            )
        name = m.group(2)
        err = _validate_checksum_name(name, checksums_path)
        if err:
            raise ValueError(f"{err} (line {lineno})")
        if name in seen_names:
            raise ValueError(
                f"release_policy: {checksums_path}:{lineno}: duplicate checksum entry for {name!r}"
            )
        seen_names.add(name)
        entries.append((m.group(1).lower(), name))
    return entries


def verify_checksums_self_consistent(
    checksums_path: pathlib.Path,
) -> tuple[bool, str, list[tuple[str, str]]]:
    """Re-hashes every file checksums.txt names and confirms each hash still
    matches. Catches a release artifact (e.g. a platform archive) modified
    AFTER checksums.txt was generated, which a signature over checksums.txt
    alone would not detect -- the signed checksums.txt is unchanged, but it
    no longer describes the bytes actually shipped (Sol11 corpus case 6).

    Sol12 P1-7: uses lstat (not is_file, which follows symlinks) to reject
    symlinked artifacts. A release artifact that is a symlink is never
    acceptable -- it could point outside the artifacts directory."""
    try:
        entries = parse_checksums(checksums_path)
    except ValueError as exc:
        return False, str(exc), []
    if not entries:
        return False, f"release_policy: {checksums_path} names no artifacts", entries
    base = checksums_path.parent
    for expected, name in entries:
        target = base / name
        try:
            st = target.lstat()
        except OSError:
            return False, f"release_policy: {name} is listed in {checksums_path} but is absent from the release", entries
        if stat_mod.S_ISLNK(st.st_mode):
            return False, f"release_policy: {name} is a symlink -- release artifacts must be regular files (Sol12 P1-7)", entries
        if not stat_mod.S_ISREG(st.st_mode):
            return False, f"release_policy: {name} is not a regular file (Sol12 P1-7)", entries
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
    artifacts').

    Sol12 P1-7: uses lstat to detect symlinks -- a symlinked artifact in the
    release directory is rejected, not silently skipped or followed."""
    listed = {name for _, name in entries}
    excluded = {"checksums.txt", "checksums.txt.minisig", "checksums.txt.hmac"}
    unlisted = []
    for entry in sorted(artifacts_dir.iterdir()):
        try:
            st = entry.lstat()
        except OSError:
            continue
        if stat_mod.S_ISLNK(st.st_mode):
            return False, (
                f"release_policy: {entry.name} in the artifacts directory is a symlink -- "
                f"release artifacts must be regular files (Sol12 P1-7)"
            )
        if not stat_mod.S_ISREG(st.st_mode):
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
    # Sol13 P0-2: verification is in-process. The deprecated verifier flags
    # remain accepted for compatibility with historical audit fixtures, but
    # are never executed and cannot affect the cryptographic decision.
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

    if args.minisign_bin_hash and args.minisign_bin:
        minisign_path = pathlib.Path(args.minisign_bin)
        minisign_sha = sha256_file(minisign_path) if minisign_path.is_file() else ""
    else:
        minisign_sha = ""
    if args.minisign_bin_hash and args.minisign_bin_hash.lower() != minisign_sha.lower():
        print(
            f"release_policy: minisign binary hash mismatch -- pinned {args.minisign_bin_hash} but "
            f"{args.minisign_bin} is {minisign_sha}; refusing stale compatibility verifier metadata",
            file=sys.stderr,
        )
        return 1

    ok, detail = verify_signature_cryptographically(pub_path, checksums_path, pathlib.Path(args.minisig))
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

    # Evidence: Minisign's signer identity is recorded, while the signature
    # itself was verified by this process's Ed25519 implementation. An
    # ambient minisign executable is not part of this verification path.
    print(json.dumps({
        "release_policy": "signature",
        "version": args.version,
        "signer_fingerprint": actual,
        "verification_key": str(pub_path),
        "signature_verifier": "in-process-ed25519",
        "minisign_binary": None,
        "minisign_sha256": "",
        "minisign_hash_pinned": False,
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
