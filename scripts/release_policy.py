#!/usr/bin/env python3
import argparse
import base64
import pathlib
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


def load_trusted_fingerprints(path: pathlib.Path) -> set[str]:
    if not path.is_file():
        return set()
    out = set()
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line.upper())
    return out


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
    # trust root, never bundled inside the release archive. Optional: a
    # caller that only wants "was it signed at all" (the pre-existing
    # check) can omit this flag.
    p.add_argument("--trusted-fingerprints-file", default="")
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
    if must_have and args.trusted_fingerprints_file:
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
