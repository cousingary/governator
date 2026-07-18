#!/usr/bin/env python3
import argparse
import pathlib
import sys


def command_signature(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--version", required=True)
    p.add_argument("--require", default="")
    p.add_argument("--minisig", required=True)
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
