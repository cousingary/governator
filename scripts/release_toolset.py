#!/usr/bin/env python3
"""scripts/release_toolset.py -- Sol11 rc5 Session 8 (P1-6): record every
release tool's absolute path + SHA-256 + version string into toolset.json,
and print a combined toolset_hash that scripts/release.sh binds into
build-manifest.json's release identity.

Before this existed, the release pipeline invoked ambient
go/python3/sha256sum/tar/gzip/minisign/git resolved via PATH. The forged-
signature result (Sol11 P0-1 / Session 1) demonstrated exactly why a
substituted tool matters: a fake minisign on PATH could emit a syntactic
packet and the release accepted it. This script makes every release tool's
exact binary identity part of the release record: a downstream verifier
can confirm the release was produced by the exact toolset the manifest
claims, and a substituted tool (different SHA-256) is visible as a
toolset_hash mismatch.

Per the report (P1-6): "Run the release in either an immutable, digest-
pinned builder image, a Nix/Guix-style declared environment, or a verified
toolchain directory with every executable and dependency hashed. The exact
release toolset hash must appear in the build manifest." This script
delivers the verified-toolchain-directory record; the builder-image pinning
itself is the workflow's responsibility (.github/workflows/release.yml's
pinned Go/Python/Minisign setup, Session 8 P1-4).

A tool that is not on PATH (e.g. minisign when asymmetric signing is not
configured) is recorded honestly as absent -- path null, sha256 empty --
rather than silently omitted. Its absence is itself part of the toolset
identity this release was produced under.

Usage:
  release_toolset.py --out <toolset.json> [--tools go,python3,...]
  Prints the combined toolset_hash to stdout (one line, 64 hex chars).
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys


# The seven ambient executables the Sol11 P1-6 report names. Each is
# resolved the same way scripts/release.sh resolves it (PATH lookup), then
# hashed so a substituted binary of the same name is detected.
DEFAULT_TOOLS = ["go", "python3", "sha256sum", "tar", "gzip", "minisign", "git"]


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_version(name: str, resolved: str) -> str:
    """Best-effort version string for the resolved tool. Never raises --
    a tool that won't report a version records an empty string, not a
    crash."""
    if not resolved:
        return ""
    for args in (["--version"], ["version"]):
        try:
            out = subprocess.run(
                [resolved, *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=10,
                text=True,
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError):
            continue
    return ""


def record_tool(name: str) -> dict:
    raw = shutil.which(name)
    if not raw:
        return {"name": name, "path": None, "sha256": "", "version": ""}
    resolved = os.path.realpath(raw)
    path_obj = pathlib.Path(resolved)
    digest = sha256_file(path_obj) if path_obj.is_file() else ""
    return {
        "name": name,
        "path": resolved,
        "sha256": digest,
        "version": tool_version(name, resolved),
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True, help="path to write toolset.json")
    p.add_argument(
        "--tools",
        default=",".join(DEFAULT_TOOLS),
        help="comma-separated tool names (default: the seven P1-6 tools)",
    )
    args = p.parse_args(argv)

    tool_names = [t.strip() for t in args.tools.split(",") if t.strip()]
    records = [record_tool(name) for name in tool_names]

    # Combined hash: sha256 of the sorted concatenation of each present
    # tool's binary sha256. Sorting makes the hash order-independent; an
    # absent tool (empty sha256) contributes nothing, so adding/removing
    # minisign when signing is configured vs not is a visible identity
    # change only when minisign is actually present in both attempts.
    present = sorted(r["sha256"] for r in records if r["sha256"])
    toolset_hash = hashlib.sha256("".join(present).encode()).hexdigest()

    doc = {
        "tools": records,
        "toolset_hash": toolset_hash,
        "note": (
            "Every release tool's absolute path + SHA-256 + version. A "
            "substituted binary of the same name (different SHA-256) is "
            "detected as a toolset_hash mismatch. See Sol11 P1-6."
        ),
    }
    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(toolset_hash)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
