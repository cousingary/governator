#!/usr/bin/env python3
"""Compute the single source and binary identity for a red-team execution.

The identity is deliberately derived from Go's tagged package selection rather
than a directory convention. A red-team corpus spans internal/redteam plus
security tests in other packages, so only `go list -tags redteam` is
authoritative about which source files and test binaries are involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


BUILD_TAG = "//go:build"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_record(root: Path, path: Path) -> dict[str, str]:
    return {"path": path.relative_to(root).as_posix(), "sha256": sha256_bytes(path.read_bytes())}


def go_output(root: Path, *args: str) -> str:
    return subprocess.run(["go", *args], cwd=root, check=True, capture_output=True, text=True).stdout


def go_packages(root: Path) -> list[dict[str, Any]]:
    output = go_output(root, "list", "-tags", "redteam", "-json", "./...")
    decoder = json.JSONDecoder()
    packages: list[dict[str, Any]] = []
    offset = 0
    while offset < len(output):
        while offset < len(output) and output[offset].isspace():
            offset += 1
        if offset == len(output):
            break
        package, offset = decoder.raw_decode(output, offset)
        packages.append(package)
    return packages


def test_names(root: Path, source_paths: list[Path]) -> list[str]:
    extractor = root / "scripts/redteam_test_names.go"
    result = subprocess.run(
        ["go", "run", "-p", "2", str(extractor), "--", *(str(path) for path in source_paths)],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return sorted(set(result.stdout.splitlines()))


def tagged_sources(root: Path, packages: list[dict[str, Any]]) -> tuple[list[dict[str, str]], dict[str, list[str]], list[str]]:
    sources: list[dict[str, str]] = []
    package_sources: dict[str, list[str]] = {}
    tagged_test_sources: list[Path] = []
    for package in packages:
        directory = Path(package["Dir"])
        selected = set(package.get("GoFiles", [])) | set(package.get("TestGoFiles", [])) | set(package.get("XTestGoFiles", []))
        selected_sources: list[str] = []
        for name in sorted(selected):
            path = directory / name
            if not path.suffix == ".go":
                continue
            content = path.read_text(encoding="utf-8")
            if not any(line.startswith(BUILD_TAG) and "redteam" in line for line in content.splitlines()):
                continue
            selected_sources.append(path.relative_to(root).as_posix())
            record = file_record(root, path)
            record["build_constraint"] = next(line for line in content.splitlines() if line.startswith("//go:build"))
            sources.append(record)
            if path.name.endswith("_test.go"):
                tagged_test_sources.append(path)
        if selected_sources:
            package_sources[package["ImportPath"]] = selected_sources
    return sorted(sources, key=lambda entry: entry["path"]), package_sources, test_names(root, tagged_test_sources)


def bound_inputs(root: Path) -> list[dict[str, str]]:
    paths = [
        root / "internal/redteam/manifest.yaml",
        root / "scripts/redteam_capabilities.py",
        root / "scripts/redteam_source_identity.py",
        root / "scripts/redteam_test_names.go",
        root / "scripts/redteam.sh",
        root / "go.mod",
        root / "go.sum",
    ]
    gate = root / "internal/redteamgate"
    paths.extend(sorted(path for path in gate.glob("*.go") if not path.name.endswith("_test.go")))
    fixtures = root / "internal/redteam/fixtures"
    if fixtures.exists():
        paths.extend(sorted(path for path in fixtures.rglob("*") if path.is_file()))
    missing = [path.relative_to(root).as_posix() for path in paths if not path.is_file()]
    if missing:
        raise SystemExit(f"redteam source identity: required bound input missing: {', '.join(missing)}")
    return sorted((file_record(root, path) for path in paths), key=lambda entry: entry["path"])


def compiled_binaries(root: Path, package_sources: dict[str, list[str]]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="governator-redteam-binaries-") as temp:
        for index, package in enumerate(sorted(package_sources)):
            output = Path(temp) / f"{index}.test"
            # Build one package at a time and cap Go's package scheduler. This
            # identity step runs during release evidence collection, where a
            # host-wide compile burst must not compete with the test tiers.
            subprocess.run(["go", "test", "-c", "-p", "2", "-tags", "redteam", "-o", str(output), package], cwd=root, check=True, capture_output=True, text=True)
            records.append({"package": package, "sha256": sha256_bytes(output.read_bytes())})
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out", required=True)
    parser.add_argument("--inventory-out")
    args = parser.parse_args(argv)

    root = Path(args.repo_root).resolve()
    packages = go_packages(root)
    sources, package_sources, inventory = tagged_sources(root, packages)
    if not sources:
        raise SystemExit("redteam source identity: no redteam-tagged source files selected")
    binaries = compiled_binaries(root, package_sources)
    build_constraints = {
        "tags": ["redteam"],
        "goos": go_output(root, "env", "GOOS").strip(),
        "goarch": go_output(root, "env", "GOARCH").strip(),
        "go_version": go_output(root, "version").strip(),
    }
    source_inputs = {
        "redteam_sources": sources,
        "bound_inputs": bound_inputs(root),
        "build_constraints": build_constraints,
    }
    # Go has one test binary per package. This digest is the canonical ordered
    # index of those binary bytes, so a changed package test binary invalidates
    # the single attestation binding field.
    identity = {
        "schema_version": 1,
        "test_source_hash": sha256_bytes(canonical_bytes(source_inputs)),
        "test_binary_sha256": sha256_bytes(canonical_bytes(binaries)),
        "redteam_sources": sources,
        "bound_inputs": source_inputs["bound_inputs"],
        "build_constraints": build_constraints,
        "compiled_test_binaries": binaries,
        "inventory": inventory,
    }
    output = canonical_bytes(identity) + b"\n"
    if args.out == "-":
        os.write(1, output)
    else:
        destination = Path(args.out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(output)
    if args.inventory_out:
        inventory_out = Path(args.inventory_out)
        inventory_out.parent.mkdir(parents=True, exist_ok=True)
        inventory_out.write_text("\n".join(inventory) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
