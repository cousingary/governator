#!/usr/bin/env python3
"""scripts/closure_manifest.py — rc8-upg15 S5 (Sol15 P0-2): the second signed
layer binding source, architecture, Assayer, install-evidence and trust-anchor
objects that necessarily come into existence after checksums.txt is signed.

upgrade-14 5029893 correctly moved install-evidence.json out of dist/ because
it cannot be covered by the release's own checksums.txt. This script adds the
missing binding: a closure-manifest.json + its own Minisign signature, produced
after installation, that binds checksums.txt's own hash plus every closure
object. Two signed layers with an explicit ordering contract.

Usage:
  closure_manifest.py generate \
    --bundle-dir DIR --checksums PATH --out PATH \
    [--minisign-key PATH] [--version LABEL]

  closure_manifest.py verify \
    --bundle-dir DIR --closure-manifest PATH \
    [--minisig PATH] [--trusted-public-keys-dir DIR]

Exit 0 on success. Exit 1 with a diagnostic on any failure.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def discover_closure_objects(bundle_dir: pathlib.Path) -> list[dict]:
    closure_dir = bundle_dir / "closure"
    objects = []
    if not closure_dir.is_dir():
        return objects
    for p in sorted(closure_dir.iterdir()):
        if p.is_file():
            objects.append({
                "path": f"closure/{p.name}",
                "sha256": sha256_file(p),
                "size": p.stat().st_size,
            })
    return objects


def generate(bundle_dir: str, checksums: str, out: str,
             minisign_key: str | None = None, version: str = "") -> int:
    bundle = pathlib.Path(bundle_dir)
    checksums_path = pathlib.Path(checksums)

    if not checksums_path.is_file():
        print(f"closure_manifest: checksums file not found: {checksums}", file=sys.stderr)
        return 1

    checksums_sha = sha256_file(checksums_path)
    closure_objects = discover_closure_objects(bundle)

    if not closure_objects:
        print("closure_manifest: no closure objects found in bundle-dir/closure/", file=sys.stderr)
        return 1

    arch_doc = None
    arch_dir = bundle / "architecture"
    if arch_dir.is_dir():
        for p in sorted(arch_dir.glob("*.md")):
            arch_doc = {"path": f"architecture/{p.name}", "sha256": sha256_file(p)}
            break

    install_evidence = None
    evidence_path = bundle / "evidence" / "install-evidence.json"
    if evidence_path.is_file():
        install_evidence = {"path": "evidence/install-evidence.json", "sha256": sha256_file(evidence_path)}

    trust_anchor = None
    trust_file = bundle / "source" / "docs" / "TRUSTED_SIGNING_KEYS.txt"
    if trust_file.is_file():
        trust_anchor = {"path": "source/docs/TRUSTED_SIGNING_KEYS.txt", "sha256": sha256_file(trust_file)}

    manifest = {
        "format_version": 1,
        "version": version,
        "checksums_sha256": checksums_sha,
        "closure_objects": closure_objects,
    }
    if arch_doc:
        manifest["architecture_doc"] = arch_doc
    if install_evidence:
        manifest["install_evidence"] = install_evidence
    if trust_anchor:
        manifest["trust_anchor"] = trust_anchor

    out_path = pathlib.Path(out)
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if minisign_key:
        minisig_path = str(out_path) + ".minisig"
        proc = subprocess.run(
            ["minisign", "-S", "-s", minisign_key, "-m", str(out_path), "-x", minisig_path,
             "-c", f"gov closure {version}"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            print(f"closure_manifest: minisign signing failed: {proc.stderr.strip()}", file=sys.stderr)
            return 1
        print(f"closure_manifest: signed {out} -> {minisig_path}", file=sys.stderr)

    print(f"closure_manifest: generated {out} ({len(closure_objects)} closure objects)", file=sys.stderr)
    return 0


def verify(bundle_dir: str, closure_manifest: str,
           minisig: str | None = None, trusted_public_keys_dir: str | None = None) -> int:
    bundle = pathlib.Path(bundle_dir)
    manifest_path = pathlib.Path(closure_manifest)

    if not manifest_path.is_file():
        print(f"closure_manifest: {closure_manifest} not found", file=sys.stderr)
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    failures: list[str] = []

    checksums_sha = manifest.get("checksums_sha256", "")
    checksums_path = bundle / "evidence" / "checksums.txt"
    if not checksums_path.is_file():
        checksums_path = bundle / "dist" / "checksums.txt"
    if checksums_path.is_file():
        actual = sha256_file(checksums_path)
        if actual != checksums_sha:
            failures.append(f"CHECKSUMS_HASH_MISMATCH: manifest declares {checksums_sha}, actual {actual}")
    else:
        failures.append("CHECKSUMS_NOT_FOUND: no checksums.txt in bundle evidence/ or dist/")

    for obj in manifest.get("closure_objects", []):
        obj_path = bundle / obj["path"]
        if not obj_path.is_file():
            failures.append(f"MISSING_CLOSURE_OBJECT: {obj['path']}")
            continue
        actual = sha256_file(obj_path)
        if actual != obj["sha256"]:
            failures.append(f"CLOSURE_OBJECT_MISMATCH: {obj['path']} sha256={actual}, manifest declares {obj['sha256']}")

    arch = manifest.get("architecture_doc")
    if arch:
        arch_path = bundle / arch["path"]
        if not arch_path.is_file():
            failures.append(f"MISSING_ARCHITECTURE_DOC: {arch['path']}")
        elif sha256_file(arch_path) != arch["sha256"]:
            failures.append(f"ARCHITECTURE_DOC_MISMATCH: {arch['path']}")

    evidence = manifest.get("install_evidence")
    if evidence:
        ev_path = bundle / evidence["path"]
        if not ev_path.is_file():
            failures.append(f"MISSING_INSTALL_EVIDENCE: {evidence['path']}")
        elif sha256_file(ev_path) != evidence["sha256"]:
            failures.append(f"INSTALL_EVIDENCE_MISMATCH: {evidence['path']}")

    trust = manifest.get("trust_anchor")
    if trust:
        trust_path = bundle / trust["path"]
        if not trust_path.is_file():
            failures.append(f"MISSING_TRUST_ANCHOR: {trust['path']}")
        elif sha256_file(trust_path) != trust["sha256"]:
            failures.append(f"TRUST_ANCHOR_MISMATCH: {trust['path']}")

    if minisig and trusted_public_keys_dir:
        keys_dir = pathlib.Path(trusted_public_keys_dir)
        verified = False
        for key_file in sorted(keys_dir.glob("*.pub")):
            proc = subprocess.run(
                ["minisign", "-V", "-p", str(key_file), "-m", str(manifest_path), "-x", minisig],
                capture_output=True, text=True,
            )
            if proc.returncode == 0:
                verified = True
                break
        if not verified:
            failures.append("CLOSURE_SIGNATURE_INVALID: no trusted key verified the closure manifest signature")

    if failures:
        for f in failures:
            print(f"closure_manifest: {f}", file=sys.stderr)
        return 1

    print(f"closure_manifest: OK — {closure_manifest} verified ({len(manifest.get('closure_objects', []))} objects bound)", file=sys.stderr)
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Closure-manifest second signed layer")
    sub = p.add_subparsers(dest="command")

    gen = sub.add_parser("generate")
    gen.add_argument("--bundle-dir", required=True)
    gen.add_argument("--checksums", required=True)
    gen.add_argument("--out", required=True)
    gen.add_argument("--minisign-key", default=None)
    gen.add_argument("--version", default="")

    ver = sub.add_parser("verify")
    ver.add_argument("--bundle-dir", required=True)
    ver.add_argument("--closure-manifest", required=True)
    ver.add_argument("--minisig", default=None)
    ver.add_argument("--trusted-public-keys-dir", default=None)

    args = p.parse_args(argv)
    if args.command == "generate":
        return generate(args.bundle_dir, args.checksums, args.out,
                        args.minisign_key, args.version)
    elif args.command == "verify":
        return verify(args.bundle_dir, args.closure_manifest,
                      args.minisig, args.trusted_public_keys_dir)
    else:
        p.print_help(sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
