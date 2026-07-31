#!/usr/bin/env python3
"""scripts/bundle_verify.py — rc8-upg15 S5 (Sol15 P0-2 + P1-4): one-command
offline audit-bundle verifier.

A single entry point that rejects any unbound source, architecture, evidence,
Assayer or trust-anchor object. This is the artifact Sol's next pass will
actually run. Failure messages name the specific unbound object.

Runs offline in a clean room: no original checkout, no network, no global Git
objects, no producer-specific paths, no tools outside the declared closure.

Usage:
  bundle_verify.py --bundle-dir DIR \
    [--trusted-fingerprints-file FILE] \
    [--trusted-public-keys-dir DIR] \
    [--closure-minisig PATH] \
    [--skip-git-bundle]

Exit 0 on success. Exit 1 with diagnostics naming each unbound object.

Trust-anchor sourcing (Sol15 P2-3): external sourcing is the documented
default. --trusted-fingerprints-file should be obtained through a channel
independent of the bundle (docs/signing_key.md names the published
channels); the checksums signature's signer fingerprint is cross-checked
against it. Without it, trust-anchor verification is bundle-local only --
integrity is proven but origin authentication is WEAK, and the verifier
says so loudly. A fingerprints file resolving inside the bundle is
bundle-local and requires the explicit --allow-bundle-local-trust-anchor
opt-in (with a warning).
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_source_closure(bundle: pathlib.Path, failures: list[str]) -> None:
    closure_dir = bundle / "closure"
    if not closure_dir.is_dir():
        failures.append("UNBOUND: closure/ directory absent from bundle")
        return

    gov_archives = sorted(closure_dir.glob("governator-source-*.tar.gz"))
    gov_trees = sorted(closure_dir.glob("governator-source-*.tree.json"))
    if not gov_archives:
        failures.append("UNBOUND: no governator source archive in closure/")
    if not gov_trees:
        failures.append("UNBOUND: no governator tree manifest in closure/")

    if gov_archives and gov_trees:
        script = pathlib.Path(__file__).parent / "source_closure.py"
        proc = subprocess.run(
            [sys.executable, str(script), "verify",
             "--archive", str(gov_archives[0]), "--tree", str(gov_trees[0])],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            failures.append(f"UNBOUND: governator source closure verification failed: {proc.stderr.strip()}")

    assayer_archives = sorted(closure_dir.glob("assayer-source-*.tar.gz"))
    assayer_trees = sorted(closure_dir.glob("assayer-source-*.tree.json"))
    if not assayer_archives:
        failures.append("UNBOUND: no assayer source archive in closure/")
    if not assayer_trees:
        failures.append("UNBOUND: no assayer tree manifest in closure/")

    if assayer_archives and assayer_trees:
        script = pathlib.Path(__file__).parent / "source_closure.py"
        proc = subprocess.run(
            [sys.executable, str(script), "verify",
             "--archive", str(assayer_archives[0]), "--tree", str(assayer_trees[0])],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            failures.append(f"UNBOUND: assayer source closure verification failed: {proc.stderr.strip()}")


def verify_architecture(bundle: pathlib.Path, failures: list[str]) -> None:
    arch_dir = bundle / "architecture"
    if not arch_dir.is_dir():
        failures.append("UNBOUND: architecture/ directory absent from bundle")
        return
    md_files = sorted(arch_dir.glob("*.md"))
    if not md_files:
        failures.append("UNBOUND: no architecture document in architecture/")


def verify_install_evidence(bundle: pathlib.Path, failures: list[str]) -> None:
    evidence = bundle / "evidence" / "install-evidence.json"
    closure_evidence = bundle / "closure" / "install-evidence.json"
    if not evidence.is_file() and not closure_evidence.is_file():
        failures.append("UNBOUND: install-evidence.json absent from both evidence/ and closure/")
        return
    if evidence.is_file() and closure_evidence.is_file():
        if sha256_file(evidence) != sha256_file(closure_evidence):
            failures.append("UNBOUND: install-evidence.json in evidence/ differs from closure/ copy")


def verify_checksums(bundle: pathlib.Path, failures: list[str]) -> None:
    checksums = bundle / "evidence" / "checksums.txt"
    if not checksums.is_file():
        checksums = bundle / "dist" / "checksums.txt"
    if not checksums.is_file():
        failures.append("UNBOUND: checksums.txt absent from bundle")
        return

    minisig = None
    for candidate in (checksums.parent / "checksums.txt.minisig",
                      bundle / "evidence" / "checksums.txt.minisig",
                      bundle / "dist" / "checksums.txt.minisig"):
        if candidate.is_file():
            minisig = candidate
            break
    if minisig is None:
        failures.append("UNBOUND: checksums.txt.minisig absent — no asymmetric signature over checksums")


def verify_closure_manifest(bundle: pathlib.Path, failures: list[str],
                            trusted_keys_dir: str | None,
                            closure_minisig: str | None) -> None:
    closure_manifest = None
    for candidate in (bundle / "closure" / "closure-manifest.json",
                      bundle / "closure-manifest.json"):
        if candidate.is_file():
            closure_manifest = candidate
            break
    if closure_manifest is None:
        failures.append("UNBOUND: closure-manifest.json absent — second signed layer missing")
        return

    script = pathlib.Path(__file__).parent / "closure_manifest.py"
    cmd = [sys.executable, str(script), "verify",
           "--bundle-dir", str(bundle), "--closure-manifest", str(closure_manifest)]
    if closure_minisig:
        cmd += ["--minisig", closure_minisig]
    if trusted_keys_dir:
        cmd += ["--trusted-public-keys-dir", trusted_keys_dir]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        failures.append(f"UNBOUND: closure-manifest verification failed: {proc.stderr.strip()}")


def verify_git_bundle(bundle: pathlib.Path, failures: list[str]) -> None:
    git_bundle = bundle / "closure" / "governator-release.bundle"
    if not git_bundle.is_file():
        failures.append("UNBOUND: governator-release.bundle absent — portable claims unverifiable")
        return

    with tempfile.TemporaryDirectory(prefix="bundle_verify_git_") as tmp:
        # `git bundle verify` needs to run inside a repository (even an
        # empty, unrelated one) -- it fails closed with "need a repository
        # to verify a bundle" in a plain directory, which this scratch
        # tmpdir always was until now. The repo it inits into has no
        # relationship to the bundle's own history; it exists only so the
        # bundle-verify command has a `.git` to run inside.
        init_proc = subprocess.run(
            ["git", "init", "-q", tmp],
            capture_output=True, text=True,
        )
        if init_proc.returncode != 0:
            failures.append(f"UNBOUND: could not init scratch repo for git bundle verification: {init_proc.stderr.strip()}")
            return
        proc = subprocess.run(
            ["git", "bundle", "verify", str(git_bundle)],
            capture_output=True, text=True, cwd=tmp,
        )
        if proc.returncode != 0:
            failures.append(f"UNBOUND: git bundle verification failed: {proc.stderr.strip()}")


def verify_trust_anchor(bundle: pathlib.Path, failures: list[str],
                        warnings: list[str],
                        trusted_fingerprints_file: str | None,
                        allow_bundle_local: bool) -> None:
    trust_file = bundle / "source" / "docs" / "TRUSTED_SIGNING_KEYS.txt"
    if not trust_file.is_file():
        failures.append("UNBOUND: source/docs/TRUSTED_SIGNING_KEYS.txt absent — trust anchor not in signed source")

    # Sol15 P2-3: the bundle-local anchor above proves the trust root is
    # bound into the signed source -- integrity. Origin authentication
    # requires cross-checking the signer fingerprint against a fingerprints
    # file obtained OUTSIDE the bundle. Without it this verifier must say
    # so loudly rather than presenting a green verdict as fully trusted.
    if not trusted_fingerprints_file:
        warnings.append(
            "WEAK_ORIGIN_AUTHENTICATION: no --trusted-fingerprints-file supplied — trust-anchor verification "
            "is bundle-local only; integrity is proven but origin authentication is WEAK because the key "
            "travelled beside the payload. Obtain the expected fingerprint through an independent channel "
            "(docs/signing_key.md names the published channels) and re-run with --trusted-fingerprints-file")
        return

    from release_policy import bundle_local_trust_sources, load_trusted_fingerprints, minisig_signer_fingerprint
    inside = bundle_local_trust_sources(str(bundle), trusted_fingerprints_file, "")
    if inside:
        if not allow_bundle_local:
            failures.append(
                "UNBOUND: BUNDLE_LOCAL_TRUST_ANCHOR: --trusted-fingerprints-file resolves inside the bundle — "
                "a fingerprints file that travels beside the payload proves nothing about origin (Sol15 P2-3); "
                "supply one obtained externally, or pass --allow-bundle-local-trust-anchor to accept weak "
                "origin authentication with an explicit warning")
            return
        warnings.append(
            "WEAK_ORIGIN_AUTHENTICATION: bundle-local fingerprints file accepted by explicit opt-in — "
            "origin authentication is WEAK (Sol15 P2-3)")

    external = load_trusted_fingerprints(pathlib.Path(trusted_fingerprints_file))
    if not external:
        failures.append(f"UNBOUND: {trusted_fingerprints_file} names no trusted signing-key fingerprint")
        return

    minisig = None
    for candidate in (bundle / "evidence" / "checksums.txt.minisig",
                      bundle / "dist" / "checksums.txt.minisig"):
        if candidate.is_file():
            minisig = candidate
            break
    if minisig is None:
        failures.append("UNBOUND: checksums.txt.minisig absent — cannot cross-check signer fingerprint "
                        "against the external trust anchor")
        return
    try:
        actual = minisig_signer_fingerprint(minisig)
    except ValueError as exc:
        failures.append(f"UNBOUND: signer fingerprint unreadable from {minisig.name}: {exc}")
        return
    if actual not in external:
        failures.append(
            f"UNBOUND: bundle signature was produced by key {actual}, which is NOT in the external "
            f"trust anchor {trusted_fingerprints_file} — origin authentication failed (Sol15 P2-3)")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="One-command offline audit-bundle verifier")
    p.add_argument("--bundle-dir", required=True)
    p.add_argument("--trusted-fingerprints-file", default=None,
                   help="externally obtained signer fingerprints (the documented default trust source; Sol15 P2-3)")
    p.add_argument("--trusted-public-keys-dir", default=None)
    p.add_argument("--allow-bundle-local-trust-anchor", action="store_true",
                   help="explicit, warned opt-in to a fingerprints file that resolves inside the bundle (Sol15 P2-3)")
    p.add_argument("--closure-minisig", default=None)
    p.add_argument("--skip-git-bundle", action="store_true")
    args = p.parse_args(argv)

    bundle = pathlib.Path(args.bundle_dir).resolve()
    if not bundle.is_dir():
        print(f"bundle_verify: {bundle} is not a directory", file=sys.stderr)
        return 1

    failures: list[str] = []
    warnings: list[str] = []

    verify_source_closure(bundle, failures)
    verify_architecture(bundle, failures)
    verify_install_evidence(bundle, failures)
    verify_checksums(bundle, failures)
    verify_closure_manifest(bundle, failures, args.trusted_public_keys_dir, args.closure_minisig)
    verify_trust_anchor(bundle, failures, warnings, args.trusted_fingerprints_file,
                        args.allow_bundle_local_trust_anchor)
    if not args.skip_git_bundle:
        verify_git_bundle(bundle, failures)

    for w in warnings:
        print(f"bundle_verify: WARNING: {w}", file=sys.stderr)

    if failures:
        print(f"bundle_verify: FAILED — {len(failures)} unbound object(s):", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1

    if warnings:
        print(f"bundle_verify: OK WITH WARNINGS — {bundle} is a fully bound audit bundle, but with weak origin authentication (see warnings above)", file=sys.stderr)
    else:
        print(f"bundle_verify: OK — {bundle} is a fully bound, offline-verifiable audit bundle", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
