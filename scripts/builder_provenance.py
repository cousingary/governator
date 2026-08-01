#!/usr/bin/env python3
"""Emit and statically validate GitHub-hosted release builder provenance."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import sys


PINNED_ACTIONS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-go": "40f1582b2485089dde7abd97c1529aa768e1baff",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/attest-build-provenance": "977bb373ede98d70efdf65b84cb5f73e068dcc2a",
    "softprops/action-gh-release": "3bb12739c298aeb8a4eeaf626c5b8d85266b0e65",
}


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_workflow(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    if "runs-on: ubuntu-24.04" not in text or "runs-on: ubuntu-latest" in text:
        raise ValueError("MUTABLE_OR_UNLISTED_RUNNER")
    found: dict[str, set[str]] = {}
    for owner_repo, ref in re.findall(r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9A-Za-z_.-]+)", text):
        found.setdefault(owner_repo, set()).add(ref)
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            raise ValueError(f"MUTABLE_ACTION_REF: {owner_repo}@{ref}")
    for action, expected in PINNED_ACTIONS.items():
        if found.get(action) != {expected}:
            raise ValueError(f"ACTION_IDENTITY_MISMATCH: {action} must resolve only to {expected}")


def emit(out: pathlib.Path, policy: pathlib.Path, workflow: pathlib.Path) -> None:
    validate_workflow(workflow)
    required = [
        "GITHUB_REPOSITORY", "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF", "GITHUB_SHA",
        "GITHUB_REF", "GITHUB_REF_NAME", "GITHUB_EVENT_NAME", "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion",
    ]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise ValueError("CI_PROVENANCE_INCOMPLETE: " + ", ".join(missing))
    if os.environ["GITHUB_REPOSITORY"] != "cousingary/governator":
        raise ValueError("CI_IDENTITY_MISMATCH: repository")
    if os.environ["GITHUB_WORKFLOW"] != "Release":
        raise ValueError("CI_IDENTITY_MISMATCH: workflow")
    if os.environ["GITHUB_EVENT_NAME"] != "push":
        raise ValueError("CI_IDENTITY_MISMATCH: event")
    if os.environ["GITHUB_REF"] != f"refs/tags/{os.environ['GITHUB_REF_NAME']}":
        raise ValueError("CI_IDENTITY_MISMATCH: tag/ref")
    expected_workflow_ref = (
        f"{os.environ['GITHUB_REPOSITORY']}/.github/workflows/release.yml"
        f"@refs/tags/{os.environ['GITHUB_REF_NAME']}"
    )
    if os.environ["GITHUB_WORKFLOW_REF"] != expected_workflow_ref:
        raise ValueError("CI_IDENTITY_MISMATCH: workflow ref/tag")
    document = {
        "schema_version": 1,
        "profile": "github-hosted-ephemeral",
        "provenance_class": "github-oidc-attestation-required",
        "authenticated": False,
        "repository": os.environ["GITHUB_REPOSITORY"],
        "workflow": os.environ["GITHUB_WORKFLOW"],
        "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
        "workflow_sha": os.environ["GITHUB_SHA"],
        "source_commit": os.environ["GITHUB_SHA"],
        "source_ref": os.environ["GITHUB_REF"],
        "event": os.environ["GITHUB_EVENT_NAME"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "runner": {
            "label": "ubuntu-24.04",
            "os": os.environ["RUNNER_OS"],
            "arch": os.environ["RUNNER_ARCH"],
            "image_os": os.environ["ImageOS"],
            "image_version": os.environ["ImageVersion"],
        },
        "actions": PINNED_ACTIONS,
        "requested_tools": {
            "go": "go.mod",
            "python": ["3.10", "3.11", "3.12", "3.13"],
            "minisign": "0.11-1",
        },
        "ci_policy_sha256": sha256_file(policy),
        "workflow_sha256": sha256_file(workflow),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--check-workflow", action="store_true")
    parser.add_argument("--policy")
    parser.add_argument("--out")
    args = parser.parse_args()
    try:
        workflow = pathlib.Path(args.workflow)
        if args.check_workflow:
            validate_workflow(workflow)
        else:
            if not args.policy or not args.out:
                parser.error("--policy and --out are required when emitting provenance")
            emit(pathlib.Path(args.out), pathlib.Path(args.policy), workflow)
        return 0
    except (OSError, ValueError) as exc:
        print(f"BUILDER_PROVENANCE_FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
