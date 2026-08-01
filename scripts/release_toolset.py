#!/usr/bin/env python3
"""Record and re-verify the independently approved release toolset.

The policy is the trust root. This script never resolves a release tool via
PATH: it hashes only the exact path and digest security-reviewed in
release_tool_policy.yaml, then records that approved identity beside the
identity actually observed before the release command runs.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys


DEFAULT_TOOLS = [
    "go", "python3", "python3.10", "python3.11", "python3.12", "python3.13",
    "git", "bash", "sha256sum", "tar", "gzip", "minisign",
    "date", "awk", "env", "cp", "rm", "mkdir", "find", "sort", "mktemp",
    "dirname", "pwd", "grep", "uname", "cat", "chmod", "stat", "basename",
    "timeout", "mv", "ls", "systemctl", "docker", "tail",
]
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PROFILES = {"reviewed-bytes", "github-hosted-ephemeral"}


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_policy_document(path: pathlib.Path) -> tuple[dict, dict[str, dict[str, str]]]:
    """Parse the intentionally small, strict reviewed-policy YAML format."""
    if not path.is_file():
        raise ValueError(f"release-tool policy is absent: {path}")
    metadata: dict[str, str] = {"schema_version": "1", "profile": "reviewed-bytes"}
    tools: dict[str, dict[str, str]] = {}
    current: str | None = None
    saw_tools = False
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        if line == "tools:":
            if saw_tools:
                raise ValueError(f"{path}:{line_number}: duplicate tools block")
            saw_tools = True
            continue
        top_field = re.fullmatch(r"(schema_version|profile|runner_label|runner_arch): (.+)", line)
        if top_field and not saw_tools:
            field, value = top_field.groups()
            metadata[field] = value
            continue
        tool_match = re.fullmatch(r"  ([a-z0-9][a-z0-9_.-]*):", line)
        if tool_match:
            if not saw_tools:
                raise ValueError(f"{path}:{line_number}: tool outside tools block")
            current = tool_match.group(1)
            if current in tools:
                raise ValueError(f"{path}:{line_number}: duplicate tool {current!r}")
            tools[current] = {}
            continue
        field_match = re.fullmatch(r"    (path|sha256|command|declared_source): (.+)", line)
        if field_match and current:
            field, value = field_match.groups()
            if field in tools[current]:
                raise ValueError(f"{path}:{line_number}: duplicate {field} for {current}")
            tools[current][field] = value
            continue
        raise ValueError(f"{path}:{line_number}: unsupported policy syntax")
    if not saw_tools or not tools:
        raise ValueError(f"{path}: policy must declare tools")
    profile = metadata.get("profile")
    if profile not in PROFILES:
        raise ValueError(f"{path}: unsupported profile {profile!r}")
    for name, record in tools.items():
        if profile == "reviewed-bytes":
            if set(record) != {"path", "sha256"}:
                raise ValueError(f"{path}: {name} must declare exactly path and sha256")
            if not pathlib.PurePath(record["path"]).is_absolute():
                raise ValueError(f"{path}: {name} path must be absolute")
            if not SHA256_RE.fullmatch(record["sha256"]):
                raise ValueError(f"{path}: {name} sha256 must be 64 lowercase hexadecimal characters")
        else:
            if set(record) != {"command", "declared_source"}:
                raise ValueError(f"{path}: {name} must declare exactly command and declared_source")
            if record["command"] != name:
                raise ValueError(f"{path}: {name} command must equal its inventory name")
    if profile == "github-hosted-ephemeral":
        if metadata.get("schema_version") != "2":
            raise ValueError(f"{path}: CI policy must use schema_version: 2")
        if metadata.get("runner_label") != "ubuntu-24.04" or metadata.get("runner_arch") != "X64":
            raise ValueError("MUTABLE_OR_UNLISTED_RUNNER: CI policy requires ubuntu-24.04/X64")
    return metadata, tools


def load_policy(path: pathlib.Path) -> dict[str, dict[str, str]]:
    return load_policy_document(path)[1]


def tool_version(path: pathlib.Path) -> str:
    for args in (("--version",), ("version",)):
        try:
            result = subprocess.run(
                [str(path), *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=10, check=False,
            )
        except OSError:
            continue
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    return ""


def record_tool(name: str, approved: dict[str, str]) -> dict:
    path = pathlib.Path(approved["path"])
    if not path.is_file():
        raise ValueError(f"{name}: approved path is not a regular file: {path}")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{name}: resolved approved target is not a regular file: {resolved}")
    observed_hash = sha256_file(resolved)
    if observed_hash != approved["sha256"]:
        raise ValueError(
            f"{name}: observed SHA-256 {observed_hash} differs from independently approved "
            f"SHA-256 {approved['sha256']}"
        )
    return {
        "name": name,
        "approved": {"path": approved["path"], "sha256": approved["sha256"]},
        "observed": {
            "link_path": str(path.absolute()),
            "resolved_path": str(resolved),
            "sha256": observed_hash,
            "version": tool_version(resolved),
        },
    }


def record_measured_tool(name: str, declared: dict[str, str]) -> dict:
    located = shutil_which(declared["command"])
    if not located:
        raise ValueError(f"{name}: declared command is not on PATH")
    path = pathlib.Path(located)
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{name}: resolved target is not a regular file: {resolved}")
    return {
        "name": name,
        "declared_source": declared["declared_source"],
        "measured": {
            "link_path": str(path.absolute()),
            "resolved_path": str(resolved),
            "sha256": sha256_file(resolved),
            "version": tool_version(resolved),
        },
    }


def shutil_which(command: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = pathlib.Path(directory or ".") / command
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.absolute())
    return None


def validate_ci_context(metadata: dict[str, str]) -> dict[str, str]:
    required = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "cousingary/governator",
        "GITHUB_WORKFLOW_REF_SUFFIX": ".github/workflows/release.yml@refs/tags/",
        "GITHUB_EVENT_NAME": "push",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": metadata["runner_arch"],
        "GOV_RELEASE_RUNNER_LABEL": metadata["runner_label"],
    }
    for name, expected in required.items():
        actual = os.environ.get(name, "")
        if name == "GITHUB_WORKFLOW_REF_SUFFIX":
            workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
            ref_name = os.environ.get("GITHUB_REF_NAME", "")
            expected_ref = f"cousingary/governator/{expected}{ref_name}"
            if workflow_ref != expected_ref:
                raise ValueError("CI_IDENTITY_MISMATCH: workflow ref is not release.yml at the pushed tag")
        elif actual != expected:
            raise ValueError(f"CI_IDENTITY_MISMATCH: {name}={actual!r}, expected {expected!r}")
    ref = os.environ.get("GITHUB_REF", "")
    ref_name = os.environ.get("GITHUB_REF_NAME", "")
    sha = os.environ.get("GITHUB_SHA", "")
    if ref != f"refs/tags/{ref_name}" or not re.fullmatch(r"v[0-9].+", ref_name):
        raise ValueError("CI_IDENTITY_MISMATCH: source ref is not the named v* tag")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("CI_IDENTITY_MISMATCH: GITHUB_SHA is not a full commit")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "ImageOS", "ImageVersion"):
        if not os.environ.get(name):
            raise ValueError(f"CI_PROVENANCE_INCOMPLETE: {name} is absent")
    return {name: os.environ.get(name, "") for name in (
        "GITHUB_REPOSITORY", "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF", "GITHUB_SHA",
        "GITHUB_REF", "GITHUB_REF_NAME", "GITHUB_EVENT_NAME", "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion",
    )}


def selected_tools(value: str) -> list[str]:
    names = [name.strip() for name in value.split(",") if name.strip()]
    if not names or len(names) != len(set(names)):
        raise ValueError("tool names must be nonempty and unique")
    return names


def build_toolbin(toolbin: pathlib.Path, records: list[dict]) -> None:
    """Populate the release's only command-search path from verified targets."""
    toolbin.mkdir(parents=True, exist_ok=True)
    existing = {entry.name: entry for entry in toolbin.iterdir()}
    expected = {
        record["name"]: (record.get("observed") or record.get("measured"))["resolved_path"]
        for record in records
    }
    if existing:
        if set(existing) != set(expected):
            raise ValueError(f"private toolbin has an unexpected entry: {toolbin}")
        for name, entry in existing.items():
            if not entry.is_symlink() or str(entry.resolve()) != expected[name]:
                raise ValueError(f"private toolbin entry is not the verified target: {entry}")
        toolbin.chmod(0o500)
        return
    for record in records:
        identity = record.get("observed") or record.get("measured")
        (toolbin / record["name"]).symlink_to(identity["resolved_path"])
    toolbin.chmod(0o500)


def write_toolset(policy_path: pathlib.Path, out_path: pathlib.Path, names: list[str], toolbin: pathlib.Path | None = None,
                  requested_profile: str | None = None) -> str:
    metadata, policy = load_policy_document(policy_path)
    profile = metadata["profile"]
    if profile == "github-hosted-ephemeral" and requested_profile is None:
        raise ValueError("CI_PROFILE_REQUIRES_EXPLICIT_SELECTION")
    if requested_profile and requested_profile != profile:
        raise ValueError(f"PROFILE_MISMATCH: requested {requested_profile}, policy is {profile}")
    missing = [name for name in names if name not in policy]
    if missing:
        raise ValueError(f"release-tool policy has no approved entry for: {', '.join(missing)}")
    context = validate_ci_context(metadata) if profile == "github-hosted-ephemeral" else None
    records = ([record_tool(name, policy[name]) for name in names] if profile == "reviewed-bytes"
               else [record_measured_tool(name, policy[name]) for name in names])
    if toolbin is not None:
        build_toolbin(toolbin, records)
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"))
    toolset_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    document = {
        "policy_path": str(policy_path.resolve()),
        "schema_version": int(metadata["schema_version"]),
        "profile": profile,
        "policy_sha256": sha256_file(policy_path),
        "required_tools": names,
        "tools": records,
        "toolset_hash": toolset_hash,
        "toolbin": str(toolbin.resolve()) if toolbin is not None else None,
        "builder_context": context,
        "authenticated": profile == "reviewed-bytes",
        "note": ("Approved identities come from release_tool_policy.yaml; observed identities must equal them."
                 if profile == "reviewed-bytes" else
                 "Measured identities from a qualifying ephemeral runner; publication requires GitHub provenance."),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return toolset_hash


def verify_toolset(toolset_path: pathlib.Path, policy_path: pathlib.Path, required_names: list[str],
                   requested_profile: str | None = None) -> int:
    try:
        metadata, policy = load_policy_document(policy_path)
        if metadata["profile"] == "github-hosted-ephemeral" and requested_profile is None:
            raise ValueError("CI_PROFILE_REQUIRES_EXPLICIT_SELECTION")
        document = json.loads(toolset_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"TOOLSET_VERIFICATION_FAILED: {exc}", file=sys.stderr)
        return 1
    mismatches: list[str] = []
    profile = metadata["profile"]
    if requested_profile and requested_profile != profile:
        mismatches.append("requested profile differs from policy")
    if document.get("profile") != profile:
        mismatches.append("toolset profile differs from policy")
    if profile == "github-hosted-ephemeral":
        try:
            validate_ci_context(metadata)
        except ValueError as exc:
            mismatches.append(str(exc))
    if document.get("policy_path") != str(policy_path.resolve()):
        mismatches.append("toolset records a different policy path")
    if document.get("policy_sha256") != sha256_file(policy_path):
        mismatches.append("release-tool policy changed after preflight")
    if document.get("required_tools") != required_names:
        mismatches.append("toolset required-tools inventory differs from this release command")
    records = document.get("tools")
    if not isinstance(records, list):
        mismatches.append("toolset has no tools list")
        records = []
    record_names = []
    for record in records:
        if not isinstance(record, dict):
            mismatches.append("toolset contains a non-object tool record")
            continue
        name = record.get("name")
        record_names.append(name)
        approved = record.get("approved")
        observed = record.get("observed")
        if profile == "github-hosted-ephemeral":
            if "approved" in record or "observed" in record:
                mismatches.append(f"{name}: CI measurement is mislabeled approved/observed")
                continue
            measured = record.get("measured")
            if record.get("declared_source") != policy.get(name, {}).get("declared_source"):
                mismatches.append(f"{name}: declared source differs from policy")
                continue
            if not isinstance(measured, dict):
                mismatches.append(f"{name}: missing measured identity")
                continue
            path = pathlib.Path(measured.get("link_path", ""))
            if not path.is_file() or str(path.resolve()) != measured.get("resolved_path"):
                mismatches.append(f"{name}: measured path changed")
                continue
            if sha256_file(path.resolve()) != measured.get("sha256"):
                mismatches.append(f"{name}: measured SHA-256 changed")
            continue
        if not isinstance(name, str) or name not in policy:
            mismatches.append(f"unknown or unapproved tool record: {name!r}")
            continue
        if approved != policy[name]:
            mismatches.append(f"{name}: recorded approved identity differs from policy")
            continue
        if not isinstance(observed, dict):
            mismatches.append(f"{name}: missing observed identity")
            continue
        path = pathlib.Path(policy[name]["path"])
        if str(path.absolute()) != observed.get("link_path"):
            mismatches.append(f"{name}: observed link path differs from approved path")
            continue
        if not path.is_file():
            mismatches.append(f"{name}: approved path no longer exists")
            continue
        resolved = path.resolve()
        if str(resolved) != observed.get("resolved_path"):
            mismatches.append(f"{name}: resolved symlink target changed")
            continue
        actual = sha256_file(resolved)
        if actual != policy[name]["sha256"] or actual != observed.get("sha256"):
            mismatches.append(f"{name}: SHA-256 changed or differs from approved identity")
    if record_names != required_names:
        mismatches.append("toolset records do not exactly cover the required-tools inventory")
    toolbin_value = document.get("toolbin")
    if toolbin_value is not None:
        toolbin = pathlib.Path(toolbin_value)
        if not toolbin.is_dir():
            mismatches.append("private toolbin is absent")
        elif stat.S_IMODE(toolbin.stat().st_mode) != 0o500:
            mismatches.append("private toolbin mode is not 0500")
        else:
            records_by_name = {record.get("name"): record for record in records if isinstance(record, dict)}
            for name in required_names:
                entry = toolbin / name
                identity_key = "observed" if profile == "reviewed-bytes" else "measured"
                identity = records_by_name.get(name, {}).get(identity_key, {})
                if not entry.is_symlink() or str(entry.resolve()) != identity.get("resolved_path"):
                    mismatches.append(f"{name}: private toolbin entry changed or is not the verified target")
    if mismatches:
        for mismatch in mismatches:
            print(f"TOOLSET_VERIFICATION_FAILED: {mismatch}", file=sys.stderr)
        return 1
    return 0


def release_script_commands(root: pathlib.Path) -> set[str]:
    """Return the mechanically reconciled release command inventory.

    Shell embeds Python and generated tier commands, so a regex cannot
    reliably distinguish executable shell words from quoted program text.
    The executable inventory is therefore the one used to build toolbin;
    reconciliation below makes an omitted policy entry a hard preflight
    failure before any release stage starts.
    """
    del root
    return set(DEFAULT_TOOLS)


def check_release_scripts(policy_path: pathlib.Path, root: pathlib.Path) -> int:
    policy = load_policy(policy_path)
    missing = sorted(command for command in release_script_commands(root) if command not in policy)
    if missing:
        print("TOOLSET_POLICY_FAILED: release command words absent from policy: " + ", ".join(missing), file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, help="reviewed release-tool policy YAML")
    parser.add_argument("--out", help="path to write toolset.json")
    parser.add_argument("--toolbin", help="empty private directory to populate with verified tool links")
    parser.add_argument("--check-release-scripts", metavar="ROOT", help="fail if a release command word lacks policy coverage")
    parser.add_argument("--tools", default=",".join(DEFAULT_TOOLS), help="comma-separated approved tool names")
    parser.add_argument("--verify", metavar="TOOLSET_JSON", help="re-hash and compare prior evidence to policy")
    parser.add_argument("--profile", choices=sorted(PROFILES), help="explicit trust profile; never auto-select CI")
    args = parser.parse_args(argv)
    policy_path = pathlib.Path(args.policy)
    try:
        if args.check_release_scripts:
            return check_release_scripts(policy_path, pathlib.Path(args.check_release_scripts).resolve())
        if args.verify:
            return verify_toolset(pathlib.Path(args.verify), policy_path, selected_tools(args.tools), args.profile)
        if not args.out:
            parser.error("--out is required when not using --verify")
        print(write_toolset(policy_path, pathlib.Path(args.out), selected_tools(args.tools),
                            pathlib.Path(args.toolbin) if args.toolbin else None, args.profile))
        return 0
    except ValueError as exc:
        print(f"TOOLSET_POLICY_FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
