#!/usr/bin/env python3
"""scripts/source_closure.py — rc8-upg15 S5 (Sol15 P0-2): source-closure
archive and per-object tree manifest from an exact Git ref.

Produces, from an exact ref, a deterministic source archive (git archive)
plus a per-object tree manifest recording for every tracked object: relative
canonical path, file type, mode, SHA-256, and symlink target where
applicable. The manifest uses deterministic (sorted) ordering; verify rejects
duplicate or reordered entries (Sol's attack).

The verify path reuses safe_extract's safety primitives (path-traversal
rejection, absolute-path rejection, device-node rejection) while allowing
symlinks that stay within the tree — source trees legitimately contain them.

Usage:
  source_closure.py generate \
    --repo PATH --ref REF --out-archive PATH --out-tree PATH \
    [--git-bin PATH] [--tar-bin PATH]

  source_closure.py verify \
    --archive PATH --tree PATH [--dest DIR]

Exit 0 on success. Exit 1 with a diagnostic on any failure.
"""
import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import tarfile
import tempfile

from safe_extract import UnsafeArchiveError


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    return sha256_bytes(pathlib.Path(path).read_bytes())


def generate(repo: str, ref: str, out_archive: str, out_tree: str,
             git_bin: str = "git", tar_bin: str = "tar",
             require_files: tuple[str, ...] = ()) -> int:
    repo = os.path.abspath(repo)
    commit = subprocess.run(
        [git_bin, "-C", repo, "rev-parse", ref],
        capture_output=True, text=True,
    )
    if commit.returncode != 0:
        print(f"source_closure: cannot resolve ref {ref!r}: {commit.stderr.strip()}", file=sys.stderr)
        return 1
    commit_sha = commit.stdout.strip()

    ls_tree = subprocess.run(
        [git_bin, "-C", repo, "ls-tree", "-r", "-t", "--format=%(objectmode) %(objecttype) %(objectname) %(path)", ref],
        capture_output=True, text=True,
    )
    if ls_tree.returncode != 0:
        print(f"source_closure: git ls-tree failed: {ls_tree.stderr.strip()}", file=sys.stderr)
        return 1

    entries = []
    seen_paths = set()
    for line in sorted(ls_tree.stdout.splitlines()):
        if not line.strip():
            continue
        parts = line.split(" ", 3)
        if len(parts) < 4:
            continue
        mode_str, obj_type, obj_sha, path = parts
        if obj_type == "tree":
            continue
        if path in seen_paths:
            print(f"source_closure: DUPLICATE_PATH in git ls-tree: {path!r}", file=sys.stderr)
            return 1
        seen_paths.add(path)

        mode_int = int(mode_str, 8)
        if obj_type == "commit":
            continue
        elif mode_str == "120000":
            entry = {
                "path": path,
                "type": "symlink",
                "mode": format(stat.S_IMODE(mode_int), "04o"),
                "sha256": obj_sha,
            }
            blob = subprocess.run(
                [git_bin, "-C", repo, "cat-file", "blob", obj_sha],
                capture_output=True,
            )
            if blob.returncode == 0:
                entry["symlink_target"] = blob.stdout.decode("utf-8", errors="replace").rstrip("\n")
            entries.append(entry)
        elif obj_type == "blob":
            blob = subprocess.run(
                [git_bin, "-C", repo, "cat-file", "blob", obj_sha],
                capture_output=True,
            )
            if blob.returncode != 0:
                print(f"source_closure: cannot read blob {obj_sha} for {path!r}", file=sys.stderr)
                return 1
            content_sha = sha256_bytes(blob.stdout)
            entry = {
                "path": path,
                "type": "file",
                "mode": format(stat.S_IMODE(mode_int), "04o"),
                "sha256": content_sha,
            }
            entries.append(entry)

    entries.sort(key=lambda e: e["path"])

    # v16 R8: LICENSE alone does not carry third-party attribution for
    # adapted content (internal/minimalism's ponytail ruleset). --require-files
    # is opt-in per caller (audit_bundle.sh passes it for the Governator
    # closure only, not Assayer's, which carries no such adaptation) so a
    # repo with a genuinely different licensing shape isn't blocked by a
    # requirement that doesn't apply to it.
    missing_required_files = [f for f in require_files if f not in seen_paths]
    if missing_required_files:
        print(
            f"source_closure: MISSING_REQUIRED_FILES: ref {ref!r} lacks required "
            f"top-level file(s) {missing_required_files} -- a source closure without "
            "third-party attribution is not a licensing-complete release",
            file=sys.stderr,
        )
        return 1

    archive_proc = subprocess.run(
        [git_bin, "-C", repo, "archive", "--format=tar.gz", "--prefix=", ref],
        capture_output=True,
    )
    if archive_proc.returncode != 0:
        print(f"source_closure: git archive failed: {archive_proc.stderr.decode().strip()}", file=sys.stderr)
        return 1
    pathlib.Path(out_archive).write_bytes(archive_proc.stdout)
    archive_sha = sha256_bytes(archive_proc.stdout)

    tree_manifest = {
        "format_version": 1,
        "ref": ref,
        "commit": commit_sha,
        "archive_sha256": archive_sha,
        "entry_count": len(entries),
        "entries": entries,
    }
    pathlib.Path(out_tree).write_text(
        json.dumps(tree_manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    print(f"source_closure: generated {out_archive} ({len(entries)} objects, sha256={archive_sha})", file=sys.stderr)
    return 0


def _check_member_safety(name: str, dest: pathlib.Path) -> None:
    if os.path.isabs(name):
        raise UnsafeArchiveError(f"ABSOLUTE_PATH: member {name!r} is an absolute path")
    normalized = os.path.normpath(name)
    if normalized.startswith("..") or "/../" in ("/" + normalized + "/"):
        raise UnsafeArchiveError(f"PATH_TRAVERSAL: member {name!r} escapes the extraction directory")
    target = (dest / normalized).resolve()
    if not str(target).startswith(str(dest) + os.sep) and target != dest:
        raise UnsafeArchiveError(f"PATH_TRAVERSAL: member {name!r} resolves outside the extraction directory")


def verify(archive: str, tree: str, dest: str | None = None) -> int:
    tree_data = json.loads(pathlib.Path(tree).read_text(encoding="utf-8"))
    entries = tree_data.get("entries", [])
    expected_archive_sha = tree_data.get("archive_sha256", "")

    actual_archive_sha = sha256_file(archive)
    if expected_archive_sha and actual_archive_sha != expected_archive_sha:
        print(
            f"source_closure: ARCHIVE_HASH_MISMATCH: tree manifest declares {expected_archive_sha}, "
            f"archive is {actual_archive_sha}",
            file=sys.stderr,
        )
        return 1

    paths_in_order = [e["path"] for e in entries]
    if paths_in_order != sorted(paths_in_order):
        print("source_closure: REORDERED_ENTRIES: tree manifest entries are not in sorted order", file=sys.stderr)
        return 1
    if len(paths_in_order) != len(set(paths_in_order)):
        print("source_closure: DUPLICATE_ENTRIES: tree manifest contains duplicate paths", file=sys.stderr)
        return 1

    if tree_data.get("entry_count") != len(entries):
        print(
            f"source_closure: ENTRY_COUNT_MISMATCH: declared {tree_data.get('entry_count')}, "
            f"actual {len(entries)}",
            file=sys.stderr,
        )
        return 1

    cleanup = False
    if dest is None:
        dest = tempfile.mkdtemp(prefix="source_closure_verify_")
        cleanup = True
    dest_path = pathlib.Path(dest).resolve()
    dest_path.mkdir(parents=True, exist_ok=True)

    try:
        seen_in_archive: set[str] = set()
        expected_by_path = {e["path"]: e for e in entries}

        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                name = member.name
                if name in seen_in_archive:
                    print(f"source_closure: DUPLICATE_MEMBER in archive: {name!r}", file=sys.stderr)
                    return 1
                seen_in_archive.add(name)

                _check_member_safety(name, dest_path)

                if member.isdev() or member.isfifo() or member.ischr() or member.isblk():
                    raise UnsafeArchiveError(
                        f"DEVICE_MEMBER: member {name!r} is a device/fifo node"
                    )

                if member.isdir():
                    continue

                if name not in expected_by_path:
                    print(f"source_closure: UNEXPECTED_MEMBER: {name!r} not in tree manifest", file=sys.stderr)
                    return 1

                expected = expected_by_path[name]

                if member.issym():
                    if expected["type"] != "symlink":
                        print(
                            f"source_closure: TYPE_MISMATCH: {name!r} is a symlink in archive "
                            f"but {expected['type']!r} in manifest",
                            file=sys.stderr,
                        )
                        return 1
                    link_target = member.linkname
                    expected_target = expected.get("symlink_target", "")
                    if expected_target and link_target != expected_target:
                        print(
                            f"source_closure: SYMLINK_TARGET_MISMATCH: {name!r} -> {link_target!r}, "
                            f"manifest declares {expected_target!r}",
                            file=sys.stderr,
                        )
                        return 1
                    link_normalized = os.path.normpath(
                        os.path.join(os.path.dirname(name), link_target)
                    )
                    resolved_link = (dest_path / link_normalized).resolve()
                    if not str(resolved_link).startswith(str(dest_path) + os.sep) and resolved_link != dest_path:
                        raise UnsafeArchiveError(
                            f"SYMLINK_ESCAPE: member {name!r} symlinks to {link_target!r} which escapes"
                        )
                elif member.isfile():
                    if expected["type"] != "file":
                        print(
                            f"source_closure: TYPE_MISMATCH: {name!r} is a file in archive "
                            f"but {expected['type']!r} in manifest",
                            file=sys.stderr,
                        )
                        return 1
                    src = tf.extractfile(member)
                    if src is None:
                        print(f"source_closure: UNREADABLE_MEMBER: {name!r}", file=sys.stderr)
                        return 1
                    content = src.read()
                    content_sha = sha256_bytes(content)
                    if content_sha != expected["sha256"]:
                        print(
                            f"source_closure: CONTENT_MISMATCH: {name!r} sha256={content_sha}, "
                            f"manifest declares {expected['sha256']}",
                            file=sys.stderr,
                        )
                        return 1
                    actual_exec = bool(stat.S_IMODE(member.mode) & 0o100)
                    expected_exec = int(expected["mode"], 8) & 0o100 != 0
                    if actual_exec != expected_exec:
                        print(
                            f"source_closure: MODE_MISMATCH: {name!r} executable={actual_exec}, "
                            f"manifest declares executable={expected_exec}",
                            file=sys.stderr,
                        )
                        return 1
                else:
                    raise UnsafeArchiveError(
                        f"NON_REGULAR_MEMBER: member {name!r} is not a regular file or symlink"
                    )

        missing = set(expected_by_path.keys()) - seen_in_archive
        if missing:
            print(
                f"source_closure: MISSING_MEMBERS: archive lacks {len(missing)} entries from manifest: "
                f"{sorted(missing)[:10]}{'...' if len(missing) > 10 else ''}",
                file=sys.stderr,
            )
            return 1

    except UnsafeArchiveError as exc:
        print(f"source_closure: UNSAFE_ARCHIVE: {exc}", file=sys.stderr)
        return 1
    finally:
        if cleanup:
            import shutil
            shutil.rmtree(dest, ignore_errors=True)

    print(
        f"source_closure: OK — {archive} verified against {tree} "
        f"({len(entries)} objects, commit {tree_data.get('commit', '?')})",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Source-closure archive and tree manifest")
    sub = p.add_subparsers(dest="command")

    gen = sub.add_parser("generate")
    gen.add_argument("--repo", required=True)
    gen.add_argument("--ref", required=True)
    gen.add_argument("--out-archive", required=True)
    gen.add_argument("--out-tree", required=True)
    gen.add_argument("--git-bin", default="git")
    gen.add_argument("--tar-bin", default="tar")
    gen.add_argument("--require-files", default="",
                      help="comma-separated top-level paths that must be tracked at ref (e.g. LICENSE,NOTICE)")

    ver = sub.add_parser("verify")
    ver.add_argument("--archive", required=True)
    ver.add_argument("--tree", required=True)
    ver.add_argument("--dest", default=None)

    args = p.parse_args(argv)
    if args.command == "generate":
        require_files = tuple(f for f in args.require_files.split(",") if f)
        return generate(args.repo, args.ref, args.out_archive, args.out_tree,
                        args.git_bin, args.tar_bin, require_files)
    elif args.command == "verify":
        return verify(args.archive, args.tree, args.dest)
    else:
        p.print_help(sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
