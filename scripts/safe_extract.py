#!/usr/bin/env python3
"""scripts/safe_extract.py — rc8-upg15 S4 (Sol15 P1-1): reusable safe tar.gz
extraction with a strict member allow-list.

Rejects absolute member paths, .. traversal, symlink escapes, hard-link
escapes, duplicate paths, unexpected members, and device/fifo members.
Extracts only allow-listed regular-file members into a fresh destination
directory.

This module is the single safe-extraction primitive for the release pipeline.
scripts/install_evidence.py uses it to verify the contained binary; S5's
scripts/source_closure.py must import it rather than fork a second
implementation.

Usage as a library:
    from safe_extract import safe_extract_tar
    members = safe_extract_tar(archive_path, dest_dir, allow_list={"gov"})

Usage as a CLI (diagnostic):
    safe_extract.py --archive PATH --dest DIR --allow gov [,gov2 ...]
"""
import os
import pathlib
import stat
import sys
import tarfile


class UnsafeArchiveError(Exception):
    """Raised when an archive member violates the safety policy."""


def safe_extract_tar(
    archive_path: str,
    dest_dir: str,
    allow_list: set[str],
) -> dict[str, str]:
    """Extract allow-listed regular-file members from a .tar.gz archive.

    Returns a dict mapping member name -> extracted absolute path.
    Raises UnsafeArchiveError on any policy violation.
    """
    dest = pathlib.Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    seen: set[str] = set()
    extracted: dict[str, str] = {}

    with tarfile.open(archive_path, "r:gz") as tf:
        for member in tf.getmembers():
            name = member.name

            if name in seen:
                raise UnsafeArchiveError(
                    f"DUPLICATE_MEMBER: archive contains duplicate entry {name!r}"
                )
            seen.add(name)

            if name not in allow_list:
                raise UnsafeArchiveError(
                    f"UNEXPECTED_MEMBER: {name!r} is not in the allow-list {sorted(allow_list)}"
                )

            if os.path.isabs(name):
                raise UnsafeArchiveError(
                    f"ABSOLUTE_PATH: member {name!r} is an absolute path"
                )

            normalized = os.path.normpath(name)
            if normalized.startswith("..") or "/../" in ("/" + normalized + "/"):
                raise UnsafeArchiveError(
                    f"PATH_TRAVERSAL: member {name!r} escapes the extraction directory"
                )

            target = (dest / normalized).resolve()
            if not str(target).startswith(str(dest) + os.sep) and target != dest:
                raise UnsafeArchiveError(
                    f"PATH_TRAVERSAL: member {name!r} resolves outside the extraction directory"
                )

            if member.issym():
                link_target = os.path.normpath(
                    os.path.join(os.path.dirname(normalized), member.linkname)
                )
                resolved_link = (dest / link_target).resolve()
                if not str(resolved_link).startswith(str(dest) + os.sep) and resolved_link != dest:
                    raise UnsafeArchiveError(
                        f"SYMLINK_ESCAPE: member {name!r} symlinks to {member.linkname!r} which escapes the extraction directory"
                    )
                raise UnsafeArchiveError(
                    f"SYMLINK_MEMBER: member {name!r} is a symlink; only regular files are permitted"
                )

            if member.islnk():
                link_target = os.path.normpath(member.linkname)
                if link_target.startswith("..") or os.path.isabs(member.linkname):
                    raise UnsafeArchiveError(
                        f"HARDLINK_ESCAPE: member {name!r} hard-links to {member.linkname!r} which escapes the extraction directory"
                    )
                resolved_link = (dest / link_target).resolve()
                if not str(resolved_link).startswith(str(dest) + os.sep) and resolved_link != dest:
                    raise UnsafeArchiveError(
                        f"HARDLINK_ESCAPE: member {name!r} hard-links to {member.linkname!r} which escapes the extraction directory"
                    )
                raise UnsafeArchiveError(
                    f"HARDLINK_MEMBER: member {name!r} is a hard link; only regular files are permitted"
                )

            if member.isdev() or member.isfifo() or member.ischr() or member.isblk():
                raise UnsafeArchiveError(
                    f"DEVICE_MEMBER: member {name!r} is a device/fifo node; only regular files are permitted"
                )

            if not member.isfile():
                raise UnsafeArchiveError(
                    f"NON_REGULAR_MEMBER: member {name!r} is not a regular file (type={member.type!r})"
                )

            parent = target.parent
            parent.mkdir(parents=True, exist_ok=True)

            src = tf.extractfile(member)
            if src is None:
                raise UnsafeArchiveError(
                    f"UNREADABLE_MEMBER: could not open {name!r} for extraction"
                )
            with open(target, "wb") as dst:
                while chunk := src.read(65536):
                    dst.write(chunk)

            os.chmod(target, stat.S_IMODE(member.mode))
            extracted[name] = str(target)

    missing = allow_list - set(extracted.keys())
    if missing:
        raise UnsafeArchiveError(
            f"MISSING_MEMBERS: archive does not contain expected entries: {sorted(missing)}"
        )

    return extracted


def main(argv: list[str]) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Safe tar.gz extraction with member allow-list")
    p.add_argument("--archive", required=True)
    p.add_argument("--dest", required=True)
    p.add_argument("--allow", required=True, help="comma-separated member names")
    args = p.parse_args(argv)

    allow = set(args.allow.split(","))
    try:
        result = safe_extract_tar(args.archive, args.dest, allow)
    except UnsafeArchiveError as exc:
        print(f"safe_extract: REJECTED: {exc}", file=sys.stderr)
        return 1
    for name, path in sorted(result.items()):
        print(f"  {name} -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
