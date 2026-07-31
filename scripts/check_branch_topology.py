#!/usr/bin/env python3
"""v16-release R1 / case 394: pre-publication branch-and-tag topology gate.

R1 (BLOCKER): the entire rc7/rc8 program lived on an unmerged side branch
while `main` was 45+ commits stale. A release tag the release branch cannot
reach is the sharpest failure mode of a stale default branch:

  - `.github/workflows/ci.yml` triggers on `push: branches: [main]` and would
    test a stale tree, not the one the signed release evidence points at;
  - `go install github.com/cousingary/governator/cmd/gov@latest` resolves the
    highest non-prerelease tag reachable from the default branch -- a stale
    `main` ships a build predating the whole release program.

`scripts/release.sh` fast-forwards nothing itself; the operator owns the merge
back to `main` (v16-release S2). This checker is the durable half of that fix:
it refuses a release while any `v*` semver release tag is unreachable from the
release branch. It is a topology assertion, not a history rewriter -- it does
not move refs, it only reports reachability.

Usage:
  check_branch_topology.py [--repo DIR] [--release-branch NAME]

Exits non-zero with:
  RELEASE_BRANCH_MISSING           the designated release branch does not exist
  RELEASE_TAG_UNREACHABLE_FROM_RELEASE_BRANCH  one or more release tags are
                                   not ancestors of the release branch
"""
import argparse
import re
import subprocess
import sys

# A Governator release tag is a leading-dot semver: v1.0.0, v1.0.2-rc8, v1.0.2.
# It deliberately excludes branch-like refs and any non-version tags. The rc
# suffix is part of the published tag set (rc1..rc8) and MUST be reachable too
# -- a stale main that drops the rc program is exactly R1.
RELEASE_TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?$")


def _git(repo, *args):
    """Run git -C <repo> and return (stdout_text, returncode)."""
    proc = subprocess.run(
        ["git", "-C", repo, *args],
        check=False,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip(), proc.returncode


def check_topology(repo, release_branch):
    # The release branch must exist as a local ref. A detached HEAD or a
    # feature-only checkout has no `main`, and that is itself a release
    # blocker -- there is no branch for tags to be reachable from.
    _, rc = _git(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{release_branch}")
    if rc != 0:
        print(
            f"check_branch_topology: FAIL -- RELEASE_BRANCH_MISSING: the "
            f"release branch '{release_branch}' does not exist in {repo}. "
            "The release branch is where CI triggers and where "
            "`go install @latest` resolves from; a release cannot ship "
            "without it.",
            file=sys.stderr,
        )
        return 1

    out, _ = _git(repo, "tag", "-l")
    release_tags = sorted({t for t in out.splitlines() if RELEASE_TAG_RE.match(t)})

    unreachable = []
    for tag in release_tags:
        # merge-base --is-ancestor <tag> <branch>: exit 0 => tag is an
        # ancestor of branch (reachable); exit 1 => not an ancestor.
        _, rc = _git(repo, "merge-base", "--is-ancestor", tag, release_branch)
        if rc != 0:
            unreachable.append(tag)

    if unreachable:
        print(
            f"check_branch_topology: FAIL -- RELEASE_TAG_UNREACHABLE_FROM_"
            f"RELEASE_BRANCH: {unreachable} are not reachable from "
            f"release branch '{release_branch}'. A release tag the default "
            "branch cannot reach is the R1 failure mode: CI would test a "
            "stale tree and `go install @latest` would resolve a build "
            "predating the release program. Merge the release branch back "
            "to '{0}' before shipping.".format(release_branch),
            file=sys.stderr,
        )
        return 1

    print(
        f"check_branch_topology: OK -- all {len(release_tags)} release tag(s) "
        f"reachable from '{release_branch}' ({release_tags})",
        file=sys.stderr,
    )
    return 0


def main(argv):
    parser = argparse.ArgumentParser(
        description="Pre-publication branch/tag topology gate (v16 R1).",
    )
    parser.add_argument("--repo", default=".", help="repository path (default: cwd)")
    parser.add_argument(
        "--release-branch",
        default="main",
        help="the branch release tags must be reachable from (default: main)",
    )
    args = parser.parse_args(argv)
    return check_topology(args.repo, args.release_branch)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
