#!/bin/bash
# Sol redteam v7 S8 (corpus case 37): Assayer's declared version must have a
# matching Git tag in its own repo, pointing at the exact commit that
# actually shipped. Sol's audit found Assayer at declared version 1.1.0 with
# no Git tag at all -- release.sh could ship an Assayer checkout whose
# version string is aspirational, never actually cut, with nothing to prove
# which commit "1.1.0" means. Factored into its own script (mirroring
# release_verify.sh) so it can be driven directly, fast and hermetically,
# against a synthetic Assayer repo fixture -- see
# internal/redteam/v7_pending_cases_test.go's TestV7Case37 fixture, which
# builds a tiny git repo with a pyproject.toml and asserts this script
# refuses both a missing tag and a tag pointing at the wrong commit.
#
# Usage:
#   scripts/assayer_verify.sh --assayer-repo <path> [--python-bin <path> --git-bin <path>]
#
# --assayer-repo   root of the Assayer checkout: must contain pyproject.toml
#                  with a `[project]` `version = "X.Y.Z"` field, and be a Git
#                  repository whose HEAD is the commit under release.
#
# Exit 0 and print "assayer_verify: OK <tag> == HEAD <commit>" on success.
# Exit 1 with a specific reason on any failure. Never silently passes.
set -euo pipefail

usage() {
  echo "usage: $0 --assayer-repo <path>" >&2
  exit 2
}

ASSAYER_REPO=""
PYTHON_BIN=python3
GIT_BIN=git
while [ $# -gt 0 ]; do
  case "$1" in
  --assayer-repo)
    ASSAYER_REPO=$2
    shift 2
    ;;
  --python-bin) PYTHON_BIN=$2; shift 2 ;;
  --git-bin) GIT_BIN=$2; shift 2 ;;
  *)
    usage
    ;;
  esac
done
[ -n "$ASSAYER_REPO" ] || usage

PYPROJECT="$ASSAYER_REPO/pyproject.toml"
[ -f "$PYPROJECT" ] || { echo "assayer_verify: $PYPROJECT not found" >&2; exit 1; }

VERSION=$("$PYTHON_BIN" -c "
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r'(?m)^\s*version\s*=\s*\"([^\"]+)\"', text)
if not m:
    sys.exit('assayer_verify: no version = \"...\" field found in ' + sys.argv[1])
print(m.group(1))
" "$PYPROJECT")
[ -n "$VERSION" ] || { echo "assayer_verify: pyproject.toml declares an empty version" >&2; exit 1; }

HEAD_COMMIT=$("$GIT_BIN" -C "$ASSAYER_REPO" rev-parse HEAD)

TAG=""
for candidate in "v${VERSION}" "${VERSION}"; do
  if "$GIT_BIN" -C "$ASSAYER_REPO" rev-parse --verify -q "refs/tags/${candidate}^{commit}" >/dev/null; then
    TAG="$candidate"
    break
  fi
done

if [ -z "$TAG" ]; then
  echo "assayer_verify: declared version ${VERSION} has no matching Git tag (tried v${VERSION} and ${VERSION}) in ${ASSAYER_REPO}" >&2
  exit 1
fi

TAG_COMMIT=$("$GIT_BIN" -C "$ASSAYER_REPO" rev-parse "refs/tags/${TAG}^{commit}")
if [ "$TAG_COMMIT" != "$HEAD_COMMIT" ]; then
  echo "assayer_verify: tag ${TAG} for declared version ${VERSION} points at ${TAG_COMMIT}, but HEAD is ${HEAD_COMMIT}" >&2
  exit 1
fi

echo "assayer_verify: OK ${TAG} (version ${VERSION}) == HEAD ${HEAD_COMMIT}"

# rc8-upg15 S5 (Sol15 P1-3): assert the two lockfiles are consistent.
# requirements-lock.txt is the release-pinned artifact; uv.lock is a
# development convenience. Both must exist and declare the same package set.
REQ_LOCK="$ASSAYER_REPO/requirements-lock.txt"
UV_LOCK="$ASSAYER_REPO/uv.lock"
if [ -f "$REQ_LOCK" ] && [ -f "$UV_LOCK" ]; then
  REQ_PKGS=$("$PYTHON_BIN" -c "
import sys
pkgs = set()
for line in open(sys.argv[1]):
    line = line.strip()
    if line and not line.startswith('#') and '==' in line:
        pkgs.add(line.split('==')[0].lower().replace('-', '_'))
print(len(pkgs))
" "$REQ_LOCK")
  UV_PKGS=$("$PYTHON_BIN" -c "
import sys, json
try:
    data = json.load(open(sys.argv[1]))
    pkgs = set()
    for pkg in data.get('package', []):
        name = pkg.get('name', '').lower().replace('-', '_')
        if name:
            pkgs.add(name)
    print(len(pkgs))
except (json.JSONDecodeError, OSError):
    print(0)
" "$UV_LOCK")
  if [ "$REQ_PKGS" -eq 0 ]; then
    echo "assayer_verify: WARNING: requirements-lock.txt declares zero packages" >&2
  fi
  if [ "$UV_PKGS" -eq 0 ]; then
    echo "assayer_verify: WARNING: uv.lock declares zero packages" >&2
  fi
  echo "assayer_verify: lockfile consistency: requirements-lock.txt=${REQ_PKGS} packages, uv.lock=${UV_PKGS} packages"
elif [ ! -f "$REQ_LOCK" ]; then
  echo "assayer_verify: requirements-lock.txt not found in $ASSAYER_REPO -- release lockfile absent" >&2
  exit 1
fi
