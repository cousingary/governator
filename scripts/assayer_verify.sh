#!/usr/bin/env bash
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
#   scripts/assayer_verify.sh --assayer-repo <path>
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
while [ $# -gt 0 ]; do
  case "$1" in
  --assayer-repo)
    ASSAYER_REPO=$2
    shift 2
    ;;
  *)
    usage
    ;;
  esac
done
[ -n "$ASSAYER_REPO" ] || usage

PYPROJECT="$ASSAYER_REPO/pyproject.toml"
[ -f "$PYPROJECT" ] || { echo "assayer_verify: $PYPROJECT not found" >&2; exit 1; }

VERSION=$(python3 -c "
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r'(?m)^\s*version\s*=\s*\"([^\"]+)\"', text)
if not m:
    sys.exit('assayer_verify: no version = \"...\" field found in ' + sys.argv[1])
print(m.group(1))
" "$PYPROJECT")
[ -n "$VERSION" ] || { echo "assayer_verify: pyproject.toml declares an empty version" >&2; exit 1; }

HEAD_COMMIT=$(git -C "$ASSAYER_REPO" rev-parse HEAD)

TAG=""
for candidate in "v${VERSION}" "${VERSION}"; do
  if git -C "$ASSAYER_REPO" rev-parse --verify -q "refs/tags/${candidate}^{commit}" >/dev/null; then
    TAG="$candidate"
    break
  fi
done

if [ -z "$TAG" ]; then
  echo "assayer_verify: declared version ${VERSION} has no matching Git tag (tried v${VERSION} and ${VERSION}) in ${ASSAYER_REPO}" >&2
  exit 1
fi

TAG_COMMIT=$(git -C "$ASSAYER_REPO" rev-parse "refs/tags/${TAG}^{commit}")
if [ "$TAG_COMMIT" != "$HEAD_COMMIT" ]; then
  echo "assayer_verify: tag ${TAG} for declared version ${VERSION} points at ${TAG_COMMIT}, but HEAD is ${HEAD_COMMIT}" >&2
  exit 1
fi

echo "assayer_verify: OK ${TAG} (version ${VERSION}) == HEAD ${HEAD_COMMIT}"
