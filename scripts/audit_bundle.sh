#!/usr/bin/env bash
# scripts/audit_bundle.sh — Sol9 P2-2: the single, canonical audit/source
# bundle generator.
#
# Before this script, the audit archive handed to a reviewer read like a
# plain directory tar: it contained a partial .venv, Python/pytest caches,
# .codegraph/, a stray .tmp_debug_docker.go, egg-info, release/runtime
# byproducts, AND a stale rc1-dirty bin/gov sitting next to the real
# dist/gov -- letting a reader accidentally treat the wrong binary as "the
# release." This script never walks the working tree directly for source/:
# `git archive` is its only source of source/ contents, and it can only
# ever emit committed, tracked bytes at a given ref -- every one of the
# above categories is structurally impossible to include, not merely
# git-ignored-and-hoped-not-there. A post-build scan still asserts none of
# the named contamination patterns exist anywhere in the finished bundle,
# so a regression (e.g. a future change that copies from the working tree
# instead of the archive) fails loudly instead of shipping quietly.
#
# Output structure (Sol9 report's recommendation):
#   source/        exact tracked tree at REF (git archive)
#   dist/          scripts/release.sh's own output, verbatim, if present
#   architecture/  the standalone architecture doc + its build metadata
#   evidence/      claims.yaml + release/test/acceptance evidence for REF
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

REF=${REF:-HEAD}
OUT_DIR=${OUT_DIR:-audit-bundle}
DIST_DIR=${DIST_DIR:-dist}
ARCHITECTURE_DOC=${GOV_ARCHITECTURE_DOC:-$ROOT/../agents/governator_architecture.md}

if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
  echo "audit_bundle: refusing to bundle a dirty tree (uncommitted/untracked changes present) -- commit or stash first" >&2
  exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/source" "$OUT_DIR/dist" "$OUT_DIR/architecture" "$OUT_DIR/evidence"

# --- source/: exactly the tracked tree at REF, nothing else is possible ----
git archive --format=tar "$REF" | tar -x -C "$OUT_DIR/source"

# --- dist/: whatever scripts/release.sh already produced, verbatim --------
if [ -d "$DIST_DIR" ] && [ -n "$(ls -A "$DIST_DIR" 2>/dev/null)" ]; then
  cp -a "$DIST_DIR"/. "$OUT_DIR/dist/"
else
  echo "audit_bundle: WARNING: $DIST_DIR is empty or absent -- run scripts/release.sh first for a populated dist/ tier" >&2
fi
# A stray previous audit_bundle.sh output nested inside dist/ (from running
# this script with OUT_DIR unset, twice, into the default location under the
# repo root) must never recurse into itself.
rm -rf "$OUT_DIR/dist/$(basename "$OUT_DIR")"

# --- architecture/: the standalone doc + its build metadata ---------------
if [ -f "$ARCHITECTURE_DOC" ]; then
  cp "$ARCHITECTURE_DOC" "$OUT_DIR/architecture/"
  if ! python3 "$ROOT/scripts/check_architecture_doc.py" "$OUT_DIR/architecture/$(basename "$ARCHITECTURE_DOC")"; then
    echo "audit_bundle: refusing to ship a bundle with a stale architecture doc (see above)" >&2
    exit 1
  fi
else
  echo "audit_bundle: WARNING: architecture doc not found at $ARCHITECTURE_DOC" >&2
fi
if [ -f "$OUT_DIR/dist/architecture-build-metadata.json" ]; then
  cp "$OUT_DIR/dist/architecture-build-metadata.json" "$OUT_DIR/architecture/"
fi

# --- evidence/: release/test/acceptance evidence for this ref -------------
for f in test-summary.json acceptance-summary.json claims-verify-report.txt \
  build-manifest.json checksums.txt checksums.txt.minisig checksums.txt.hmac; do
  if [ -f "$OUT_DIR/dist/$f" ]; then
    cp "$OUT_DIR/dist/$f" "$OUT_DIR/evidence/$f"
  fi
done

# ---------------------------------------------------------------------------
# claims.yaml provenance (Sol9 P2-2: "current source is two documentation
# commits ahead of the release commit; docs/claims.yaml therefore differs
# from the claims embedded in the release"). This bundle can legitimately
# carry TWO different claims.yaml files with two different meanings --
# source/docs/claims.yaml (current source tree at REF) and dist/claims.yaml
# (the exact bytes release.sh hashed into CLAIMS_HASH and embedded in the
# shipped binary via -ldflags, frozen at build time, possibly from an
# earlier commit than REF). evidence/ never gets a third, unlabeled copy --
# that is exactly the ambiguity the audit found. Instead this always writes
# an explicit provenance record naming both paths, both hashes, and whether
# they diverge, so a reader is never left to guess which is authoritative
# for what.
# ---------------------------------------------------------------------------
CLAIMS_PROVENANCE="$OUT_DIR/evidence/CLAIMS_PROVENANCE.txt"
SOURCE_CLAIMS_SHA=$(sha256sum "$OUT_DIR/source/docs/claims.yaml" | awk '{print $1}')
{
  echo "source/docs/claims.yaml (current source tree at ${REF}): sha256=${SOURCE_CLAIMS_SHA}"
  if [ -f "$OUT_DIR/dist/claims.yaml" ]; then
    DIST_CLAIMS_SHA=$(sha256sum "$OUT_DIR/dist/claims.yaml" | awk '{print $1}')
    echo "dist/claims.yaml (frozen into the shipped release build, may predate ${REF}): sha256=${DIST_CLAIMS_SHA}"
    if [ "$SOURCE_CLAIMS_SHA" = "$DIST_CLAIMS_SHA" ]; then
      echo "status: identical -- no divergence between current source and the shipped release."
    else
      echo "status: DIVERGENT -- current source/docs/claims.yaml differs from the claims embedded in dist/. This is expected when source has moved on since the release commit; treat source/ as current, dist/ as historical record of what that specific release actually shipped. Do not conflate the two."
    fi
  else
    echo "dist/claims.yaml: absent (no dist/ tier populated for this bundle -- run scripts/release.sh first if a frozen release copy is needed)."
  fi
} >"$CLAIMS_PROVENANCE"

# ---------------------------------------------------------------------------
# Post-build contamination scan (belt-and-suspenders): the exact categories
# the audit found, asserted absent from the finished bundle by content, not
# assumed absent because of how it was built.
# ---------------------------------------------------------------------------
CONTAMINATION_FOUND=false
while IFS= read -r -d '' hit; do
  echo "audit_bundle: contamination in bundle: $hit" >&2
  CONTAMINATION_FOUND=true
done < <(find "$OUT_DIR" \( \
  -name '.venv' -o -name 'venv' -o -name '__pycache__' -o -name '*.egg-info' \
  -o -name '.codegraph' -o -name '.tmp_debug_*' -o -name 'gov.bak-*' \
  -o -path '*/bin/gov' \
  \) -print0)
if [ "$CONTAMINATION_FOUND" = true ]; then
  echo "audit_bundle: refusing to ship a bundle containing the above -- this indicates a regression in this script, not the source tree" >&2
  exit 1
fi

echo "audit_bundle: OK — $OUT_DIR" >&2
find "$OUT_DIR" -maxdepth 2 >&2
