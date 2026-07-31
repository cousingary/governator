#!/usr/bin/bash
# scripts/audit_bundle.sh — Sol9 P2-2 / Sol11 P0-2: the single, canonical
# audit/source bundle generator.
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
# Sol11 P0-2: this used to treat ANY nonempty dist/ as sufficient release
# content -- run against a dist/ containing only a truncated
# test-unit.log, it printed "audit_bundle: OK" with a bundle carrying no
# binary/manifest/checksums/signature/summaries. There are now TWO
# EXPLICIT, SEPARATE bundle modes (AUDIT_BUNDLE_MODE):
#   release (the default) -- requires a COMPLETE, verified release dist/
#     (platform archives, checksums.txt + valid signature, build-manifest,
#     architecture-build-metadata, sbom, claims.yaml, test-summary,
#     acceptance-summary, claims-verify-report, every test-evidence log,
#     PASS overall results, zero production red-team skips, exact
#     tag-and-commit match). A partial/incomplete dist/ FAILS LOUDLY with
#     INCOMPLETE_RELEASE_EVIDENCE -- never "audit_bundle: OK".
#   source-only -- invoked explicitly via AUDIT_BUNDLE_MODE=source-only.
#     Skips every release-evidence requirement above; the bundle
#     prominently declares NOT A RELEASE / NO EXECUTABLE ARTIFACT VERIFIED
#     (a file written into the bundle AND printed to stderr).
#
# Output structure (Sol9 report's recommendation):
#   source/        exact tracked tree at REF (git archive)
#   dist/          scripts/release.sh's own output, verbatim, if present
#   architecture/  the standalone architecture doc + its build metadata
#   evidence/      claims.yaml + release/test/acceptance evidence for REF
set -euo pipefail

ROOT=$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)
cd "$ROOT"

PYTHON_BIN=python3
GIT_BIN=git
TAR_BIN=tar
SHA256SUM_BIN=sha256sum
AWK_BIN=awk
CP_BIN=cp
RM_BIN=rm
MKDIR_BIN=mkdir
FIND_BIN=find
BASENAME_BIN=basename
LS_BIN=ls
while [ $# -gt 0 ]; do
  case "$1" in
    --python-bin) PYTHON_BIN=$2; shift 2 ;;
    --git-bin) GIT_BIN=$2; shift 2 ;;
    --tar-bin) TAR_BIN=$2; shift 2 ;;
    --sha256sum-bin) SHA256SUM_BIN=$2; shift 2 ;;
    --awk-bin) AWK_BIN=$2; shift 2 ;;
    --cp-bin) CP_BIN=$2; shift 2 ;;
    --rm-bin) RM_BIN=$2; shift 2 ;;
    --mkdir-bin) MKDIR_BIN=$2; shift 2 ;;
    --find-bin) FIND_BIN=$2; shift 2 ;;
    --basename-bin) BASENAME_BIN=$2; shift 2 ;;
    --ls-bin) LS_BIN=$2; shift 2 ;;
    *) echo "audit_bundle: unsupported argument $1" >&2; exit 2 ;;
  esac
done

REF=${REF:-HEAD}
VERSION=${VERSION:-}
ASSAYER_REPO=${ASSAYER_REPO:-/mnt/e/downloads/assayer}
AUDIT_BUNDLE_MODE=${AUDIT_BUNDLE_MODE:-release}
case "$AUDIT_BUNDLE_MODE" in
  release|source-only) ;;
  *)
    echo "audit_bundle: unsupported AUDIT_BUNDLE_MODE=${AUDIT_BUNDLE_MODE} -- must be 'release' (default) or 'source-only'" >&2
    exit 2
    ;;
esac
# P1-6 (Sol10 rc4 Session 8): the bundle used to land inside the checkout
# by default ("audit-bundle" resolves under $ROOT), which the report found
# can misle source counts, get recursively packaged by a later step, or
# leave an ambiguous dirty-state report. Default to a sibling directory
# now; OUT_DIR set explicitly to anything still resolving inside the
# checkout is refused below, not just discouraged.
OUT_DIR=${OUT_DIR:-"$(cd "$ROOT/.." && pwd)/governator-audit-bundle"}
DIST_DIR=${DIST_DIR:-dist}
ARCHITECTURE_DOC=${GOV_ARCHITECTURE_DOC:-$ROOT/../agents/governator_architecture.md}

if [ -n "$("$GIT_BIN" status --porcelain --untracked-files=all)" ]; then
  echo "audit_bundle: refusing to bundle a dirty tree (uncommitted/untracked changes present) -- commit or stash first" >&2
  exit 1
fi

OUT_DIR_ABS=$("$PYTHON_BIN" -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$OUT_DIR")
case "$OUT_DIR_ABS" in
  "$ROOT"|"$ROOT"/*)
    echo "audit_bundle: refusing to generate the bundle inside the source checkout (${OUT_DIR_ABS} is under ${ROOT}) -- set OUT_DIR to a sibling or /tmp path (P1-6)" >&2
    exit 1
    ;;
esac
OUT_DIR=$OUT_DIR_ABS

"$RM_BIN" -rf "$OUT_DIR"
"$MKDIR_BIN" -p "$OUT_DIR/source" "$OUT_DIR/dist" "$OUT_DIR/architecture" "$OUT_DIR/evidence"

# --- source/: exactly the tracked tree at REF, nothing else is possible ----
"$GIT_BIN" archive --format=tar "$REF" | "$TAR_BIN" -x -C "$OUT_DIR/source"

# --- dist/: whatever scripts/release.sh already produced, verbatim --------
# Exception: dist/assayer-venvs/ is BUILD SCAFFOLDING, not release evidence.
# release.sh materializes one virtualenv per Python in the Assayer support
# matrix (3.10-3.13) to run that tier; the venvs carry pip-installed
# site-packages full of __pycache__, .venv and *.egg-info -- the exact
# categories the contamination scan below refuses by name. They are not
# checksummed, not signed, and not referenced by any manifest: the tier's
# evidence is assayer-python*.log.gz, which IS copied. Copying them in made a
# release-mode bundle impossible (rc6 Session 9 -- first cycle to ever get a
# release-mode bundle this far).
if [ -d "$DIST_DIR" ] && [ -n "$("$LS_BIN" -A "$DIST_DIR" 2>/dev/null)" ]; then
  "$CP_BIN" -a "$DIST_DIR"/. "$OUT_DIR/dist/"
  "$RM_BIN" -rf "$OUT_DIR/dist/assayer-venvs"
else
  echo "audit_bundle: WARNING: $DIST_DIR is empty or absent -- run scripts/release.sh first for a populated dist/ tier" >&2
fi
# A stray previous audit_bundle.sh output nested inside dist/ (from running
# this script with OUT_DIR unset, twice, into the default location under the
# repo root) must never recurse into itself.
"$RM_BIN" -rf "$OUT_DIR/dist/$("$BASENAME_BIN" "$OUT_DIR")"
# A prior release attempt's checkpoint state directory (scripts/
# release_checkpoint.py, P1-5) is internal working state, not shipped
# release evidence -- never part of an audit bundle.
"$RM_BIN" -rf "$OUT_DIR/dist/.checkpoints"

# S8: a machine-readable live-install claim must carry its signed record in
# the bundle itself. An operator may supply the live record outside dist/;
# copy it into the packaged evidence location before release-mode validation.
#
# Sol14 rc7 Session 10: that location is evidence/, NEVER dist/. Installation
# evidence describes installing the finished release, so it necessarily comes
# into existence AFTER checksums.txt was generated and signed -- it can never
# be one of the files checksums.txt covers. Copying it into dist/ (as S8 did)
# therefore put a permanently-uncoverable file inside the very directory
# release_policy.py sweeps for "every shipped file is checksummed", and
# release-mode validation failed closed on `missing: install-evidence.json`
# for every live-install claim -- unsatisfiable by construction. Another path
# that had never run end to end: S8 built and tested the evidence tooling, but
# no release had yet reached a release-mode bundle carrying a real record.
# evidence/ is where the bundle already keeps release/test/acceptance evidence,
# it is outside the coverage sweep, and audit_bundle_validate.py takes the
# record's path explicitly, so nothing is weakened by moving it there.
if [ -n "${INSTALL_EVIDENCE:-}" ]; then
  if [ ! -f "$INSTALL_EVIDENCE" ]; then
    echo "audit_bundle: INSTALL_EVIDENCE does not name a file: $INSTALL_EVIDENCE" >&2
    exit 1
  fi
  "$CP_BIN" "$INSTALL_EVIDENCE" "$OUT_DIR/evidence/install-evidence.json"
fi

if [ "$AUDIT_BUNDLE_MODE" = source-only ]; then
  NOTICE="$OUT_DIR/NOT_A_RELEASE.txt"
  {
    echo "NOT A RELEASE"
    echo "NO EXECUTABLE ARTIFACT VERIFIED"
    echo
    echo "This bundle was generated with AUDIT_BUNDLE_MODE=source-only. It carries"
    echo "the tracked source tree at ${REF} and, if present, whatever release.sh"
    echo "output happened to already exist in ${DIST_DIR} -- NONE of that dist/"
    echo "content has been checked for completeness, and no cryptographic"
    echo "signature, checksum, or test-evidence verification has run. Do not"
    echo "treat any binary or archive in this bundle's dist/ as a verified"
    echo "release artifact. For a verified release bundle, run this script"
    echo "without AUDIT_BUNDLE_MODE set (or AUDIT_BUNDLE_MODE=release) against"
    echo "a dist/ produced by a full, passing scripts/release.sh run."
  } >"$NOTICE"
  echo "audit_bundle: NOT A RELEASE / NO EXECUTABLE ARTIFACT VERIFIED -- AUDIT_BUNDLE_MODE=source-only, see ${NOTICE}" >&2
fi

# --- architecture/: the standalone doc + its build metadata ---------------
if [ -f "$ARCHITECTURE_DOC" ]; then
  "$CP_BIN" "$ARCHITECTURE_DOC" "$OUT_DIR/architecture/"
  if ! "$PYTHON_BIN" "$ROOT/scripts/check_architecture_doc.py" "$OUT_DIR/architecture/$("$BASENAME_BIN" "$ARCHITECTURE_DOC")" --repo "$ROOT" --dist-dir "$OUT_DIR/dist"; then
    echo "audit_bundle: refusing to ship a bundle with a stale/contradictory architecture doc (see above)" >&2
    exit 1
  fi
else
  echo "audit_bundle: WARNING: architecture doc not found at $ARCHITECTURE_DOC" >&2
fi
if [ -f "$OUT_DIR/dist/architecture-build-metadata.json" ]; then
  "$CP_BIN" "$OUT_DIR/dist/architecture-build-metadata.json" "$OUT_DIR/architecture/"
fi

# --- release mode (P0-2, default): the dist/ tier just copied above must be
# a COMPLETE, verified release -- not merely nonempty. A partial dist/
# (e.g. only a truncated test-unit.log, the exact rc4 state this finding
# was found against) fails LOUDLY here, before any further processing, with
# INCOMPLETE_RELEASE_EVIDENCE naming exactly what's missing.
if [ "$AUDIT_BUNDLE_MODE" = release ]; then
  RELEASE_COMMIT=$("$GIT_BIN" rev-parse "$REF")
  ARCH_DOC_FOR_VALIDATE=""
  if [ -f "$OUT_DIR/architecture/$("$BASENAME_BIN" "$ARCHITECTURE_DOC" 2>/dev/null || true)" ]; then
    ARCH_DOC_FOR_VALIDATE="$OUT_DIR/architecture/$("$BASENAME_BIN" "$ARCHITECTURE_DOC")"
  fi
  VALIDATE_ARGS=(--dist-dir "$OUT_DIR/dist" --repo "$ROOT" --release-commit "$RELEASE_COMMIT")
  if [ -n "$ARCH_DOC_FOR_VALIDATE" ]; then
    VALIDATE_ARGS+=(--architecture-doc "$ARCH_DOC_FOR_VALIDATE")
  fi
  if [ -f "$ROOT/docs/TRUSTED_SIGNING_KEYS.txt" ] && [ -d "$ROOT/docs/signing_keys" ]; then
    VALIDATE_ARGS+=(--trusted-fingerprints-file "$ROOT/docs/TRUSTED_SIGNING_KEYS.txt" --trusted-public-keys-dir "$ROOT/docs/signing_keys")
  fi
  INSTALL_EVIDENCE_FILE="$OUT_DIR/evidence/install-evidence.json"
  if [ -f "$INSTALL_EVIDENCE_FILE" ]; then
    VALIDATE_ARGS+=(--install-evidence "$INSTALL_EVIDENCE_FILE")
  fi
  if ! "$PYTHON_BIN" "$ROOT/scripts/audit_bundle_validate.py" "${VALIDATE_ARGS[@]}"; then
    echo "audit_bundle: refusing to ship a release-mode bundle over incomplete/unverified release evidence -- set AUDIT_BUNDLE_MODE=source-only for an explicit, clearly-labeled source-only bundle instead" >&2
    exit 1
  fi
fi

# --- evidence/: release/test/acceptance evidence for this ref -------------
# install-evidence.json is deliberately absent from this list: it is copied
# straight into evidence/ above (Sol14 rc7 Session 10) and never lands in
# dist/, because it cannot be covered by the release's own checksums.txt.
for f in test-summary.json acceptance-summary.json claims-verify-report.txt \
  build-manifest.json checksums.txt checksums.txt.minisig checksums.txt.hmac; do
  if [ -f "$OUT_DIR/dist/$f" ]; then
    "$CP_BIN" "$OUT_DIR/dist/$f" "$OUT_DIR/evidence/$f"
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
SOURCE_CLAIMS_SHA=$("$SHA256SUM_BIN" "$OUT_DIR/source/docs/claims.yaml" | "$AWK_BIN" '{print $1}')
{
  echo "source/docs/claims.yaml (current source tree at ${REF}): sha256=${SOURCE_CLAIMS_SHA}"
  if [ -f "$OUT_DIR/dist/claims.yaml" ]; then
    DIST_CLAIMS_SHA=$("$SHA256SUM_BIN" "$OUT_DIR/dist/claims.yaml" | "$AWK_BIN" '{print $1}')
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
# rc8-upg15 S5 (Sol15 P0-2 + P1-3 + P1-4): source-closure objects. The
# signed set previously covered only platform archives, build-manifest,
# checksums and signatures — source/, architecture/ and install-evidence
# were unbound. This section produces the six closure objects Sol names and
# a Git bundle for portable claims, so the one-command offline verifier
# (scripts/bundle_verify.py) can reject any tampered source, architecture,
# Assayer, install-record or trust-anchor byte.
# ---------------------------------------------------------------------------
"$MKDIR_BIN" -p "$OUT_DIR/closure"

GOV_VERSION_LABEL="${VERSION:-$("$GIT_BIN" describe --tags --always "$REF" 2>/dev/null || echo "$REF")}"
GOV_SOURCE_ARCHIVE="$OUT_DIR/closure/governator-source-${GOV_VERSION_LABEL}.tar.gz"
GOV_SOURCE_TREE="$OUT_DIR/closure/governator-source-${GOV_VERSION_LABEL}.tree.json"
if ! "$PYTHON_BIN" "$ROOT/scripts/source_closure.py" generate \
  --repo "$ROOT" --ref "$REF" \
  --out-archive "$GOV_SOURCE_ARCHIVE" --out-tree "$GOV_SOURCE_TREE" \
  --git-bin "$GIT_BIN" --tar-bin "$TAR_BIN" \
  --require-files LICENSE,NOTICE; then
  echo "audit_bundle: source-closure generation failed for governator at ${REF}" >&2
  exit 1
fi

if [ -d "$ASSAYER_REPO" ] && [ -d "$ASSAYER_REPO/.git" ]; then
  ASSAYER_VERSION_LABEL=$("$GIT_BIN" -C "$ASSAYER_REPO" describe --tags --exact-match HEAD 2>/dev/null || "$GIT_BIN" -C "$ASSAYER_REPO" rev-parse --short HEAD)
  ASSAYER_SOURCE_ARCHIVE="$OUT_DIR/closure/assayer-source-${ASSAYER_VERSION_LABEL}.tar.gz"
  ASSAYER_SOURCE_TREE="$OUT_DIR/closure/assayer-source-${ASSAYER_VERSION_LABEL}.tree.json"
  if ! "$PYTHON_BIN" "$ROOT/scripts/source_closure.py" generate \
    --repo "$ASSAYER_REPO" --ref HEAD \
    --out-archive "$ASSAYER_SOURCE_ARCHIVE" --out-tree "$ASSAYER_SOURCE_TREE" \
    --git-bin "$GIT_BIN" --tar-bin "$TAR_BIN"; then
    echo "audit_bundle: source-closure generation failed for assayer" >&2
    exit 1
  fi
else
  echo "audit_bundle: WARNING: ASSAYER_REPO=${ASSAYER_REPO} is not a git checkout -- skipping Assayer source closure" >&2
fi

if [ -f "$OUT_DIR/architecture/$("$BASENAME_BIN" "$ARCHITECTURE_DOC" 2>/dev/null || true)" ]; then
  "$CP_BIN" "$OUT_DIR/architecture/$("$BASENAME_BIN" "$ARCHITECTURE_DOC")" "$OUT_DIR/closure/"
fi
if [ -f "$OUT_DIR/evidence/install-evidence.json" ]; then
  "$CP_BIN" "$OUT_DIR/evidence/install-evidence.json" "$OUT_DIR/closure/"
fi

# P1-4: portable Git bundle containing the release commit and its ancestry.
GIT_BUNDLE="$OUT_DIR/closure/governator-release.bundle"
if "$GIT_BIN" bundle create "$GIT_BUNDLE" "$REF" --not --remotes=origin 2>/dev/null || \
   "$GIT_BIN" bundle create "$GIT_BUNDLE" "$REF" 2>/dev/null; then
  :
else
  echo "audit_bundle: WARNING: git bundle creation failed -- portable claims will not be verifiable offline" >&2
fi

# ---------------------------------------------------------------------------
# Post-build contamination scan (belt-and-suspenders): the exact categories
# the audit found, asserted absent from the finished bundle by content, not
# assumed absent because of how it was built.
# ---------------------------------------------------------------------------
CONTAMINATION_FOUND=false
while IFS= read -r -d '' hit; do
  echo "audit_bundle: contamination in bundle: $hit" >&2
  CONTAMINATION_FOUND=true
done < <("$FIND_BIN" "$OUT_DIR" \( \
  -name '.venv' -o -name 'venv' -o -name '__pycache__' -o -name '*.egg-info' \
  -o -name '.codegraph' -o -name '.tmp_debug_*' -o -name 'gov.bak-*' \
  -o -path '*/bin/gov' \
  \) -print0)
if [ "$CONTAMINATION_FOUND" = true ]; then
  echo "audit_bundle: refusing to ship a bundle containing the above -- this indicates a regression in this script, not the source tree" >&2
  exit 1
fi

echo "audit_bundle: OK (mode=${AUDIT_BUNDLE_MODE}) — $OUT_DIR" >&2
"$FIND_BIN" "$OUT_DIR" -maxdepth 2 >&2
