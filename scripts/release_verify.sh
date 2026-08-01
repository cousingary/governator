#!/bin/bash
# Sol redteam v4 S8 (P0-7, report attacks 24/25): the hard, release-blocking
# gate that closes the gap the audit found -- a shipped binary two security
# commits behind the submitted source, packaged at mode 0777, with full
# claims verification never having run against the exact archived artifact.
#
# scripts/release.sh calls this once, after build-manifest.json is fully
# finalized, as its last release-blocking check. It is factored into its own
# script (rather than inlined) so it can also be driven directly, fast and
# hermetically, against a synthetic dist/ directory -- see
# internal/redteam/release_test.go's attack 24/25 fixtures, which build a
# tiny fake release (a hostile 0777 binary; a binary whose self-reported
# commit drifts from the manifest) and assert this script refuses both.
#
# Usage:
#   scripts/release_verify.sh --out-dir <dir> --repo <repo-root> --platform <platform_id> --python-bin <path> --tar-bin <path> [--gov-bin <path> --mktemp-bin <path> --rm-bin <path> --stat-bin <path>]
#
# --out-dir   the release staging directory (release.sh's $OUT_DIR / "dist"):
#             must already contain claims.yaml, build-manifest.json, and
#             gov_<version>_<platform>.tar.gz for --platform.
# --repo      the repository root whose docs/claims.yaml is re-hashed and
#             compared against the manifest's claims_hash (release.sh passes
#             its own $ROOT -- this is what catches a claims.yaml edited
#             after the manifest was written).
# --platform  the platform id (e.g. linux_amd64) whose archive to extract
#             and verify -- normally the host platform, since that is the
#             only archive release.sh's acceptance smoke test can execute.
# --python-bin and --tar-bin are the exact approved executables selected by
#             release_tool_policy.yaml; this verifier never looks them up.
# --gov-bin   OPTIONAL. Which `gov` binary runs `claims verify`. Defaults to
#             the just-extracted artifact itself (self-hosting: the shipped
#             binary proves it can verify its own release, which is the real
#             production path). Tests override this with a real, separately
#             built `gov` binary when the artifact under test is a synthetic
#             fixture binary that doesn't implement the claims CLI itself.
set -euo pipefail

usage() {
  echo "usage: $0 --out-dir <dir> --repo <repo-root> --platform <platform_id> --python-bin <path> --tar-bin <path> [--gov-bin <path>]" >&2
  exit 2
}

OUT_DIR=""
REPO=""
PLATFORM=""
GOV_BIN_OVERRIDE=""
PYTHON_BIN=""
TAR_BIN=""
MKTEMP_BIN=mktemp
RM_BIN=rm
STAT_BIN=stat
while [ $# -gt 0 ]; do
  case "$1" in
  --out-dir)
    OUT_DIR=$2
    shift 2
    ;;
  --repo)
    REPO=$2
    shift 2
    ;;
  --platform)
    PLATFORM=$2
    shift 2
    ;;
  --gov-bin)
    GOV_BIN_OVERRIDE=$2
    shift 2
    ;;
  --python-bin)
    PYTHON_BIN=$2
    shift 2
    ;;
  --tar-bin)
    TAR_BIN=$2
    shift 2
    ;;
  --mktemp-bin) MKTEMP_BIN=$2; shift 2 ;;
  --rm-bin) RM_BIN=$2; shift 2 ;;
  --stat-bin) STAT_BIN=$2; shift 2 ;;
  *)
    usage
    ;;
  esac
done
[ -n "$OUT_DIR" ] && [ -n "$REPO" ] && [ -n "$PLATFORM" ] && [ -n "$PYTHON_BIN" ] && [ -n "$TAR_BIN" ] || usage

MANIFEST="$OUT_DIR/build-manifest.json"
CLAIMS_FILE="$OUT_DIR/claims.yaml"
[ -f "$MANIFEST" ] || { echo "release_verify: $MANIFEST not found" >&2; exit 1; }
[ -f "$CLAIMS_FILE" ] || { echo "release_verify: $CLAIMS_FILE not found" >&2; exit 1; }

VERSION=$("$PYTHON_BIN" -c "import json; print(json.load(open('$MANIFEST'))['version'])")
ARCHIVE="$OUT_DIR/gov_${VERSION}_${PLATFORM}.tar.gz"
[ -f "$ARCHIVE" ] || { echo "release_verify: $ARCHIVE not found" >&2; exit 1; }

EXTRACT_DIR=$("$MKTEMP_BIN" -d)
trap '"$RM_BIN" -rf "$EXTRACT_DIR"' EXIT
# -p/--preserve-permissions: without it, GNU tar applies the EXTRACTING
# user's umask to the archived mode bits when run as a non-root user --
# verified empirically on this host (umask 0022 silently turns an archived
# 0777 into an extracted 0755). That would make the very check below blind
# to exactly the attack it exists to catch, purely as a function of who
# happens to run this script. -p makes extraction reproduce the archived
# mode bit-for-bit, so the mode assertion is deterministic regardless of the
# caller's environment.
"$TAR_BIN" -xzf "$ARCHIVE" -C "$EXTRACT_DIR" -p
EXTRACTED_BIN="$EXTRACT_DIR/gov"
[ -f "$EXTRACTED_BIN" ] || { echo "release_verify: archive $ARCHIVE does not contain a 'gov' binary" >&2; exit 1; }

# Report attack 24: the archived binary shipped at mode 0777. Asserted here,
# against the binary as it lands on disk after extraction -- not the
# in-staging binary before archiving, which is what let this slip through
# originally (tar's own owner/perm bits, or a hand-edited archive, can still
# diverge from what was chmod'd before packaging).
MODE=$("$STAT_BIN" -c '%a' "$EXTRACTED_BIN" 2>/dev/null || "$STAT_BIN" -f '%OLp' "$EXTRACTED_BIN")
if [ "$MODE" != "755" ]; then
  echo "release_verify: extracted binary mode is $MODE, must be exactly 755 (no group/world write bit)" >&2
  exit 1
fi

GOV_BIN=${GOV_BIN_OVERRIDE:-$EXTRACTED_BIN}

# Report attack 25: full claims verification against the exact archived
# artifact + the finalized manifest. --release refuses to run degraded
# (cmd/gov/main.go's claimsCmd) -- this call must always carry a real
# --artifact/--manifest pair pointing at what was actually just extracted,
# never the pre-archive staging copy.
echo "release_verify: verifying ${ARCHIVE} (platform=${PLATFORM}) via ${GOV_BIN}" >&2
"$GOV_BIN" claims verify --release --file "$CLAIMS_FILE" --repo "$REPO" --artifact "$EXTRACTED_BIN" --manifest "$MANIFEST"
