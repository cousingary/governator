#!/bin/bash
# Sol redteam v3 S14 (finding #20 / P2.2): the single, canonical release
# pipeline. Before this session, two incompatible generations existed side
# by side: this script (single-platform, real ldflags identity, no
# checksums/SBOM/test-summary) and .goreleaser.yml (multi-platform, but its
# snapshot mode — the only mode usable without a git tag and a GitHub
# remote, neither of which this repo has — stamps every archive
# "0.0.0-SNAPSHOT-none" / "commit: none" and was never wired to embed the
# same version/commit/claims-hash identity this script already computed).
# .goreleaser.yml has been deleted; this script now builds every platform,
# in one empty staging directory, and emits the complete file set the audit
# requires: gov_<version>_<platform>.tar.gz (one per platform), checksums.txt,
# build-manifest.json, sbom.json, claims.yaml, test-summary.json,
# acceptance-summary.json, checksums.txt.hmac (only when
# GOV_RELEASE_HMAC_KEY is set -- Sol9 P2-2 renamed this from the ambiguous
# "signature" and stopped writing an "UNSIGNED" placeholder when absent).
set -euo pipefail

ROOT=$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)
cd "$ROOT"

# Captured once, on the very first invocation, before anything narrows
# $PATH -- and deliberately NOT re-captured on the detached-scratch
# re-invocation below, which inherits this from the outer process's
# environment. Without the already-set guard, the inner script would
# capture $PATH *after* the outer script already narrowed it to its own
# toolbin (a fresh mkdtemp path, gone once that process exits), so
# TEST_TIER_PATH further down would end up as one dead toolbin path
# concatenated with another live one -- never the real ambient PATH. This
# happened in practice: the first attempt at broadening the test-tier PATH
# recorded PATH=<outer-toolbin>:<inner-toolbin> in the unit checkpoint,
# with no system directory in it at all.
if [ -z "${GOV_RELEASE_AMBIENT_PATH:-}" ]; then
  export GOV_RELEASE_AMBIENT_PATH="$PATH"
fi

# Sol13 P0-2/P1-4: the checked-in policy is the independent trust root for
# every release tool. Parse its deliberately narrow YAML shape using bash
# builtins, then execute the policy's Python directly to hash every approved
# object before even asking Git whether the tree is clean. There is no PATH
# lookup for go, python3, sha256sum, tar, gzip, minisign, or git below.
RELEASE_TOOL_POLICY=${GOV_RELEASE_TOOL_POLICY:-"$ROOT/scripts/release_tool_policy.yaml"}
release_tool_value() {
  local wanted_tool=$1 wanted_field=$2 line active=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$line" = "  ${wanted_tool}:" ]; then
      active=1
      continue
    fi
    # Sol13 rc6 Session 9: `[ "$x" = "prefix"* ]` is a LITERAL comparison --
    # `[` does no pattern matching, and the unquoted `*` is only subject to
    # (here always failing) pathname expansion, so this test could never be
    # true and release_tool_value always returned 1. Every approved tool
    # therefore read as "absent from the policy" and release.sh aborted
    # before its first step. It went unnoticed because S4 introduced this
    # loop and Session 9 is the first end-to-end release.sh run. `case` is
    # POSIX and actually globs.
    if [ "$active" = 1 ]; then
      case "$line" in
      "    ${wanted_field}: "*)
        printf '%s\n' "${line#"    ${wanted_field}: "}"
        return 0
        ;;
      esac
    fi
    if [ "$active" = 1 ] && [ "${line#  }" != "$line" ] && [ "${line#    }" = "$line" ]; then
      return 1
    fi
  done <"$RELEASE_TOOL_POLICY"
  return 1
}

for release_tool in go python3 python3.10 python3.11 python3.12 python3.13 sha256sum tar gzip minisign git bash date awk env cp rm mkdir find sort mktemp dirname pwd grep uname cat chmod stat basename timeout mv ls systemctl docker tail; do
  release_tool_path=$(release_tool_value "$release_tool" path) || {
    echo "release: approved tool ${release_tool} is absent from ${RELEASE_TOOL_POLICY}" >&2
    exit 1
  }
  case "$release_tool" in
    go) GO_TOOL=$release_tool_path ;;
    python3) PYTHON_TOOL=$release_tool_path ;;
    python3.10) PYTHON310_TOOL=$release_tool_path ;;
    python3.11) PYTHON311_TOOL=$release_tool_path ;;
    python3.12) PYTHON312_TOOL=$release_tool_path ;;
    python3.13) PYTHON313_TOOL=$release_tool_path ;;
    sha256sum) SHA256SUM_TOOL=$release_tool_path ;;
    tar) TAR_TOOL=$release_tool_path ;;
    gzip) GZIP_TOOL=$release_tool_path ;;
    minisign) MINISIGN_TOOL=$release_tool_path ;;
    git) GIT_TOOL=$release_tool_path ;;
    bash) BASH_TOOL=$release_tool_path ;;
    date) DATE_TOOL=$release_tool_path ;;
    awk) AWK_TOOL=$release_tool_path ;;
    env) ENV_TOOL=$release_tool_path ;;
    cp) CP_TOOL=$release_tool_path ;;
    rm) RM_TOOL=$release_tool_path ;;
    mkdir) MKDIR_TOOL=$release_tool_path ;;
    find) FIND_TOOL=$release_tool_path ;;
    sort) SORT_TOOL=$release_tool_path ;;
    mktemp) MKTEMP_TOOL=$release_tool_path ;;
    dirname) DIRNAME_TOOL=$release_tool_path ;;
    pwd) PWD_TOOL=$release_tool_path ;;
    grep) GREP_TOOL=$release_tool_path ;;
    uname) UNAME_TOOL=$release_tool_path ;;
    cat) CAT_TOOL=$release_tool_path ;;
    chmod) CHMOD_TOOL=$release_tool_path ;;
    stat) STAT_TOOL=$release_tool_path ;;
    basename) BASENAME_TOOL=$release_tool_path ;;
    timeout) TIMEOUT_TOOL=$release_tool_path ;;
    mv) MV_TOOL=$release_tool_path ;;
    ls) LS_TOOL=$release_tool_path ;;
    systemctl) SYSTEMCTL_TOOL=$release_tool_path ;;
    docker) DOCKER_TOOL=$release_tool_path ;;
    tail) TAIL_TOOL=$release_tool_path ;;
  esac
done

# Bootstrap copies, captured before the toolbin-routed reassignment below
# overwrites these names. A fresh release attempt wipes $OUT_DIR wholesale
# and immediately needs to recreate a directory under it; using these
# bootstrap (policy-resolved, pre-toolbin) paths rather than the
# toolbin-routed ones means that step never depends on the toolbin's own
# location or lifecycle at all -- exactly the single documented
# ambient-resolution exception already established for the initial
# preflight build above (P0-1 work item 7): the one place hermetic tooling
# cannot be routed through the hermetic toolchain itself.
BOOTSTRAP_PYTHON_TOOL=$PYTHON_TOOL
BOOTSTRAP_RM_TOOL=$RM_TOOL
BOOTSTRAP_MKDIR_TOOL=$MKDIR_TOOL

# The toolbin's mode 0500 is the enforcement primitive (P0-1): a directory
# whose permission bits genuinely cannot be widened is what makes "only
# verified entries are reachable via PATH" a real property rather than a
# claim. $ROOT (and therefore $OUT_DIR, which lives under it) can be a 9p
# (drvfs) mount when this repo's working copy sits on a mounted Windows
# drive -- chmod there silently no-ops instead of erroring, so a toolbin
# nested under $OUT_DIR would report mode 0500 immediately after chmod but
# read back as the mount's fixed mode (777 observed) on every later
# verification, permanently failing Sol12 P1-4's re-check with no way to
# satisfy it by fixing anything in this script. tempfile.mkdtemp honors
# $TMPDIR (real tmpfs/ext4 in this environment) precisely so the toolbin
# lands somewhere chmod actually holds, decoupling its enforcement from
# wherever the source checkout happens to be mounted.
TOOLBIN_DIR=$("$PYTHON_TOOL" -c 'import tempfile; print(tempfile.mkdtemp(prefix="governator-release-toolbin-"))')
BOOTSTRAP_TOOLSET=$("$PYTHON_TOOL" -c 'import tempfile; print(tempfile.mkstemp(prefix="governator-release-toolset-")[1])')
if ! "$PYTHON_TOOL" "$ROOT/scripts/release_toolset.py" --policy "$RELEASE_TOOL_POLICY" --out "$BOOTSTRAP_TOOLSET" --toolbin "$TOOLBIN_DIR" >/dev/null; then
  "$PYTHON_TOOL" -c 'import os,sys; os.unlink(sys.argv[1])' "$BOOTSTRAP_TOOLSET"
  echo "release: approved release-tool policy verification failed" >&2
  exit 1
fi
"$PYTHON_TOOL" -c 'import os,sys; os.unlink(sys.argv[1])' "$BOOTSTRAP_TOOLSET"
if ! "$PYTHON_TOOL" "$ROOT/scripts/release_toolset.py" --policy "$RELEASE_TOOL_POLICY" --check-release-scripts "$ROOT"; then
  echo "release: release command inventory is not fully covered by the approved tool policy" >&2
  exit 1
fi
# Built from GOV_RELEASE_AMBIENT_PATH (captured at the top of this script,
# before any narrowing, and preserved across the detached-scratch
# re-invocation) rather than the current $PATH, which by this point may
# already be narrowed. The narrow toolbin is the right PATH for this
# SCRIPT's own evidence-producing invocations (build, hash, sign,
# archive) -- exactly Sol12 P0-1's threat model. It is the WRONG PATH for
# the `go test` tiers below: those run governor's own application/test
# code, which legitimately shells out to arbitrary host controller tools
# (systemd-run, unshare, docker helpers, ...) that have nothing to do with
# release-evidence production and were never meant to be pinned by
# release_tool_policy.yaml. Narrowing PATH for the test binaries too was
# tried and silently degraded a large swath of internal/runtime's
# containment tests to a weaker code path instead of failing loud -- e.g.
# TestScopeKillsDetachedSetsidDescendant falls back from
# "systemd-user-scope" to "process-group-degraded" and then fails its own
# assertion, not because containment is broken but because systemd-run
# isn't reachable. TEST_TIER_PATH below is used only for the tier commands
# themselves (release_tier_pipeline.sh's --spec), never for this script's
# own direct tool invocations.
TEST_TIER_PATH="$TOOLBIN_DIR:$GOV_RELEASE_AMBIENT_PATH"
export PATH="$TOOLBIN_DIR"
# From this point, explicit child arguments use the private directory's
# verified links, never a policy-path symlink or a caller-provided PATH entry.
GO_TOOL="$TOOLBIN_DIR/go"
PYTHON_TOOL="$TOOLBIN_DIR/python3"
PYTHON310_TOOL="$TOOLBIN_DIR/python3.10"
PYTHON311_TOOL="$TOOLBIN_DIR/python3.11"
PYTHON312_TOOL="$TOOLBIN_DIR/python3.12"
PYTHON313_TOOL="$TOOLBIN_DIR/python3.13"
SHA256SUM_TOOL="$TOOLBIN_DIR/sha256sum"
TAR_TOOL="$TOOLBIN_DIR/tar"
GZIP_TOOL="$TOOLBIN_DIR/gzip"
MINISIGN_TOOL="$TOOLBIN_DIR/minisign"
GIT_TOOL="$TOOLBIN_DIR/git"
BASH_TOOL="$TOOLBIN_DIR/bash"
DATE_TOOL="$TOOLBIN_DIR/date"
AWK_TOOL="$TOOLBIN_DIR/awk"
ENV_TOOL="$TOOLBIN_DIR/env"
CP_TOOL="$TOOLBIN_DIR/cp"
RM_TOOL="$TOOLBIN_DIR/rm"
MKDIR_TOOL="$TOOLBIN_DIR/mkdir"
FIND_TOOL="$TOOLBIN_DIR/find"
SORT_TOOL="$TOOLBIN_DIR/sort"
MKTEMP_TOOL="$TOOLBIN_DIR/mktemp"
DIRNAME_TOOL="$TOOLBIN_DIR/dirname"
PWD_TOOL="$TOOLBIN_DIR/pwd"
GREP_TOOL="$TOOLBIN_DIR/grep"
UNAME_TOOL="$TOOLBIN_DIR/uname"
CAT_TOOL="$TOOLBIN_DIR/cat"
CHMOD_TOOL="$TOOLBIN_DIR/chmod"
STAT_TOOL="$TOOLBIN_DIR/stat"
BASENAME_TOOL="$TOOLBIN_DIR/basename"
TIMEOUT_TOOL="$TOOLBIN_DIR/timeout"
MV_TOOL="$TOOLBIN_DIR/mv"
LS_TOOL="$TOOLBIN_DIR/ls"
SYSTEMCTL_TOOL="$TOOLBIN_DIR/systemctl"
DOCKER_TOOL="$TOOLBIN_DIR/docker"
TAIL_TOOL="$TOOLBIN_DIR/tail"

require_clean_tree() {
  local stage=${1:-release}
  if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
    echo "release: refusing to build from a dirty tree (${stage})" >&2
    exit 1
  fi
}

# redteamgate_verify_artifact_unchanged LABEL RECORDED_SHA256 CURRENT_SHA256
# Prints an error and returns non-zero when CURRENT_SHA256 no longer equals
# RECORDED_SHA256 for the named artifact (rc8-upg15 S3, Sol15 P0-4: "rerun
# final acceptance after integration without rebuilding"). This is the bash
# release-time enforcement of the exact same contract
# internal/redteamgate.VerifyArtifactUnchanged defines and
# internal/redteam/v15_s3_exact_artifact_test.go's TestV15Case365 unit-tests
# -- one property, one Go spec, one bash enforcement point.
redteamgate_verify_artifact_unchanged() {
  local label=$1 recorded=$2 current=$3
  if [ -z "$recorded" ]; then
    echo "${label}: no recorded sha256 to compare against"
    return 1
  fi
  if [ -z "$current" ]; then
    echo "${label}: no current sha256 to compare"
    return 1
  fi
  if [ "$recorded" != "$current" ]; then
    echo "${label}: sha256 changed from ${recorded} to ${current} -- a rebuild occurred after the integration tier bound this artifact's identity"
    return 1
  fi
  return 0
}

if [ "${GOV_RELEASE_IN_SCRATCH:-0}" != 1 ]; then
  require_clean_tree "source checkout"
  SOURCE_ROOT=$ROOT
  OUT_DIR_ABS=$("$PYTHON_TOOL" -c 'import os,sys; root,out=sys.argv[1:3]; print(out if os.path.isabs(out) else os.path.join(root, out))' "$SOURCE_ROOT" "${OUT_DIR:-dist}")
  SCRATCH_PARENT=$("$MKTEMP_TOOL" -d)
  SCRATCH_TREE="$SCRATCH_PARENT/governator-release"
  cleanup() {
    git -C "$SOURCE_ROOT" worktree remove --force "$SCRATCH_TREE" >/dev/null 2>&1 || rm -rf "$SCRATCH_PARENT"
  }
  trap cleanup EXIT
  git worktree add --detach "$SCRATCH_TREE" HEAD >/dev/null
  ARCH_DOC_DEFAULT="$SOURCE_ROOT/../agents/governator_architecture.md"
  export GOV_RELEASE_IN_SCRATCH=1
  export GOV_RELEASE_SOURCE_ROOT="$SOURCE_ROOT"
  export OUT_DIR="$OUT_DIR_ABS"
  if [ -z "${GOV_ARCHITECTURE_DOC:-}" ] && [ -f "$ARCH_DOC_DEFAULT" ]; then
    export GOV_ARCHITECTURE_DOC="$ARCH_DOC_DEFAULT"
  fi
  (cd "$SCRATCH_TREE" && "$BASH_TOOL" "$SCRATCH_TREE/scripts/release.sh")
  exit $?
fi

require_clean_tree "detached scratch checkout"
COMMIT=$(git rev-parse HEAD)
SHORT_COMMIT=$(git rev-parse --short=12 HEAD)
SOURCE_ROOT=${GOV_RELEASE_SOURCE_ROOT:-$ROOT}
if [ -z "${VERSION:-}" ]; then
  EXACT_TAG=$(git describe --tags --exact-match HEAD 2>/dev/null || true)
  if [ -n "$EXACT_TAG" ]; then
    VERSION=${EXACT_TAG#v}
  else
    VERSION="local-candidate-${SHORT_COMMIT}"
  fi
fi

# Sol12 P1-3 (rc5 Session 7): release strictness is derived from the VERSION
# string itself, not from caller-settable environment variables. For any
# version matching vX.Y.Z or vX.Y.Z-rcN (i.e. a real distribution candidate),
# the following are ALWAYS enforced and CANNOT be weakened by env vars:
#   - exact tag at HEAD matching v${VERSION}
#   - zero production security-test skips
#   - asymmetric cryptographic signature
#   - clean source tree
#   - complete evidence
# Development builds use the unmistakable identity local-candidate-<commit>
# and are marked non-publishable; they keep weaker defaults.
#
# This closes the Sol12 P1-3 defect: REQUIRE_TAG=0 / REQUIRE_ZERO_SKIPS=0
# could previously build an rc as a signed but non-tag-strict candidate.
EXACT_TAG_AT_HEAD=$(git describe --tags --exact-match HEAD 2>/dev/null || true)
RELEASE_MODE=""
case "$VERSION" in
  local-candidate-*)
    RELEASE_MODE="development"
    ;;
  *)
    if printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$'; then
      RELEASE_MODE="production"
    else
      RELEASE_MODE="development"
    fi
    ;;
esac
DISTRIBUTION_ALLOWED=false
if [ "$RELEASE_MODE" = "production" ]; then
  DISTRIBUTION_ALLOWED=true
  REQUIRE_TAG=1
  REQUIRE_ZERO_SKIPS=1
  REQUIRE_ASYMMETRIC_SIGNATURE=1
  TAG_AT_HEAD=$(git tag --points-at HEAD | grep -x "v${VERSION}" || true)
  if [ -z "$TAG_AT_HEAD" ]; then
    echo "release: version ${VERSION} is a production release (vX.Y.Z / vX.Y.Z-rcN) -- HEAD MUST be tagged v${VERSION} (strictness is version-derived and cannot be disabled by environment variables, Sol12 P1-3)" >&2
    exit 1
  fi
else
  REQUIRE_TAG=${REQUIRE_TAG:-0}
  REQUIRE_ZERO_SKIPS=${GOV_RELEASE_REQUIRE_ZERO_SKIPS:-0}
  if [ -z "${REQUIRE_ASYMMETRIC_SIGNATURE:-}" ]; then
    REQUIRE_ASYMMETRIC_SIGNATURE=0
  fi
  if [ "$REQUIRE_TAG" = 1 ]; then
    TAG_AT_HEAD=$(git tag --points-at HEAD | grep -x "v${VERSION}" || true)
    if [ -z "$TAG_AT_HEAD" ]; then
      echo "release: REQUIRE_TAG=1 but HEAD is not tagged v${VERSION}" >&2
      exit 1
    fi
  fi
fi

ARCHITECTURE_DOC=${GOV_ARCHITECTURE_DOC:-$SOURCE_ROOT/../agents/governator_architecture.md}
if [ -f "$ARCHITECTURE_DOC" ]; then
  ARCH_DOC_COMMIT=$(python3 -c 'import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text()
m=re.search(r"Source HEAD `([0-9a-f]{7,40})`", text)
print(m.group(1) if m else "")' "$ARCHITECTURE_DOC")
  if [ -z "$ARCH_DOC_COMMIT" ]; then
    echo "release: architecture doc $ARCHITECTURE_DOC does not declare a Source HEAD commit" >&2
    exit 1
  fi
  case "$COMMIT" in
    ${ARCH_DOC_COMMIT}* ) ;;
    * )
      echo "release: architecture doc Source HEAD ${ARCH_DOC_COMMIT} does not match release HEAD ${COMMIT}" >&2
      exit 1
      ;;
  esac
  # Sol9 P2-3: a Source-HEAD match doesn't catch a stale *narrative* inside
  # the doc (the audit found an accurate Status header sitting next to a
  # Remediation-history section that still described an older release as
  # current). Sol11 P1-7 extends the same checker to also validate a
  # front-matter-style doc's five contradiction categories (tag/commit,
  # release_state without artifacts, manifest hash, live-deployment claims)
  # when the doc carries that block -- --repo/--dist-dir are always passed;
  # a prose-only doc (today's live doc) has no front matter, so those extra
  # checks are simply inert for it.
  if ! python3 "$ROOT/scripts/check_architecture_doc.py" "$ARCHITECTURE_DOC" --repo "$SOURCE_ROOT" --dist-dir "${OUT_DIR:-dist}"; then
    echo "release: refusing to release with a stale/contradictory architecture doc (see above)" >&2
    exit 1
  fi
fi

# v16 R3: SECURITY.md is the file GitHub surfaces in the security tab, and
# went stale by roughly nineteen release-candidate-cycles' worth of work
# because no checker ever looked at it. check_release_docs.py's second mode
# asserts it still links to the real register/containment docs and does not
# describe any docs/security.md-fixed finding as open.
if ! python3 "$ROOT/scripts/check_release_docs.py" "$ROOT/SECURITY.md" "$ROOT/docs/security.md"; then
  echo "release: refusing to release with a stale/contradictory SECURITY.md (see above)" >&2
  exit 1
fi

# v16 R1: the entire rc7/rc8 program lived on an unmerged side branch while
# main was 45+ commits stale -- CI triggers on push: [main] and would test a
# stale tree, and `go install ...@latest` resolves the highest non-prerelease
# tag reachable from the default branch. release.sh fast-forwards nothing
# itself; the operator owns the merge back to main (v16-release S2). This
# checker is the durable half of that fix: it refuses a release while any v*
# semver release tag is unreachable from the release branch. It runs against
# the real repo ($SOURCE_ROOT), not the detached scratch worktree, so it sees
# the `main` ref and every tag.
if ! python3 "$ROOT/scripts/check_branch_topology.py" --repo "$SOURCE_ROOT"; then
  echo "release: refusing to release with a stale branch/tag topology (see above)" >&2
  exit 1
fi

BUILD_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CLAIMS_HASH=$(sha256sum docs/claims.yaml | awk '{print $1}')
ADAPTER_PROTOCOL_VERSION=${ADAPTER_PROTOCOL_VERSION:-adapter-protocol-v1}
GO_VERSION=$("$GO_TOOL" version | awk '{print $3}')
FUZZ_SECONDS=${FUZZ_SECONDS:-15}
# Attempt 1/2 of the rc3 cut (2026-07-20) both failed on host contention, not
# code defects: with Docker fully quiet, the default go test concurrency
# (package-level -p and within-package -parallel both default to GOMAXPROCS,
# 8 on this host) still pushed SQLite writers and timing-budget tests past
# their margins (SQLITE_BUSY, wall-clock budget tests missing their window by
# 4x). Capping both knobs trades wall-clock time for headroom; tune via env
# if a future host has more room.
GO_TEST_PARALLELISM=${GO_TEST_PARALLELISM:-2}
# Sol3 P1.8 (S12) confirmed session's own machine can build all four
# platforms with CGO_ENABLED=0 (modernc.org/sqlite is pure Go, no cgo
# toolchain needed for cross-compilation).
# v16-release Session 6 (R4): darwin/amd64 is dropped from the default
# platform set. GitHub's free macOS runners are Apple-silicon (arm64) only;
# there is no free native host that could ever produce executed acceptance
# evidence for darwin/amd64, so publishing it would ship an archive nobody
# can attest -- exactly the credibility risk R4 names. Rosetta 2 runs the
# arm64 archive on Intel Macs. darwin/arm64 is retained for the eventual
# evidence-based promotion once its native acceptance + corpus clear.
PLATFORMS=${PLATFORMS:-"linux/amd64 linux/arm64 darwin/arm64"}
# Sol12 P1-1 (rc5 Session 6): PLATFORMS is caller-controlled with no prior
# validation -- an operator setting PLATFORMS="windows/amd64" would reach
# the build loop below unchecked, and the per-artifact "approving" flag
# further down defaulted true for anything that didn't literally start with
# "darwin_", so an unsupported platform would have shipped silently marked
# fully approving. Refuse outright instead: every requested platform's GOOS
# must be exactly "linux" or "darwin" -- mirrors
# internal/redteamgate.ApprovedPlatforms/ClassifyPlatform, the one Go-side
# source of truth TestV12Case36 tests directly. Kept in sync by hand: this
# script cannot import the Go package it is building.
# Sol15 P1-2: this guard is a BUILD eligibility check only. Approval is
# keyed on executed acceptance evidence per platform (see the artifact
# labeling block below): only the host platform that ran the acceptance
# check is approving; cross-compiled platforms are non-approving.
for platform in $PLATFORMS; do
  platform_goos=${platform%/*}
  case "$platform_goos" in
    linux|darwin) ;;
    *)
      echo "release: refusing to build unsupported platform '${platform}' -- GOOS '${platform_goos}' is not in the recognized set (linux, darwin). See docs/security.md's Session 6 closure entry (Sol12 P1-1) and internal/redteamgate.ClassifyPlatform." >&2
      exit 1
      ;;
  esac
done
# P1-4 (Sol11 rc5 Session 8): ASSAYER_REPO defaults to the sibling checkout
# for local runs; .github/workflows/release.yml sets it explicitly to the
# path actions/checkout materialized Assayer at (the local default
# /mnt/e/downloads/assayer does not exist on a GitHub-hosted runner).
ASSAYER_REPO=${ASSAYER_REPO:-/mnt/e/downloads/assayer}
# P1-4: assayer.lock is the version-controlled pin of which Assayer ref
# both local and CI releases must check out. When the Assayer checkout
# exists, record the locked ref in the release record so a downstream
# verifier can confirm this release was built against the declared Assayer
# version, not an arbitrary HEAD. scripts/assayer_verify.sh independently
# confirms the checkout's HEAD carries a Git tag matching Assayer's own
# pyproject.toml version.
ASSAYER_LOCK_FILE="$SOURCE_ROOT/assayer.lock"
ASSAYER_LOCKED_REF=""
if [ -f "$ASSAYER_LOCK_FILE" ]; then
  ASSAYER_LOCKED_REF=$(python3 -c "
import sys
for line in open(sys.argv[1]):
    line = line.split('#', 1)[0].strip()
    if line.startswith('ref='):
        print(line[4:]); break
" "$ASSAYER_LOCK_FILE" 2>/dev/null || true)
fi
if ! printf '%s' "$ASSAYER_LOCKED_REF" | grep -qE '^[0-9a-f]{40}$'; then
  echo "release: assayer.lock must pin an immutable 40-character commit, not a tag or branch" >&2
  exit 1
fi
# P1-5: Assayer's commit is part of release IDENTITY (a checkpoint from a
# release attempt built against a different Assayer checkout must never be
# reused) -- computed here, before any test tier runs, rather than only
# later when architecture-build-metadata.json is written.
if [ -d "$ASSAYER_REPO" ]; then
  ASSAYER_COMMIT=$(git -C "$ASSAYER_REPO" rev-parse HEAD 2>/dev/null || echo "unknown")
else
  ASSAYER_COMMIT="absent"
fi
if [ "$ASSAYER_COMMIT" != "$ASSAYER_LOCKED_REF" ]; then
  echo "release: ASSAYER_REPO commit $ASSAYER_COMMIT does not equal assayer.lock $ASSAYER_LOCKED_REF" >&2
  exit 1
fi

GO_SUM_HASH=$(sha256sum go.sum | awk '{print $1}')

# ---------------------------------------------------------------------------
# P1-6 (Sol11 rc5 Session 8): record every release tool's exact binary
# identity (absolute path + SHA-256 + version) into toolset.json BEFORE the
# checkpoint identity is computed, so the toolset_hash is folded into
# TOOLCHAIN_HASH below -- a substituted tool (different binary SHA-256, same
# name on PATH) invalidates every prior checkpoint, exactly as the forged-
# minisign result (S1/P0-1) demonstrated matters. toolset.json itself is
# written to a temp file here (OUT_DIR may be wiped below for a fresh
# attempt) and moved into place once OUT_DIR is settled.
# ---------------------------------------------------------------------------
TOOLSET_JSON_TEMP=$(mktemp)
TOOLSET_HASH=$(python3 "$ROOT/scripts/release_toolset.py" --policy "$RELEASE_TOOL_POLICY" --out "$TOOLSET_JSON_TEMP")

# ---------------------------------------------------------------------------
# P1-5 (Sol11): release-attempt state machine identity + resumable
# checkpoints. Every field below, if it changes between a crashed attempt
# and a resuming one, invalidates every existing tier checkpoint -- a fresh
# release_attempt_id is minted and OUT_DIR is wiped before any tier runs.
# When every field matches, OUT_DIR (and its checkpoints) are left exactly
# as the crashed attempt left them, and each tier below reuses its
# checkpoint instead of re-running (scripts/release_tier_pipeline.sh).
# ---------------------------------------------------------------------------
# P1-6: TOOLCHAIN_HASH now folds in TOOLSET_HASH (actual binary hashes), not
# just go/python version strings -- a checkpoint from an attempt whose go
# binary changed underneath it (same go version string, different binary)
# is correctly invalidated.
TOOLCHAIN_HASH=$(printf '%s|%s|%s\n' "$("$GO_TOOL" version)" "$(python3 --version 2>&1)" "$TOOLSET_HASH" | sha256sum | awk '{print $1}')
ENVIRONMENT_HASH=$(printf '%s|GOMAXPROCS=%s|parallelism=%s|platforms=%s\n' "$(uname -a)" "${GOMAXPROCS:-}" "$GO_TEST_PARALLELISM" "$PLATFORMS" | sha256sum | awk '{print $1}')
# Sol14 rc7 Session 10: host CAPABILITY STATE is part of release identity.
# A red-team tier's result is a function of which capabilities the host
# actually had -- a Docker-absent run legitimately SKIPs the real-daemon
# cases, a Docker-present run must RUN them. ENVIRONMENT_HASH above covers
# uname/GOMAXPROCS/parallelism/platforms and does NOT capture that, so a
# checkpoint from a Docker-absent attempt was reusable by a Docker-present
# one: the gate then scored a FRESH capability probe against a STALE tier
# log and could authorize or reject skips under capabilities that were not
# in effect when the log was produced. Found end to end on the rc7 cut,
# where TestV12Case31 was reported as an unauthorized skip.
#
# Only the capability STATES are hashed, deliberately: each record also
# carries a probe timestamp and host identity, and folding those in would
# change the hash on every invocation and make every checkpoint permanently
# unreusable -- defeating the resumable-checkpoint design (P1-5).
RELEASE_CAPABILITIES_JSON=$("$PYTHON_TOOL" "$ROOT/scripts/redteam_capabilities.py" --git-bin "$GIT_TOOL" --docker-bin "$DOCKER_TOOL" --systemctl-bin "$SYSTEMCTL_TOOL")
CAPABILITIES_HASH=$(printf '%s' "$RELEASE_CAPABILITIES_JSON" | python3 -c "
import hashlib, json, sys
records = json.load(sys.stdin)
states = {name: record.get('state', 'unknown') for name, record in records.items()}
canonical = json.dumps(states, sort_keys=True, separators=(',', ':'))
print(hashlib.sha256(canonical.encode()).hexdigest())
")
# Sol12 P1-5 (rc5 Session 7): use the expected v${VERSION} tag directly
# rather than the first sorted tag at HEAD -- multiple tags on one commit
# must bind to the exact expected tag, not an arbitrary one.
RELEASE_TAG_FOR_IDENTITY="v${VERSION}"

OUT_DIR=${OUT_DIR:-dist}
CHECKPOINT_STATE_DIR="$OUT_DIR/.checkpoints"
mkdir -p "$CHECKPOINT_STATE_DIR"

# v16-release S3 / R5: detect an OUT_DIR on a filesystem that silently coerces
# file modes (9p/drvfs, e.g. /mnt/e, rewrites every extracted mode to 0777).
# This release writes mode-0500 toolbins and mode-0755 executables whose modes
# release_policy.py / install_evidence.py re-check; on a coercing filesystem
# those assertions are theater and every shipped artifact carries 0777. Fail
# closed with the named OUT_DIR_COERCES_FILE_MODES error rather than producing
# coerced artifacts -- this is the manual OUT_DIR redirect rc8 Session 8
# applied, now an enforced invariant. Detection is behavioural (chmod a probe
# dir 0500, read the mode back), never a hardcoded path. The probe itself
# lives in scripts/release_policy.py (out-dir-mode-probe) so release.sh and
# audit_bundle.sh share one implementation and cannot drift.
if ! python3 "$ROOT/scripts/release_policy.py" out-dir-mode-probe --dist-dir "$OUT_DIR"; then
  echo "release: refusing to use a mode-coercing OUT_DIR (rc8 Session 8's manual /mnt/e workaround is now enforced -- v16 S3 / R5). Set OUT_DIR to a native filesystem path (e.g. OUT_DIR=/home/lam/governator-release-dist)." >&2
  exit 1
fi

CANDIDATE_IDENTITY=$(mktemp)
python3 "$ROOT/scripts/release_checkpoint.py" identity \
  --governator-commit "$COMMIT" --governator-tag "$RELEASE_TAG_FOR_IDENTITY" \
  --assayer-commit "$ASSAYER_COMMIT" --go-sum-hash "$GO_SUM_HASH" \
  --toolchain-hash "$TOOLCHAIN_HASH" --environment-hash "$ENVIRONMENT_HASH" \
  --capabilities-hash "$CAPABILITIES_HASH" \
  --go-test-parallelism "$GO_TEST_PARALLELISM" \
  --requested-version "$VERSION" --expected-exact-tag "v${VERSION}" \
  --release-mode "$RELEASE_MODE" --distribution-allowed "$DISTRIBUTION_ALLOWED" >"$CANDIDATE_IDENTITY"
PEEK=$(python3 "$ROOT/scripts/release_checkpoint.py" peek --state-dir "$CHECKPOINT_STATE_DIR" --identity-file "$CANDIDATE_IDENTITY")
RESUMED=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['resumed'])" "$PEEK")
if [ "$RESUMED" = True ]; then
  RELEASE_ATTEMPT_ID=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['attempt_id'])" "$PEEK")
  echo "release: RESUMING release_attempt_id=${RELEASE_ATTEMPT_ID} -- prior checkpoints in ${OUT_DIR} match this attempt's identity exactly and will be reused where possible" >&2
else
  # Every field above (Sol11 rc5 P0-2/P1-5) EMPTY staging directory
  # requirement: any identity mismatch (different commit, toolchain,
  # Assayer commit, go.sum, environment, or parallelism) OR a first-ever
  # invocation both fall here -- start a brand-new, empty attempt so no
  # stale evidence from a different attempt can ever be aggregated
  # (corpus case 16: "mixed tier evidence from two release attempts").
  RELEASE_ATTEMPT_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
  echo "release: starting a FRESH release_attempt_id=${RELEASE_ATTEMPT_ID} (no matching prior attempt identity) -- wiping ${OUT_DIR}" >&2
  "$BOOTSTRAP_RM_TOOL" -rf "$OUT_DIR"
  "$BOOTSTRAP_MKDIR_TOOL" -p "$CHECKPOINT_STATE_DIR"
fi
# The FRESH branch above deletes $OUT_DIR wholesale, so rebuilding whatever
# lives there can only use the bootstrap tools captured before any toolbin
# existed. The toolbin itself is no longer inside $OUT_DIR (it now lives on
# a native filesystem, mkdtemp'd earlier in this script) and does NOT get
# rm -rf'd here: its mode-0500 lockdown is now real (this is the whole
# point of moving it off the 9p/drvfs mount), and a genuinely read-only
# directory cannot have its entries unlinked -- rm -rf would fail on its
# own prior output. release_toolset.py's write_toolset/build_toolbin is
# already idempotent against an existing toolbin whose entries exactly
# match the requested set (re-verifies, re-chmods, returns); the identical
# --tools default is requested every call this script makes, so calling it
# again here is a no-op re-verification, not a rebuild, and a genuine
# mismatch still fails loudly rather than being silently papered over by a
# wipe-and-recreate.
"$BOOTSTRAP_RM_TOOL" -f "$TOOLSET_JSON_TEMP"
"$BOOTSTRAP_PYTHON_TOOL" "$ROOT/scripts/release_toolset.py" --policy "$RELEASE_TOOL_POLICY" --out "$OUT_DIR/toolset.json" --toolbin "$TOOLBIN_DIR" >/dev/null
export PATH="$TOOLBIN_DIR"
IDENTITY_FILE="$CHECKPOINT_STATE_DIR/identity.json"
python3 "$ROOT/scripts/release_checkpoint.py" init --state-dir "$CHECKPOINT_STATE_DIR" --identity-file "$CANDIDATE_IDENTITY" --attempt-id "$RELEASE_ATTEMPT_ID" >/dev/null
rm -f "$CANDIDATE_IDENTITY"

# P1-6: now that OUT_DIR is settled (either reused from a matching prior
# attempt or freshly wiped+recreated), materialize the toolset record that
# was computed against the temp file above into its shipped location.

# ---------------------------------------------------------------------------
# Sol15 P0-1 (rc8-upg15 S2b): declare the hermetic builder. This is the one
# object binding "every tool release_tier_pipeline.sh actually verified" to
# "the exact PATH and host that ran the release" in one place -- toolset.json
# alone records tool identities, not the builder they ran on or the narrowed
# PATH they ran under. Best-effort like preflight.json above (libc detection
# via the stdlib, no bare subprocess call): a probe this host can't answer
# never blocks the release.
# ---------------------------------------------------------------------------
"$PYTHON_TOOL" -c '
import json, pathlib, platform, sys
toolset_path, path_in_force, toolbin_dir, out_path = sys.argv[1:5]
toolset = json.loads(pathlib.Path(toolset_path).read_text())
libc_name, libc_version = platform.libc_ver()
document = {
    "builder": {
        "hostname": platform.node(),
        "system": platform.system(),
        "machine": platform.machine(),
    },
    "kernel": platform.uname().release,
    "libc": {"name": libc_name or "unknown", "version": libc_version or "unknown"},
    "path_in_force": path_in_force,
    "toolbin": toolbin_dir,
    "toolset_hash": toolset.get("toolset_hash"),
    "tools": toolset.get("tools", []),
}
pathlib.Path(out_path).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
' "$OUT_DIR/toolset.json" "$TOOLBIN_DIR" "$TOOLBIN_DIR" "$OUT_DIR/release-environment.json"

# ---------------------------------------------------------------------------
# Stability preflight (Sol11 P1-5): record the exact host conditions this
# attempt started under, before any tier runs -- so an abnormal termination
# leaves a human enough evidence on disk to distinguish "the code is wrong"
# from "the host ran out of $RESOURCE mid-run". Best-effort throughout: a
# probe this host can't answer (no systemd, no Docker CLI, no Landlock
# introspection) records "unknown", never blocks or fails the release.
# ---------------------------------------------------------------------------
python3 "$ROOT/scripts/release_preflight.py" --out "$OUT_DIR/preflight.json" \
  --release-attempt-id "$RELEASE_ATTEMPT_ID" --go-test-parallelism "$GO_TEST_PARALLELISM" \
  --platforms "$PLATFORMS" --go-bin "$GO_TOOL" >&2

TEST_RUN_ID="go-test-${COMMIT}"
ACCEPTANCE_RUN_ID="version-self-check-${COMMIT}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.sourceCommit=${COMMIT} -X main.buildTimestamp=${BUILD_TS} -X main.claimsHash=${CLAIMS_HASH} -X main.adapterProtocolVersion=${ADAPTER_PROTOCOL_VERSION}"

# ---------------------------------------------------------------------------
# rc8-upg15 S3 (Sol15 P0-4, required correction): build the final release
# archives FIRST, using final release flags, and extract+verify the host
# platform's BEFORE any test tier runs. Before this session, the mandatory
# Assayer/context-graph integration tier tested a SEPARATE binary
# (dist/integration-gov, built with default CGO -- dynamically linked) while
# the shipped release binary (CGO_ENABLED=0, statically linked) never
# participated in mandatory evidence at all: the integration and final SHAs
# diverged by construction (fb70a417... vs d3592a92...). Building here means
# the exact bytes that go into the test tiers below are the exact bytes that
# ship -- one executable identity across build, archive, extraction,
# integration, and acceptance. No second "equivalent" Governator binary
# participates in mandatory release evidence.
#
# Sol12 P1-4: re-verify toolset identity before the build phase -- a tool
# substituted between preflight and build would produce artifacts whose
# toolset_hash claim is a lie.
# ---------------------------------------------------------------------------
if ! python3 "$ROOT/scripts/release_toolset.py" --policy "$RELEASE_TOOL_POLICY" --verify "$OUT_DIR/toolset.json"; then
  echo "release: refusing to build -- a release tool changed identity since preflight (Sol12 P1-4)" >&2
  exit 1
fi
HOST_PLATFORM_ID="$("$GO_TOOL" env GOOS)_$("$GO_TOOL" env GOARCH)"
HOST_ARCHIVE_NAME=""
HOST_ARCHIVE_SHA=""
HOST_BIN_SHA=""

# v16-release Session 6 (R4): executed native acceptance evidence feed.
# EVIDENCE_DIR (optional) points at a directory of per-platform
# acceptance.json files produced by the native-acceptance CI job
# (.github/workflows/ci.yml :: native-acceptance, runners macos-latest and
# ubuntu-24.04-arm). A platform is approving only with executed native
# acceptance evidence -- this is the release-path mirror of
# internal/redteamgate.ClassifyPlatformWithEvidence (Sol15 P1-2 / v16 S6),
# kept in sync by hand because this script builds the very binary whose
# package defines that function. An unset/empty EVIDENCE_DIR preserves the
# historic behavior unchanged: only the host platform -- which this script
# acceptance-tests itself below -- is approving, and every cross-compiled
# platform is non-approving. A record with overall_result != PASS or any
# failed check never promotes a platform (rule 13: evidence must be real).
EVIDENCE_PLATFORMS=""
if [ -n "${EVIDENCE_DIR:-}" ]; then
  if [ ! -d "$EVIDENCE_DIR" ]; then
    echo "release: EVIDENCE_DIR=$EVIDENCE_DIR is not a directory -- refusing rather than silently dropping native acceptance evidence" >&2
    exit 1
  fi
  EVIDENCE_PLATFORMS=$(python3 - "$EVIDENCE_DIR" <<'PYEV'
import json, pathlib, sys
d = pathlib.Path(sys.argv[1])
required = ("archive_extracted", "executable_bit_preserved",
            "binary_hash_matches_build", "version_json_matches_manifest")
evidence = []
for f in sorted(d.glob("*.json")):
    try:
        rec = json.loads(f.read_text())
    except Exception:
        continue  # malformed evidence never promotes a platform
    checks = rec.get("checks", {})
    if (rec.get("overall_result") == "PASS"
            and rec.get("extracted_platform")
            and all(checks.get(k) is True for k in required)):
        evidence.append(rec["extracted_platform"])
print(" ".join(evidence))
PYEV
)
  if [ -n "$EVIDENCE_PLATFORMS" ]; then
    echo "release: native acceptance evidence promotes: ${EVIDENCE_PLATFORMS}" >&2
  else
    echo "release: EVIDENCE_DIR provided but contained no passing native acceptance evidence (all platforms stay cross-compiled/non-approving)" >&2
  fi
fi

ARTIFACTS_JSON="$OUT_DIR/.artifacts.jsonl"
: >"$ARTIFACTS_JSON"
for platform in $PLATFORMS; do
  require_clean_tree "before build ${platform}"
  GOOS_VALUE=${platform%/*}
  GOARCH_VALUE=${platform#*/}
  PLATFORM_ID="${GOOS_VALUE}_${GOARCH_VALUE}"
  STAGE="$OUT_DIR/stage-${PLATFORM_ID}"
  mkdir -p "$STAGE"
  # Found 2026-07-14 (Session 1 of the post-v4 hardening plan): OUT_DIR can
  # sit on a filesystem that does not honor Unix permission bits at all
  # (e.g. WSL's DrvFs mount for a Windows drive -- chmod exits 0 but every
  # file reports 777 regardless). tar bakes in whatever mode stat() reports
  # at archive time, so a binary built/chmod'd directly under such an
  # OUT_DIR ships with the wrong mode no matter what chmod says -- this is
  # exactly the "shipped at mode 0777" shape the acceptance check below
  # (report attack 24) exists to catch, except self-inflicted by the build
  # itself rather than a hostile archive. Build and chmod in a native-fs
  # temp dir instead (same mktemp -d pattern the acceptance smoke test
  # below already uses for extraction) and tar from there -- only the
  # binary INSIDE the archive needs a real Unix mode; the .tar.gz written
  # into OUT_DIR is opaque data and unaffected by the host mount's
  # permission quirks. A copy also lands at $STAGE/gov (whatever OUT_DIR's
  # mount reports for it) purely for the other places in this script that
  # read it by content -- hash comparisons, or a local convenience binary
  # -- never as a tar source.
  NATIVE_STAGE=$(mktemp -d)
  BIN="$NATIVE_STAGE/gov"
  GOOS=$GOOS_VALUE GOARCH=$GOARCH_VALUE CGO_ENABLED=0 "$GO_TOOL" build -trimpath -ldflags "$LDFLAGS" -o "$BIN" ./cmd/gov
  chmod 0755 "$BIN"
  cp "$BIN" "$STAGE/gov"
  ARCHIVE_NAME="gov_${VERSION}_${PLATFORM_ID}.tar.gz"
  ARCHIVE="$OUT_DIR/${ARCHIVE_NAME}"
  # Explicit owner/perm normalization: tar preserves the source file's mode
  # (0755, just chmod'd above) by default, but --owner/--group/--numeric-owner
  # keep the archive reproducible across build machines instead of baking in
  # whichever uid/gid happened to run this script (audit: "several outer ZIP
  # ELF files stored without executable permission" — normalize instead of
  # trusting the ambient umask).
  tar --numeric-owner --owner=0 --group=0 -czf "$ARCHIVE" -C "$NATIVE_STAGE" gov
  rm -rf "$NATIVE_STAGE"
  ARCHIVE_SHA=$(sha256sum "$ARCHIVE" | awk '{print $1}')
  BIN_SHA=$(sha256sum "$STAGE/gov" | awk '{print $1}')
  SIZE=$(stat -c%s "$ARCHIVE" 2>/dev/null || stat -f%z "$ARCHIVE")
  python3 -c "
import json, sys
platform_id = sys.argv[1]
host_platform_id = sys.argv[6]
evidence_platforms = set(sys.argv[7].split()) if len(sys.argv) > 7 and sys.argv[7] else set()
# v16 S6 / R4: approval mirrors internal/redteamgate.ClassifyPlatformWithEvidence
# (kept in sync by hand). A platform is approving only when its GOOS is
# approval-eligible (linux) AND it carries executed native acceptance evidence
# (evidence_platforms, fed from EVIDENCE_DIR). The host platform is approving
# unconditionally here because this script runs its own acceptance check on it
# below; a cross-compiled linux platform needs CI evidence to promote, else it
# stays non-approving (cross-compiled-no-native-acceptance). darwin is
# non-approving (degradedPlatforms) until promoted with native evidence AND a
# passing native corpus -- its acceptance smoke alone does not promote it.
# Sol12 P1-1: the PLATFORMS validation loop above already refuses any GOOS
# outside {linux, darwin} before this ever runs, so an unrecognized
# platform_id here means that guard was bypassed; fail loud.
goos = platform_id.split('_', 1)[0]
if platform_id == host_platform_id:
    feature_limited = False
    degraded_modes = []
elif goos == 'linux' and platform_id in evidence_platforms:
    feature_limited = False
    degraded_modes = []
elif goos == 'linux':
    feature_limited = True
    degraded_modes = ['cross-compiled-no-native-acceptance']
elif goos == 'darwin':
    feature_limited = True
    degraded_modes = ['non-approving']
else:
    sys.exit('release: unrecognized platform_id %r reached artifact labeling despite the PLATFORMS guard (internal/redteamgate.ClassifyPlatform, Sol12 P1-1) -- refusing to default it to approving' % platform_id)
print(json.dumps({
    'platform': platform_id,
    'archive_path': sys.argv[2],
    'archive_sha256': sys.argv[3],
    'extracted_binary_sha256': sys.argv[4],
    'archive': sys.argv[2],
    'binary_sha256': sys.argv[4],
    'size_bytes': int(sys.argv[5]),
    'feature_limited': feature_limited,
    'approving': not feature_limited,
    'known_degraded_modes': degraded_modes,
}))" "$PLATFORM_ID" "$ARCHIVE_NAME" "$ARCHIVE_SHA" "$BIN_SHA" "$SIZE" "$HOST_PLATFORM_ID" "$EVIDENCE_PLATFORMS" >>"$ARTIFACTS_JSON"
  echo "release: built ${ARCHIVE_NAME} (${ARCHIVE_SHA})" >&2
  if [ "$PLATFORM_ID" = "$HOST_PLATFORM_ID" ]; then
    HOST_ARCHIVE_NAME=$ARCHIVE_NAME
    HOST_ARCHIVE_SHA=$ARCHIVE_SHA
    HOST_BIN_SHA=$BIN_SHA
  fi
done

# Host-platform binary stays unpacked in the staging root too, so any local
# `./dist/gov version` doesn't need to extract an archive just to sanity-
# check the build that matches this machine.
if [ -f "$OUT_DIR/stage-${HOST_PLATFORM_ID}/gov" ]; then
  cp "$OUT_DIR/stage-${HOST_PLATFORM_ID}/gov" "$OUT_DIR/gov"
fi

HOST_ARCHIVE="$OUT_DIR/gov_${VERSION}_${HOST_PLATFORM_ID}.tar.gz"

# run_acceptance_check EXTRACT_DIR OUT_JSON RUN_ID
# Extracts $HOST_ARCHIVE into a clean EXTRACT_DIR and verifies mode, hash
# (against $HOST_BIN_SHA, recorded above), and self-reported
# version/commit/claims/dirty. Sets ACCEPTANCE_RESULT and writes OUT_JSON.
# rc8-upg15 S3 (Sol15 P0-4 required correction #3/#4): this deliberately
# stops at binary self-consistency -- it does NOT call `gov claims verify`
# itself (P0-7 / report attack 25: that used to happen here, without
# --artifact/--manifest, which is exactly how a claims-verify gap stayed
# invisible). Full claims verification against the finalized manifest is its
# own, later, independently release-blocking stage.
run_acceptance_check() {
  local extract_dir=$1 out_json=$2 run_id=$3
  rm -rf "$extract_dir"
  mkdir -p "$extract_dir"
  local notes_file
  notes_file=$(mktemp)
  : >"$notes_file"
  local accept_ok=true executable_bit_ok=true hash_match_ok=true version_match_ok=true archive_extracted=false
  if [ -f "$HOST_ARCHIVE" ]; then
    archive_extracted=true
    # -p: without it, a restrictive umask on the extracting machine silently
    # masks a hostile archived mode bit, making the mode assertion below
    # meaningless.
    tar -xzf "$HOST_ARCHIVE" -C "$extract_dir" -p
    local extracted_bin="$extract_dir/gov"
    # Report attack 24: the archived binary shipped at mode 0777. Assert the
    # EXACT mode after extraction (not "is it executable at all" — 0777 is
    # also executable) and fail on any group/world write bit.
    local extracted_mode
    extracted_mode=$(stat -c '%a' "$extracted_bin" 2>/dev/null || stat -f '%OLp' "$extracted_bin")
    if [ "$extracted_mode" != "755" ]; then
      accept_ok=false
      executable_bit_ok=false
      echo "extracted binary mode is ${extracted_mode}, must be exactly 755 (no group/world write bit)" >>"$notes_file"
    fi
    local extracted_sha
    extracted_sha=$(sha256sum "$extracted_bin" | awk '{print $1}')
    if [ "$extracted_sha" != "$HOST_BIN_SHA" ]; then
      accept_ok=false
      hash_match_ok=false
      echo "extracted binary hash (${extracted_sha}) does not match the built binary (${HOST_BIN_SHA})" >>"$notes_file"
    fi
    local version_out reported_version reported_commit reported_claims reported_dirty
    if version_out=$("$extracted_bin" version --json 2>&1); then
      reported_version=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('version',''))" "$version_out" 2>/dev/null || echo "")
      reported_commit=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('source_commit',''))" "$version_out" 2>/dev/null || echo "")
      reported_claims=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('claims_hash',''))" "$version_out" 2>/dev/null || echo "")
      reported_dirty=$(python3 -c "import json,sys; v=json.loads(sys.argv[1]); print(v.get('dirty', '__missing__'))" "$version_out" 2>/dev/null || echo "__missing__")
      if [ "$reported_version" != "$VERSION" ] || [ "$reported_commit" != "$COMMIT" ] || [ "$reported_claims" != "$CLAIMS_HASH" ]; then
        accept_ok=false
        version_match_ok=false
        echo "gov version --json (${reported_version}/${reported_commit}/${reported_claims}) does not match build-manifest.json (${VERSION}/${COMMIT}/${CLAIMS_HASH})" >>"$notes_file"
      fi
      if [ "$reported_dirty" != "False" ] && [ "$reported_dirty" != "false" ]; then
        accept_ok=false
        version_match_ok=false
        echo "gov version --json reports dirty=${reported_dirty}; release artifacts must report dirty=false" >>"$notes_file"
      fi
    else
      accept_ok=false
      version_match_ok=false
      echo "gov version --json failed: ${version_out}" >>"$notes_file"
    fi
  else
    accept_ok=false
    executable_bit_ok=false
    hash_match_ok=false
    version_match_ok=false
    echo "no archive built for this host's platform (${HOST_PLATFORM_ID}); nothing to extract and smoke-test" >>"$notes_file"
  fi
  if [ "$accept_ok" = true ]; then ACCEPTANCE_RESULT=PASS; else ACCEPTANCE_RESULT=FAIL; fi
  python3 - "$out_json" "$run_id" "$ACCEPTANCE_RESULT" "$HOST_PLATFORM_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$archive_extracted" "$executable_bit_ok" "$hash_match_ok" "$version_match_ok" "$notes_file" <<'PYACCEPT'
import json, pathlib, sys

(path, run_id, result, platform, generated_at,
 archive_extracted, executable_bit_ok, hash_match_ok, version_match_ok, notes_file) = sys.argv[1:]

notes = [line for line in pathlib.Path(notes_file).read_text().splitlines() if line.strip()]

def as_bool(s):
    return s == "true"

data = {
    "generated_at": generated_at,
    "acceptance_run_id": run_id,
    "extracted_platform": platform,
    "checks": {
        "archive_extracted": as_bool(archive_extracted),
        "executable_bit_preserved": as_bool(executable_bit_ok),
        "binary_hash_matches_build": as_bool(hash_match_ok),
        "version_json_matches_manifest": as_bool(version_match_ok),
    },
    "notes": notes,
    "overall_result": result,
}
pathlib.Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PYACCEPT
  rm -f "$notes_file"
}

# First acceptance pass: extract into a DURABLE directory (not a throwaway
# mktemp -- GOV_INTEGRATION_GOV_BIN below must remain a stable path for the
# entire test-tier run) and require it PASS before any test tier is allowed
# to start. This IS the exact executable the mandatory integration tier
# tests (required correction #5).
PRE_INTEGRATION_ACCEPTANCE="$OUT_DIR/.acceptance-pre-integration.json"
run_acceptance_check "$OUT_DIR/acceptance" "$PRE_INTEGRATION_ACCEPTANCE" "${ACCEPTANCE_RUN_ID}-pre-integration"
if [ "$ACCEPTANCE_RESULT" != PASS ]; then
  echo "release: acceptance smoke test FAILED before the test tiers ever ran — see ${PRE_INTEGRATION_ACCEPTANCE}" >&2
  exit 1
fi

echo "release: version=${VERSION} commit=${COMMIT} go=${GO_VERSION} release_attempt_id=${RELEASE_ATTEMPT_ID}" >&2

# ---------------------------------------------------------------------------
# Test tiers. No cached results, no skips (audit P2.3): every tier below runs
# for real THIS ATTEMPT (unless reused from an exact-identity-matching prior
# checkpoint of the SAME attempt -- see release_tier_pipeline.sh), and its
# outcome is recorded in test-summary.json rather than asserted from a prior
# log or from "the test function exists".
#
# P1-5 (Sol11): the six tiers below are driven through
# scripts/release_tier_pipeline.sh as ONE fail-fast sequence backed by
# scripts/release_checkpoint.py's atomic, identity-scoped checkpoints
# (corpus case 19: "required tier fails and later tiers do not run" -- the
# pipeline aborts immediately on the first FAIL and never invokes later
# tiers in the spec). "fresh, uncached test evidence is mandatory... exact
# commit, toolchain, dependency lock state, test command, start/end time,
# exit status, log hash" (P0-7 / Sol redteam v4 S8) is exactly what each
# checkpoint records; test-summary.json below reads it back out.
# ---------------------------------------------------------------------------
UNIT_LOG="$OUT_DIR/test-unit.log"
RACE_LOG="$OUT_DIR/test-race.log"
INTEGRATION_LOG="$OUT_DIR/test-integration.log"
INTEGRATION_JSON_LOG="$OUT_DIR/.integration.jsonl"
# rc8-upg15 S3 (Sol15 P0-4, required corrections #5/#6/#8/#9): this is the
# EXACT executable the acceptance check above already extracted from the
# host archive and verified (mode/hash/version/commit) -- never a separately
# built "integration-gov". Each integration TestMain receives this path
# through GOV_INTEGRATION_GOV_BIN, points enforce.SelfExeFDOverride at it
# (the fd-backed route, not the pathname-copy SelfExeOverride route), and
# records its SHA-256; `gov integration-gate verify` below requires that
# recorded identity to equal $HOST_BIN_SHA. One executable identity now
# holds across build, archive, extraction, integration, and acceptance; no
# second "equivalent" Governator binary participates in mandatory release
# evidence.
INTEGRATION_GOV_BIN="$OUT_DIR/acceptance/gov"
INTEGRATION_EVIDENCE_DIR="$OUT_DIR/integration-evidence"
INTEGRATION_EXPECTED_NAMES="$OUT_DIR/integration-expected-names.txt"
INTEGRATION_EXPECTED_PACKAGES="$OUT_DIR/integration-expected-packages.txt"
INTEGRATION_GATE_JSON="$OUT_DIR/.integration-gate.json"
CORPUS_LOG="$OUT_DIR/test-corpus.log"
REDTEAM_LOG="$OUT_DIR/test-redteam.log"
REDTEAM_RACE_LOG="$OUT_DIR/test-redteam-race.log"

MAIN_TIER_SPEC=$(mktemp)
if [ ! -f "$INTEGRATION_GOV_BIN" ]; then
  echo "release: ${INTEGRATION_GOV_BIN} is missing -- the pre-integration acceptance extraction (which must run before the test tiers) did not produce it" >&2
  exit 1
fi
# Sol15 P0-4 required correction #6: the integration tier's candidate SHA
# must equal the host artifact's recorded executable identity, asserted
# explicitly here rather than merely relying on "it happens to be the same
# path" -- this is release.sh's half of the SHA-equality gate;
# internal/redteamgate's ExpectedGovernorBinarySHA256 check (fed this exact
# hash via --governator-binary below) is the other half, re-verified against
# the harness evidence after the tier runs.
INTEGRATION_GOV_BIN_SHA=$(sha256sum "$INTEGRATION_GOV_BIN" | awk '{print $1}')
if [ "$INTEGRATION_GOV_BIN_SHA" != "$HOST_BIN_SHA" ]; then
  echo "release: refusing to run the integration tier -- ${INTEGRATION_GOV_BIN} sha256 (${INTEGRATION_GOV_BIN_SHA}) does not equal the host artifact's recorded executable_sha256 (${HOST_BIN_SHA})" >&2
  exit 1
fi
mkdir -p "$INTEGRATION_EVIDENCE_DIR"
cat >"$INTEGRATION_EXPECTED_NAMES" <<'EOF_INTEGRATION_NAMES'
TestEvaluateAgainstRealCLIPassAndFail
TestEvaluateShaMismatchAfterEvaluationIsError
TestEvaluateNonzeroExitIsError
TestEvaluateTimeout
TestEvaluateUnparseableStdoutIsError
TestSol3ArtifactDeclaredPathReachesRealAssayerFilePathCheck
TestInspectCodeGraphStatus
TestPrepareBuildsFingerprintAndQueries
TestPrepareAutoDegradesOnProviderFailure
EOF_INTEGRATION_NAMES
cat >"$INTEGRATION_EXPECTED_PACKAGES" <<'EOF_INTEGRATION_PACKAGES'
assay
contextgraph
EOF_INTEGRATION_PACKAGES
{
  printf 'unit\t%s\tPATH=%q %q test -p %s -parallel %s -count=1 ./...\n' "$UNIT_LOG" "$TEST_TIER_PATH" "$GO_TOOL" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM"
  printf 'race\t%s\tPATH=%q %q test -race -timeout=30m -p %s -parallel %s -count=1 ./...\n' "$RACE_LOG" "$TEST_TIER_PATH" "$GO_TOOL" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM"
  printf 'integration\t%s\tPATH=%q ASSAYER_REPO=%q GOV_INTEGRATION_ASSAYER_COMMIT=%q GOV_INTEGRATION_GOV_BIN=%q GOV_INTEGRATION_EVIDENCE_OUT=%q %q test -json -tags integration -p %s -parallel %s -count=1 ./internal/assay/... ./internal/contextgraph/... > %q && %q integration-gate verify --log %q --expected-names %q --harness-evidence %q --governator-binary %q --expected-packages %q --assayer-commit %q > %q && %q %q\n' "$INTEGRATION_LOG" "$TEST_TIER_PATH" "$ASSAYER_REPO" "$ASSAYER_COMMIT" "$INTEGRATION_GOV_BIN" "$INTEGRATION_EVIDENCE_DIR" "$GO_TOOL" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM" "$INTEGRATION_JSON_LOG" "$INTEGRATION_GOV_BIN" "$INTEGRATION_JSON_LOG" "$INTEGRATION_EXPECTED_NAMES" "$INTEGRATION_EVIDENCE_DIR" "$INTEGRATION_GOV_BIN" "$INTEGRATION_EXPECTED_PACKAGES" "$ASSAYER_COMMIT" "$INTEGRATION_GATE_JSON" "$CAT_TOOL" "$INTEGRATION_JSON_LOG"
  # Sol redteam v6 S0 (P0-18, partial): the build-tagged internal/redteam/
  # corpus was never actually compiled by any release or CI command --
  # "black_box_corpus" here only runs Sol3-prefixed tests, which never
  # triggers the `redteam` build tag. redteam/redteam_race below are the
  # exact commands the v6 report requires.
  printf 'corpus\t%s\tPATH=%q %q test -run '"'"'Sol3'"'"' -v -p %s -parallel %s -count=1 ./...\n' "$CORPUS_LOG" "$TEST_TIER_PATH" "$GO_TOOL" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM"
  # Sol14 P0-2/P0-3 (rc7 Session 10): the redteam tiers MUST carry the same
  # ASSAYER_REPO/commit binding the integration tier above does. The S5/S6
  # corpus cases (TestV14Case322-329) spawn a nested real integration tier,
  # and internal/redteam/v14_s5_integration_harness_test.go deliberately
  # falls back to the SIBLING checkout (<repo>/../assayer) only for a
  # standalone local run. A release runs from a detached scratch worktree
  # under $(mktemp -d), where that sibling is /tmp/tmp.XXXX/assayer and does
  # not exist -- so all eight cases failed closed (correctly: S5 made this
  # tier fail rather than skip) on the first end-to-end rc7 attempt. The
  # tests were only ever exercised by hand from the real checkout, where the
  # sibling fallback happens to resolve. Same defect class as every other
  # rc6/rc7 release blocker: a path that had never executed end to end.
  printf 'redteam\t%s\tPATH=%q ASSAYER_REPO=%q GOV_INTEGRATION_ASSAYER_COMMIT=%q %q test -v -timeout=30m -tags redteam -p %s -parallel %s -count=1 ./...\n' "$REDTEAM_LOG" "$TEST_TIER_PATH" "$ASSAYER_REPO" "$ASSAYER_COMMIT" "$GO_TOOL" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM"
  printf 'redteam_race\t%s\tPATH=%q ASSAYER_REPO=%q GOV_INTEGRATION_ASSAYER_COMMIT=%q %q test -v -race -timeout=30m -tags redteam -p %s -parallel %s -count=1 ./...\n' "$REDTEAM_RACE_LOG" "$TEST_TIER_PATH" "$ASSAYER_REPO" "$ASSAYER_COMMIT" "$GO_TOOL" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM"
} >"$MAIN_TIER_SPEC"

MAIN_TIER_JSONL="$OUT_DIR/.tier-pipeline-main.jsonl"
MAIN_TIER_PIPELINE_OK=true
# Sol12 P1-4 (rc5 Session 7): verify no release tool was substituted between
# preflight (toolset.json creation) and the first tier execution. A same-UID
# process could swap a tool binary after the hash was recorded; this check
# catches it before any tier evidence is produced with a different tool.
if ! python3 "$ROOT/scripts/release_toolset.py" --policy "$RELEASE_TOOL_POLICY" --verify "$OUT_DIR/toolset.json"; then
  echo "release: refusing to run test tiers -- a release tool changed identity since preflight (Sol12 P1-4)" >&2
  exit 1
fi
# Sol15 P0-1 (rc8-upg15 S2b): --policy/--toolset-json make
# release_tier_pipeline.sh re-verify the approved toolset itself,
# immediately before and immediately after EVERY tier it actually runs --
# closing the window this one pipeline-wide preflight check (above) cannot:
# a same-UID substitution between two tiers, or during one tier's own
# execution.
if ! "$BASH_TOOL" "$ROOT/scripts/release_tier_pipeline.sh" run --state-dir "$CHECKPOINT_STATE_DIR" --identity-file "$IDENTITY_FILE" --spec "$MAIN_TIER_SPEC" --python-bin "$PYTHON_TOOL" --bash-bin "$BASH_TOOL" --sha256sum-bin "$SHA256SUM_TOOL" --date-bin "$DATE_TOOL" --awk-bin "$AWK_TOOL" --mkdir-bin "$MKDIR_TOOL" --mktemp-bin "$MKTEMP_TOOL" --rm-bin "$RM_TOOL" --dirname-bin "$DIRNAME_TOOL" --cat-bin "$CAT_TOOL" --policy "$RELEASE_TOOL_POLICY" --toolset-json "$OUT_DIR/toolset.json" --toolset-py "$ROOT/scripts/release_toolset.py" >"$MAIN_TIER_JSONL"; then
  MAIN_TIER_PIPELINE_OK=false
fi
rm -f "$MAIN_TIER_SPEC"

# tier_field NAME FIELD reads one field out of the tier's own JSON line
# (the line whose "tier" key equals NAME) in $MAIN_TIER_JSONL. A tier that
# never ran because an earlier required tier failed (fail-fast) has no line
# at all -- tier_field then returns an empty string, and the FAIL default
# below keeps that tier correctly reported as not-PASS rather than crashing
# this script on a missing value.
tier_field() {
  python3 -c "
import json, sys
name, field = sys.argv[1], sys.argv[2]
for line in open(sys.argv[3]):
    line = line.strip()
    if not line:
        continue
    obj = json.loads(line)
    if obj.get('tier') == name:
        print(obj.get(field, ''))
        break
" "$1" "$2" "$MAIN_TIER_JSONL"
}

UNIT_RESULT=$(tier_field unit result); UNIT_RESULT=${UNIT_RESULT:-FAIL}
UNIT_SECONDS=$(tier_field unit duration_seconds); UNIT_SECONDS=${UNIT_SECONDS:-0}
UNIT_STARTED=$(tier_field unit started)
UNIT_ENDED=$(tier_field unit completed)
UNIT_LOG_SHA=$(tier_field unit log_sha256)

RACE_RESULT=$(tier_field race result); RACE_RESULT=${RACE_RESULT:-FAIL}
RACE_SECONDS=$(tier_field race duration_seconds); RACE_SECONDS=${RACE_SECONDS:-0}
RACE_STARTED=$(tier_field race started)
RACE_ENDED=$(tier_field race completed)
RACE_LOG_SHA=$(tier_field race log_sha256)

INTEGRATION_RESULT=$(tier_field integration result); INTEGRATION_RESULT=${INTEGRATION_RESULT:-FAIL}
INTEGRATION_SECONDS=$(tier_field integration duration_seconds); INTEGRATION_SECONDS=${INTEGRATION_SECONDS:-0}
INTEGRATION_STARTED=$(tier_field integration started)
INTEGRATION_ENDED=$(tier_field integration completed)
INTEGRATION_LOG_SHA=$(tier_field integration log_sha256)
if [ -f "$INTEGRATION_GATE_JSON" ] && [ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("ok", False))' "$INTEGRATION_GATE_JSON")" = True ]; then
  INTEGRATION_GATE_OK=true
else
  INTEGRATION_GATE_OK=false
  echo "release: integration-gate verify FAILED — verdict:" >&2
  if [ -f "$INTEGRATION_GATE_JSON" ]; then cat "$INTEGRATION_GATE_JSON" >&2; fi
fi

CORPUS_RESULT=$(tier_field corpus result); CORPUS_RESULT=${CORPUS_RESULT:-FAIL}
CORPUS_SECONDS=$(tier_field corpus duration_seconds); CORPUS_SECONDS=${CORPUS_SECONDS:-0}
CORPUS_STARTED=$(tier_field corpus started)
CORPUS_ENDED=$(tier_field corpus completed)
CORPUS_LOG_SHA=$(tier_field corpus log_sha256)
CORPUS_TESTS_RUN=0
CORPUS_TESTS_FAILED=0
if [ -f "$CORPUS_LOG" ]; then
  CORPUS_TESTS_RUN=$(grep -c '^--- PASS\|^--- FAIL' "$CORPUS_LOG" || true)
  CORPUS_TESTS_FAILED=$(grep -c '^--- FAIL' "$CORPUS_LOG" || true)
fi

REDTEAM_RESULT=$(tier_field redteam result); REDTEAM_RESULT=${REDTEAM_RESULT:-FAIL}
REDTEAM_SECONDS=$(tier_field redteam duration_seconds); REDTEAM_SECONDS=${REDTEAM_SECONDS:-0}
REDTEAM_STARTED=$(tier_field redteam started)
REDTEAM_ENDED=$(tier_field redteam completed)
REDTEAM_LOG_SHA=$(tier_field redteam log_sha256)

REDTEAM_RACE_RESULT=$(tier_field redteam_race result); REDTEAM_RACE_RESULT=${REDTEAM_RACE_RESULT:-FAIL}
REDTEAM_RACE_SECONDS=$(tier_field redteam_race duration_seconds); REDTEAM_RACE_SECONDS=${REDTEAM_RACE_SECONDS:-0}
REDTEAM_RACE_STARTED=$(tier_field redteam_race started)
REDTEAM_RACE_ENDED=$(tier_field redteam_race completed)
REDTEAM_RACE_LOG_SHA=$(tier_field redteam_race log_sha256)

if [ "$MAIN_TIER_PIPELINE_OK" != true ]; then
  echo "release: refusing to package -- a required test tier failed; scripts/release_tier_pipeline.sh halted the remaining tiers (fail-fast, P1-5). See ${MAIN_TIER_JSONL} for exactly which tier failed and which were never run." >&2
  exit 1
fi
if [ "$INTEGRATION_GATE_OK" != true ]; then
  echo "release: refusing to package — integration-gate verify rejected the mandatory integration tier (missing/failed/skipped test, wrong candidate binary, or incomplete sandbox evidence); see ${INTEGRATION_GATE_JSON}" >&2
  exit 1
fi

# Sol redteam v7 S7 (HS4): the old count-based gate (MIN_REDTEAM_TESTS /
# EXPECTED_REDTEAM_SKIPS) validated skip *count*, not the exact identity or
# reason of each skip — a wrong test skipping while the total stayed the
# same still passed. internal/redteam/manifest.yaml is now the single
# source of truth for the manifest-defined mandatory redteam corpus, and `gov
# redteam-gate verify` checks exact test identity against it: every
# required case present and passing, every skip individually authorized by
# name via the manifest's allowed_skip predicate+reason. See
# agents/governator-sol-upgrade7-plan.md Session 7.
REDTEAM_MANIFEST="internal/redteam/manifest.yaml"
# Sol14 rc7 Session 9c (P1-2): the name-inventoried exact manifests that drain
# the former exclusion list. Every *.yaml under internal/redteam/manifests/ is
# passed to the gate as --exact-manifest; the gate accounts for each listed test
# by name (not unmanifested drift) and S9d enforces zero unaccounted skips
# across the set: under --require-zero-skips, a skip by an exact-manifest test
# is authorized only when the manifest's required_capabilities are proven ABSENT
# in the capability record. An empty directory leaves the array empty and aborts
# the release below, so a release cannot accidentally run with a missing manifest
# set. NUL-delimited collection (mapfile -d '') is required: a plain `mapfile -t`
# over NUL-separated input silently collapses the whole list to one entry, which
# would pass only the first manifest and make the other five look like drift.
REDTEAM_EXACT_MANIFEST_DIR="internal/redteam/manifests"
mapfile -d '' -t REDTEAM_EXACT_MANIFEST_ARGS < <(
  shopt -s nullglob
  for f in "$REDTEAM_EXACT_MANIFEST_DIR"/*.yaml; do printf '%s\0' "$f"; done
)
if [ "${#REDTEAM_EXACT_MANIFEST_ARGS[@]}" -eq 0 ]; then
  echo "release: no exact manifests found in $REDTEAM_EXACT_MANIFEST_DIR (Sol14 S9c requires the manifest set)" >&2
  exit 1
fi
REDTEAM_EXACT_MANIFEST_FLAGS=()
for f in "${REDTEAM_EXACT_MANIFEST_ARGS[@]}"; do
  REDTEAM_EXACT_MANIFEST_FLAGS+=(--exact-manifest "$f")
done
# Sol12 rc5 Session 1 (P0-3): capability evidence is tri-state (present |
# absent | unknown). The gate now requires EVERY predicate the manifest
# references to be proven present/absent in this record, or it refuses with
# CAPABILITY_EVIDENCE_INCOMPLETE (a missing key no longer collapses to
# "absent" and authorizes a conditional skip). Each record carries its probe,
# host, platform, and timestamp so the evidence is self-describing; the
# signed per-host capability attestations aggregated at release (Sessions
# 5/6/9) carry the full evidence_hash/signature on top of this same schema.
#
# Sol14 rc7 Session 10: the probe itself now runs ONCE, before the checkpoint
# identity is computed (see CAPABILITIES_HASH above), and this gate consumes
# that exact evidence. Re-probing here would score a fresh capability record
# against a tier log that may have been produced under different host
# capabilities -- the same stale-evidence class this cycle keeps closing.
REDTEAM_CAPABILITIES_JSON=$RELEASE_CAPABILITIES_JSON
# Sol13 rc6 Session 1 (P0-4): this one shared computation supplies the
# tagged source inventory, source identity, and aggregate compiled-test-binary
# identity. Directory names are never used to decide which attack source is
# bound into a capability attestation.
REDTEAM_SOURCE_IDENTITY="$OUT_DIR/redteam-source-identity.json"
REDTEAM_INVENTORY="$OUT_DIR/.redteam-inventory.txt"
"$PYTHON_TOOL" scripts/redteam_source_identity.py --repo-root . --out "$REDTEAM_SOURCE_IDENTITY" --inventory-out "$REDTEAM_INVENTORY" --go-bin "$GO_TOOL"
# Sol12 P1-3 (rc5 Session 7): REQUIRE_ZERO_SKIPS is already set by the
# version-derived strictness block above (production versions always get 1,
# development versions default to 0 but the operator can opt in via
# GOV_RELEASE_REQUIRE_ZERO_SKIPS). Do NOT re-derive it here from env vars --
# that was the old P1-3 defect (REQUIRE_ZERO_SKIPS=0 could weaken a v* release).
REDTEAM_GATE_EXTRA_ARGS=()
if [ "$REQUIRE_ZERO_SKIPS" = 1 ]; then
  REDTEAM_GATE_EXTRA_ARGS+=(--require-zero-skips)
fi
# Sol13 rc6 Session 2: capability evidence is produced only by a real host
# running `gov attest capability`. This release host never manufactures five
# category labels from its one local log. S3 permits a production skip only
# when verified remote evidence records that exact test under the manifest's
# matching capability category; unsigned, relabeled, non-approving, or local
# capability-absence evidence cannot waive it.
ATTESTATIONS_DIR="${GOV_ATTESTATIONS_DIR:-}"
ASSAYER_COMMIT_ATTEST=$(git -C "${ASSAYER_REPO:-$SOURCE_ROOT/../assayer}" rev-parse HEAD 2>/dev/null || echo "unknown")
TEST_SOURCE_HASH=$(python3 -c "import json; print(json.load(open('$REDTEAM_SOURCE_IDENTITY'))['test_source_hash'])")
TEST_BINARY_SHA256=$(python3 -c "import json; print(json.load(open('$REDTEAM_SOURCE_IDENTITY'))['test_binary_sha256'])")
TOOLCHAIN_HASH=$("$GO_TOOL" version | sha256sum | awk '{print $1}')
if [ -n "$ATTESTATIONS_DIR" ]; then
  if [ ! -d "$ATTESTATIONS_DIR" ]; then
    echo "release: GOV_ATTESTATIONS_DIR is not a directory: $ATTESTATIONS_DIR" >&2
    exit 1
  fi
  RELEASE_ATTESTATION_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  REDTEAM_GATE_EXTRA_ARGS+=(--attestations "$ATTESTATIONS_DIR" --attestation-governator-commit "$COMMIT" --attestation-assayer-commit "$ASSAYER_COMMIT_ATTEST" --attestation-release-version "$VERSION" --attestation-source-identity "$REDTEAM_SOURCE_IDENTITY" --attestation-toolchain-hash "$TOOLCHAIN_HASH" --attestation-release-time "$RELEASE_ATTESTATION_TIME" --attestation-max-age "24h")
fi
REDTEAM_GATE_JSON="$OUT_DIR/.redteam-gate.json"
if "$GO_TOOL" run ./cmd/gov redteam-gate verify --manifest "$REDTEAM_MANIFEST" --log "$REDTEAM_LOG" --capabilities "$REDTEAM_CAPABILITIES_JSON" --inventory "$REDTEAM_INVENTORY" "${REDTEAM_EXACT_MANIFEST_FLAGS[@]}" "${REDTEAM_GATE_EXTRA_ARGS[@]}" >"$REDTEAM_GATE_JSON" 2>"$OUT_DIR/.redteam-gate.stderr"; then
  REDTEAM_GATE_OK=true
else
  REDTEAM_GATE_OK=false
  cat "$OUT_DIR/.redteam-gate.stderr" >&2
fi
read REDTEAM_TESTS_DISCOVERED REDTEAM_TESTS_RUN REDTEAM_TESTS_SKIPPED REDTEAM_TESTS_FAILED < <(python3 -c "
import json
d = json.load(open('$REDTEAM_GATE_JSON'))
print(d['discovered'], d['run'], d['skipped'], d['failed'])
")
if [ "$REDTEAM_GATE_OK" != true ]; then
  echo "release: redteam-gate verify FAILED — verdict:" >&2
  cat "$REDTEAM_GATE_JSON" >&2
fi

FUZZ_TARGETS=(
  "internal/contracts FuzzContractParser"
  "internal/policy FuzzClassifyShellCommand"
  "internal/runtime FuzzBashProtectedReason"
)
FUZZ_RESULTS_JSON="$OUT_DIR/.fuzz-results.jsonl"
: >"$FUZZ_RESULTS_JSON"
FUZZ_OK=true
for entry in "${FUZZ_TARGETS[@]}"; do
  pkg=${entry% *}
  fn=${entry#* }
  flog="$OUT_DIR/test-fuzz-${fn}.log"
  fstart=$(date +%s)
  if "$GO_TOOL" test -run "^${fn}\$" -fuzz "^${fn}\$" -fuzztime "${FUZZ_SECONDS}s" "./${pkg}" >"$flog" 2>&1; then
    fresult=PASS
  else
    fresult=FAIL
    FUZZ_OK=false
    cat "$flog" >&2
  fi
  fend=$(date +%s)
  echo "release: fuzz ${fn} ${fresult} ($((fend - fstart))s)" >&2
  python3 -c "import json,sys; print(json.dumps({'target': sys.argv[1], 'package': sys.argv[2], 'result': sys.argv[3], 'duration_seconds': int(sys.argv[4])}))" \
    "$fn" "$pkg" "$fresult" "$((fend - fstart))" >>"$FUZZ_RESULTS_JSON"
done

# Assayer's own release evidence must be a REAL Python 3.10/3.11/3.12/3.13
# matrix, not one host interpreter mislabeled as a matrix. Each interpreter's
# record includes the exact command, exit code, timeout status, timestamps,
# duration, and log hash. Missing interpreters or a missing Assayer checkout
# are release-blocking FAIL states, not silently omitted or renamed PASS.
ASSAYER_LOG="$OUT_DIR/test-assayer.log"
ASSAYER_MATRIX_JSON="$OUT_DIR/assayer-matrix.json"
: >"$ASSAYER_LOG"
if [ -d "$ASSAYER_REPO" ]; then
  python3 - "$ASSAYER_MATRIX_JSON" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_text("[]\n")
PY
  ASSAYER_RESULT=PASS
  ASSAYER_VENV_BASE="$OUT_DIR/assayer-venvs"
  mkdir -p "$ASSAYER_VENV_BASE"
  for ASSAYER_PY in 3.10 3.11 3.12 3.13; do
    ASSAYER_BIN="python${ASSAYER_PY}"
    ASSAYER_CASE_LOG="$OUT_DIR/test-assayer-py${ASSAYER_PY}.log"
    ASSAYER_CASE_STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    ASSAYER_CASE_START_EPOCH=$(date +%s)
    ASSAYER_EXIT_CODE=0
    ASSAYER_TIMEOUT=false
    ASSAYER_WHEEL_HASHES=""
    # P1-1 (Sol10 rc4 Session 8): the matrix used to record only the
    # requested minor version (e.g. "3.13"), which is what let a release
    # evidence file claim a clean run on "3.13" while the audit's actual
    # 3.13.5 install hung on shutdown -- there was no way to tell which
    # patch release the matrix ran without re-deriving it. Ask the
    # interpreter directly; a mismatch or empty result fails the case.
    ASSAYER_PY_FULL=""
    if command -v "$ASSAYER_BIN" >/dev/null 2>&1; then
      ASSAYER_PY_FULL=$("$ASSAYER_BIN" -c 'import platform; print(platform.python_version())' 2>/dev/null || true)
      # Sol12 P1-2: create a dedicated per-version venv and install from
      # the hash-locked requirements-lock.txt. A clean GitHub runner is not
      # guaranteed to provide pytest (or any Assayer dependency) in every
      # installed interpreter; the venv isolates each matrix case from
      # global runner packages and records exactly which wheels were
      # installed, so the release evidence proves the dependency closure.
      ASSAYER_VENV="$ASSAYER_VENV_BASE/py${ASSAYER_PY}"
      ASSAYER_VENV_OK=true
      if ! "$ASSAYER_BIN" -m venv "$ASSAYER_VENV" >>"$ASSAYER_CASE_LOG" 2>&1; then
        ASSAYER_VENV_OK=false
        echo "FAILED to create venv for $ASSAYER_BIN" >>"$ASSAYER_CASE_LOG"
      fi
      if [ "$ASSAYER_VENV_OK" = true ] && [ -f "$ASSAYER_REPO/requirements-lock.txt" ]; then
        if ! "$ASSAYER_VENV/bin/pip" install --quiet --disable-pip-version-check \
            -r "$ASSAYER_REPO/requirements-lock.txt" >>"$ASSAYER_CASE_LOG" 2>&1; then
          ASSAYER_VENV_OK=false
          echo "FAILED to install locked dependencies for $ASSAYER_BIN" >>"$ASSAYER_CASE_LOG"
        fi
      elif [ "$ASSAYER_VENV_OK" = true ]; then
        ASSAYER_VENV_OK=false
        echo "requirements-lock.txt not found in $ASSAYER_REPO" >>"$ASSAYER_CASE_LOG"
      fi
      if [ "$ASSAYER_VENV_OK" = true ]; then
        ASSAYER_WHEEL_HASHES=$("$ASSAYER_VENV/bin/python" -c "
import hashlib, importlib.metadata, json, pathlib
hashes = {}
for dist in importlib.metadata.distributions():
    name = dist.metadata['Name']
    ver = dist.metadata['Version']
    record = dist.read_text('RECORD')
    if record:
        hashes[f'{name}=={ver}'] = hashlib.sha256(record.encode()).hexdigest()
print(json.dumps(hashes, sort_keys=True))
" 2>/dev/null || echo "{}")
        if timeout 900s bash -lc "cd '$ASSAYER_REPO' && '$ASSAYER_VENV/bin/python' -m pytest -q" >"$ASSAYER_CASE_LOG" 2>&1; then
          ASSAYER_CASE_RESULT=PASS
        else
          ASSAYER_EXIT_CODE=$?
          if [ "$ASSAYER_EXIT_CODE" -eq 124 ]; then
            ASSAYER_TIMEOUT=true
          fi
          ASSAYER_CASE_RESULT=FAIL
          ASSAYER_RESULT=FAIL
          cat "$ASSAYER_CASE_LOG" >&2
        fi
      else
        ASSAYER_CASE_RESULT=FAIL
        ASSAYER_EXIT_CODE=1
        ASSAYER_RESULT=FAIL
        cat "$ASSAYER_CASE_LOG" >&2
      fi
      # A dedicated conftest.py hook (tests/conftest.py, P1-1) asserts
      # multiprocessing.active_children()==[], no unexpected non-daemon
      # threads, and no surviving cli.py subprocess at session end, and
      # forces pytest's own exit status non-zero if any of them hold --
      # "197 passed" alone is not release evidence of a clean exit.
      # `timeout` still bounds the case in case the process hangs anyway.
      if ! echo "$ASSAYER_PY_FULL" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        ASSAYER_CASE_RESULT=FAIL
        ASSAYER_RESULT=FAIL
        echo "could not determine ${ASSAYER_BIN}'s full patch version (got '${ASSAYER_PY_FULL}')" >>"$ASSAYER_CASE_LOG"
      fi
    else
      ASSAYER_CASE_RESULT=FAIL
      ASSAYER_EXIT_CODE=127
      ASSAYER_RESULT=FAIL
      echo "${ASSAYER_BIN} not present on this machine" >"$ASSAYER_CASE_LOG"
      cat "$ASSAYER_CASE_LOG" >&2
    fi
    ASSAYER_CASE_ENDED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    ASSAYER_CASE_END_EPOCH=$(date +%s)
    ASSAYER_CASE_SUMMARY=$("$TAIL_TOOL" -1 "$ASSAYER_CASE_LOG")
    ASSAYER_CASE_LOG_SHA=$(sha256sum "$ASSAYER_CASE_LOG" | awk '{print $1}')
    # P1-4 (Sol10 rc4 Session 8): a published hash with no retrievable
    # object behind it proves nothing. Ship the log itself, gzip-
    # compressed (Go's stdlib compress/gzip verifies it back in
    # internal/claims without a new external decompressor dependency),
    # named after the interpreter's own reported version so it survives
    # alongside every other patch build in the same $OUT_DIR.
    ASSAYER_CASE_LOG_PATH="assayer-python${ASSAYER_PY_FULL//./}.log.gz"
    gzip -c "$ASSAYER_CASE_LOG" >"$OUT_DIR/$ASSAYER_CASE_LOG_PATH"
    python3 - "$ASSAYER_MATRIX_JSON" "$ASSAYER_PY" "$ASSAYER_PY_FULL" "$ASSAYER_BIN" "$ASSAYER_CASE_RESULT" "$ASSAYER_EXIT_CODE" "$ASSAYER_TIMEOUT" "$ASSAYER_CASE_STARTED" "$ASSAYER_CASE_ENDED" "$((ASSAYER_CASE_END_EPOCH - ASSAYER_CASE_START_EPOCH))" "$ASSAYER_CASE_LOG_SHA" "$ASSAYER_CASE_SUMMARY" "$ASSAYER_CASE_LOG_PATH" "$ASSAYER_WHEEL_HASHES" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text())
wheel_hashes = {}
if len(sys.argv) > 14 and sys.argv[14].strip():
    try:
        wheel_hashes = json.loads(sys.argv[14])
    except (json.JSONDecodeError, ValueError):
        pass
data.append({
    "python_version": sys.argv[3] or sys.argv[2],
    "python_version_requested": sys.argv[2],
    "python_executable": sys.argv[4],
    "command": f"{sys.argv[4]} -m pytest -q",
    "result": sys.argv[5],
    "exit_code": int(sys.argv[6]),
    "timeout": sys.argv[7] == "true",
    "started_at": sys.argv[8],
    "ended_at": sys.argv[9],
    "duration_seconds": int(sys.argv[10]),
    "log_sha256": sys.argv[11],
    "log_path": sys.argv[13],
    "summary": sys.argv[12].strip(),
    "wheel_hashes": wheel_hashes,
    "isolated_venv": True,
})
path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PY
    printf '%s %s\n' "$ASSAYER_BIN" "$ASSAYER_CASE_SUMMARY" >>"$ASSAYER_LOG"
  done
  ASSAYER_SUMMARY=$(python3 - "$ASSAYER_MATRIX_JSON" <<'PY'
import json, sys
rows = json.loads(open(sys.argv[1]).read())
print("; ".join(f"python{r['python_version']}={r['result']} ({r['summary']})" for r in rows))
PY
)
else
  ASSAYER_RESULT=FAIL
  ASSAYER_SUMMARY="ASSAYER_REPO ${ASSAYER_REPO} not present on this machine"
  echo "$ASSAYER_SUMMARY" >"$ASSAYER_LOG"
  python3 - "$ASSAYER_MATRIX_JSON" "$ASSAYER_SUMMARY" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps([
    {
        "python_version": "3.10-3.13",
        "python_executable": "",
        "command": "pythonX.Y -m pytest -q",
        "result": "FAIL",
        "exit_code": 127,
        "timeout": False,
        "started_at": "",
        "ended_at": "",
        "duration_seconds": 0,
        "log_sha256": "",
        "summary": sys.argv[2],
    }
], indent=2, sort_keys=True) + "\n")
PY
fi

# Sol redteam v7 S8 (corpus case 37): a passing pytest matrix says nothing
# about whether the Assayer commit under test is the one its own declared
# version claims to be -- the audit found Assayer at declared version 1.1.0
# with no Git tag at all. scripts/assayer_verify.sh is factored out (mirrors
# release_verify.sh) so it can also be driven directly and hermetically by
# internal/redteam/v7_pending_cases_test.go's TestV7Case37.
ASSAYER_VERSION_TAG_LOG="$OUT_DIR/test-assayer-version-tag.log"
if [ -d "$ASSAYER_REPO" ]; then
  if "$BASH_TOOL" "$ROOT/scripts/assayer_verify.sh" --assayer-repo "$ASSAYER_REPO" --python-bin "$PYTHON_TOOL" --git-bin "$GIT_TOOL" >"$ASSAYER_VERSION_TAG_LOG" 2>&1; then
    ASSAYER_VERSION_TAG_RESULT=PASS
  else
    ASSAYER_VERSION_TAG_RESULT=FAIL
    cat "$ASSAYER_VERSION_TAG_LOG" >&2
  fi
  ASSAYER_VERSION_TAG_SUMMARY=$("$TAIL_TOOL" -1 "$ASSAYER_VERSION_TAG_LOG")
else
  ASSAYER_VERSION_TAG_RESULT=SKIPPED
  ASSAYER_VERSION_TAG_SUMMARY="ASSAYER_REPO ${ASSAYER_REPO} not present on this machine"
  echo "$ASSAYER_VERSION_TAG_SUMMARY" >"$ASSAYER_VERSION_TAG_LOG"
fi

# The six main go-test tiers already fail-fast-exited above (P1-5) the
# moment scripts/release_tier_pipeline.sh reported a non-PASS result, so
# UNIT_RESULT..REDTEAM_RACE_RESULT are all guaranteed PASS here; this check
# stays as belt-and-suspenders against a future edit reordering that exit.
if [ "$UNIT_RESULT" != PASS ] || [ "$RACE_RESULT" != PASS ] || [ "$INTEGRATION_RESULT" != PASS ] || [ "$CORPUS_RESULT" != PASS ] || [ "$REDTEAM_RESULT" != PASS ] || [ "$REDTEAM_RACE_RESULT" != PASS ] || [ "$FUZZ_OK" != true ]; then
  echo "release: refusing to package — a required test tier failed" >&2
  exit 1
fi
# P1-5: the final manifest may only aggregate checkpoint evidence that
# belongs to THIS resolved release_attempt_id -- reject silently-mixed
# evidence from an earlier, different attempt (corpus case 16) even if a
# stale checkpoint file happens to still be sitting in $CHECKPOINT_STATE_DIR.
if ! python3 "$ROOT/scripts/release_checkpoint.py" aggregate --state-dir "$CHECKPOINT_STATE_DIR" --identity-file "$IDENTITY_FILE" \
  --required unit,race,integration,corpus,redteam,redteam_race >"$OUT_DIR/.checkpoint-aggregate.json"; then
  echo "release: refusing to package — release_checkpoint.py aggregate rejected the tier checkpoints (incomplete or mixed release-attempt evidence); see above" >&2
  exit 1
fi
if [ "$REDTEAM_GATE_OK" != true ]; then
  echo "release: refusing to package — redteam-gate verify rejected the corpus (missing/unexpected/failed test or unauthorized skip); see ${REDTEAM_GATE_JSON}" >&2
  exit 1
fi
if [ "$ASSAYER_RESULT" != PASS ]; then
  echo "release: refusing to package — the Assayer matrix is ${ASSAYER_RESULT}, not PASS (blocking release gate, P0-7)" >&2
  exit 1
fi
if [ "$ASSAYER_VERSION_TAG_RESULT" != PASS ]; then
  echo "release: refusing to package — Assayer version/tag provenance is ${ASSAYER_VERSION_TAG_RESULT}, not PASS (blocking release gate, Sol v7 S8 case 37): ${ASSAYER_VERSION_TAG_SUMMARY}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# rc8-upg15 S3 (Sol15 P0-4, required correction #10: "rerun final acceptance
# after integration without rebuilding"). Every platform archive and the host
# executable were built and extracted BEFORE the test tiers ran (see the
# build+acceptance block above, right after LDFLAGS) precisely so the
# mandatory integration tier could test the exact final bytes. This is the
# other half of that guarantee: re-hash every recorded artifact now, after
# every tier and gate above has passed, and refuse to package if a single
# byte differs from what was recorded at build time -- there is no rebuild
# step below this point, and this proves it, rather than merely asserting it
# by the absence of a second `go build` call.
# ---------------------------------------------------------------------------
while IFS= read -r artifact_line; do
  [ -z "$artifact_line" ] && continue
  RECORDED_ARCHIVE=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['archive_path'])" "$artifact_line")
  RECORDED_ARCHIVE_SHA=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['archive_sha256'])" "$artifact_line")
  CURRENT_ARCHIVE_SHA=$(sha256sum "$OUT_DIR/${RECORDED_ARCHIVE}" | awk '{print $1}')
  if ! ARTIFACT_UNCHANGED_ERR=$(redteamgate_verify_artifact_unchanged "archive ${RECORDED_ARCHIVE}" "$RECORDED_ARCHIVE_SHA" "$CURRENT_ARCHIVE_SHA"); then
    echo "release: refusing to package — $ARTIFACT_UNCHANGED_ERR" >&2
    exit 1
  fi
done <"$ARTIFACTS_JSON"
CURRENT_HOST_BIN_SHA=$(sha256sum "$INTEGRATION_GOV_BIN" | awk '{print $1}')
if ! ARTIFACT_UNCHANGED_ERR=$(redteamgate_verify_artifact_unchanged "host executable (${INTEGRATION_GOV_BIN})" "$HOST_BIN_SHA" "$CURRENT_HOST_BIN_SHA"); then
  echo "release: refusing to package — $ARTIFACT_UNCHANGED_ERR" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# claims.yaml travels with the release unmodified — same bytes hashed into
# CLAIMS_HASH above and embedded in every binary via -ldflags.
# ---------------------------------------------------------------------------
cp docs/claims.yaml "$OUT_DIR/claims.yaml"

# ---------------------------------------------------------------------------
# SBOM (CycloneDX 1.5 JSON), derived from the real module graph — no new
# build dependency required (cyclonedx-gomod is not vendored here and this
# script must not silently reach out to the network to install one).
# ---------------------------------------------------------------------------
SBOM="$OUT_DIR/sbom.json"
"$GO_TOOL" list -m -json all >"$OUT_DIR/.modules.json"
python3 - "$SBOM" "$VERSION" "$COMMIT" "$BUILD_TS" <<'PYSBOM'
import json, pathlib, sys

sbom_path, version, commit, build_ts = sys.argv[1:]
modules_raw = pathlib.Path(sys.argv[1]).parent.joinpath(".modules.json").read_text()

def iter_modules(raw):
    dec = json.JSONDecoder()
    idx = 0
    raw = raw.strip()
    while idx < len(raw):
        obj, end = dec.raw_decode(raw, idx)
        yield obj
        idx = end
        while idx < len(raw) and raw[idx].isspace():
            idx += 1

components = []
for mod in iter_modules(modules_raw):
    if mod.get("Main"):
        continue
    path = mod.get("Path", "")
    ver = mod.get("Version", "")
    components.append({
        "type": "library",
        "name": path,
        "version": ver,
        "purl": f"pkg:golang/{path}@{ver}" if ver else f"pkg:golang/{path}",
    })

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:governator-{commit}",
    "version": 1,
    "metadata": {
        "timestamp": build_ts,
        "component": {
            "type": "application",
            "name": "gov",
            "version": version,
        },
    },
    "components": components,
}
pathlib.Path(sbom_path).write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n")
PYSBOM
rm -f "$OUT_DIR/.modules.json"
echo "release: wrote sbom.json ($(python3 -c "import json;print(len(json.load(open('$SBOM'))['components']))") components)" >&2

# ---------------------------------------------------------------------------
# test-summary.json — a real record of the tiers this invocation actually
# ran above, not an assertion that test functions merely exist (audit P2.3:
# "test-function existence and cached logs are not release proof"). P0-7
# (Sol redteam v4 S8) additionally records the exact dependency lock state
# (go.sum hash) and, per suite, real start/end timestamps and a hash of the
# tier's own captured log — "fresh, uncached test evidence."
# ---------------------------------------------------------------------------
TEST_SUMMARY="$OUT_DIR/test-summary.json"
python3 - "$TEST_SUMMARY" "$COMMIT" "$GO_VERSION" "$BUILD_TS" "$GO_SUM_HASH" \
  "$UNIT_RESULT" "$UNIT_SECONDS" "$UNIT_STARTED" "$UNIT_ENDED" "$UNIT_LOG_SHA" \
  "$RACE_RESULT" "$RACE_SECONDS" "$RACE_STARTED" "$RACE_ENDED" "$RACE_LOG_SHA" \
  "$INTEGRATION_RESULT" "$INTEGRATION_SECONDS" "$INTEGRATION_STARTED" "$INTEGRATION_ENDED" "$INTEGRATION_LOG_SHA" "$INTEGRATION_GATE_OK" "$INTEGRATION_GATE_JSON" "$INTEGRATION_EVIDENCE_DIR" \
  "$CORPUS_RESULT" "$CORPUS_SECONDS" "$CORPUS_STARTED" "$CORPUS_ENDED" "$CORPUS_LOG_SHA" "$CORPUS_TESTS_RUN" "$CORPUS_TESTS_FAILED" \
  "$REDTEAM_RESULT" "$REDTEAM_SECONDS" "$REDTEAM_STARTED" "$REDTEAM_ENDED" "$REDTEAM_LOG_SHA" \
  "$REDTEAM_TESTS_DISCOVERED" "$REDTEAM_TESTS_RUN" "$REDTEAM_TESTS_SKIPPED" "$REDTEAM_TESTS_FAILED" "$REDTEAM_GATE_OK" "$REDTEAM_GATE_JSON" "$REDTEAM_MANIFEST" "$REDTEAM_SOURCE_IDENTITY" \
  "$REDTEAM_RACE_RESULT" "$REDTEAM_RACE_SECONDS" "$REDTEAM_RACE_STARTED" "$REDTEAM_RACE_ENDED" "$REDTEAM_RACE_LOG_SHA" \
  "$FUZZ_RESULTS_JSON" "$ASSAYER_RESULT" "$ASSAYER_SUMMARY" "$ASSAYER_MATRIX_JSON" "$ASSAYER_VERSION_TAG_RESULT" "$ASSAYER_VERSION_TAG_SUMMARY" "$GO_TEST_PARALLELISM" <<'PYTESTSUMMARY'
import json, pathlib, sys

(summary_path, commit, go_version, build_ts, go_sum_sha256,
 unit_result, unit_seconds, unit_started, unit_ended, unit_log_sha,
 race_result, race_seconds, race_started, race_ended, race_log_sha,
 integration_result, integration_seconds, integration_started, integration_ended, integration_log_sha, integration_gate_ok, integration_gate_json_path, integration_evidence_dir,
 corpus_result, corpus_seconds, corpus_started, corpus_ended, corpus_log_sha, corpus_tests_run, corpus_tests_failed,
 redteam_result, redteam_seconds, redteam_started, redteam_ended, redteam_log_sha,
 redteam_tests_discovered, redteam_tests_run, redteam_tests_skipped, redteam_tests_failed, redteam_gate_ok, redteam_gate_json_path, redteam_manifest_path, redteam_source_identity_path,
 redteam_race_result, redteam_race_seconds, redteam_race_started, redteam_race_ended, redteam_race_log_sha,
 fuzz_results_path, assayer_result, assayer_summary, assayer_matrix_path,
 assayer_version_tag_result, assayer_version_tag_summary, go_test_parallelism) = sys.argv[1:]

par = f"-p {go_test_parallelism} -parallel {go_test_parallelism}"

redteam_gate = json.loads(pathlib.Path(redteam_gate_json_path).read_text())
redteam_source_identity = json.loads(pathlib.Path(redteam_source_identity_path).read_text())
integration_gate = json.loads(pathlib.Path(integration_gate_json_path).read_text())
integration_evidence = {}
for evidence_path in sorted(pathlib.Path(integration_evidence_dir).glob("*.json")):
    integration_evidence[evidence_path.stem] = json.loads(evidence_path.read_text())

fuzz = []
for line in pathlib.Path(fuzz_results_path).read_text().splitlines():
    if line.strip():
        fuzz.append(json.loads(line))

data = {
    "generated_at": build_ts,
    "source_commit": commit,
    "go_version": go_version,
    "go_sum_sha256": go_sum_sha256,
    "environment_capabilities": {
        "goos": __import__("platform").system().lower(),
        "machine": __import__("platform").machine(),
        "python": __import__("sys").version.split()[0],
    },
    "suites": {
        # P1-4 (Sol10 rc4 Session 8): "a third party can see the claimed
        # hashes but cannot retrieve and verify the objects those hashes
        # identify." log_path names the gzip-compressed object this
        # invocation writes into $OUT_DIR right after this file is written
        # (see the compression loop below) -- log_sha256 is always the hash
        # of the DECOMPRESSED content, so a verifier gunzips log_path and
        # compares, never trusts the summary's word alone.
        "unit": {"command": f"go test {par} -count=1 ./...", "result": unit_result, "duration_seconds": int(unit_seconds), "started_at": unit_started, "ended_at": unit_ended, "log_sha256": unit_log_sha, "log_path": "unit.log.gz"},
        "race": {"command": f"go test -race {par} -count=1 ./...", "result": race_result, "duration_seconds": int(race_seconds), "started_at": race_started, "ended_at": race_ended, "log_sha256": race_log_sha, "log_path": "race.log.gz"},
        "integration": {"command": f"go test -json -tags integration {par} -count=1 ./internal/assay/... ./internal/contextgraph/...", "result": integration_result, "duration_seconds": int(integration_seconds), "started_at": integration_started, "ended_at": integration_ended, "log_sha256": integration_log_sha, "log_path": "integration.log.gz", "expected_tests": ["TestEvaluateAgainstRealCLIPassAndFail", "TestEvaluateShaMismatchAfterEvaluationIsError", "TestEvaluateNonzeroExitIsError", "TestEvaluateTimeout", "TestEvaluateUnparseableStdoutIsError", "TestSol3ArtifactDeclaredPathReachesRealAssayerFilePathCheck", "TestInspectCodeGraphStatus", "TestPrepareBuildsFingerprintAndQueries", "TestPrepareAutoDegradesOnProviderFailure"], "identity_gate": {**integration_gate, "ok": integration_gate_ok == "true"}, "harness_evidence": integration_evidence},
        "black_box_corpus": {
            "command": f"go test -run Sol3 -v {par} -count=1 ./...",
            "result": corpus_result,
            "duration_seconds": int(corpus_seconds),
            "started_at": corpus_started,
            "ended_at": corpus_ended,
            "log_sha256": corpus_log_sha,
            "log_path": "corpus.log.gz",
            "tests_run": int(corpus_tests_run),
            "tests_failed": int(corpus_tests_failed),
        },
        "redteam": {
            "command": f"go test -v -tags redteam {par} -count=1 ./...",
            "result": redteam_result,
            "source_commit": commit,
            "duration_seconds": int(redteam_seconds),
            "started_at": redteam_started,
            "ended_at": redteam_ended,
            "log_sha256": redteam_log_sha,
            "log_path": "redteam.log.gz",
            "tests_discovered": int(redteam_tests_discovered),
            "tests_run": int(redteam_tests_run),
            "tests_skipped": int(redteam_tests_skipped),
            "tests_failed": int(redteam_tests_failed),
            # Sol v7 S7 (HS4): identity-based, not count-based. manifest is
            # internal/redteam/manifest.yaml (the manifest-defined single source of
            # truth); gate is `gov redteam-gate verify`'s full structured
            # verdict -- exact missing/unexpected/failed/unexpected-skip test
            # names, not just totals.
            "manifest": redteam_manifest_path,
            "source_identity": redteam_source_identity,
            "identity_gate": {**redteam_gate, "ok": redteam_gate_ok == "true"},
        },
        "redteam_race": {
            "command": f"go test -v -race -tags redteam {par} -count=1 ./...",
            "result": redteam_race_result,
            "duration_seconds": int(redteam_race_seconds),
            "started_at": redteam_race_started,
            "ended_at": redteam_race_ended,
            "log_sha256": redteam_race_log_sha,
            "log_path": "redteam-race.log.gz",
        },
        "fuzz": fuzz,
        "assayer_matrix": {
            "result": assayer_result,
            "summary": assayer_summary.strip(),
            "versions": json.loads(pathlib.Path(assayer_matrix_path).read_text()),
            # Sol v7 S8 (corpus case 37): a matching Git tag for Assayer's
            # own declared version, proving which commit "the shipped
            # Assayer" actually is -- see scripts/assayer_verify.sh.
            "version_tag": {"result": assayer_version_tag_result, "summary": assayer_version_tag_summary.strip()},
        },
    },
}
overall = "PASS"
for suite in ("unit", "race", "integration", "black_box_corpus", "redteam", "redteam_race"):
    if data["suites"][suite]["result"] != "PASS":
        overall = "FAIL"
if not data["suites"]["redteam"]["identity_gate"]["ok"]:
    overall = "FAIL"
if not data["suites"]["integration"]["identity_gate"]["ok"]:
    overall = "FAIL"
for f in fuzz:
    if f["result"] != "PASS":
        overall = "FAIL"
if assayer_result != "PASS":
    overall = "FAIL"
if assayer_version_tag_result != "PASS":
    overall = "FAIL"
data["overall_result"] = overall
pathlib.Path(summary_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PYTESTSUMMARY

# P1-4: ship the evidence objects test-summary.json's log_sha256 fields
# describe, not just their hashes -- gzip each tier's raw log to the exact
# log_path named above and keep it in $OUT_DIR (covered by checksums.txt
# below), instead of deleting it once its hash is captured.
for _entry in "$UNIT_LOG:unit.log.gz" "$RACE_LOG:race.log.gz" "$INTEGRATION_LOG:integration.log.gz" "$CORPUS_LOG:corpus.log.gz" "$REDTEAM_LOG:redteam.log.gz" "$REDTEAM_RACE_LOG:redteam-race.log.gz"; do
  _raw=${_entry%%:*}
  _dest=${_entry##*:}
  gzip -c "$_raw" >"$OUT_DIR/$_dest"
done
rm -f "$FUZZ_RESULTS_JSON" "$UNIT_LOG" "$RACE_LOG" "$INTEGRATION_LOG" "$INTEGRATION_JSON_LOG" "$CORPUS_LOG" "$REDTEAM_LOG" "$REDTEAM_RACE_LOG" "$ASSAYER_LOG" "$ASSAYER_VERSION_TAG_LOG" "$ASSAYER_MATRIX_JSON" "$OUT_DIR"/test-assayer-py*.log "$OUT_DIR"/test-fuzz-*.log

# ---------------------------------------------------------------------------
# Final acceptance pass: rerun the EXACT SAME check the pre-integration pass
# ran (extract the exact distributable archive for THIS host's platform on a
# clean path, then exercise it exactly like an operator installing it
# would), now that every test tier and gate above has passed. This is Sol15
# P0-4 required correction #10 ("rerun final acceptance after integration
# without rebuilding") -- run_acceptance_check and its no-rebuild sibling
# (redteamgate_verify_artifact_unchanged, checked above, right after the
# test-tier gates) are what jointly prove no rebuild happened: the archive
# on disk did not change, so re-extracting and re-checking it here reaches
# the identical verdict as the pre-integration pass. This step deliberately
# stops at binary self-consistency (mode, hash, self-reported
# version/commit/claims-hash) — it does NOT call `gov claims verify` itself
# (P0-7 / report attack 25: that used to happen here, without
# --artifact/--manifest, which is exactly how a claims-verify gap stayed
# invisible). Full claims verification against the finalized manifest is its
# own, later, independently release-blocking stage below.
# ---------------------------------------------------------------------------
ACCEPTANCE="$OUT_DIR/acceptance-summary.json"
run_acceptance_check "$OUT_DIR/.acceptance-final" "$ACCEPTANCE" "$ACCEPTANCE_RUN_ID"
rm -rf "$OUT_DIR/.acceptance-final"

if [ "$ACCEPTANCE_RESULT" != PASS ]; then
  echo "release: acceptance smoke test FAILED — see ${ACCEPTANCE}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# build-manifest.json — the one document every other file's identity must
# agree with: version, source commit, build timestamp, claims hash, adapter
# protocol version, every artifact this release actually produced, AND (P0-7
# / Sol redteam v4 S8) the finalized identity of the host-platform artifact
# (the one every check above just exercised) plus this run's real test and
# acceptance evidence — written only now, after both are known, so nothing
# downstream can read a manifest describing a run that hasn't finished yet.
# ---------------------------------------------------------------------------
ARCHITECTURE_METADATA="$OUT_DIR/architecture-build-metadata.json"
ASSAYER_COMMIT=$(git -C "$ASSAYER_REPO" rev-parse HEAD)
ASSAYER_VERSION=$(git -C "$ASSAYER_REPO" describe --tags --exact-match HEAD 2>/dev/null || echo "untagged-${ASSAYER_COMMIT}")
python3 - "$ARCHITECTURE_METADATA" "$VERSION" "$COMMIT" "$ASSAYER_COMMIT" "$ASSAYER_VERSION" "$PLATFORMS" "$HOST_PLATFORM_ID" <<'PYARCH'
import json, pathlib, sys
metadata_path, version, commit, assayer_commit, assayer_version, platforms, host_platform_id = sys.argv[1:]
platform_list = [p for p in platforms.split() if p]
degraded = []
for platform in platform_list:
    # Sol12 P1-1: same explicit allow-list as the artifact-labeling block
    # above -- the PLATFORMS guard already refuses anything outside
    # {linux, darwin} before this runs.
    pid = platform.replace('/', '_')
    if platform.startswith('darwin/'):
        degraded.append({'platform': pid, 'mode': 'non-approving'})
    elif platform.startswith('linux/'):
        # Sol15 P1-2: a linux platform that is not the host has no native
        # acceptance evidence and is non-approving.
        if pid != host_platform_id:
            degraded.append({'platform': pid, 'mode': 'cross-compiled-no-native-acceptance'})
    else:
        sys.exit('release: unrecognized platform %r reached architecture metadata despite the PLATFORMS guard (Sol12 P1-1) -- refusing' % platform)
pathlib.Path(metadata_path).write_text(json.dumps({
    'version': version,
    'source_commit': commit,
    'assayer_commit': assayer_commit,
    'assayer_version': assayer_version,
    'platforms': [p.replace('/', '_') for p in platform_list],
    'known_degraded_modes': degraded,
}, indent=2, sort_keys=True) + "\n")
PYARCH

MANIFEST="$OUT_DIR/build-manifest.json"
python3 - "$MANIFEST" "$VERSION" "$COMMIT" "$BUILD_TS" "$GO_VERSION" "$LDFLAGS" "$CLAIMS_HASH" "$ADAPTER_PROTOCOL_VERSION" "$ARTIFACTS_JSON" \
  "$HOST_ARCHIVE_NAME" "$HOST_ARCHIVE_SHA" "$HOST_BIN_SHA" "$(basename "$INTEGRATION_GOV_BIN")" "$TEST_RUN_ID" "$TEST_SUMMARY" "$ACCEPTANCE_RUN_ID" "$ACCEPTANCE_RESULT" "$(basename "$ARCHITECTURE_METADATA")" "$RELEASE_ATTEMPT_ID" \
  "$TOOLSET_HASH" "$ASSAYER_LOCKED_REF" "$ASSAYER_VERSION" <<'PYMANIFEST'
import json, pathlib, sys

(manifest, version, commit, build_ts, go_version, build_flags, claims_hash,
 adapter_protocol_version, artifacts_path,
 host_archive_name, host_archive_sha, host_bin_sha, executable_path, test_run_id, test_summary_path, acceptance_run_id, acceptance_result, architecture_metadata_path,
 release_attempt_id,
 toolset_hash, assayer_locked_ref, assayer_version) = sys.argv[1:]

artifacts = []
for line in pathlib.Path(artifacts_path).read_text().splitlines():
    if line.strip():
        artifacts.append(json.loads(line))

data = {
    "version": version,
    "source_commit": commit,
    "build_timestamp": build_ts,
    "go_version": go_version,
    "build_flags": build_flags,
    "claims_hash": claims_hash,
    "adapter_protocol_version": adapter_protocol_version,
    "artifacts": artifacts,
    # Host-platform artifact identity: the specific archive/binary the
    # acceptance smoke test, the mandatory integration tier, and the full
    # claims-verification stage below all extract, test, and inspect.
    # rc8-upg15 S3 (Sol15 P2-2): archive_path/archive_sha256 name the
    # ARCHIVE; executable_path/executable_sha256 name the CONTAINED BINARY
    # itself -- the ambiguity Sol found in the old artifact_path/
    # artifact_sha256 pair (one path label serving both). Kept for one
    # release as deprecated aliases (see docs/migration.md);
    # internal/claims.verifyArtifactManifest's expectedExtractedBinarySHA256
    # prefers executable_sha256 first, then extracted_binary_sha256, then
    # artifact_sha256.
    "archive_path": host_archive_name,
    "archive_sha256": host_archive_sha,
    "executable_path": executable_path,
    "executable_sha256": host_bin_sha,
    "extracted_binary_sha256": host_bin_sha,
    "artifact_path": host_archive_name,
    "artifact_sha256": host_bin_sha,
    "architecture_build_metadata_path": architecture_metadata_path,
    "build_info": {"vcs_revision": commit},
    "test_run_id": test_run_id,
    "test_result": "PASS",
    "test_summary_path": pathlib.Path(test_summary_path).name,
    "acceptance_run_id": acceptance_run_id,
    "acceptance_result": acceptance_result,
    # P1-5: the manifest names the exact release-attempt whose checkpoint
    # evidence it aggregates -- a downstream verifier (audit_bundle.sh's
    # release-mode check, Session 3) can confirm every piece of evidence it
    # ships actually belongs to this one attempt.
    "release_attempt_id": release_attempt_id,
    # P1-6 (Sol11 rc5 Session 8): the exact release-toolset hash -- every
    # release tool's binary SHA-256 is recorded in toolset.json (shipped
    # alongside this manifest); this combined hash is the identity a
    # downstream verifier compares to confirm the release was produced by
    # the exact toolset this manifest claims, not ambient PATH-resolved
    # executables a substituted binary could have intercepted.
    "toolset_hash": toolset_hash,
    "toolset_path": "toolset.json",
    # P1-4 (Sol11 rc5 Session 8): the Assayer ref assayer.lock declared for
    # this release -- the version-controlled pin both local and CI releases
    # check out, so the two produce byte-for-byte comparable evidence.
    # scripts/assayer_verify.sh independently confirms the checkout's HEAD
    # carries a Git tag matching Assayer's own pyproject.toml version.
    "assayer_locked_ref": assayer_locked_ref,
    "assayer_version": assayer_version,
}
key = pathlib.os.environ.get("GOV_RELEASE_HMAC_KEY", "")
if key:
    import hmac, hashlib
    unsigned = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    data["manifest_hmac_sha256"] = hmac.new(key.encode(), unsigned, hashlib.sha256).hexdigest()
pathlib.Path(manifest).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PYMANIFEST
rm -f "$ARTIFACTS_JSON"

# ---------------------------------------------------------------------------
# Full claims verification against the exact archived artifact (P0-7 / Sol
# redteam v4 S8, report attack 25). This is the release-blocking gate the
# audit found missing: the acceptance step above never called
# `gov claims verify --artifact --manifest`, so a shipped binary could drift
# from both the submitted source and the claims ledger without CI ever
# noticing. scripts/release_verify.sh extracts the host archive fresh (a
# second, independent extraction from the acceptance step's) and runs
# `claims verify --release`, which cmd/gov/main.go refuses to run at all
# without --artifact/--manifest.
# ---------------------------------------------------------------------------
CLAIMS_VERIFY_REPORT="$OUT_DIR/claims-verify-report.txt"
if ! "$BASH_TOOL" "$ROOT/scripts/release_verify.sh" --out-dir "$OUT_DIR" --repo "$ROOT" --platform "$HOST_PLATFORM_ID" --python-bin "$PYTHON_TOOL" --tar-bin "$TAR_TOOL" --mktemp-bin "$MKTEMP_TOOL" --rm-bin "$RM_TOOL" --stat-bin "$STAT_TOOL" >"$CLAIMS_VERIFY_REPORT" 2>&1; then
  echo "release: full claims verification FAILED — see ${CLAIMS_VERIFY_REPORT}" >&2
  cat "$CLAIMS_VERIFY_REPORT" >&2
  exit 1
fi
echo "release: full claims verification OK — see ${CLAIMS_VERIFY_REPORT}" >&2

# Staging subdirectories (stage-<platform>/) held the unpacked binary used
# to build each archive; they're not part of the shipped file set.
rm -rf "$OUT_DIR"/stage-*

# ---------------------------------------------------------------------------
# checksums.txt covers every file this release actually ships (every
# platform archive, the manifest, the SBOM, claims.yaml, both summaries, the
# full claims-verification report) — generated last, over the final
# directory contents, so it can never omit an artifact the way the audit
# found ("checksums covering the stale snapshot archives but not the current
# production binary").
# ---------------------------------------------------------------------------
# P1-5 evidence-object cleanup: dotfile working scratch (tier-pipeline JSONL
# transcript, checkpoint-aggregate summary) is not itself shipped release
# evidence -- the checkpoints it was derived from remain under
# $CHECKPOINT_STATE_DIR (needed for a future resume) but these two ARE
# regular top-level $OUT_DIR files release_policy.py's checksum-coverage
# check (below) would otherwise flag as unlisted.
rm -f "$MAIN_TIER_JSONL" "$OUT_DIR/.checkpoint-aggregate.json"
rm -f "$OUT_DIR/.redteam-gate.json" "$OUT_DIR/.redteam-gate.stderr" "$OUT_DIR/.redteam-inventory.txt"
# Sol14 rc7 Session 10: .integration-gate.json is the same shape of working
# scratch as .redteam-gate.json directly above -- the integration gate's
# parsed verdict, already folded into test-summary.json's
# suites.integration.identity_gate (alongside expected_tests,
# harness_evidence and log_sha256, all of which ARE checksummed). Added to
# $OUT_DIR by this cycle's Session 5 without being removed here or listed
# below, so the first rc7 release to reach packaging failed the coverage
# check on it.
rm -f "$INTEGRATION_GATE_JSON"

CHECKSUMS="$OUT_DIR/checksums.txt"
# Sol13 rc6 Session 9: attestations/ exists only when the operator supplied
# GOV_ATTESTATIONS_DIR (release.sh treats it as optional -- `${GOV_ATTESTATIONS_DIR:-}`).
# Listing `attestations/*.json` unconditionally made sha256sum fail outright on
# every release that does not carry capability attestations, after all six tiers,
# the fuzz targets, and all four platform artifacts had already been built. Like
# the approved-tool policy parser, this path had never executed end to end.
# Enumerate the directory instead, so present attestations are still covered --
# release_policy.py's checksum-coverage check independently fails the release if
# any shipped file is missing from checksums.txt, so omitting a directory that
# does not exist cannot weaken coverage, while omitting one that DOES exist
# would still be caught there.
#
# redteam-source-identity.json (Sol13 rc6 Session 1 P0-4) is shipped evidence:
# unlike its siblings .redteam-inventory.txt / .redteam-gate.json, it is not
# dot-prefixed and is not removed above. It was added to $OUT_DIR without being
# added here, so the first rc6 release built every artifact, signed checksums.txt,
# and only then failed the coverage check in release_policy.py -- rc5 never hit
# it because the file did not exist. It is written unconditionally before the
# tier pipeline's checkpoints can affect anything, so listing it cannot recreate
# the attestations-style "listed but absent" sha256sum failure described above.
(
  cd "$OUT_DIR"
  checksum_inputs=(
    *.tar.gz build-manifest.json architecture-build-metadata.json sbom.json
    claims.yaml test-summary.json acceptance-summary.json claims-verify-report.txt
    preflight.json toolset.json release-environment.json gov *.log.gz redteam-source-identity.json
    acceptance/gov integration-expected-names.txt integration-expected-packages.txt
    .acceptance-pre-integration.json
  )
  for attestation_file in attestations/*.json; do
    [ -e "$attestation_file" ] || break
    checksum_inputs+=("$attestation_file")
  done
  # rc8-upg15 S3 (Sol15 P0-4): the separate dist/integration-gov build is
  # gone -- acceptance/gov (the archive-extracted, mode/hash/version-verified
  # host executable, built before any test tier ran) is what every
  # integration-evidence record binds to as governor_binary_sha256 now, and
  # it is also the exact contained binary of the host .tar.gz already listed
  # above and the loose `gov` convenience copy beside it (all three are the
  # same bytes by construction -- see the no-rebuild guard above). Its
  # presence here, alongside the two expected-name/package lists that are the
  # literal inputs `gov integration-gate verify` consumed, is what makes
  # "the integration tier exercised the rc candidate" verifiable rather than
  # merely asserted: without it in the signed manifest, that binding would
  # name an object the release does not carry.
  #
  # Sol14 P0-2 (rc7 Session 5): the per-package integration TestMain records
  # the candidate-binary identity, Assayer identity, and real sandbox
  # mechanism here. They are release evidence, not disposable scratch, so
  # bind every record into the signed checksum manifest just like a remote
  # capability attestation.
  for integration_evidence in integration-evidence/*.json; do
    [ -e "$integration_evidence" ] || break
    checksum_inputs+=("$integration_evidence")
  done
  sha256sum -- "${checksum_inputs[@]}" >"$(basename "$CHECKSUMS")"
)

# ---------------------------------------------------------------------------
# checksums.txt.hmac — HMAC-SHA256 over checksums.txt, keyed by an
# operator-supplied secret. Sol9 P2-2: this file used to be named plain
# "signature" and was ALWAYS written, including the literal text "UNSIGNED:
# set GOV_RELEASE_HMAC_KEY..." when no key was configured -- sitting right
# next to a real checksums.txt.minisig, a file named exactly "signature"
# saying "UNSIGNED" reads as "this release is unsigned" even when the
# asymmetric signature below is present and real. Renamed to name what it
# actually is, and omitted entirely (not written as a placeholder) when no
# HMAC key is configured -- its absence is the honest signal, not a fabricated
# file.
#
# P0-7 (Sol redteam v4 S8): docs/security.md flagged the underlying gap —
# "HMAC with a shared secret is not publicly verifiable." An HMAC key that
# signs is also a key that can forge; anyone who can verify a release can
# also mint a fake one. When GOV_RELEASE_MINISIGN_KEY (path to an
# UNENCRYPTED minisign secret key — `minisign -G -W`, no interactive
# password prompt to automate around) and the `minisign` binary are both
# available, this additionally produces checksums.txt.minisig: an Ed25519
# signature verifiable by anyone holding only the corresponding *public*
# key, with no shared secret in the loop. This augments, not replaces, the
# HMAC file above (existing tooling/docs keep working); when minisign isn't
# configured, no .minisig file is written — never a fabricated one.
# ---------------------------------------------------------------------------
HMAC_SIGNATURE="$OUT_DIR/checksums.txt.hmac"
python3 "$ROOT/scripts/release_hmac_sign.py" --checksums "$CHECKSUMS" --out "$HMAC_SIGNATURE"

MINISIG="$OUT_DIR/checksums.txt.minisig"
if [ -n "${GOV_RELEASE_MINISIGN_KEY:-}" ]; then
  if minisign -S -s "$GOV_RELEASE_MINISIGN_KEY" -m "$CHECKSUMS" -x "$MINISIG" -c "gov release ${VERSION} ${COMMIT}" </dev/null >&2; then
    echo "release: signed checksums.txt with minisign (asymmetric, publicly verifiable)" >&2
  else
    echo "release: minisign signing failed (is GOV_RELEASE_MINISIGN_KEY an unencrypted key?)" >&2
    rm -f "$MINISIG"
  fi
else
  echo "release: no asymmetric signature — set GOV_RELEASE_MINISIGN_KEY (+ minisign on PATH) to add one" >&2
fi
# P1-5 (Sol10 rc4 Session 8) + Sol11 P0-1: when a signature is required
# (true production releases), the release gate now CRYPTOGRAPHICALLY
# verifies the signature -- not just the signer key ID. Three trust roots
# cooperate, none discovered beside the release:
#   1. docs/TRUSTED_SIGNING_KEYS.txt  -- the out-of-band-published signer
#      fingerprint(s) (agents/ repo + VPS mirror are the independent
#      channels). The .minisig's own signer key ID must be anchored here.
#   2. docs/signing_keys/<fp>.pub    -- the release toolchain's PINNED copy
#      of the Ed25519 verification public key. Its fingerprint must match
#      root #1. A key ID alone cannot verify a signature; this is the key
#      the in-process Ed25519 verifier actually uses.
#   3. scripts/release_tool_policy.yaml -- the separately reviewed identity
#      for every executable used to create the release. The policy's
#      minisign entry is used only for signing; verification never executes
#      a Minisign binary, so a fake PATH entry cannot influence the result.
# A REQUIRE_ASYMMETRIC_SIGNATURE=1 release whose signature does not
# cryptographically verify over the exact checksums.txt bytes, whose
# checksums no longer describe the shipped artifacts, or whose verifier
# was substituted now fails closed here.
TRUSTED_SIGNING_KEYS_FILE="$SOURCE_ROOT/docs/TRUSTED_SIGNING_KEYS.txt"
TRUSTED_PUBLIC_KEYS_DIR="$SOURCE_ROOT/docs/signing_keys"
python3 "$ROOT/scripts/release_policy.py" signature \
  --version "$VERSION" \
  --require "$REQUIRE_ASYMMETRIC_SIGNATURE" \
  --minisig "$MINISIG" \
  --trusted-fingerprints-file "$TRUSTED_SIGNING_KEYS_FILE" \
  --checksums "$CHECKSUMS" \
  --trusted-public-keys-dir "$TRUSTED_PUBLIC_KEYS_DIR" \
  --artifacts-dir "$OUT_DIR"

# S4 closes the same-UID replacement window through the final release gate.
# The shipped toolset evidence is valid only if the approved objects still
# match after signing and in-process verification have completed.
if ! python3 "$ROOT/scripts/release_toolset.py" --policy "$RELEASE_TOOL_POLICY" --verify "$OUT_DIR/toolset.json"; then
  echo "release: refusing to complete -- a release tool changed after preflight (Sol13 P0-2/P1-4)" >&2
  exit 1
fi

echo "release: OK — $OUT_DIR" >&2
ls -la "$OUT_DIR" >&2
echo "$MANIFEST"
