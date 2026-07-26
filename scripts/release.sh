#!/usr/bin/env bash
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

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

require_clean_tree() {
  local stage=${1:-release}
  if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
    echo "release: refusing to build from a dirty tree (${stage})" >&2
    exit 1
  fi
}

if [ "${GOV_RELEASE_IN_SCRATCH:-0}" != 1 ]; then
  require_clean_tree "source checkout"
  SOURCE_ROOT=$ROOT
  OUT_DIR_ABS=$(python3 -c 'import os,sys; root,out=sys.argv[1:3]; print(out if os.path.isabs(out) else os.path.join(root, out))' "$SOURCE_ROOT" "${OUT_DIR:-dist}")
  SCRATCH_PARENT=$(mktemp -d)
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
  (cd "$SCRATCH_TREE" && "$SCRATCH_TREE/scripts/release.sh")
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

BUILD_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CLAIMS_HASH=$(sha256sum docs/claims.yaml | awk '{print $1}')
ADAPTER_PROTOCOL_VERSION=${ADAPTER_PROTOCOL_VERSION:-adapter-protocol-v1}
GO_VERSION=$(go version | awk '{print $3}')
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
PLATFORMS=${PLATFORMS:-"linux/amd64 linux/arm64 darwin/amd64 darwin/arm64"}
# Sol12 P1-1 (rc5 Session 6): PLATFORMS is caller-controlled with no prior
# validation -- an operator setting PLATFORMS="windows/amd64" would reach
# the build loop below unchecked, and the per-artifact "approving" flag
# further down defaulted true for anything that didn't literally start with
# "darwin_", so an unsupported platform would have shipped silently marked
# fully approving. Refuse outright instead: every requested platform's GOOS
# must be exactly "linux" (fully approving) or "darwin" (explicitly
# non-approving/degraded, never silently trusted) -- mirrors
# internal/redteamgate.ApprovedPlatforms/ClassifyPlatform, the one Go-side
# source of truth TestV12Case36 tests directly. Kept in sync by hand: this
# script cannot import the Go package it is building.
for platform in $PLATFORMS; do
  platform_goos=${platform%/*}
  case "$platform_goos" in
    linux|darwin) ;;
    *)
      echo "release: refusing to build unsupported platform '${platform}' -- GOOS '${platform_goos}' is not in the approved set (linux: fully approving; darwin: explicitly non-approving/degraded). See docs/security.md's Session 6 closure entry (Sol12 P1-1) and internal/redteamgate.ClassifyPlatform." >&2
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
# P1-5: Assayer's commit is part of release IDENTITY (a checkpoint from a
# release attempt built against a different Assayer checkout must never be
# reused) -- computed here, before any test tier runs, rather than only
# later when architecture-build-metadata.json is written.
if [ -d "$ASSAYER_REPO" ]; then
  ASSAYER_COMMIT=$(git -C "$ASSAYER_REPO" rev-parse HEAD 2>/dev/null || echo "unknown")
else
  ASSAYER_COMMIT="absent"
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
TOOLSET_HASH=$(python3 "$ROOT/scripts/release_toolset.py" --out "$TOOLSET_JSON_TEMP")

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
TOOLCHAIN_HASH=$(printf '%s|%s|%s\n' "$(go version)" "$(python3 --version 2>&1)" "$TOOLSET_HASH" | sha256sum | awk '{print $1}')
ENVIRONMENT_HASH=$(printf '%s|GOMAXPROCS=%s|parallelism=%s|platforms=%s\n' "$(uname -a)" "${GOMAXPROCS:-}" "$GO_TEST_PARALLELISM" "$PLATFORMS" | sha256sum | awk '{print $1}')
# Sol12 P1-5 (rc5 Session 7): use the expected v${VERSION} tag directly
# rather than the first sorted tag at HEAD -- multiple tags on one commit
# must bind to the exact expected tag, not an arbitrary one.
RELEASE_TAG_FOR_IDENTITY="v${VERSION}"

OUT_DIR=${OUT_DIR:-dist}
CHECKPOINT_STATE_DIR="$OUT_DIR/.checkpoints"
mkdir -p "$CHECKPOINT_STATE_DIR"
CANDIDATE_IDENTITY=$(mktemp)
python3 "$ROOT/scripts/release_checkpoint.py" identity \
  --governator-commit "$COMMIT" --governator-tag "$RELEASE_TAG_FOR_IDENTITY" \
  --assayer-commit "$ASSAYER_COMMIT" --go-sum-hash "$GO_SUM_HASH" \
  --toolchain-hash "$TOOLCHAIN_HASH" --environment-hash "$ENVIRONMENT_HASH" \
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
  rm -rf "$OUT_DIR"
  mkdir -p "$CHECKPOINT_STATE_DIR"
fi
IDENTITY_FILE="$CHECKPOINT_STATE_DIR/identity.json"
python3 "$ROOT/scripts/release_checkpoint.py" init --state-dir "$CHECKPOINT_STATE_DIR" --identity-file "$CANDIDATE_IDENTITY" --attempt-id "$RELEASE_ATTEMPT_ID" >/dev/null
rm -f "$CANDIDATE_IDENTITY"

# P1-6: now that OUT_DIR is settled (either reused from a matching prior
# attempt or freshly wiped+recreated), materialize the toolset record that
# was computed against the temp file above into its shipped location.
mv "$TOOLSET_JSON_TEMP" "$OUT_DIR/toolset.json"

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
  --platforms "$PLATFORMS" >&2

TEST_RUN_ID="go-test-${COMMIT}"
ACCEPTANCE_RUN_ID="version-self-check-${COMMIT}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.sourceCommit=${COMMIT} -X main.buildTimestamp=${BUILD_TS} -X main.claimsHash=${CLAIMS_HASH} -X main.adapterProtocolVersion=${ADAPTER_PROTOCOL_VERSION}"

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
CORPUS_LOG="$OUT_DIR/test-corpus.log"
REDTEAM_LOG="$OUT_DIR/test-redteam.log"
REDTEAM_RACE_LOG="$OUT_DIR/test-redteam-race.log"

MAIN_TIER_SPEC=$(mktemp)
{
  printf 'unit\t%s\tgo test -p %s -parallel %s -count=1 ./...\n' "$UNIT_LOG" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM"
  printf 'race\t%s\tgo test -race -timeout=30m -p %s -parallel %s -count=1 ./...\n' "$RACE_LOG" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM"
  printf 'integration\t%s\tgo test -tags integration -p %s -parallel %s -count=1 ./internal/assay/...\n' "$INTEGRATION_LOG" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM"
  # Sol redteam v6 S0 (P0-18, partial): the build-tagged internal/redteam/
  # corpus was never actually compiled by any release or CI command --
  # "black_box_corpus" here only runs Sol3-prefixed tests, which never
  # triggers the `redteam` build tag. redteam/redteam_race below are the
  # exact commands the v6 report requires.
  printf 'corpus\t%s\tgo test -run '"'"'Sol3'"'"' -v -p %s -parallel %s -count=1 ./...\n' "$CORPUS_LOG" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM"
  printf 'redteam\t%s\tgo test -v -timeout=30m -tags redteam -p %s -parallel %s -count=1 ./...\n' "$REDTEAM_LOG" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM"
  printf 'redteam_race\t%s\tgo test -v -race -timeout=30m -tags redteam -p %s -parallel %s -count=1 ./...\n' "$REDTEAM_RACE_LOG" "$GO_TEST_PARALLELISM" "$GO_TEST_PARALLELISM"
} >"$MAIN_TIER_SPEC"

MAIN_TIER_JSONL="$OUT_DIR/.tier-pipeline-main.jsonl"
MAIN_TIER_PIPELINE_OK=true
# Sol12 P1-4 (rc5 Session 7): verify no release tool was substituted between
# preflight (toolset.json creation) and the first tier execution. A same-UID
# process could swap a tool binary after the hash was recorded; this check
# catches it before any tier evidence is produced with a different tool.
if ! python3 "$ROOT/scripts/release_toolset.py" --verify "$OUT_DIR/toolset.json"; then
  echo "release: refusing to run test tiers -- a release tool changed identity since preflight (Sol12 P1-4)" >&2
  exit 1
fi
if ! bash "$ROOT/scripts/release_tier_pipeline.sh" run --state-dir "$CHECKPOINT_STATE_DIR" --identity-file "$IDENTITY_FILE" --spec "$MAIN_TIER_SPEC" >"$MAIN_TIER_JSONL"; then
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
# Sol12 rc5 Session 1 (P0-3): capability evidence is tri-state (present |
# absent | unknown). The gate now requires EVERY predicate the manifest
# references to be proven present/absent in this record, or it refuses with
# CAPABILITY_EVIDENCE_INCOMPLETE (a missing key no longer collapses to
# "absent" and authorizes a conditional skip). Each record carries its probe,
# host, platform, and timestamp so the evidence is self-describing; the
# signed per-host capability attestations aggregated at release (Sessions
# 5/6/9) carry the full evidence_hash/signature on top of this same schema.
REDTEAM_CAPABILITIES_JSON=$(python3 scripts/redteam_capabilities.py)
# Sol13 rc6 Session 1 (P0-4): this one shared computation supplies the
# tagged source inventory, source identity, and aggregate compiled-test-binary
# identity. Directory names are never used to decide which attack source is
# bound into a capability attestation.
REDTEAM_SOURCE_IDENTITY="$OUT_DIR/redteam-source-identity.json"
REDTEAM_INVENTORY="$OUT_DIR/.redteam-inventory.txt"
python3 scripts/redteam_source_identity.py --repo-root . --out "$REDTEAM_SOURCE_IDENTITY" --inventory-out "$REDTEAM_INVENTORY"
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
# category labels from its one local log. S3 will decide whether verified,
# category-aware remote evidence can satisfy skips; S2 keeps every skip
# blocking even when an attestation directory is supplied.
ATTESTATIONS_DIR="${GOV_ATTESTATIONS_DIR:-}"
ASSAYER_COMMIT_ATTEST=$(git -C "${ASSAYER_REPO:-$SOURCE_ROOT/../assayer}" rev-parse HEAD 2>/dev/null || echo "unknown")
TEST_SOURCE_HASH=$(python3 -c "import json; print(json.load(open('$REDTEAM_SOURCE_IDENTITY'))['test_source_hash'])")
TEST_BINARY_SHA256=$(python3 -c "import json; print(json.load(open('$REDTEAM_SOURCE_IDENTITY'))['test_binary_sha256'])")
TOOLCHAIN_HASH=$(go version | sha256sum | awk '{print $1}')
if [ -n "$ATTESTATIONS_DIR" ]; then
  if [ ! -d "$ATTESTATIONS_DIR" ]; then
    echo "release: GOV_ATTESTATIONS_DIR is not a directory: $ATTESTATIONS_DIR" >&2
    exit 1
  fi
  RELEASE_ATTESTATION_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  REDTEAM_GATE_EXTRA_ARGS+=(--attestations "$ATTESTATIONS_DIR" --attestation-governator-commit "$COMMIT" --attestation-assayer-commit "$ASSAYER_COMMIT_ATTEST" --attestation-release-version "$VERSION" --attestation-source-identity "$REDTEAM_SOURCE_IDENTITY" --attestation-toolchain-hash "$TOOLCHAIN_HASH" --attestation-release-time "$RELEASE_ATTESTATION_TIME" --attestation-max-age "24h")
fi
REDTEAM_GATE_JSON="$OUT_DIR/.redteam-gate.json"
if go run ./cmd/gov redteam-gate verify --manifest "$REDTEAM_MANIFEST" --log "$REDTEAM_LOG" --capabilities "$REDTEAM_CAPABILITIES_JSON" --inventory "$REDTEAM_INVENTORY" "${REDTEAM_GATE_EXTRA_ARGS[@]}" >"$REDTEAM_GATE_JSON" 2>"$OUT_DIR/.redteam-gate.stderr"; then
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
  if go test -run "^${fn}\$" -fuzz "^${fn}\$" -fuzztime "${FUZZ_SECONDS}s" "./${pkg}" >"$flog" 2>&1; then
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
    ASSAYER_CASE_SUMMARY=$(tail -1 "$ASSAYER_CASE_LOG")
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
  if bash "$ROOT/scripts/assayer_verify.sh" --assayer-repo "$ASSAYER_REPO" >"$ASSAYER_VERSION_TAG_LOG" 2>&1; then
    ASSAYER_VERSION_TAG_RESULT=PASS
  else
    ASSAYER_VERSION_TAG_RESULT=FAIL
    cat "$ASSAYER_VERSION_TAG_LOG" >&2
  fi
  ASSAYER_VERSION_TAG_SUMMARY=$(tail -1 "$ASSAYER_VERSION_TAG_LOG")
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
# Build every platform into the same empty staging directory.
# Sol12 P1-4: re-verify toolset identity before the build phase -- a tool
# substituted between test tiers and the build would produce artifacts whose
# toolset_hash claim is a lie.
# ---------------------------------------------------------------------------
if ! python3 "$ROOT/scripts/release_toolset.py" --verify "$OUT_DIR/toolset.json"; then
  echo "release: refusing to build -- a release tool changed identity since preflight (Sol12 P1-4)" >&2
  exit 1
fi
HOST_PLATFORM_ID="$(go env GOOS)_$(go env GOARCH)"
HOST_ARCHIVE_NAME=""
HOST_ARCHIVE_SHA=""
HOST_BIN_SHA=""

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
  GOOS=$GOOS_VALUE GOARCH=$GOARCH_VALUE CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$BIN" ./cmd/gov
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
# Sol12 P1-1: explicit allow-list, not a 'darwin_ means limited, everything
# else defaults approving' fallback -- the PLATFORMS validation loop above
# already refuses any GOOS outside {linux, darwin} before this ever runs,
# so an unrecognized platform_id here means that guard was bypassed; fail
# loud rather than silently mislabeling it approving.
if platform_id.startswith('linux_'):
    feature_limited = False
elif platform_id.startswith('darwin_'):
    feature_limited = True
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
    'known_degraded_modes': ['non-approving'] if feature_limited else [],
}))" "$PLATFORM_ID" "$ARCHIVE_NAME" "$ARCHIVE_SHA" "$BIN_SHA" "$SIZE" >>"$ARTIFACTS_JSON"
  echo "release: built ${ARCHIVE_NAME} (${ARCHIVE_SHA})" >&2
  if [ "$PLATFORM_ID" = "$HOST_PLATFORM_ID" ]; then
    HOST_ARCHIVE_NAME=$ARCHIVE_NAME
    HOST_ARCHIVE_SHA=$ARCHIVE_SHA
    HOST_BIN_SHA=$BIN_SHA
  fi
done

# Host-platform binary stays unpacked in the staging root too, so the
# acceptance smoke test below (and any local `./dist/gov version`) doesn't
# need to extract an archive just to sanity-check the build that matches
# this machine.
if [ -f "$OUT_DIR/stage-${HOST_PLATFORM_ID}/gov" ]; then
  cp "$OUT_DIR/stage-${HOST_PLATFORM_ID}/gov" "$OUT_DIR/gov"
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
go list -m -json all >"$OUT_DIR/.modules.json"
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
  "$INTEGRATION_RESULT" "$INTEGRATION_SECONDS" "$INTEGRATION_STARTED" "$INTEGRATION_ENDED" "$INTEGRATION_LOG_SHA" \
  "$CORPUS_RESULT" "$CORPUS_SECONDS" "$CORPUS_STARTED" "$CORPUS_ENDED" "$CORPUS_LOG_SHA" "$CORPUS_TESTS_RUN" "$CORPUS_TESTS_FAILED" \
  "$REDTEAM_RESULT" "$REDTEAM_SECONDS" "$REDTEAM_STARTED" "$REDTEAM_ENDED" "$REDTEAM_LOG_SHA" \
  "$REDTEAM_TESTS_DISCOVERED" "$REDTEAM_TESTS_RUN" "$REDTEAM_TESTS_SKIPPED" "$REDTEAM_TESTS_FAILED" "$REDTEAM_GATE_OK" "$REDTEAM_GATE_JSON" "$REDTEAM_MANIFEST" "$REDTEAM_SOURCE_IDENTITY" \
  "$REDTEAM_RACE_RESULT" "$REDTEAM_RACE_SECONDS" "$REDTEAM_RACE_STARTED" "$REDTEAM_RACE_ENDED" "$REDTEAM_RACE_LOG_SHA" \
  "$FUZZ_RESULTS_JSON" "$ASSAYER_RESULT" "$ASSAYER_SUMMARY" "$ASSAYER_MATRIX_JSON" "$ASSAYER_VERSION_TAG_RESULT" "$ASSAYER_VERSION_TAG_SUMMARY" "$GO_TEST_PARALLELISM" <<'PYTESTSUMMARY'
import json, pathlib, sys

(summary_path, commit, go_version, build_ts, go_sum_sha256,
 unit_result, unit_seconds, unit_started, unit_ended, unit_log_sha,
 race_result, race_seconds, race_started, race_ended, race_log_sha,
 integration_result, integration_seconds, integration_started, integration_ended, integration_log_sha,
 corpus_result, corpus_seconds, corpus_started, corpus_ended, corpus_log_sha, corpus_tests_run, corpus_tests_failed,
 redteam_result, redteam_seconds, redteam_started, redteam_ended, redteam_log_sha,
 redteam_tests_discovered, redteam_tests_run, redteam_tests_skipped, redteam_tests_failed, redteam_gate_ok, redteam_gate_json_path, redteam_manifest_path, redteam_source_identity_path,
 redteam_race_result, redteam_race_seconds, redteam_race_started, redteam_race_ended, redteam_race_log_sha,
 fuzz_results_path, assayer_result, assayer_summary, assayer_matrix_path,
 assayer_version_tag_result, assayer_version_tag_summary, go_test_parallelism) = sys.argv[1:]

par = f"-p {go_test_parallelism} -parallel {go_test_parallelism}"

redteam_gate = json.loads(pathlib.Path(redteam_gate_json_path).read_text())
redteam_source_identity = json.loads(pathlib.Path(redteam_source_identity_path).read_text())

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
        "integration": {"command": f"go test -tags integration {par} -count=1 ./internal/assay/...", "result": integration_result, "duration_seconds": int(integration_seconds), "started_at": integration_started, "ended_at": integration_ended, "log_sha256": integration_log_sha, "log_path": "integration.log.gz"},
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
rm -f "$FUZZ_RESULTS_JSON" "$UNIT_LOG" "$RACE_LOG" "$INTEGRATION_LOG" "$CORPUS_LOG" "$REDTEAM_LOG" "$REDTEAM_RACE_LOG" "$ASSAYER_LOG" "$ASSAYER_VERSION_TAG_LOG" "$ASSAYER_MATRIX_JSON" "$OUT_DIR"/test-assayer-py*.log "$OUT_DIR"/test-fuzz-*.log

# ---------------------------------------------------------------------------
# Acceptance smoke test: extract the exact distributable archive for THIS
# host's platform on a clean path (never trust the staging tree we just
# built from), then exercise it exactly like an operator installing it would.
# This step deliberately stops at binary self-consistency (mode, hash,
# self-reported version/commit/claims-hash) — it does NOT call
# `gov claims verify` itself (P0-7 / report attack 25: that used to happen
# here, without --artifact/--manifest, which is exactly how a claims-verify
# gap stayed invisible). Full claims verification against the finalized
# manifest is its own, later, independently release-blocking stage below.
# ---------------------------------------------------------------------------
ACCEPTANCE="$OUT_DIR/acceptance-summary.json"
SMOKE_DIR=$(mktemp -d)
trap 'rm -rf "$SMOKE_DIR"' EXIT
HOST_ARCHIVE="$OUT_DIR/gov_${VERSION}_${HOST_PLATFORM_ID}.tar.gz"
NOTES_FILE="$OUT_DIR/.acceptance-notes.txt"
: >"$NOTES_FILE"
ACCEPT_OK=true
EXECUTABLE_BIT_OK=true
HASH_MATCH_OK=true
VERSION_MATCH_OK=true
ARCHIVE_EXTRACTED=false
if [ -f "$HOST_ARCHIVE" ]; then
  ARCHIVE_EXTRACTED=true
  # -p: see scripts/release_verify.sh's identical comment -- without it, a
  # restrictive umask on the extracting machine silently masks a hostile
  # archived mode bit, making the mode assertion below meaningless.
  tar -xzf "$HOST_ARCHIVE" -C "$SMOKE_DIR" -p
  EXTRACTED_BIN="$SMOKE_DIR/gov"
  # Report attack 24: the archived binary shipped at mode 0777. Assert the
  # EXACT mode after extraction (not "is it executable at all" — 0777 is
  # also executable) and fail on any group/world write bit.
  EXTRACTED_MODE=$(stat -c '%a' "$EXTRACTED_BIN" 2>/dev/null || stat -f '%OLp' "$EXTRACTED_BIN")
  if [ "$EXTRACTED_MODE" != "755" ]; then
    ACCEPT_OK=false
    EXECUTABLE_BIT_OK=false
    echo "extracted binary mode is ${EXTRACTED_MODE}, must be exactly 755 (no group/world write bit)" >>"$NOTES_FILE"
  fi
  EXTRACTED_SHA=$(sha256sum "$EXTRACTED_BIN" | awk '{print $1}')
  STAGE_SHA=$(sha256sum "$OUT_DIR/stage-${HOST_PLATFORM_ID}/gov" | awk '{print $1}')
  if [ "$EXTRACTED_SHA" != "$STAGE_SHA" ]; then
    ACCEPT_OK=false
    HASH_MATCH_OK=false
    echo "extracted binary hash ($EXTRACTED_SHA) does not match the built binary ($STAGE_SHA)" >>"$NOTES_FILE"
  fi
  if VERSION_OUT=$("$EXTRACTED_BIN" version --json 2>&1); then
    REPORTED_VERSION=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('version',''))" "$VERSION_OUT" 2>/dev/null || echo "")
    REPORTED_COMMIT=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('source_commit',''))" "$VERSION_OUT" 2>/dev/null || echo "")
    REPORTED_CLAIMS=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('claims_hash',''))" "$VERSION_OUT" 2>/dev/null || echo "")
    REPORTED_DIRTY=$(python3 -c "import json,sys; v=json.loads(sys.argv[1]); print(v.get('dirty', '__missing__'))" "$VERSION_OUT" 2>/dev/null || echo "__missing__")
    if [ "$REPORTED_VERSION" != "$VERSION" ] || [ "$REPORTED_COMMIT" != "$COMMIT" ] || [ "$REPORTED_CLAIMS" != "$CLAIMS_HASH" ]; then
      ACCEPT_OK=false
      VERSION_MATCH_OK=false
      echo "gov version --json ($REPORTED_VERSION/$REPORTED_COMMIT/$REPORTED_CLAIMS) does not match build-manifest.json ($VERSION/$COMMIT/$CLAIMS_HASH)" >>"$NOTES_FILE"
    fi
    if [ "$REPORTED_DIRTY" != "False" ] && [ "$REPORTED_DIRTY" != "false" ]; then
      ACCEPT_OK=false
      VERSION_MATCH_OK=false
      echo "gov version --json reports dirty=$REPORTED_DIRTY; release artifacts must report dirty=false" >>"$NOTES_FILE"
    fi
  else
    ACCEPT_OK=false
    VERSION_MATCH_OK=false
    echo "gov version --json failed: $VERSION_OUT" >>"$NOTES_FILE"
  fi
else
  ACCEPT_OK=false
  EXECUTABLE_BIT_OK=false
  HASH_MATCH_OK=false
  VERSION_MATCH_OK=false
  echo "no archive built for this host's platform (${HOST_PLATFORM_ID}); nothing to extract and smoke-test" >>"$NOTES_FILE"
fi

if [ "$ACCEPT_OK" = true ]; then ACCEPTANCE_RESULT=PASS; else ACCEPTANCE_RESULT=FAIL; fi

python3 - "$ACCEPTANCE" "$ACCEPTANCE_RUN_ID" "$ACCEPTANCE_RESULT" "$HOST_PLATFORM_ID" "$BUILD_TS" "$ARCHIVE_EXTRACTED" "$EXECUTABLE_BIT_OK" "$HASH_MATCH_OK" "$VERSION_MATCH_OK" "$NOTES_FILE" <<'PYACCEPT'
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
rm -f "$NOTES_FILE"

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
python3 - "$ARCHITECTURE_METADATA" "$VERSION" "$COMMIT" "$ASSAYER_COMMIT" "$ASSAYER_VERSION" "$PLATFORMS" <<'PYARCH'
import json, pathlib, sys
metadata_path, version, commit, assayer_commit, assayer_version, platforms = sys.argv[1:]
platform_list = [p for p in platforms.split() if p]
degraded = []
for platform in platform_list:
    # Sol12 P1-1: same explicit allow-list as the artifact-labeling block
    # above -- the PLATFORMS guard already refuses anything outside
    # {linux, darwin} before this runs.
    if platform.startswith('darwin/'):
        degraded.append({'platform': platform.replace('/', '_'), 'mode': 'non-approving'})
    elif not platform.startswith('linux/'):
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
  "$HOST_ARCHIVE_NAME" "$HOST_ARCHIVE_SHA" "$HOST_BIN_SHA" "$TEST_RUN_ID" "$TEST_SUMMARY" "$ACCEPTANCE_RUN_ID" "$ACCEPTANCE_RESULT" "$(basename "$ARCHITECTURE_METADATA")" "$RELEASE_ATTEMPT_ID" \
  "$TOOLSET_HASH" "$ASSAYER_LOCKED_REF" "$ASSAYER_VERSION" <<'PYMANIFEST'
import json, pathlib, sys

(manifest, version, commit, build_ts, go_version, build_flags, claims_hash,
 adapter_protocol_version, artifacts_path,
 host_archive_name, host_archive_sha, host_bin_sha, test_run_id, test_summary_path, acceptance_run_id, acceptance_result, architecture_metadata_path,
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
    # acceptance smoke test and the full claims-verification stage below
    # both extract and inspect. internal/claims.verifyArtifactManifest reads
    # archive_path/extracted_binary_sha256 directly off this manifest.
    "archive_path": host_archive_name,
    "archive_sha256": host_archive_sha,
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
if ! "$ROOT/scripts/release_verify.sh" --out-dir "$OUT_DIR" --repo "$ROOT" --platform "$HOST_PLATFORM_ID" >"$CLAIMS_VERIFY_REPORT" 2>&1; then
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

CHECKSUMS="$OUT_DIR/checksums.txt"
(cd "$OUT_DIR" && sha256sum -- *.tar.gz build-manifest.json architecture-build-metadata.json sbom.json claims.yaml test-summary.json acceptance-summary.json claims-verify-report.txt preflight.json toolset.json gov *.log.gz attestations/*.json >"$(basename "$CHECKSUMS")")

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
if [ -n "${GOV_RELEASE_MINISIGN_KEY:-}" ] && command -v minisign >/dev/null 2>&1; then
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
#      minisign -V actually uses.
#   3. the minisign verifier itself, resolved to an absolute path and
#      recorded by SHA-256 so a fake minisign on PATH cannot intercept
#      verification (a forged packet is rejected by minisign -V regardless).
#      Hash-anchoring against a pre-recorded expected value lands with the
#      immutable builder image (S8 / P1-6); here the absolute-path pin +
#      recorded hash is the minimum Sol11 P0-1 asks for.
# A REQUIRE_ASYMMETRIC_SIGNATURE=1 release whose signature does not
# cryptographically verify over the exact checksums.txt bytes, whose
# checksums no longer describe the shipped artifacts, or whose verifier
# was substituted now fails closed here.
TRUSTED_SIGNING_KEYS_FILE="$SOURCE_ROOT/docs/TRUSTED_SIGNING_KEYS.txt"
TRUSTED_PUBLIC_KEYS_DIR="$SOURCE_ROOT/docs/signing_keys"
MINISIGN_BIN=$(command -v minisign || true)
MINISIGN_BIN_HASH=""
if [ -n "$MINISIGN_BIN" ]; then
  MINISIGN_BIN_HASH=$(sha256sum "$MINISIGN_BIN" | awk '{print $1}')
fi
python3 "$ROOT/scripts/release_policy.py" signature \
  --version "$VERSION" \
  --require "$REQUIRE_ASYMMETRIC_SIGNATURE" \
  --minisig "$MINISIG" \
  --trusted-fingerprints-file "$TRUSTED_SIGNING_KEYS_FILE" \
  --checksums "$CHECKSUMS" \
  --trusted-public-keys-dir "$TRUSTED_PUBLIC_KEYS_DIR" \
  --artifacts-dir "$OUT_DIR" \
  --minisign-bin "$MINISIGN_BIN" \
  --minisign-bin-hash "$MINISIGN_BIN_HASH"

echo "release: OK — $OUT_DIR" >&2
ls -la "$OUT_DIR" >&2
echo "$MANIFEST"
