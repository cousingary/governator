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
# acceptance-summary.json, signature.
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

# P0-7 (Sol redteam v4 S8): "build releases only from a clean, tagged
# commit." REQUIRE_TAG defaults off so docs/publishing.md's documented local
# dry-run ("check the pipeline is clean before tagging") keeps working
# unchanged; .github/workflows/release.yml -- the actual publish path,
# triggered only by a v* tag push -- sets REQUIRE_TAG=1, so the one pipeline
# that ships a real release always asserts HEAD carries the exact tag this
# VERSION claims.
REQUIRE_TAG=${REQUIRE_TAG:-0}
if [ "$REQUIRE_TAG" = 1 ]; then
  TAG_AT_HEAD=$(git tag --points-at HEAD | grep -x "v${VERSION}" || true)
  if [ -z "$TAG_AT_HEAD" ]; then
    echo "release: REQUIRE_TAG=1 but HEAD is not tagged v${VERSION}" >&2
    exit 1
  fi
else
  case "$VERSION" in
    local-candidate-*|*-candidate*|*-rc*|*+*) ;;
    *)
      TAG_AT_HEAD=$(git tag --points-at HEAD | grep -x "v${VERSION}" || true)
      if [ -z "$TAG_AT_HEAD" ]; then
        echo "release: refusing ambiguous untagged version ${VERSION}; use a local-candidate/rc version or set REQUIRE_TAG=1 on a matching tag" >&2
        exit 1
      fi
      ;;
  esac
fi

if [ -z "${REQUIRE_ASYMMETRIC_SIGNATURE:-}" ]; then
  case "$VERSION" in
    local-candidate-*|*-candidate*|*+*) REQUIRE_ASYMMETRIC_SIGNATURE=0 ;;
    *) REQUIRE_ASYMMETRIC_SIGNATURE=1 ;;
  esac
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
fi

BUILD_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CLAIMS_HASH=$(sha256sum docs/claims.yaml | awk '{print $1}')
ADAPTER_PROTOCOL_VERSION=${ADAPTER_PROTOCOL_VERSION:-adapter-protocol-v1}
GO_VERSION=$(go version | awk '{print $3}')
FUZZ_SECONDS=${FUZZ_SECONDS:-15}
# Sol3 P1.8 (S12) confirmed session's own machine can build all four
# platforms with CGO_ENABLED=0 (modernc.org/sqlite is pure Go, no cgo
# toolchain needed for cross-compilation).
PLATFORMS=${PLATFORMS:-"linux/amd64 linux/arm64 darwin/amd64 darwin/arm64"}
ASSAYER_REPO=${ASSAYER_REPO:-/mnt/e/downloads/assayer}

# Every release starts from an EMPTY staging directory (audit finding #20:
# "several outer ZIP ELF files stored without executable permission" and
# stale snapshot archives sitting alongside a real production binary both
# trace back to OUT_DIR accumulating across unrelated invocations).
OUT_DIR=${OUT_DIR:-dist}
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

TEST_RUN_ID="go-test-${COMMIT}"
ACCEPTANCE_RUN_ID="version-self-check-${COMMIT}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.sourceCommit=${COMMIT} -X main.buildTimestamp=${BUILD_TS} -X main.claimsHash=${CLAIMS_HASH} -X main.adapterProtocolVersion=${ADAPTER_PROTOCOL_VERSION}"

echo "release: version=${VERSION} commit=${COMMIT} go=${GO_VERSION}" >&2

# ---------------------------------------------------------------------------
# Test tiers. No cached results, no skips (audit P2.3): every tier below runs
# for real, this invocation, and its outcome is recorded in test-summary.json
# rather than asserted from a prior log or from "the test function exists".
# ---------------------------------------------------------------------------
# Writes PASS/FAIL and elapsed seconds into the two caller-provided variable
# names via `declare -g` rather than relying on the function's own exit code:
# an earlier version of this script fed run_tier's result through
# `read ... < <(run_tier ...) || tier_ok=false`, which is a real bash trap —
# `read` reading from a process substitution reports its OWN exit status
# (success, since it read two words fine), never the substituted command's,
# so a failing tier was silently swallowed and the release packaged anyway.
# Direct string comparison against an explicit global avoids that trap.
# P0-7 (Sol redteam v4 S8): "fresh, uncached test evidence is mandatory...
# recording exact commit, toolchain, dependency lock state, test command,
# start/end time, exit status, log hash." start/end are now real ISO-8601
# timestamps (not just an elapsed-seconds delta), and log_sha_var records the
# sha256 of the tier's own captured output -- so test-summary.json's record
# of "this tier passed" is bound to one specific, hashable transcript, not
# just a PASS/FAIL word a later edit could quietly detach from the evidence.
run_tier() {
  local name=$1 log=$2 result_var=$3 seconds_var=$4 started_var=$5 ended_var=$6 log_sha_var=$7
  shift 7
  local start end started_at ended_at
  start=$(date +%s)
  started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if "$@" >"$log" 2>&1; then
    end=$(date +%s)
    echo "release: tier ${name} PASS ($((end - start))s)" >&2
    printf -v "$result_var" '%s' PASS
  else
    end=$(date +%s)
    echo "release: tier ${name} FAIL ($((end - start))s) — see ${log}" >&2
    cat "$log" >&2
    printf -v "$result_var" '%s' FAIL
  fi
  ended_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf -v "$seconds_var" '%s' "$((end - start))"
  printf -v "$started_var" '%s' "$started_at"
  printf -v "$ended_var" '%s' "$ended_at"
  printf -v "$log_sha_var" '%s' "$(sha256sum "$log" | awk '{print $1}')"
}

GO_SUM_HASH=$(sha256sum go.sum | awk '{print $1}')

UNIT_LOG="$OUT_DIR/test-unit.log"
run_tier unit "$UNIT_LOG" UNIT_RESULT UNIT_SECONDS UNIT_STARTED UNIT_ENDED UNIT_LOG_SHA go test -count=1 ./...

RACE_LOG="$OUT_DIR/test-race.log"
run_tier race "$RACE_LOG" RACE_RESULT RACE_SECONDS RACE_STARTED RACE_ENDED RACE_LOG_SHA go test -race -timeout=30m -count=1 ./...

INTEGRATION_LOG="$OUT_DIR/test-integration.log"
run_tier integration "$INTEGRATION_LOG" INTEGRATION_RESULT INTEGRATION_SECONDS INTEGRATION_STARTED INTEGRATION_ENDED INTEGRATION_LOG_SHA go test -tags integration -count=1 ./internal/assay/...

CORPUS_LOG="$OUT_DIR/test-corpus.log"
run_tier black_box_corpus "$CORPUS_LOG" CORPUS_RESULT CORPUS_SECONDS CORPUS_STARTED CORPUS_ENDED CORPUS_LOG_SHA go test -run 'Sol3' -v -count=1 ./...
CORPUS_TESTS_RUN=$(grep -c '^--- PASS\|^--- FAIL' "$CORPUS_LOG" || true)
CORPUS_TESTS_FAILED=$(grep -c '^--- FAIL' "$CORPUS_LOG" || true)

# Sol redteam v6 S0 (P0-18, partial): the build-tagged internal/redteam/
# corpus was never actually compiled by any release or CI command —
# "black_box_corpus" above only runs Sol3-prefixed tests, which never
# triggers the `redteam` build tag. A release could report
# black_box_corpus: PASS while every permanent red-team attack was excluded
# from compilation. These two tiers are the exact commands the v6 report
# requires. Skips are not failures here — the corpus's skip count is the
# project burn-down (agents/governator-sol-upgrade6-plan.md). Full record
# fields (discovered/run/skipped/failed counts as first-class release
# evidence, and rejection of any *unexpected* skip) land in S8, not here.
REDTEAM_LOG="$OUT_DIR/test-redteam.log"
run_tier redteam "$REDTEAM_LOG" REDTEAM_RESULT REDTEAM_SECONDS REDTEAM_STARTED REDTEAM_ENDED REDTEAM_LOG_SHA go test -v -tags redteam -count=1 ./...

REDTEAM_RACE_LOG="$OUT_DIR/test-redteam-race.log"
run_tier redteam_race "$REDTEAM_RACE_LOG" REDTEAM_RACE_RESULT REDTEAM_RACE_SECONDS REDTEAM_RACE_STARTED REDTEAM_RACE_ENDED REDTEAM_RACE_LOG_SHA go test -v -race -timeout=30m -tags redteam -count=1 ./...

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
REDTEAM_CAPABILITIES_JSON=$(python3 -c "
import json, os, platform
print(json.dumps({
    'linux': platform.system().lower() == 'linux',
    'has_systemd_user': os.environ.get('GOV_REDTEAM_HAS_SYSTEMD_USER', '') == '1',
    'has_second_uid': os.environ.get('GOV_REDTEAM_HAS_SECOND_UID', '') == '1',
    'has_kernel_landlock_full_abi': os.environ.get('GOV_REDTEAM_HAS_LANDLOCK_FULL_ABI', '') == '1',
}))
")
REDTEAM_GATE_JSON="$OUT_DIR/.redteam-gate.json"
if go run ./cmd/gov redteam-gate verify --manifest "$REDTEAM_MANIFEST" --log "$REDTEAM_LOG" --capabilities "$REDTEAM_CAPABILITIES_JSON" >"$REDTEAM_GATE_JSON" 2>"$OUT_DIR/.redteam-gate.stderr"; then
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
  for ASSAYER_PY in 3.10 3.11 3.12 3.13; do
    ASSAYER_BIN="python${ASSAYER_PY}"
    ASSAYER_CASE_LOG="$OUT_DIR/test-assayer-py${ASSAYER_PY}.log"
    ASSAYER_CASE_STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    ASSAYER_CASE_START_EPOCH=$(date +%s)
    ASSAYER_EXIT_CODE=0
    ASSAYER_TIMEOUT=false
    if command -v "$ASSAYER_BIN" >/dev/null 2>&1; then
      if timeout 900s bash -lc "cd '$ASSAYER_REPO' && '$ASSAYER_BIN' -m pytest -q" >"$ASSAYER_CASE_LOG" 2>&1; then
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
      ASSAYER_EXIT_CODE=127
      ASSAYER_RESULT=FAIL
      echo "${ASSAYER_BIN} not present on this machine" >"$ASSAYER_CASE_LOG"
      cat "$ASSAYER_CASE_LOG" >&2
    fi
    ASSAYER_CASE_ENDED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    ASSAYER_CASE_END_EPOCH=$(date +%s)
    ASSAYER_CASE_SUMMARY=$(tail -1 "$ASSAYER_CASE_LOG")
    ASSAYER_CASE_LOG_SHA=$(sha256sum "$ASSAYER_CASE_LOG" | awk '{print $1}')
    python3 - "$ASSAYER_MATRIX_JSON" "$ASSAYER_PY" "$ASSAYER_BIN" "$ASSAYER_CASE_RESULT" "$ASSAYER_EXIT_CODE" "$ASSAYER_TIMEOUT" "$ASSAYER_CASE_STARTED" "$ASSAYER_CASE_ENDED" "$((ASSAYER_CASE_END_EPOCH - ASSAYER_CASE_START_EPOCH))" "$ASSAYER_CASE_LOG_SHA" "$ASSAYER_CASE_SUMMARY" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text())
data.append({
    "python_version": sys.argv[2],
    "python_executable": sys.argv[3],
    "command": f"{sys.argv[3]} -m pytest -q",
    "result": sys.argv[4],
    "exit_code": int(sys.argv[5]),
    "timeout": sys.argv[6] == "true",
    "started_at": sys.argv[7],
    "ended_at": sys.argv[8],
    "duration_seconds": int(sys.argv[9]),
    "log_sha256": sys.argv[10],
    "summary": sys.argv[11].strip(),
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

if [ "$UNIT_RESULT" != PASS ] || [ "$RACE_RESULT" != PASS ] || [ "$INTEGRATION_RESULT" != PASS ] || [ "$CORPUS_RESULT" != PASS ] || [ "$REDTEAM_RESULT" != PASS ] || [ "$REDTEAM_RACE_RESULT" != PASS ] || [ "$FUZZ_OK" != true ]; then
  echo "release: refusing to package — a required test tier failed" >&2
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
# ---------------------------------------------------------------------------
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
feature_limited = platform_id.startswith('darwin_')
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
  "$REDTEAM_TESTS_DISCOVERED" "$REDTEAM_TESTS_RUN" "$REDTEAM_TESTS_SKIPPED" "$REDTEAM_TESTS_FAILED" "$REDTEAM_GATE_OK" "$REDTEAM_GATE_JSON" "$REDTEAM_MANIFEST" \
  "$REDTEAM_RACE_RESULT" "$REDTEAM_RACE_SECONDS" "$REDTEAM_RACE_STARTED" "$REDTEAM_RACE_ENDED" "$REDTEAM_RACE_LOG_SHA" \
  "$FUZZ_RESULTS_JSON" "$ASSAYER_RESULT" "$ASSAYER_SUMMARY" "$ASSAYER_MATRIX_JSON" "$ASSAYER_VERSION_TAG_RESULT" "$ASSAYER_VERSION_TAG_SUMMARY" <<'PYTESTSUMMARY'
import json, pathlib, sys

(summary_path, commit, go_version, build_ts, go_sum_sha256,
 unit_result, unit_seconds, unit_started, unit_ended, unit_log_sha,
 race_result, race_seconds, race_started, race_ended, race_log_sha,
 integration_result, integration_seconds, integration_started, integration_ended, integration_log_sha,
 corpus_result, corpus_seconds, corpus_started, corpus_ended, corpus_log_sha, corpus_tests_run, corpus_tests_failed,
 redteam_result, redteam_seconds, redteam_started, redteam_ended, redteam_log_sha,
 redteam_tests_discovered, redteam_tests_run, redteam_tests_skipped, redteam_tests_failed, redteam_gate_ok, redteam_gate_json_path, redteam_manifest_path,
 redteam_race_result, redteam_race_seconds, redteam_race_started, redteam_race_ended, redteam_race_log_sha,
 fuzz_results_path, assayer_result, assayer_summary, assayer_matrix_path,
 assayer_version_tag_result, assayer_version_tag_summary) = sys.argv[1:]

redteam_gate = json.loads(pathlib.Path(redteam_gate_json_path).read_text())

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
        "unit": {"command": "go test -count=1 ./...", "result": unit_result, "duration_seconds": int(unit_seconds), "started_at": unit_started, "ended_at": unit_ended, "log_sha256": unit_log_sha},
        "race": {"command": "go test -race -count=1 ./...", "result": race_result, "duration_seconds": int(race_seconds), "started_at": race_started, "ended_at": race_ended, "log_sha256": race_log_sha},
        "integration": {"command": "go test -tags integration -count=1 ./internal/assay/...", "result": integration_result, "duration_seconds": int(integration_seconds), "started_at": integration_started, "ended_at": integration_ended, "log_sha256": integration_log_sha},
        "black_box_corpus": {
            "command": "go test -run Sol3 -v -count=1 ./...",
            "result": corpus_result,
            "duration_seconds": int(corpus_seconds),
            "started_at": corpus_started,
            "ended_at": corpus_ended,
            "log_sha256": corpus_log_sha,
            "tests_run": int(corpus_tests_run),
            "tests_failed": int(corpus_tests_failed),
        },
        "redteam": {
            "command": "go test -v -tags redteam -count=1 ./...",
            "result": redteam_result,
            "source_commit": commit,
            "duration_seconds": int(redteam_seconds),
            "started_at": redteam_started,
            "ended_at": redteam_ended,
            "log_sha256": redteam_log_sha,
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
            "identity_gate": {**redteam_gate, "ok": redteam_gate_ok == "true"},
        },
        "redteam_race": {
            "command": "go test -v -race -tags redteam -count=1 ./...",
            "result": redteam_race_result,
            "duration_seconds": int(redteam_race_seconds),
            "started_at": redteam_race_started,
            "ended_at": redteam_race_ended,
            "log_sha256": redteam_race_log_sha,
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
    if platform.startswith('darwin/'):
        degraded.append({'platform': platform.replace('/', '_'), 'mode': 'non-approving'})
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
  "$HOST_ARCHIVE_NAME" "$HOST_ARCHIVE_SHA" "$HOST_BIN_SHA" "$TEST_RUN_ID" "$TEST_SUMMARY" "$ACCEPTANCE_RUN_ID" "$ACCEPTANCE_RESULT" "$(basename "$ARCHITECTURE_METADATA")" <<'PYMANIFEST'
import json, pathlib, sys

(manifest, version, commit, build_ts, go_version, build_flags, claims_hash,
 adapter_protocol_version, artifacts_path,
 host_archive_name, host_archive_sha, host_bin_sha, test_run_id, test_summary_path, acceptance_run_id, acceptance_result, architecture_metadata_path) = sys.argv[1:]

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
CHECKSUMS="$OUT_DIR/checksums.txt"
(cd "$OUT_DIR" && sha256sum -- *.tar.gz build-manifest.json architecture-build-metadata.json sbom.json claims.yaml test-summary.json acceptance-summary.json claims-verify-report.txt gov >"$(basename "$CHECKSUMS")")

# ---------------------------------------------------------------------------
# signature — HMAC-SHA256 over checksums.txt, keyed by an operator-supplied
# secret. Never fabricated: an unsigned release says so in plain text rather
# than shipping a signature file that isn't one.
#
# P0-7 (Sol redteam v4 S8): docs/security.md flagged this as the release's
# real gap — "HMAC with a shared secret is not publicly verifiable." An HMAC
# key that signs is also a key that can forge; anyone who can verify a
# release can also mint a fake one. When GOV_RELEASE_MINISIGN_KEY (path to
# an UNENCRYPTED minisign secret key — `minisign -G -W`, no interactive
# password prompt to automate around) and the `minisign` binary are both
# available, this additionally produces checksums.txt.minisig: an Ed25519
# signature verifiable by anyone holding only the corresponding *public*
# key, with no shared secret in the loop. This augments, not replaces, the
# HMAC signature above (existing tooling/docs keep working); when minisign
# isn't configured, no .minisig file is written — never a fabricated one.
# ---------------------------------------------------------------------------
SIGNATURE="$OUT_DIR/signature"
if [ -n "${GOV_RELEASE_HMAC_KEY:-}" ]; then
  python3 -c "
import hmac, hashlib, os, sys
key = os.environ['GOV_RELEASE_HMAC_KEY'].encode()
data = open(sys.argv[1], 'rb').read()
print('hmac-sha256:' + hmac.new(key, data, hashlib.sha256).hexdigest())
" "$CHECKSUMS" >"$SIGNATURE"
else
  echo "UNSIGNED: set GOV_RELEASE_HMAC_KEY to sign checksums.txt for this release" >"$SIGNATURE"
fi

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
python3 "$ROOT/scripts/release_policy.py" signature --version "$VERSION" --require "$REQUIRE_ASYMMETRIC_SIGNATURE" --minisig "$MINISIG"

echo "release: OK — $OUT_DIR" >&2
ls -la "$OUT_DIR" >&2
echo "$MANIFEST"
