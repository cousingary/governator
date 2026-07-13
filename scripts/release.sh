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

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "release: refusing to build from a dirty tree" >&2
  exit 1
fi

VERSION=${VERSION:-1.0.0}
COMMIT=$(git rev-parse HEAD)
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
run_tier() {
  local name=$1 log=$2 result_var=$3 seconds_var=$4
  shift 4
  local start end
  start=$(date +%s)
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
  printf -v "$seconds_var" '%s' "$((end - start))"
}

UNIT_LOG="$OUT_DIR/test-unit.log"
run_tier unit "$UNIT_LOG" UNIT_RESULT UNIT_SECONDS go test -count=1 ./...

RACE_LOG="$OUT_DIR/test-race.log"
run_tier race "$RACE_LOG" RACE_RESULT RACE_SECONDS go test -race -count=1 ./...

INTEGRATION_LOG="$OUT_DIR/test-integration.log"
run_tier integration "$INTEGRATION_LOG" INTEGRATION_RESULT INTEGRATION_SECONDS go test -tags integration -count=1 ./internal/assay/...

CORPUS_LOG="$OUT_DIR/test-corpus.log"
run_tier black_box_corpus "$CORPUS_LOG" CORPUS_RESULT CORPUS_SECONDS go test -run 'Sol3' -v -count=1 ./...
CORPUS_TESTS_RUN=$(grep -c '^--- PASS\|^--- FAIL' "$CORPUS_LOG" || true)
CORPUS_TESTS_FAILED=$(grep -c '^--- FAIL' "$CORPUS_LOG" || true)

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

# Assayer's own pytest matrix lives in a separate repo/checkout (not a
# submodule of this one) — best-effort, honestly reported as SKIPPED with a
# reason when that checkout isn't present on this machine, never silently
# omitted from test-summary.json.
ASSAYER_LOG="$OUT_DIR/test-assayer.log"
if [ -d "$ASSAYER_REPO" ]; then
  if (cd "$ASSAYER_REPO" && python3 -m pytest -q) >"$ASSAYER_LOG" 2>&1; then
    ASSAYER_RESULT=PASS
  else
    ASSAYER_RESULT=FAIL
    cat "$ASSAYER_LOG" >&2
  fi
  ASSAYER_SUMMARY=$(tail -1 "$ASSAYER_LOG")
else
  ASSAYER_RESULT=SKIPPED
  ASSAYER_SUMMARY="ASSAYER_REPO ${ASSAYER_REPO} not present on this machine"
  echo "$ASSAYER_SUMMARY" >"$ASSAYER_LOG"
fi

if [ "$UNIT_RESULT" != PASS ] || [ "$RACE_RESULT" != PASS ] || [ "$INTEGRATION_RESULT" != PASS ] || [ "$CORPUS_RESULT" != PASS ] || [ "$FUZZ_OK" != true ]; then
  echo "release: refusing to package — a required test tier failed" >&2
  exit 1
fi
# Assayer's matrix is advisory to *this* pipeline (it's proof for the
# Assayer repo's own release, not Governator's), but a FAIL (as opposed to
# SKIPPED) here means the checkout is present and broke — that must not be
# silently packaged over.
if [ "$ASSAYER_RESULT" = FAIL ]; then
  echo "release: refusing to package — the Assayer matrix is present and failing" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Build every platform into the same empty staging directory.
# ---------------------------------------------------------------------------
ARTIFACTS_JSON="$OUT_DIR/.artifacts.jsonl"
: >"$ARTIFACTS_JSON"
for platform in $PLATFORMS; do
  GOOS_VALUE=${platform%/*}
  GOARCH_VALUE=${platform#*/}
  PLATFORM_ID="${GOOS_VALUE}_${GOARCH_VALUE}"
  STAGE="$OUT_DIR/stage-${PLATFORM_ID}"
  mkdir -p "$STAGE"
  BIN="$STAGE/gov"
  GOOS=$GOOS_VALUE GOARCH=$GOARCH_VALUE CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$BIN" ./cmd/gov
  chmod 0755 "$BIN"
  ARCHIVE_NAME="gov_${VERSION}_${PLATFORM_ID}.tar.gz"
  ARCHIVE="$OUT_DIR/${ARCHIVE_NAME}"
  # Explicit owner/perm normalization: tar preserves the source file's mode
  # (0755, just chmod'd above) by default, but --owner/--group/--numeric-owner
  # keep the archive reproducible across build machines instead of baking in
  # whichever uid/gid happened to run this script (audit: "several outer ZIP
  # ELF files stored without executable permission" — normalize instead of
  # trusting the ambient umask).
  tar --numeric-owner --owner=0 --group=0 -czf "$ARCHIVE" -C "$STAGE" gov
  ARCHIVE_SHA=$(sha256sum "$ARCHIVE" | awk '{print $1}')
  BIN_SHA=$(sha256sum "$BIN" | awk '{print $1}')
  SIZE=$(stat -c%s "$ARCHIVE" 2>/dev/null || stat -f%z "$ARCHIVE")
  python3 -c "
import json, sys
print(json.dumps({
    'platform': sys.argv[1], 'archive': sys.argv[2], 'archive_sha256': sys.argv[3],
    'binary_sha256': sys.argv[4], 'size_bytes': int(sys.argv[5]),
}))" "$PLATFORM_ID" "$ARCHIVE_NAME" "$ARCHIVE_SHA" "$BIN_SHA" "$SIZE" >>"$ARTIFACTS_JSON"
  echo "release: built ${ARCHIVE_NAME} (${ARCHIVE_SHA})" >&2
done

# Host-platform binary stays unpacked in the staging root too, so the
# acceptance smoke test below (and any local `./dist/gov version`) doesn't
# need to extract an archive just to sanity-check the build that matches
# this machine.
HOST_PLATFORM_ID="$(go env GOOS)_$(go env GOARCH)"
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
# build-manifest.json — the one document every other file's identity must
# agree with: version, source commit, build timestamp, claims hash, adapter
# protocol version, plus every artifact this release actually produced.
# ---------------------------------------------------------------------------
MANIFEST="$OUT_DIR/build-manifest.json"
python3 - "$MANIFEST" "$VERSION" "$COMMIT" "$BUILD_TS" "$GO_VERSION" "$LDFLAGS" "$CLAIMS_HASH" "$ADAPTER_PROTOCOL_VERSION" "$TEST_RUN_ID" "$ARTIFACTS_JSON" <<'PYMANIFEST'
import json, pathlib, sys

(manifest, version, commit, build_ts, go_version, build_flags, claims_hash,
 adapter_protocol_version, test_run_id, artifacts_path) = sys.argv[1:]

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
    "test_run_id": test_run_id,
    "artifacts": artifacts,
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
# test-summary.json — a real record of the tiers this invocation actually
# ran above, not an assertion that test functions merely exist (audit P2.3:
# "test-function existence and cached logs are not release proof").
# ---------------------------------------------------------------------------
TEST_SUMMARY="$OUT_DIR/test-summary.json"
python3 - "$TEST_SUMMARY" "$COMMIT" "$GO_VERSION" "$BUILD_TS" \
  "$UNIT_RESULT" "$UNIT_SECONDS" "$RACE_RESULT" "$RACE_SECONDS" \
  "$INTEGRATION_RESULT" "$INTEGRATION_SECONDS" \
  "$CORPUS_RESULT" "$CORPUS_SECONDS" "$CORPUS_TESTS_RUN" "$CORPUS_TESTS_FAILED" \
  "$FUZZ_RESULTS_JSON" "$ASSAYER_RESULT" "$ASSAYER_SUMMARY" <<'PYTESTSUMMARY'
import json, pathlib, sys

(summary_path, commit, go_version, build_ts, unit_result, unit_seconds,
 race_result, race_seconds, integration_result, integration_seconds,
 corpus_result, corpus_seconds, corpus_tests_run, corpus_tests_failed,
 fuzz_results_path, assayer_result, assayer_summary) = sys.argv[1:]

fuzz = []
for line in pathlib.Path(fuzz_results_path).read_text().splitlines():
    if line.strip():
        fuzz.append(json.loads(line))

data = {
    "generated_at": build_ts,
    "source_commit": commit,
    "go_version": go_version,
    "suites": {
        "unit": {"command": "go test -count=1 ./...", "result": unit_result, "duration_seconds": int(unit_seconds)},
        "race": {"command": "go test -race -count=1 ./...", "result": race_result, "duration_seconds": int(race_seconds)},
        "integration": {"command": "go test -tags integration -count=1 ./internal/assay/...", "result": integration_result, "duration_seconds": int(integration_seconds)},
        "black_box_corpus": {
            "command": "go test -run Sol3 -v -count=1 ./...",
            "result": corpus_result,
            "duration_seconds": int(corpus_seconds),
            "tests_run": int(corpus_tests_run),
            "tests_failed": int(corpus_tests_failed),
        },
        "fuzz": fuzz,
        "assayer_matrix": {"result": assayer_result, "summary": assayer_summary.strip()},
    },
}
overall = "PASS"
for suite in ("unit", "race", "integration", "black_box_corpus"):
    if data["suites"][suite]["result"] != "PASS":
        overall = "FAIL"
for f in fuzz:
    if f["result"] != "PASS":
        overall = "FAIL"
if assayer_result == "FAIL":
    overall = "FAIL"
data["overall_result"] = overall
pathlib.Path(summary_path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PYTESTSUMMARY
rm -f "$FUZZ_RESULTS_JSON" "$UNIT_LOG" "$RACE_LOG" "$INTEGRATION_LOG" "$CORPUS_LOG" "$ASSAYER_LOG" "$OUT_DIR"/test-fuzz-*.log

# ---------------------------------------------------------------------------
# Acceptance smoke test: extract the exact distributable archive for THIS
# host's platform on a clean path (never trust the staging tree we just
# built from), then exercise it exactly like an operator installing it would.
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
  tar -xzf "$HOST_ARCHIVE" -C "$SMOKE_DIR"
  EXTRACTED_BIN="$SMOKE_DIR/gov"
  if [ ! -x "$EXTRACTED_BIN" ]; then
    ACCEPT_OK=false
    EXECUTABLE_BIT_OK=false
    echo "extracted binary is not executable — executable bit not preserved in archive" >>"$NOTES_FILE"
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
    if [ "$REPORTED_VERSION" != "$VERSION" ] || [ "$REPORTED_COMMIT" != "$COMMIT" ] || [ "$REPORTED_CLAIMS" != "$CLAIMS_HASH" ]; then
      ACCEPT_OK=false
      VERSION_MATCH_OK=false
      echo "gov version --json ($REPORTED_VERSION/$REPORTED_COMMIT/$REPORTED_CLAIMS) does not match build-manifest.json ($VERSION/$COMMIT/$CLAIMS_HASH)" >>"$NOTES_FILE"
    fi
  else
    ACCEPT_OK=false
    VERSION_MATCH_OK=false
    echo "gov version --json failed: $VERSION_OUT" >>"$NOTES_FILE"
  fi
  if CLAIMS_LOG=$("$EXTRACTED_BIN" claims verify --file "$OUT_DIR/claims.yaml" --repo "$ROOT" 2>&1); then
    CLAIMS_RESULT=PASS
  else
    CLAIMS_RESULT=FAIL
    ACCEPT_OK=false
    echo "gov claims verify failed: $CLAIMS_LOG" >>"$NOTES_FILE"
  fi
else
  ACCEPT_OK=false
  CLAIMS_RESULT=SKIPPED
  EXECUTABLE_BIT_OK=false
  HASH_MATCH_OK=false
  VERSION_MATCH_OK=false
  echo "no archive built for this host's platform (${HOST_PLATFORM_ID}); nothing to extract and smoke-test" >>"$NOTES_FILE"
fi

if [ "$ACCEPT_OK" = true ]; then ACCEPTANCE_RESULT=PASS; else ACCEPTANCE_RESULT=FAIL; fi

python3 - "$ACCEPTANCE" "$ACCEPTANCE_RUN_ID" "$ACCEPTANCE_RESULT" "$HOST_PLATFORM_ID" "$CLAIMS_RESULT" "$BUILD_TS" "$ARCHIVE_EXTRACTED" "$EXECUTABLE_BIT_OK" "$HASH_MATCH_OK" "$VERSION_MATCH_OK" "$NOTES_FILE" <<'PYACCEPT'
import json, pathlib, sys

(path, run_id, result, platform, claims_result, generated_at,
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
        "claims_verify": claims_result,
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

# Staging subdirectories (stage-<platform>/) held the unpacked binary used
# to build each archive; they're not part of the shipped file set.
rm -rf "$OUT_DIR"/stage-*

# ---------------------------------------------------------------------------
# checksums.txt covers every file this release actually ships (every
# platform archive, the manifest, the SBOM, claims.yaml, both summaries) —
# generated last, over the final directory contents, so it can never omit
# an artifact the way the audit found ("checksums covering the stale
# snapshot archives but not the current production binary").
# ---------------------------------------------------------------------------
CHECKSUMS="$OUT_DIR/checksums.txt"
(cd "$OUT_DIR" && sha256sum -- *.tar.gz build-manifest.json sbom.json claims.yaml test-summary.json acceptance-summary.json gov >"$(basename "$CHECKSUMS")")

# ---------------------------------------------------------------------------
# signature — HMAC-SHA256 over checksums.txt, keyed by an operator-supplied
# secret. Never fabricated: an unsigned release says so in plain text rather
# than shipping a signature file that isn't one.
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

echo "release: OK — $OUT_DIR" >&2
ls -la "$OUT_DIR" >&2
echo "$MANIFEST"
