#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "release: refusing to build from a dirty tree" >&2
  exit 1
fi

VERSION=${VERSION:-1.5.0-dev}
GOOS_VALUE=${GOOS:-$(go env GOOS)}
GOARCH_VALUE=${GOARCH:-$(go env GOARCH)}
COMMIT=$(git rev-parse HEAD)
BUILD_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CLAIMS_HASH=$(sha256sum docs/claims.yaml | awk '{print $1}')
ADAPTER_PROTOCOL_VERSION=${ADAPTER_PROTOCOL_VERSION:-adapter-protocol-v1}
TEST_RUN_ID="go-test-${COMMIT}"
ACCEPTANCE_RUN_ID="version-self-check-${COMMIT}"
OUT_DIR=${OUT_DIR:-dist}
mkdir -p "$OUT_DIR"
ARTIFACT="$OUT_DIR/gov_${VERSION}_${GOOS_VALUE}_${GOARCH_VALUE}"
MANIFEST="$OUT_DIR/build-manifest-${VERSION}-${COMMIT}.json"
TEST_LOG="$OUT_DIR/test-${COMMIT}.log"
VERSION_JSON="$OUT_DIR/version-${COMMIT}.json"
BUILDINFO_TXT="$OUT_DIR/buildinfo-${COMMIT}.txt"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.sourceCommit=${COMMIT} -X main.buildTimestamp=${BUILD_TS} -X main.claimsHash=${CLAIMS_HASH} -X main.adapterProtocolVersion=${ADAPTER_PROTOCOL_VERSION}"

if go test ./... >"$TEST_LOG" 2>&1; then
  TEST_RESULT=PASS
else
  TEST_RESULT=FAIL
  cat "$TEST_LOG" >&2
  exit 1
fi

GOOS=$GOOS_VALUE GOARCH=$GOARCH_VALUE CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$ARTIFACT" ./cmd/gov
ARTIFACT_SHA=$(sha256sum "$ARTIFACT" | awk '{print $1}')
go version -m "$ARTIFACT" >"$BUILDINFO_TXT"
if "$ARTIFACT" version --json >"$VERSION_JSON"; then
  ACCEPTANCE_RESULT=PASS
else
  ACCEPTANCE_RESULT=FAIL
  cat "$VERSION_JSON" >&2 || true
  exit 1
fi

python3 - "$MANIFEST" "$VERSION" "$COMMIT" "$(go version | awk '{print $3}')" "$LDFLAGS" "$ARTIFACT" "$ARTIFACT_SHA" "$CLAIMS_HASH" "$TEST_RUN_ID" "$TEST_RESULT" "$ACCEPTANCE_RUN_ID" "$ACCEPTANCE_RESULT" "$VERSION_JSON" "$BUILDINFO_TXT" <<'PYMANIFEST'
import json, pathlib, sys
(manifest, version, commit, go_version, build_flags, artifact, artifact_sha, claims_hash,
 test_run_id, test_result, acceptance_run_id, acceptance_result, version_json, buildinfo_txt) = sys.argv[1:]
self_report = json.loads(pathlib.Path(version_json).read_text())
buildinfo = pathlib.Path(buildinfo_txt).read_text()
data = {
    "version": version,
    "source_commit": commit,
    "go_version": go_version,
    "build_flags": build_flags,
    "artifact_path": artifact,
    "artifact_sha256": artifact_sha,
    "build_info": {
        "raw": buildinfo,
        "vcs_revision": commit,
        "self_reported_version": self_report.get("version", ""),
        "self_reported_source_commit": self_report.get("source_commit", ""),
        "self_reported_claims_hash": self_report.get("claims_hash", ""),
    },
    "claims_hash": claims_hash,
    "test_run_id": test_run_id,
    "test_result": test_result,
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

echo "$MANIFEST"
