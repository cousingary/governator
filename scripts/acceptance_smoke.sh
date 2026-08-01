#!/usr/bin/env bash
# scripts/acceptance_smoke.sh — v16-release Session 6 (R4): the native
# acceptance smoke test, extracted as a standalone form so a GitHub Actions
# runner on each native architecture can run the SAME four checks the release
# flow runs. This is not a second implementation: it mirrors
# scripts/release.sh's run_acceptance_check (the canonical source, lines
# ~782-870) check-for-check. The two must stay in sync; release.sh remains the
# release-of-record path and this script is its CI-runnable twin for producing
# per-platform native acceptance evidence.
#
# The four checks (the exact names the release's acceptance JSON carries):
#   archive_extracted            — the platform tarball extracts cleanly
#   executable_bit_preserved     — the extracted binary is mode 0755 exactly
#   binary_hash_matches_build    — the extracted binary hashes to the built one
#   version_json_matches_manifest — gov version --json reports the build identity
#
# Usage:
#   acceptance_smoke.sh GOV_BIN VERSION COMMIT CLAIMS_HASH OUT_JSON
#
# GOV_BIN       path to the freshly built gov binary for this runner's arch
# VERSION       the release version string (e.g. 1.0.2-rc8)
# COMMIT        the source commit the binary was built from
# CLAIMS_HASH   the claims hash the binary must self-report
# OUT_JSON      path to write the acceptance JSON evidence record
#
# Exit 0 if all four checks pass; exit 1 with a named diagnostic on any failure.
set -eu

GOV_BIN="${1:?GOV_BIN required}"
VERSION="${2:?VERSION required}"
COMMIT="${3:?COMMIT required}"
CLAIMS_HASH="${4:?CLAIMS_HASH required}"
OUT_JSON="${5:?OUT_JSON required}"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

archive_extracted=false
executable_bit_ok=false
hash_match_ok=false
version_match_ok=true
notes=()

archive="$work_dir/gov.tar.gz"
# Preserve the exact mode in the archive (tar remembers the on-disk mode).
chmod 755 "$GOV_BIN"
tar -czf "$archive" -C "$(dirname "$GOV_BIN")" "$(basename "$GOV_BIN")"

extract_dir="$work_dir/extracted"
mkdir -p "$extract_dir"
if tar -xzf "$archive" -C "$extract_dir" -p 2>/dev/null; then
	archive_extracted=true
else
	notes+=("archive failed to extract")
fi

extracted_bin="$extract_dir/$(basename "$GOV_BIN")"
if [ -f "$extracted_bin" ]; then
	extracted_mode=$(stat -c '%a' "$extracted_bin" 2>/dev/null || stat -f '%OLp' "$extracted_bin")
	if [ "$extracted_mode" = "755" ]; then
		executable_bit_ok=true
	else
		version_match_ok=false
		notes+=("extracted binary mode is ${extracted_mode}, must be exactly 755")
	fi

	built_sha=$(sha256sum "$GOV_BIN" 2>/dev/null | awk '{print $1}')
	[ -n "$built_sha" ] || built_sha=$(shasum -a 256 "$GOV_BIN" | awk '{print $1}')
	extracted_sha=$(sha256sum "$extracted_bin" 2>/dev/null | awk '{print $1}')
	[ -n "$extracted_sha" ] || extracted_sha=$(shasum -a 256 "$extracted_bin" | awk '{print $1}')
	if [ "$extracted_sha" = "$built_sha" ]; then
		hash_match_ok=true
	else
		notes+=("extracted binary hash (${extracted_sha}) does not match the built binary (${built_sha})")
	fi
else
	notes+=("extracted binary not found after archive extraction")
fi

# version_json_matches_manifest: the binary must self-report the build identity
# and dirty=false. This is the native-execution proof — the binary RUNS on this
# architecture and reports consistently.
if version_out=$("$extracted_bin" version --json 2>&1); then
	reported_version=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('version',''))" "$version_out" 2>/dev/null || echo "")
	reported_commit=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('source_commit',''))" "$version_out" 2>/dev/null || echo "")
	reported_claims=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('claims_hash',''))" "$version_out" 2>/dev/null || echo "")
	reported_dirty=$(python3 -c "import json,sys; v=json.loads(sys.argv[1]); print(v.get('dirty','__missing__'))" "$version_out" 2>/dev/null || echo "__missing__")
	if [ "$reported_version" != "$VERSION" ] || [ "$reported_commit" != "$COMMIT" ] || [ "$reported_claims" != "$CLAIMS_HASH" ]; then
		version_match_ok=false
		notes+=("gov version --json (${reported_version}/${reported_commit}/${reported_claims}) does not match build identity (${VERSION}/${COMMIT}/${CLAIMS_HASH})")
	fi
	if [ "$reported_dirty" != "False" ] && [ "$reported_dirty" != "false" ]; then
		version_match_ok=false
		notes+=("gov version --json reports dirty=${reported_dirty}; release artifacts must report dirty=false")
	fi
else
	version_match_ok=false
	notes+=("gov version --json failed: ${version_out}")
fi

overall=PASS
if [ "$archive_extracted" != true ] || [ "$executable_bit_ok" != true ] || [ "$hash_match_ok" != true ] || [ "$version_match_ok" != true ]; then
	overall=FAIL
fi

platform_id="$(python3 -c "
import platform
goos={'linux':'linux','darwin':'darwin'}.get(platform.system().lower(), platform.system().lower())
m=platform.machine().lower()
goarch={'x86_64':'amd64','amd64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(m,m)
print(f'{goos}_{goarch}')
")"

python3 - "$OUT_JSON" "$overall" "$platform_id" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	"$archive_extracted" "$executable_bit_ok" "$hash_match_ok" "$version_match_ok" ${notes[@]+"${notes[@]}"} <<'PYACCEPT'
import json, pathlib, sys

(path, result, platform, generated_at,
 archive_extracted, executable_bit_ok, hash_match_ok, version_match_ok, *notes) = sys.argv[1:]

data = {
    "generated_at": generated_at,
    "extracted_platform": platform,
    "checks": {
        "archive_extracted": archive_extracted == "true",
        "executable_bit_preserved": executable_bit_ok == "true",
        "binary_hash_matches_build": hash_match_ok == "true",
        "version_json_matches_manifest": version_match_ok == "true",
    },
    "notes": [n for n in notes if n.strip()],
    "overall_result": result,
}
pathlib.Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PYACCEPT

if [ "$overall" = PASS ]; then
	echo "acceptance_smoke: PASS — native acceptance evidence for ${platform_id} written to ${OUT_JSON}" >&2
	exit 0
fi
echo "acceptance_smoke: FAIL — see ${OUT_JSON}" >&2
exit 1
