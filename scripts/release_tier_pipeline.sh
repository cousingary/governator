#!/bin/bash
# scripts/release_tier_pipeline.sh -- Sol11 rc5 Session 3 (P1-5): runs a
# sequence of named tiers, each backed by an atomic, identity-scoped
# checkpoint (scripts/release_checkpoint.py), with fail-fast semantics: the
# first required tier that does not pass PASS aborts the whole pipeline
# immediately -- later tiers in the same spec are never executed (corpus
# case 19: "required tier fails and later tiers do not run").
#
# A tier whose checkpoint already matches the current release identity
# byte-for-byte (same commit, same toolchain, same Assayer commit, same
# go.sum hash, same environment, same go test parallelism, same exact
# command) AND whose recorded result is PASS is reused instead of re-run --
# this is what makes a crashed-and-restarted scripts/release.sh invocation
# resumable rather than a full always-run-everything-again retry (corpus
# case 18: "resume after exact matching completed checkpoint" must SUCCEED
# and reuse, not re-run).
#
# Usage:
#   release_tier_pipeline.sh run --state-dir DIR --identity-file FILE --spec SPECFILE
#     --python-bin PATH --bash-bin PATH --sha256sum-bin PATH --date-bin PATH --awk-bin PATH
#     [--policy PATH --toolset-json PATH --toolset-py PATH --toolset-profile PROFILE]
#
# Sol15 P0-1 (rc8-upg15 S2b): when --policy and --toolset-json are BOTH
# supplied, every tier that actually runs (never one reused from a matching
# checkpoint) is bracketed by an independent
# `release_toolset.py --policy POLICY --verify TOOLSET_JSON` re-verification,
# once immediately before the tier's command starts and once immediately
# after it returns. This is deliberately per-tier, not a single pipeline-wide
# check: release.sh already re-verifies once before this whole pipeline
# starts (Sol12 P1-4) and again after it ends, but neither catches a same-UID
# tool substitution that happens BETWEEN two tiers or DURING one tier's own
# execution -- exactly Sol15's "tool executable replaced after preflight" and
# "symlinked tool target changed after resolution" attacks. A pre-check
# failure fails the tier WITHOUT ever invoking its command (the substituted
# tool is never given a chance to run); a post-check failure overrides an
# otherwise-PASSing tier to FAIL (a tier cannot buy trust by swapping tools
# back before this script notices, because the swap already happened while
# untrusted). Omitting both flags reproduces the exact pre-S2b behavior,
# which existing callers (internal/redteam/v11_s3_release_checkpoint_test.go)
# depend on.
#
# SPECFILE: one tier per line, TAB-separated: name<TAB>logfile<TAB>command
# (command is executed via `bash -c "$command"`). Blank lines and lines
# starting with # are ignored.
#
# Emits one JSON object per line to stdout (JSON Lines), one per tier
# actually visited, in spec order. On the first tier whose result is not
# PASS, one final {"tier":"__pipeline__","aborted":true,...} line names the
# failed tier and every tier that was skipped as a result, and this script
# exits 1. On full success it exits 0 after every spec tier's line has been
# emitted.
set -euo pipefail

ROOT=$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)
CHECKPOINT_PY="$ROOT/scripts/release_checkpoint.py"

usage() {
  echo "usage: $0 run --state-dir DIR --identity-file FILE --spec SPECFILE [--python-bin PATH --bash-bin PATH --sha256sum-bin PATH --date-bin PATH --awk-bin PATH] [--policy PATH --toolset-json PATH --toolset-py PATH --toolset-profile PROFILE]" >&2
  exit 2
}

[ "${1:-}" = "run" ] || usage
shift

STATE_DIR=""
IDENTITY_FILE=""
SPEC=""
PYTHON_BIN=python3
BASH_BIN=bash
SHA256SUM_BIN=sha256sum
DATE_BIN=date
AWK_BIN=awk
MKDIR_BIN=mkdir
MKTEMP_BIN=mktemp
RM_BIN=rm
DIRNAME_BIN=dirname
CAT_BIN=cat
POLICY=""
TOOLSET_JSON=""
TOOLSET_PY="$ROOT/scripts/release_toolset.py"
TOOLSET_PROFILE="reviewed-bytes"
while [ $# -gt 0 ]; do
  case "$1" in
    --state-dir) STATE_DIR=$2; shift 2 ;;
    --identity-file) IDENTITY_FILE=$2; shift 2 ;;
    --spec) SPEC=$2; shift 2 ;;
    --python-bin) PYTHON_BIN=$2; shift 2 ;;
    --bash-bin) BASH_BIN=$2; shift 2 ;;
    --sha256sum-bin) SHA256SUM_BIN=$2; shift 2 ;;
    --date-bin) DATE_BIN=$2; shift 2 ;;
    --awk-bin) AWK_BIN=$2; shift 2 ;;
    --mkdir-bin) MKDIR_BIN=$2; shift 2 ;;
    --mktemp-bin) MKTEMP_BIN=$2; shift 2 ;;
    --rm-bin) RM_BIN=$2; shift 2 ;;
    --dirname-bin) DIRNAME_BIN=$2; shift 2 ;;
    --cat-bin) CAT_BIN=$2; shift 2 ;;
    --policy) POLICY=$2; shift 2 ;;
    --toolset-json) TOOLSET_JSON=$2; shift 2 ;;
    --toolset-py) TOOLSET_PY=$2; shift 2 ;;
    --toolset-profile) TOOLSET_PROFILE=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$STATE_DIR" ] && [ -n "$IDENTITY_FILE" ] && [ -n "$SPEC" ] || usage
[ -f "$SPEC" ] || { echo "release_tier_pipeline: spec file $SPEC not found" >&2; exit 2; }
"$MKDIR_BIN" -p "$STATE_DIR"

# emit_json_line: print one JSON object built entirely from argv (never from
# string-interpolated bash variables inside a python -c body) -- avoids any
# quoting/injection hazard from a tier name, log path, or command containing
# characters meaningful to Python source.
emit_json_line() {
  "$PYTHON_BIN" - "$@" <<'PY'
import json, sys
keys = sys.argv[1::2]
vals = sys.argv[2::2]
def coerce(v):
    if v in ("__true__", "__false__"):
        return v == "__true__"
    try:
        return int(v)
    except ValueError:
        return v
print(json.dumps(dict(zip(keys, (coerce(v) for v in vals)))))
PY
}

FAILED_TIER=""
declare -a SPEC_NAMES=()
while IFS=$'\t' read -r t_name _t_log _t_cmd || [ -n "$t_name" ]; do
  [ -z "$t_name" ] && continue
  case "$t_name" in \#*) continue ;; esac
  SPEC_NAMES+=("$t_name")
done <"$SPEC"

ABORTED=false
while IFS=$'\t' read -r NAME LOG CMD || [ -n "$NAME" ]; do
  [ -z "$NAME" ] && continue
  case "$NAME" in \#*) continue ;; esac

  if [ "$ABORTED" = true ]; then
    break
  fi

  CKPT="$STATE_DIR/${NAME}.json"
  RESUMED=false
  RESULT=""
  SECONDS_=0
  STARTED=""
  ENDED=""
  LOGSHA=""
  EXITCODE=0
  TOOL_IDENTITY_PRE=""
  TOOL_IDENTITY_POST=""

  CHECK_ERR_FILE=$("$MKTEMP_BIN")
  if CHECK_OUT=$("$PYTHON_BIN" "$CHECKPOINT_PY" check --checkpoint "$CKPT" --identity-file "$IDENTITY_FILE" --command "$CMD" 2>"$CHECK_ERR_FILE"); then
    if [ -f "$LOG" ]; then
      RESUMED=true
      RESULT=$("$PYTHON_BIN" -c "import json,sys; print(json.load(open(sys.argv[1]))['result'])" "$CKPT")
      SECONDS_=$("$PYTHON_BIN" -c "import json,sys; print(json.load(open(sys.argv[1])).get('duration_seconds',0))" "$CKPT")
      STARTED=$("$PYTHON_BIN" -c "import json,sys; print(json.load(open(sys.argv[1]))['started'])" "$CKPT")
      ENDED=$("$PYTHON_BIN" -c "import json,sys; print(json.load(open(sys.argv[1]))['completed'])" "$CKPT")
      LOGSHA=$("$PYTHON_BIN" -c "import json,sys; print(json.load(open(sys.argv[1]))['log_sha256'])" "$CKPT")
      EXITCODE=$("$PYTHON_BIN" -c "import json,sys; print(json.load(open(sys.argv[1]))['exit_code'])" "$CKPT")
    else
      echo "release_tier_pipeline: tier ${NAME} checkpoint matches identity but its log ${LOG} is missing on disk -- re-running rather than trusting an unretrievable result" >&2
    fi
  else
    echo "release_tier_pipeline: tier ${NAME} checkpoint not reusable: $("$CAT_BIN" "$CHECK_ERR_FILE")" >&2
  fi
  "$RM_BIN" -f "$CHECK_ERR_FILE"

  if [ "$RESUMED" != true ]; then
    START_EPOCH=$("$DATE_BIN" +%s)
    STARTED=$("$DATE_BIN" -u +%Y-%m-%dT%H:%M:%SZ)
    "$MKDIR_BIN" -p "$("$DIRNAME_BIN" "$LOG")"

    TOOL_IDENTITY_PRE="SKIPPED"
    TOOL_IDENTITY_POST="SKIPPED"
    RUN_COMMAND=true
    if [ -n "$POLICY" ] && [ -n "$TOOLSET_JSON" ]; then
      if "$PYTHON_BIN" "$TOOLSET_PY" --policy "$POLICY" --verify "$TOOLSET_JSON" --profile "$TOOLSET_PROFILE" >"$LOG" 2>&1; then
        TOOL_IDENTITY_PRE="PASS"
      else
        TOOL_IDENTITY_PRE="FAIL"
        RUN_COMMAND=false
        echo "release_tier_pipeline: tier ${NAME} refused -- release tool identity differs from the approved toolset BEFORE this tier ran (Sol15 P0-1 S2b); the tier command was never executed" >>"$LOG"
      fi
    else
      : >"$LOG"
    fi

    if [ "$RUN_COMMAND" = true ]; then
      set +e
      "$BASH_BIN" -c "$CMD" >>"$LOG" 2>&1
      EXITCODE=$?
      set -e
    else
      EXITCODE=97
    fi

    if [ "$RUN_COMMAND" = true ] && [ -n "$POLICY" ] && [ -n "$TOOLSET_JSON" ]; then
      if "$PYTHON_BIN" "$TOOLSET_PY" --policy "$POLICY" --verify "$TOOLSET_JSON" --profile "$TOOLSET_PROFILE" >>"$LOG" 2>&1; then
        TOOL_IDENTITY_POST="PASS"
      else
        TOOL_IDENTITY_POST="FAIL"
        echo "release_tier_pipeline: tier ${NAME} release tool identity changed DURING execution (Sol15 P0-1 S2b) -- forcing FAIL regardless of the tier's own exit code" >>"$LOG"
      fi
    fi

    if [ "$EXITCODE" -eq 0 ] && [ "$TOOL_IDENTITY_POST" != "FAIL" ]; then RESULT=PASS; else RESULT=FAIL; fi
    END_EPOCH=$("$DATE_BIN" +%s)
    ENDED=$("$DATE_BIN" -u +%Y-%m-%dT%H:%M:%SZ)
    SECONDS_=$((END_EPOCH - START_EPOCH))
    LOGSHA=$("$SHA256SUM_BIN" "$LOG" | "$AWK_BIN" '{print $1}')
    "$PYTHON_BIN" "$CHECKPOINT_PY" write --checkpoint "$CKPT" --identity-file "$IDENTITY_FILE" \
      --command "$CMD" --started "$STARTED" --completed "$ENDED" \
      --exit-code "$EXITCODE" --log-sha256 "$LOGSHA" --result "$RESULT" --duration-seconds "$SECONDS_" \
      --tool-identity-pre "$TOOL_IDENTITY_PRE" --tool-identity-post "$TOOL_IDENTITY_POST" >/dev/null
  fi

  echo "release_tier_pipeline: tier ${NAME} $([ "$RESUMED" = true ] && echo REUSED || echo RAN) result=${RESULT} (${SECONDS_}s)" >&2

  emit_json_line \
    tier "$NAME" \
    ran "$([ "$RESUMED" = true ] && echo __false__ || echo __true__)" \
    resumed "$([ "$RESUMED" = true ] && echo __true__ || echo __false__)" \
    result "$RESULT" \
    duration_seconds "$SECONDS_" \
    started "$STARTED" \
    completed "$ENDED" \
    log_sha256 "$LOGSHA" \
    exit_code "$EXITCODE" \
    log_path "$LOG" \
    tool_identity_pre "$TOOL_IDENTITY_PRE" \
    tool_identity_post "$TOOL_IDENTITY_POST"

  if [ "$RESULT" != PASS ]; then
    ABORTED=true
    FAILED_TIER="$NAME"
  fi
done <"$SPEC"

if [ "$ABORTED" = true ]; then
  SKIPPED=()
  found=false
  for n in "${SPEC_NAMES[@]}"; do
    if [ "$found" = true ]; then
      SKIPPED+=("$n")
    fi
    if [ "$n" = "$FAILED_TIER" ]; then
      found=true
    fi
  done
  SKIPPED_JSON=$("$PYTHON_BIN" -c "import json,sys; print(json.dumps(sys.argv[1:]))" "${SKIPPED[@]}")
  "$PYTHON_BIN" -c "
import json, sys
print(json.dumps({'tier': '__pipeline__', 'aborted': True, 'failed_tier': sys.argv[1], 'skipped_tiers': json.loads(sys.argv[2])}))
" "$FAILED_TIER" "$SKIPPED_JSON"
  echo "release_tier_pipeline: required tier ${FAILED_TIER} FAILED -- aborting, ${#SKIPPED[@]} later tier(s) not run: ${SKIPPED[*]:-none}" >&2
  exit 1
fi

exit 0
