"""assay: CLI for inspecting assayer traces and quarantine.

No third-party deps beyond `supabase` (present in the deployment venv) and
optionally `python-dotenv` for local env loading.
"""

import argparse
import hashlib
import json
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from assayer import checks as checks_mod
from assayer import profiles as profiles_mod
from assayer import verify_scored
from assayer.store import Store

_SINCE_RE = re.compile(r"^(\d+)([dh])$")

# Wire-protocol version for the `evaluate` request/response shape (Phase 3A
# Governator<->Assayer bridge). Bump only if the JSON fields themselves
# change in an incompatible way; profile-content changes do not need a bump
# here (each profile can carry its own semver later, in 3B).
#
# v2 (Sol audit Assayer v2 repair, weaknesses 3/4): response field renames
# (checks_hash -> checks_result_hash) and semantics changes (trace_id now
# null instead of always a random uuid; evaluation_id added) are exactly the
# "incompatible JSON field change" this constant exists to flag.
EVALUATE_PROTOCOL_VERSION = "gov-assay-evaluate-v2"

# ARTIFACT_PROTOCOL_VERSION (Sol audit finding #17 / P1.7) is a distinct
# version from EVALUATE_PROTOCOL_VERSION/policy_version above. policy_version
# is an opaque caller-supplied tag this CLI only ever echoes back (never
# validates); protocol_version is the artifact-identity wire shape
# (artifact_declared_path/artifact_stored_path/artifact_media_type/
# artifact_language) that Governator's internal/assay.Evaluate always
# stamps. A request whose protocol_version doesn't match exactly is rejected
# outright (see _cmd_evaluate) rather than silently evaluated against
# whichever fields happen to be present — an old Governator (missing these
# fields) or a mismatched one must fail closed, not silently skip the
# file-aware checks that depend on them.
ARTIFACT_PROTOCOL_VERSION = "gov-assay-artifact-protocol-v1"


def parse_since(value: str) -> str:
    """Parse Nd / Nh (e.g. '7d', '24h') into a UTC ISO cutoff timestamp."""
    match = _SINCE_RE.match(value.strip())
    if not match:
        raise ValueError(f"invalid --since value: {value!r} (expected e.g. '7d' or '24h')")

    amount = int(match.group(1))
    unit = match.group(2)
    delta = timedelta(days=amount) if unit == "d" else timedelta(hours=amount)
    cutoff = datetime.now(timezone.utc) - delta
    return cutoff.isoformat()


def _load_checks_json(raw):
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return {}
    return raw or {}


def compute_stats(rows):
    per_pipeline = {}
    per_check_fail = {}
    per_model = {}

    for row in rows:
        pipeline = row.get("pipeline") or "unknown"
        verdict = row.get("verdict") or "error"
        model = row.get("model") or "unknown"

        per_pipeline.setdefault(pipeline, {"pass": 0, "fail": 0, "error": 0})
        per_pipeline[pipeline][verdict] = per_pipeline[pipeline].get(verdict, 0) + 1

        per_model.setdefault(model, {"pass": 0, "fail": 0, "error": 0})
        per_model[model][verdict] = per_model[model].get(verdict, 0) + 1

        checks_json = _load_checks_json(row.get("checks_json"))
        for name, result in checks_json.items():
            if isinstance(result, dict) and not result.get("ok", True):
                per_check_fail[name] = per_check_fail.get(name, 0) + 1

    return per_pipeline, per_check_fail, per_model


def _build_parser():
    parser = argparse.ArgumentParser(prog="assay")
    sub = parser.add_subparsers(dest="command", required=True)

    quarantine = sub.add_parser("quarantine")
    qsub = quarantine.add_subparsers(dest="qcommand", required=True)

    qlist = qsub.add_parser("list")
    qlist.add_argument("--pipeline")
    qlist.add_argument("--since")
    qlist.add_argument("--status", default="open")

    qshow = qsub.add_parser("show")
    qshow.add_argument("id", type=int)

    qrelease = qsub.add_parser("release")
    qrelease.add_argument("id", type=int)

    qdiscard = qsub.add_parser("discard")
    qdiscard.add_argument("id", type=int)

    stats = sub.add_parser("stats")
    stats.add_argument("--since", default="7d")
    stats.add_argument("--brief", action="store_true")

    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--profile", default=None)

    return parser


def _cmd_quarantine_list(store, args):
    since_iso = parse_since(args.since) if args.since else None
    rows = store.list_quarantine(
        pipeline=args.pipeline, since_iso=since_iso, status=args.status
    )
    for row in rows:
        reasons = row.get("reasons_json") or []
        if isinstance(reasons, str):
            try:
                reasons = json.loads(reasons)
            except Exception:
                reasons = []
        if isinstance(reasons, dict):
            reasons = [f"{k}: {v}" for k, v in reasons.items()]
        first_reason = str(reasons[0]) if reasons else ""
        if len(first_reason) > 60:
            first_reason = first_reason[:60]
        print(
            f"{row.get('id')}\t{row.get('ts')}\t{row.get('pipeline')}\t"
            f"{first_reason}\t{row.get('status')}"
        )


def _cmd_quarantine_show(store, args):
    row = store.get_quarantine(args.id)
    if row is None:
        print(f"no quarantine row with id {args.id}")
        return
    print(json.dumps(row, indent=2, default=str))


def _cmd_quarantine_release(store, args):
    row = store.get_quarantine(args.id)
    if row is None:
        print(f"no quarantine row with id {args.id}")
        return
    # Round 1: print the payload for manual/pipeline re-insertion.
    # Round 2 (future work): automatically re-insert into the brain.
    print(json.dumps(row.get("payload_json"), indent=2, default=str))
    store.set_quarantine_status(args.id, "released")


def _cmd_quarantine_discard(store, args):
    store.set_quarantine_status(args.id, "discarded")


def _cmd_stats(store, args):
    if args.brief:
        since_iso = parse_since("24h")
    else:
        since_iso = parse_since(args.since)

    rows = store.stats(since_iso=since_iso)
    per_pipeline, per_check_fail, per_model = compute_stats(rows)

    if args.brief:
        total_pass = sum(p.get("pass", 0) for p in per_pipeline.values())
        total_fail = sum(p.get("fail", 0) for p in per_pipeline.values())
        total_error = sum(p.get("error", 0) for p in per_pipeline.values())
        total_traced = total_pass + total_fail + total_error

        if total_fail == 0 and total_error == 0:
            line1 = f"ASSAYER: all pass ({total_traced} traced, 24h)"
        else:
            line1 = f"ASSAYER: {total_fail + total_error} fail / {total_pass} pass (24h)"

        if per_check_fail:
            top_name, top_count = max(per_check_fail.items(), key=lambda kv: kv[1])
            line2 = f"top failing check: {top_name} ({top_count})"
        else:
            line2 = "-"

        open_quarantine = store.list_quarantine(status="open")
        line3 = f"open quarantine: {len(open_quarantine)}"

        print(line1)
        print(line2)
        print(line3)
        return

    print("per-pipeline:")
    for pipeline, counts in sorted(per_pipeline.items()):
        print(
            f"  {pipeline}: pass={counts.get('pass', 0)} "
            f"fail={counts.get('fail', 0)} error={counts.get('error', 0)}"
        )

    print("per-check failures:")
    if per_check_fail:
        for name, count in sorted(per_check_fail.items(), key=lambda kv: -kv[1]):
            print(f"  {name}: {count}")
    else:
        print("  (none)")

    print("per-model:")
    for model, counts in sorted(per_model.items()):
        print(
            f"  {model}: pass={counts.get('pass', 0)} "
            f"fail={counts.get('fail', 0)} error={counts.get('error', 0)}"
        )


def _hash_obj(obj) -> str:
    """sha256 of the canonical (sorted-key) JSON of any JSON-serializable
    object. Deterministic for identical content."""
    canonical = json.dumps(obj, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# checks_result_hash (renamed from checks_hash, Sol audit Assayer weakness 3:
# "checks_hash is an outcome hash... cannot prove which validator
# implementation or configuration produced the result") is kept as its own
# function name for clarity at call sites, but is just _hash_obj under the
# hood — a hash of the *outcome* (verify() results), never of the checks
# that produced it. See _profile_definition_hash/_validator_config_hash/
# _validator_implementation_hash below for the other three.
_checks_result_hash = _hash_obj


def _validator_implementation_hash() -> str:
    """sha256 of assayer/checks.py's own source bytes — "which validator
    implementation" produced a result, independent of the outcome and of
    which profile/config selected which checks. Computed once per process,
    not per evaluation: the module's source doesn't change mid-run.

    Reads through checks_mod.__loader__.get_data() rather than a plain
    Path(...).read_bytes(): both the regular SourceFileLoader and
    zipimport's zipimporter implement get_data(path), so this works
    identically whether this process was launched against a real directory
    or against a Governator-sealed single-file package (Sol11 P0-6) — a
    plain filesystem read would raise FileNotFoundError for the latter,
    since checks_mod.__file__ is then a composite "archive/member" string
    with no corresponding real path on disk.
    """
    return hashlib.sha256(checks_mod.__loader__.get_data(checks_mod.__file__)).hexdigest()


_VALIDATOR_IMPLEMENTATION_HASH = _validator_implementation_hash()


def _verdict_payload(
    verdict,
    failed_checks,
    had_error,
    *,
    checks_result_hash,
    profile_definition_hash="",
    validator_config_hash="",
    policy_version,
    reason=None,
):
    payload = {
        "verdict": verdict,
        "failed_checks": failed_checks,
        "had_error": had_error,
        # evaluation_id: a real per-call identifier for *this* evaluation
        # (Sol audit Assayer weakness 4: "trace_id is not a real trace" —
        # the old field emitted a random UUID while creating no trace row).
        # trace_id stays null here: 3A has no async persistence wired up (no
        # Store call on this offline path), so there is genuinely no
        # persisted trace row yet for this evaluation_id to point at. A
        # caller that later persists one (3B/3C) can set trace_id then.
        "evaluation_id": str(uuid.uuid4()),
        "trace_id": None,
        "quarantine_id": "",
        "checks_result_hash": checks_result_hash,
        "profile_definition_hash": profile_definition_hash,
        "validator_implementation_hash": _VALIDATOR_IMPLEMENTATION_HASH,
        "validator_config_hash": validator_config_hash,
        "policy_version": policy_version,
    }
    if reason is not None:
        payload["reason"] = reason
    return payload


def _emit(payload):
    print(json.dumps(payload))


def _cmd_evaluate(args, stdin_text=None):
    """Read one evaluate request from stdin (or `stdin_text`, for tests),
    run the named check profile, and write one verdict JSON object to
    stdout. Never touches the network or a Store (Phase 3A: synchronous,
    offline, local-only bridge — see plan Phase 3, subsection 3A).

    Always writes valid JSON and returns 0 for any *handled* outcome
    (pass/advisory/fail/error alike) — an "error" verdict is itself a
    successfully-computed, well-formed result, not a crash. Governator's
    subprocess caller treats a nonzero exit as its own separate ERROR
    fallback for cases where even this handler couldn't run (e.g. the
    interpreter itself failing), so returning 0 here whenever we managed to
    emit a verdict keeps the two signaling paths from conflicting.
    """
    raw = stdin_text if stdin_text is not None else sys.stdin.read()

    try:
        request = json.loads(raw)
    except Exception as exc:
        _emit(_verdict_payload(
            "error", [], True,
            checks_result_hash=_checks_result_hash({}), policy_version=None,
            reason=f"malformed JSON on stdin: {exc}",
        ))
        return 0

    if not isinstance(request, dict):
        _emit(_verdict_payload(
            "error", [], True,
            checks_result_hash=_checks_result_hash({}), policy_version=None,
            reason="request must be a JSON object",
        ))
        return 0

    # Echo the caller's policy_version if given; otherwise fall back to this
    # bridge's own wire-protocol version so the field is never silently null.
    policy_version = request.get("policy_version") or EVALUATE_PROTOCOL_VERSION

    # Sol audit finding #17 / P1.7: the artifact-identity wire shape is a
    # separate, strictly-enforced protocol version from policy_version above
    # (see ARTIFACT_PROTOCOL_VERSION's doc comment). A missing or mismatched
    # value fails closed here, before any check profile or payload is even
    # looked at — an old Governator not sending these fields, or a
    # mismatched one, must not silently evaluate with whatever partial
    # artifact identity happens to be present.
    request_protocol_version = request.get("protocol_version")
    if request_protocol_version != ARTIFACT_PROTOCOL_VERSION:
        _emit(_verdict_payload(
            "error", [], True,
            checks_result_hash=_checks_result_hash({}), policy_version=policy_version,
            reason=(
                f"artifact protocol_version mismatch: governator sent "
                f"{request_protocol_version!r}, assayer expects {ARTIFACT_PROTOCOL_VERSION!r}"
            ),
        ))
        return 0

    profile_name = args.profile or request.get("check_profile") or ""
    profile = profiles_mod.get_profile(profile_name)
    if profile is None:
        _emit(_verdict_payload(
            "error", [], True,
            checks_result_hash=_checks_result_hash({}), policy_version=policy_version,
            reason=f"unknown or empty check_profile: {profile_name!r}",
        ))
        return 0

    payload = request.get("payload")
    if not isinstance(payload, dict):
        payload = {}
    item = dict(payload)
    item["artifact_name"] = request.get("artifact_name")
    item["artifact_sha256"] = request.get("artifact_sha256")
    # artifact_declared_path (Sol audit finding #17) is the artifact's real
    # workspace-relative path — what file_path_consistency should check a
    # declared language's extension against, not artifact_name (a logical
    # handle that was never meant to double as a filename). Media
    # type/language are also made available to validators (reserved for
    # future file-aware checks); artifact_stored_path is deliberately NOT
    # copied here — the audit: "the stored absolute path should not be
    # exposed unnecessarily to validators."
    item["artifact_declared_path"] = request.get("artifact_declared_path")
    item["artifact_media_type"] = request.get("artifact_media_type")
    item["artifact_language"] = request.get("artifact_language")

    live_checks = profiles_mod.build_checks(profile)
    result = verify_scored(item, live_checks, enforcement=profile["enforcement"])

    _emit(_verdict_payload(
        result.verdict, result.failed, result.had_error,
        checks_result_hash=_checks_result_hash(result.checks),
        profile_definition_hash=profiles_mod.profile_definition_hash(profile_name, profile),
        validator_config_hash=_hash_obj(profiles_mod.resolved_check_configs(profile)),
        policy_version=policy_version,
    ))
    return 0


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "evaluate":
        return _cmd_evaluate(args)

    store = Store()

    if args.command == "quarantine":
        if args.qcommand == "list":
            _cmd_quarantine_list(store, args)
        elif args.qcommand == "show":
            _cmd_quarantine_show(store, args)
        elif args.qcommand == "release":
            _cmd_quarantine_release(store, args)
        elif args.qcommand == "discard":
            _cmd_quarantine_discard(store, args)
    elif args.command == "stats":
        _cmd_stats(store, args)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
