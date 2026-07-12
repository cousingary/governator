"""Profile registry for assayer.evaluate() (Governator<->Assayer bridge,
Phase 3A — see /mnt/e/downloads/agents/governator_hardening_plan.md).

A profile is metadata + a list of check specs, not live Check objects: some
checks need runtime context (e.g. `dedup` needs a Store), so profiles stay
declarative and `build_checks()` resolves them into callables for a given
evaluation.
"""

import hashlib
import json

from assayer import checks as checks_mod

# TUNABLE: minimal required shape of a coding artifact's payload. `content`
# (the rendered/generated text) is the only field every coding artifact is
# guaranteed to carry; anything more specific (language, file path, ...)
# would over-constrain payload shapes assayer hasn't seen yet.
CODING_OUTPUT_REQUIRED_FIELDS = {"content": str}

# The request envelope's own identifying fields (set by the Governator
# caller, not the agent) — validated separately from the payload so a
# malformed/missing artifact_name or artifact_sha256 is distinguishable
# from bad artifact *content*.
CODING_OUTPUT_ENVELOPE_FIELDS = {"artifact_name": str, "artifact_sha256": str}

# v2's payload schema: adds `language` on top of v1's bare `content`. Sol
# audit weakness 1 ("coding-output-v1 is too weak") reproduced
# `{"content": "x"}` passing v1 outright; v2 requires an artifact-specific
# schema (a coding artifact must at minimum declare what language it is)
# so that declaration can also drive file_path_consistency/domain_validator
# below instead of leaving them unable to check anything.
CODING_OUTPUT_V2_REQUIRED_FIELDS = {"content": str, "language": str}

# Profile registry: name -> {version, checks, enforcement, on_fail,
# on_error}. `version` is the profile's own semver (Sol audit Assayer
# weakness 6 — bumped independently of the assayer package version: a
# profile's check list can change shape without the package's public API
# changing at all, and vice versa). `checks` is a list of {"kind": ...,
# "args": {...}} specs resolved by build_checks(). `enforcement` feeds
# assayer.verify_scored()'s 4-way verdict; `on_fail`/`on_error` are metadata
# for the caller (Governator) to act on — assayer itself does not
# quarantine anything in 3A (no store on this synchronous, offline path).
PROFILES = {
    "coding-output-v1": {
        "version": "1.0.0",
        "enforcement": "blocking",
        "on_fail": "quarantine",
        "on_error": "quarantine",
        "checks": [
            # required_fields: the payload itself must look like a coding
            # artifact (minimally, non-missing/non-mistyped `content`).
            {"kind": "schema", "name": "required_fields", "args": {"required_fields": CODING_OUTPUT_REQUIRED_FIELDS}},
            {"kind": "no_placeholder", "args": {"field": "content"}},
            {"kind": "no_boilerplate", "args": {"field": "content"}},
            # artifact_schema: the request *envelope* is well-formed (the
            # artifact was correctly named/hashed before its content is
            # even evaluated). Reuses the same schema() factory as
            # required_fields, per the plan, with a distinct check name so
            # both results are visible in the verdict independently.
            {"kind": "schema", "name": "artifact_schema", "args": {"required_fields": CODING_OUTPUT_ENVELOPE_FIELDS}},
            # no_unexpected_duplication (checks.dedup) is intentionally left
            # out of the 3A check list: dedup() needs a live Store, and this
            # synchronous subprocess path is explicitly offline / no-network
            # (plan Phase 3A: "no network calls, no Supabase writes on this
            # synchronous merge-gating path"). Wiring a store into this path
            # is 3B/3C work, not 3A's.
        ],
    },
    "coding-output-v2": {
        "version": "2.0.0",
        "enforcement": "blocking",
        "on_fail": "quarantine",
        "on_error": "quarantine",
        # Duplicate-detection policy (Sol audit Assayer Phase J: "deterministic
        # duplicate policy"): dedup is intentionally excluded from this
        # profile's checks for the same offline-bridge reason as v1 (see
        # above) — the point being made explicit here is that a fixed,
        # declared check list that never includes dedup on this path is
        # itself the deterministic policy: every evaluation on this profile
        # runs the exact same checks every time, with no check whose
        # pass/fail meaning silently depends on whether a caller happened to
        # wire a store in. Real duplicate detection stays 3B/3C (async) work.
        "checks": [
            {"kind": "schema", "name": "required_fields", "args": {"required_fields": CODING_OUTPUT_V2_REQUIRED_FIELDS}},
            {"kind": "nonempty", "args": {"field": "content"}},
            {"kind": "language_sane", "args": {"field": "content"}},
            {"kind": "no_placeholder", "args": {"field": "content"}},
            {"kind": "no_boilerplate", "args": {"field": "content"}},
            {"kind": "schema", "name": "artifact_schema", "args": {"required_fields": CODING_OUTPUT_ENVELOPE_FIELDS}},
            {"kind": "file_path_consistency", "args": {}},
            {"kind": "domain_validator", "args": {}},
        ],
    },
}


def get_profile(name):
    """Return the profile dict for `name`, or None if unknown/blank."""
    if not name:
        return None
    return PROFILES.get(name)


def _json_safe(value):
    """Recursively convert `type` objects (e.g. required_fields' `str`,
    `int`) to their `.__name__` so a profile/config dict can go through
    json.dumps for hashing without a custom encoder."""
    if isinstance(value, type):
        return value.__name__
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


def _build_check(spec):
    """Resolve one check spec into (live Check, resolved_config). The two
    are built together, from the same branch, so they can never drift apart
    — resolved_config always describes exactly the check that was built."""
    kind = spec["kind"]
    args = dict(spec.get("args", {}))
    name = spec.get("name")

    if kind == "schema":
        base = checks_mod.schema(args["required_fields"])
        resolved_args = {"required_fields": _json_safe(args["required_fields"])}
    elif kind == "no_placeholder":
        base = checks_mod.no_placeholder(args["field"])
        resolved_args = {"field": args["field"]}
    elif kind == "no_boilerplate":
        base = checks_mod.no_boilerplate(args["field"])
        resolved_args = {"field": args["field"]}
    elif kind == "nonempty":
        min_chars = args.get("min_chars", checks_mod.NONEMPTY_MIN_CHARS)
        base = checks_mod.nonempty(args["field"], min_chars)
        resolved_args = {"field": args["field"], "min_chars": min_chars}
    elif kind == "max_len":
        max_chars = args.get("max_chars", checks_mod.MAX_LEN_MAX_CHARS)
        base = checks_mod.max_len(args["field"], max_chars)
        resolved_args = {"field": args["field"], "max_chars": max_chars}
    elif kind == "language_sane":
        base = checks_mod.language_sane(args["field"])
        resolved_args = {"field": args["field"]}
    elif kind == "file_path_consistency":
        field = args.get("field", "language")
        name_field = args.get("name_field", "artifact_name")
        base = checks_mod.file_path_consistency(field, name_field)
        resolved_args = {"field": field, "name_field": name_field}
    elif kind == "domain_validator":
        field = args.get("field", "language")
        base = checks_mod.domain_validator(field)
        resolved_args = {
            "field": field,
            "registered_domains": sorted(checks_mod.DOMAIN_VALIDATORS),
        }
    else:
        raise ValueError(f"unknown check kind: {kind}")

    check_name = name or base.name
    # Rename: two schema() checks in the same profile would otherwise both
    # be named "schema" and collide in verify()'s results dict.
    check = checks_mod.Check(check_name, base) if name else base
    return check, {"name": check_name, "kind": kind, "args": resolved_args}


def build_checks(profile):
    """Resolve a profile's check specs into live Check objects."""
    return [check for check, _ in (_build_check(spec) for spec in profile["checks"])]


def resolved_check_configs(profile):
    """Resolve a profile's check specs into their fully-resolved configs
    (spec args merged with whatever module-level default each check
    factory filled in, e.g. checks.NONEMPTY_MIN_CHARS). Used for
    validator_config_hash — kept separate from profile_definition_hash (the
    raw declared spec) so a change to a checks.py TUNABLE default is visible
    in the hash even when profiles.py itself is untouched."""
    return [config for _, config in (_build_check(spec) for spec in profile["checks"])]


def profile_definition_hash(profile_name, profile):
    """sha256 of the canonical JSON of a profile's own declared shape (name,
    enforcement, on_fail/on_error, raw check specs) — proves *which profile
    definition* produced a verdict, independent of the outcome itself and
    independent of the resolved runtime config (see resolved_check_configs)."""
    serializable = {
        "name": profile_name,
        "version": profile.get("version", ""),
        "enforcement": profile["enforcement"],
        "on_fail": profile["on_fail"],
        "on_error": profile["on_error"],
        "checks": [
            {"kind": spec["kind"], "name": spec.get("name"), "args": _json_safe(spec.get("args", {}))}
            for spec in profile["checks"]
        ],
    }
    canonical = json.dumps(serializable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
