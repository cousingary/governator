"""Profile registry for assayer.evaluate() (Governator<->Assayer bridge,
Phase 3A — see /mnt/e/downloads/agents/governator_hardening_plan.md).

A profile is metadata + a list of check specs, not live Check objects: some
checks need runtime context (e.g. `dedup` needs a Store), so profiles stay
declarative and `build_checks()` resolves them into callables for a given
evaluation.
"""

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

# Profile registry: name -> {checks, enforcement, on_fail, on_error}.
# `checks` is a list of {"kind": ..., "args": {...}} specs resolved by
# build_checks(). `enforcement` feeds assayer.verify_scored()'s 4-way
# verdict; `on_fail`/`on_error` are metadata for the caller (Governator) to
# act on — assayer itself does not quarantine anything in 3A (no store on
# this synchronous, offline path).
PROFILES = {
    "coding-output-v1": {
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
}


def get_profile(name):
    """Return the profile dict for `name`, or None if unknown/blank."""
    if not name:
        return None
    return PROFILES.get(name)


def _build_check(spec):
    kind = spec["kind"]
    args = spec.get("args", {})
    name = spec.get("name")

    if kind == "schema":
        base = checks_mod.schema(args["required_fields"])
    elif kind == "no_placeholder":
        base = checks_mod.no_placeholder(args["field"])
    elif kind == "no_boilerplate":
        base = checks_mod.no_boilerplate(args["field"])
    elif kind == "nonempty":
        base = checks_mod.nonempty(args["field"], args.get("min_chars", checks_mod.NONEMPTY_MIN_CHARS))
    elif kind == "max_len":
        base = checks_mod.max_len(args["field"], args.get("max_chars", checks_mod.MAX_LEN_MAX_CHARS))
    elif kind == "language_sane":
        base = checks_mod.language_sane(args["field"])
    else:
        raise ValueError(f"unknown check kind: {kind}")

    if name:
        # Rename: two schema() checks in the same profile would otherwise
        # both be named "schema" and collide in verify()'s results dict.
        return checks_mod.Check(name, base)
    return base


def build_checks(profile):
    """Resolve a profile's check specs into live Check objects."""
    return [_build_check(spec) for spec in profile["checks"]]
