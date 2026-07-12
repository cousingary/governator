"""Check factories for assayer.verify().

Each factory returns a Check object: a callable with a `.name` attribute.
All checks are pure (no I/O) except `dedup`, which talks to a store.
"""

import re

# TUNABLE
NONEMPTY_MIN_CHARS = 20
# TUNABLE
MAX_LEN_MAX_CHARS = 2000
# TUNABLE
PRINTABLE_RATIO = 0.90
# TUNABLE
REPEAT_NGRAM_RATIO = 0.50
# TUNABLE
REPEAT_NGRAM_MIN_WORDS = 6

# TUNABLE
BOILERPLATE_PREFIXES = [
    "as an ai",
    "i cannot",
    "i can't",
    "i'm sorry",
    "i am sorry",
    "here is",
    "here are",
    "sure,",
    "certainly",
]

# TUNABLE
BOILERPLATE_SUBSTRINGS = [
    "as an ai language model",
]

# TUNABLE
PROMPT_ECHO_SUBSTRINGS = [
    "atomic insight",
    "declarative statement",
    "return json",
]

# TUNABLE
PLACEHOLDER_SUBSTRINGS = [
    "[todo",
    "todo:",
    "{{",
    "}}",
    "lorem ipsum",
    "[insert",
    "[placeholder",
    "[]",
    "[...]",
]

_XXX_WORD_RE = re.compile(r"\bxxx\b", re.IGNORECASE)


class Check:
    """A named, callable check. `fn(item) -> (ok, detail)`."""

    def __init__(self, name, fn):
        self.name = name
        self._fn = fn

    def __call__(self, item):
        return self._fn(item)


def schema(required_fields: dict):
    """Every key in required_fields must be present in item and isinstance
    of the mapped type. Detail names the first missing/mistyped field."""

    def fn(item):
        for field_name, expected_type in required_fields.items():
            if field_name not in item:
                return False, f"missing field: {field_name}"
            if not isinstance(item[field_name], expected_type):
                return False, (
                    f"wrong type for field: {field_name} "
                    f"(expected {expected_type.__name__}, "
                    f"got {type(item[field_name]).__name__})"
                )
        return True, "ok"

    return Check("schema", fn)


def nonempty(field, min_chars=NONEMPTY_MIN_CHARS):
    def fn(item):
        value = item.get(field)
        if not isinstance(value, str):
            return False, f"{field} is not a string"
        if len(value.strip()) < min_chars:
            return False, f"{field} shorter than {min_chars} chars"
        return True, "ok"

    return Check(f"nonempty:{field}", fn)


def max_len(field, max_chars=MAX_LEN_MAX_CHARS):
    def fn(item):
        value = item.get(field)
        if not isinstance(value, str):
            return False, f"{field} is not a string"
        if len(value) > max_chars:
            return False, f"{field} longer than {max_chars} chars"
        return True, "ok"

    return Check(f"max_len:{field}", fn)


def no_boilerplate(field):
    def fn(item):
        value = item.get(field)
        if not isinstance(value, str):
            return False, f"{field} is not a string"

        stripped = value.strip()
        lowered = stripped.lower()

        for prefix in BOILERPLATE_PREFIXES:
            if lowered.startswith(prefix):
                return False, f"{field} starts with boilerplate prefix: {prefix!r}"

        for substring in BOILERPLATE_SUBSTRINGS:
            if substring in lowered:
                return False, f"{field} contains boilerplate: {substring!r}"

        if stripped.startswith("```"):
            return False, f"{field} is fenced code/JSON"

        for substring in PROMPT_ECHO_SUBSTRINGS:
            if substring in lowered:
                return False, f"{field} echoes prompt instructions: {substring!r}"

        return True, "ok"

    return Check(f"no_boilerplate:{field}", fn)


def no_placeholder(field):
    def fn(item):
        value = item.get(field)
        if not isinstance(value, str):
            return False, f"{field} is not a string"

        lowered = value.lower()

        for substring in PLACEHOLDER_SUBSTRINGS:
            if substring in lowered:
                return False, f"{field} contains placeholder artifact: {substring!r}"

        if _XXX_WORD_RE.search(value):
            return False, f"{field} contains placeholder word: 'xxx'"

        return True, "ok"

    return Check(f"no_placeholder:{field}", fn)


def language_sane(field):
    def fn(item):
        value = item.get(field)
        if not isinstance(value, str):
            return False, f"{field} is not a string"

        if len(value) == 0:
            return False, f"{field} is empty"

        printable_count = sum(1 for c in value if c.isprintable() or c in "\n\t")
        ratio = printable_count / len(value)
        if ratio < PRINTABLE_RATIO:
            return False, f"{field} printable ratio {ratio:.2f} below {PRINTABLE_RATIO}"

        words = value.split()
        if len(words) >= REPEAT_NGRAM_MIN_WORDS:
            trigrams = [
                tuple(words[i : i + 3]) for i in range(len(words) - 2)
            ]
            if trigrams:
                counts = {}
                for tg in trigrams:
                    counts[tg] = counts.get(tg, 0) + 1
                top_count = max(counts.values())
                top_ratio = top_count / len(trigrams)
                if top_ratio > REPEAT_NGRAM_RATIO:
                    return False, (
                        f"{field} looks like degenerate repetition "
                        f"(top 3-gram ratio {top_ratio:.2f})"
                    )

        return True, "ok"

    return Check(f"language_sane:{field}", fn)


def dedup(store, pipeline, hash_getter):
    def fn(item):
        h = hash_getter(item)
        try:
            seen = store.seen_pass(pipeline, h)
        except Exception:
            return True, "dedup skipped: store unavailable"

        if seen:
            return False, f"duplicate of previously passed item {h[:8]}"
        return True, "ok"

    return Check("dedup", fn)
