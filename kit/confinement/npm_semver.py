"""Small semver range matcher for npm peer ranges and advisory ranges.

The matcher follows the node-semver rules with prerelease versions included, because both the
npm resolver and the bulk advisory check use that setting. It is deliberately strict: a range
it cannot parse raises SemverError and the caller refuses, so an unusual range never passes
silently. Only the operators npm itself accepts are supported: the comparators less than,
less than or equal, greater than, greater than or equal and equal, the tilde and caret
operators, x-ranges and partial versions, hyphen ranges and the double bar union.
"""

import re


MAX_RANGE_CHARS = 1024
MAX_SETS = 32
MAX_COMPARATORS = 32
MAX_NUMBER_DIGITS = 16
LOWEST_PRERELEASE = (0,)

_NUMBER = r"(?:0|[1-9][0-9]*)"
_PART = r"(?:[xX*]|" + _NUMBER + r")"
_VERSION_RE = re.compile(
    r"v?(?P<major>" + _NUMBER + r")\.(?P<minor>" + _NUMBER + r")\.(?P<patch>" + _NUMBER + r")"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\Z"
)
_COMPARATOR_RE = re.compile(
    r"(?P<op><=|>=|<|>|=|~>|~|\^)?v?(?P<major>" + _PART + r")"
    r"(?:\.(?P<minor>" + _PART + r")"
    r"(?:\.(?P<patch>" + _PART + r")"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?)?)?\Z"
)
_HYPHEN_RE = re.compile(r"\s*(?P<low>\S+)\s+-\s+(?P<high>\S+)\s*\Z")
_OPERATOR_SPACE_RE = re.compile(r"([<>=~^])\s+")
_PRERELEASE_ID_RE = re.compile(r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)\Z")


class SemverError(Exception):
    """The version or range is not valid; the message is a fixed token."""


def _fail():
    raise SemverError("semver_invalid")


def _number(text):
    if len(text) > MAX_NUMBER_DIGITS:
        _fail()
    return int(text)


def _prerelease(text):
    if text is None:
        return ()
    identifiers = []
    for part in text.split("."):
        if _PRERELEASE_ID_RE.fullmatch(part) is None:
            _fail()
        identifiers.append(_number(part) if part.isdigit() else part)
    return tuple(identifiers)


def parse_version(text):
    """Return (major, minor, patch, prerelease) for one exact version string."""
    if type(text) is not str or len(text) > 256:
        _fail()
    match = _VERSION_RE.fullmatch(text)
    if match is None:
        _fail()
    return (
        _number(match.group("major")), _number(match.group("minor")),
        _number(match.group("patch")), _prerelease(match.group("pre")),
    )


def _identifier_order(left, right):
    left_numeric = type(left) is int
    right_numeric = type(right) is int
    if left_numeric and right_numeric:
        return (left > right) - (left < right)
    if left_numeric:
        return -1
    if right_numeric:
        return 1
    return (left > right) - (left < right)


def compare_versions(left, right):
    """Return -1, 0 or 1 for two parsed versions."""
    for index in range(3):
        if left[index] != right[index]:
            return -1 if left[index] < right[index] else 1
    left_pre = left[3]
    right_pre = right[3]
    if not left_pre and not right_pre:
        return 0
    if not left_pre:
        return 1
    if not right_pre:
        return -1
    for left_id, right_id in zip(left_pre, right_pre):
        order = _identifier_order(left_id, right_id)
        if order:
            return order
    return (len(left_pre) > len(right_pre)) - (len(left_pre) < len(right_pre))


def _wild(text):
    return text is None or text in ("x", "X", "*")


def _parts(match):
    major = match.group("major")
    minor = match.group("minor")
    patch = match.group("patch")
    if _wild(major):
        return None, None, None, ()
    if _wild(minor):
        return _number(major), None, None, ()
    if _wild(patch):
        return _number(major), _number(minor), None, ()
    return _number(major), _number(minor), _number(patch), _prerelease(match.group("pre"))


def _low(major, minor, patch, pre=LOWEST_PRERELEASE):
    return (">=", (major, minor, patch, pre))


def _high(major, minor, patch):
    return ("<", (major, minor, patch, LOWEST_PRERELEASE))


def _expand(operator, major, minor, patch, pre):
    """Turn one comparator with possibly partial parts into plain comparators."""
    if major is None:
        if operator in ("", "=", ">=", "<=", "~", "~>", "^"):
            return []
        _fail()
    if operator in ("", "="):
        if minor is None:
            return [_low(major, 0, 0), _high(major + 1, 0, 0)]
        if patch is None:
            return [_low(major, minor, 0), _high(major, minor + 1, 0)]
        return [("=", (major, minor, patch, pre))]
    if operator == ">":
        if minor is None:
            return [_low(major + 1, 0, 0)]
        if patch is None:
            return [_low(major, minor + 1, 0)]
        return [(">", (major, minor, patch, pre))]
    if operator == ">=":
        if minor is None:
            return [_low(major, 0, 0)]
        if patch is None:
            return [_low(major, minor, 0)]
        return [_low(major, minor, patch, pre)]
    if operator == "<":
        if minor is None:
            return [_high(major, 0, 0)]
        if patch is None:
            return [_high(major, minor, 0)]
        return [("<", (major, minor, patch, pre))]
    if operator == "<=":
        if minor is None:
            return [_high(major + 1, 0, 0)]
        if patch is None:
            return [_high(major, minor + 1, 0)]
        return [("<=", (major, minor, patch, pre))]
    if operator in ("~", "~>"):
        if minor is None:
            return [_low(major, 0, 0), _high(major + 1, 0, 0)]
        if patch is None:
            return [_low(major, minor, 0), _high(major, minor + 1, 0)]
        return [_low(major, minor, patch, pre), _high(major, minor + 1, 0)]
    if operator == "^":
        if minor is None:
            return [_low(major, 0, 0), _high(major + 1, 0, 0)]
        if patch is None:
            if major > 0:
                return [_low(major, minor, 0), _high(major + 1, 0, 0)]
            if minor > 0:
                return [_low(0, minor, 0), _high(0, minor + 1, 0)]
            return [_low(0, 0, 0), _high(0, 1, 0)]
        if major > 0:
            return [_low(major, minor, patch, pre), _high(major + 1, 0, 0)]
        if minor > 0:
            return [_low(0, minor, patch, pre), _high(0, minor + 1, 0)]
        return [_low(0, 0, patch, pre), _high(0, 0, patch + 1)]
    _fail()


def _comparator(token):
    match = _COMPARATOR_RE.fullmatch(token)
    if match is None:
        _fail()
    operator = match.group("op") or ""
    major, minor, patch, pre = _parts(match)
    return _expand(operator, major, minor, patch, pre)


def _hyphen(low, high):
    low_match = _COMPARATOR_RE.fullmatch(low)
    high_match = _COMPARATOR_RE.fullmatch(high)
    if (low_match is None or high_match is None or low_match.group("op")
            or high_match.group("op")):
        _fail()
    lower = _expand(">=", *_parts(low_match))
    upper = _expand("<=", *_parts(high_match))
    return lower + upper


def _parse_set(text):
    hyphen = _HYPHEN_RE.fullmatch(text)
    if hyphen is not None:
        return _hyphen(hyphen.group("low"), hyphen.group("high"))
    normalized = _OPERATOR_SPACE_RE.sub(r"\1", text)
    tokens = normalized.split()
    if len(tokens) > MAX_COMPARATORS:
        _fail()
    comparators = []
    for token in tokens:
        comparators.extend(_comparator(token))
    return comparators


def parse_range(text):
    """Return the union of comparator sets for a range string."""
    if type(text) is not str or len(text) > MAX_RANGE_CHARS:
        _fail()
    if any(ord(character) < 0x20 or ord(character) > 0x7e for character in text):
        _fail()
    sets = text.split("||")
    if len(sets) > MAX_SETS:
        _fail()
    return [_parse_set(item.strip()) for item in sets]


def _matches(version, operator, bound):
    order = compare_versions(version, bound)
    if operator == "=":
        return order == 0
    if operator == "<":
        return order < 0
    if operator == "<=":
        return order <= 0
    if operator == ">":
        return order > 0
    if operator == ">=":
        return order >= 0
    _fail()


def satisfies(version_text, range_text):
    """Return True when the exact version satisfies the range; raise SemverError if unparsable."""
    version = parse_version(version_text)
    for comparators in parse_range(range_text):
        if all(_matches(version, operator, bound) for operator, bound in comparators):
            return True
    return False
