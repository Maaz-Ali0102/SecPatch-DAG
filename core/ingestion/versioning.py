from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cmp_to_key

from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class VersionCheck:
    value: bool | None
    issue: str | None = None
    # When ``value`` is True and the range closes with a ``fixed`` event, this
    # is the first fixed version above the installed version (the fix that
    # actually remediates this installation).
    fixed_version: str | None = None


_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _compare_prerelease(left: str, right: str) -> int:
    """SemVer 2.0.0 section 11: compare dot-separated identifiers.

    Numeric identifiers compare numerically and sort before alphanumeric ones;
    a shorter identifier list sorts first when all shared fields are equal.
    """
    left_parts, right_parts = left.split("."), right.split(".")
    for a, b in zip(left_parts, right_parts):
        a_num, b_num = a.isdigit(), b.isdigit()
        if a_num and b_num:
            if int(a) != int(b):
                return (int(a) > int(b)) - (int(a) < int(b))
        elif a_num != b_num:
            return -1 if a_num else 1
        elif a != b:
            return (a > b) - (a < b)
    return (len(left_parts) > len(right_parts)) - (len(left_parts) < len(right_parts))


def compare_versions(ecosystem: str, left: str, right: str) -> int | None:
    """Compare only explicitly supported version schemes.

    npm and ecosystems explicitly marked semver use strict SemVer. PyPI uses
    PEP 440 through ``packaging``. Other ecosystems are intentionally unknown.
    """
    normalized = ecosystem.lower()
    if normalized in {"npm", "semver"}:
        left_match, right_match = _SEMVER.match(left), _SEMVER.match(right)
        if not left_match or not right_match:
            return None
        left_parts = (int(left_match.group(1)), int(left_match.group(2)), int(left_match.group(3)))
        right_parts = (int(right_match.group(1)), int(right_match.group(2)), int(right_match.group(3)))
        if left_parts != right_parts:
            return (left_parts > right_parts) - (left_parts < right_parts)
        left_pre, right_pre = left_match.group(4), right_match.group(4)
        if left_pre == right_pre:
            return 0
        if left_pre is None:
            return 1
        if right_pre is None:
            return -1
        return _compare_prerelease(left_pre, right_pre)
    if normalized in {"pypi", "python"}:
        try:
            left_version, right_version = Version(left), Version(right)
        except InvalidVersion:
            return None
        return (left_version > right_version) - (left_version < right_version)
    return None


_EVENT_KINDS = ("introduced", "fixed", "last_affected")
# Ordering used when two events share a version: an interval that is
# introduced and fixed at the same version is empty, so "fixed" must win.
_KIND_ORDER = {"introduced": 0, "last_affected": 1, "fixed": 2}


def version_in_range(package: str, version: str | None, affected_range: dict[str, object]) -> VersionCheck:
    """Evaluate one OSV ``ECOSYSTEM`` range following the OSV schema algorithm.

    Events are sorted by version and walked in order, so ranges that contain
    several introduced/fixed pairs (for example separate release branches)
    are evaluated correctly. ``package`` is the ecosystem name.
    """
    if version is None:
        return VersionCheck(None, "missing_installed_version")
    range_type = affected_range.get("type")
    if range_type != "ECOSYSTEM":
        return VersionCheck(None, "unsupported_range_type")
    events = affected_range.get("events")
    if not isinstance(events, list):
        return VersionCheck(None, "malformed_range_events")
    parsed: list[tuple[str, str]] = []
    for event in events:
        if not isinstance(event, dict):
            return VersionCheck(None, "malformed_range_event")
        for kind in _EVENT_KINDS:
            if kind in event:
                parsed.append((kind, str(event[kind])))
    if not parsed:
        return VersionCheck(None, "empty_range_events")
    if not any(kind == "introduced" for kind, _ in parsed):
        # The OSV schema requires an "introduced" event; without one the range
        # cannot be evaluated and must not be reported as unaffected.
        return VersionCheck(None, "range_missing_introduced")
    if compare_versions(package, version, version) is None:
        return VersionCheck(None, "unsupported_version")

    def event_compare(left: tuple[str, str], right: tuple[str, str]) -> int:
        lv, rv = left[1], right[1]
        if lv == "0" and left[0] == "introduced":
            result = 0 if (rv == "0" and right[0] == "introduced") else -1
        elif rv == "0" and right[0] == "introduced":
            result = 1
        else:
            comparison = compare_versions(package, lv, rv)
            if comparison is None:
                raise ValueError("unsupported_version")
            result = comparison
        return result or (_KIND_ORDER[left[0]] - _KIND_ORDER[right[0]])

    def installed_vs(event_version: str, kind: str) -> int:
        if kind == "introduced" and event_version == "0":
            return 1
        comparison = compare_versions(package, version, event_version)
        if comparison is None:
            raise ValueError("unsupported_version")
        return comparison

    try:
        ordered = sorted(parsed, key=cmp_to_key(event_compare))
        affected = False
        next_index = len(ordered)
        for index, (kind, event_version) in enumerate(ordered):
            comparison = installed_vs(event_version, kind)
            if kind == "introduced":
                if comparison < 0:
                    next_index = index
                    break
                affected = True
            elif kind == "fixed":
                if comparison < 0:
                    next_index = index
                    break
                affected = False
            else:  # last_affected: version itself is still affected
                if comparison <= 0:
                    next_index = index
                    break
                affected = False
    except ValueError:
        return VersionCheck(None, "unsupported_version")
    fixed_version = None
    if affected and next_index < len(ordered) and ordered[next_index][0] == "fixed":
        fixed_version = ordered[next_index][1]
    return VersionCheck(affected, None, fixed_version)
