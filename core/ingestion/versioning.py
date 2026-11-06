from __future__ import annotations

import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class VersionCheck:
    value: bool | None
    issue: str | None = None


_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


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
        return (left_pre > right_pre) - (left_pre < right_pre)
    if normalized in {"pypi", "python"}:
        try:
            left_version, right_version = Version(left), Version(right)
        except InvalidVersion:
            return None
        return (left_version > right_version) - (left_version < right_version)
    return None


def version_in_range(package: str, version: str | None, affected_range: dict[str, object]) -> VersionCheck:
    if version is None:
        return VersionCheck(None, "missing_installed_version")
    range_type = affected_range.get("type")
    if range_type != "ECOSYSTEM":
        return VersionCheck(None, "unsupported_range_type")
    events = affected_range.get("events")
    if not isinstance(events, list):
        return VersionCheck(None, "malformed_range_events")
    state = False
    saw_boundary = False
    for event in events:
        if not isinstance(event, dict):
            return VersionCheck(None, "malformed_range_event")
        if "introduced" in event:
            introduced = str(event["introduced"])
            if introduced == "0":
                state = True
                saw_boundary = True
            else:
                comparison = compare_versions(package, version, introduced)
                if comparison is None:
                    return VersionCheck(None, "unsupported_version")
                state = comparison >= 0
                saw_boundary = True
        if "fixed" in event:
            comparison = compare_versions(package, version, str(event["fixed"]))
            if comparison is None:
                return VersionCheck(None, "unsupported_version")
            state = state and comparison < 0
            saw_boundary = True
        if "last_affected" in event:
            comparison = compare_versions(package, version, str(event["last_affected"]))
            if comparison is None:
                return VersionCheck(None, "unsupported_version")
            state = state and comparison <= 0
            saw_boundary = True
    if not saw_boundary:
        return VersionCheck(None, "empty_range_events")
    return VersionCheck(state)
