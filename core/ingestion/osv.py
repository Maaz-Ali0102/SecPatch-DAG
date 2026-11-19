from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..models import Dataset
from .models import (
    AffectedRange,
    IngestionIssue,
    IngestionResult,
    InstalledPackage,
    PackageIdentity,
    RemediationCandidate,
    VulnerabilityRecord,
    candidate_to_action,
    match_key,
)
from .limits import (
    MAX_ASSET_IDENTIFIER,
    MAX_ECOSYSTEM,
    MAX_INVENTORY_ROWS,
    MAX_OSV_RECORDS,
    MAX_PACKAGE_NAME,
    MAX_VERSION,
    MAX_VULNERABILITY_ID,
    text_problem,
)
from .versioning import compare_versions, version_in_range


def ingest_osv(
    payload: dict[str, Any],
    inventory_payload: dict[str, Any],
    dependencies: tuple[tuple[str, str], ...] = (),
) -> IngestionResult:
    issues: list[IngestionIssue] = []
    vulnerabilities: list[VulnerabilityRecord] = []
    inventory = _parse_inventory(inventory_payload, issues)
    raw_records = payload.get("vulns") if isinstance(payload, dict) else None
    if isinstance(raw_records, list) and len(raw_records) > MAX_OSV_RECORDS:
        raise ValueError(f"OSV payload has {len(raw_records)} records; at most {MAX_OSV_RECORDS} are accepted per import")
    if not isinstance(raw_records, list):
        raise ValueError("OSV payload must contain a vulns array")
    seen_records: dict[tuple[str, str, str], VulnerabilityRecord] = {}
    for index, raw in enumerate(raw_records):
        record_id = raw.get("id") if isinstance(raw, dict) else None
        if text_problem(record_id, MAX_VULNERABILITY_ID):
            issues.append(IngestionIssue("malformed_record", f"Record {index} id {text_problem(record_id, MAX_VULNERABILITY_ID)}", str(index), "error"))
            continue
        for parsed in _parse_record(raw, record_id, issues):
            key = (parsed.vulnerability_id, *match_key(parsed.package))
            previous = seen_records.get(key)
            if previous is not None:
                if previous.fixed_versions != parsed.fixed_versions:
                    issues.append(IngestionIssue("conflicting_fixed_versions", f"Conflicting fixes for {record_id}", record_id, "error"))
                else:
                    issues.append(IngestionIssue("duplicate_record", f"Duplicate vulnerability record {record_id}", record_id))
                continue
            seen_records[key] = parsed
            vulnerabilities.append(parsed)
    candidates_by_id: dict[str, RemediationCandidate] = {}
    inventory_by_package: dict[tuple[str, str], list[InstalledPackage]] = defaultdict(list)
    for installed in inventory:
        inventory_by_package[match_key(installed.package)].append(installed)
    checks = {item: {"asset": item.asset_id, "package": item.package.name,
                     "ecosystem": item.package.ecosystem, "version": item.version,
                     "status": "no_match", "fixes": []} for item in inventory}
    rank = {"no_match": 0, "unaffected": 1, "unknown": 2, "affected": 3}
    for vulnerability in vulnerabilities:
        installed_items = inventory_by_package.get(match_key(vulnerability.package), [])
        if not installed_items:
            issues.append(IngestionIssue("package_not_in_inventory", f"{vulnerability.package.key} does not appear in the imported inventory.", vulnerability.source_record_id))
            continue
        for installed in installed_items:
            applicability, applicability_issues, fixed_version = _applicability(vulnerability, installed)
            check = checks[installed]
            if rank[applicability] > rank[check["status"]]:
                check["status"] = applicability
            if applicability == "affected" and fixed_version and fixed_version not in check["fixes"]:
                check["fixes"].append(fixed_version)
            if applicability == "unaffected":
                continue
            unresolved = list(applicability_issues)
            if not vulnerability.fixed_versions or (applicability == "affected" and fixed_version is None):
                unresolved.append("missing_fixed_version")
                issues.append(IngestionIssue("missing_fixed_version", f"No fixed version for {vulnerability.vulnerability_id} at {installed.asset_id}", vulnerability.source_record_id))
            candidate = RemediationCandidate(
                candidate_id=f"{installed.asset_id}:{vulnerability.vulnerability_id}",
                asset_id=installed.asset_id,
                # Use the installed identity so persistence finds the stored
                # package row even when OSV spells the name differently.
                package=installed.package,
                vulnerability_id=vulnerability.vulnerability_id,
                aliases=vulnerability.aliases,
                recommended_fixed_version=fixed_version,
                source=vulnerability.source,
                applicability=applicability,
                unresolved_issues=tuple(sorted(set(unresolved))),
                installed_version=installed.version,
            )
            previous = candidates_by_id.get(candidate.candidate_id)
            candidates_by_id[candidate.candidate_id] = candidate if previous is None else _merge_candidates(previous, candidate, issues)
    candidates = list(candidates_by_id.values())
    package_ids = tuple(sorted({installed.package.key for installed in inventory}))
    return IngestionResult(tuple(vulnerabilities), inventory, tuple(candidates), tuple(issues), Dataset(package_ids, dependencies, ()), tuple(checks.values()))


def approve_candidates(
    result: IngestionResult,
    estimates: dict[str, dict[str, Any]],
) -> IngestionResult:
    actions = []
    issues = list(result.issues)
    for candidate in result.candidates:
        estimate = estimates.get(candidate.candidate_id)
        if candidate.applicability != "affected" or candidate.recommended_fixed_version is None or candidate.unresolved_issues or estimate is None:
            if estimate is not None and candidate.applicability == "affected":
                issues.append(IngestionIssue("candidate_not_approved", f"{candidate.candidate_id} is not safe to approve", candidate.vulnerability_id))
            continue
        try:
            actions.append(candidate_to_action(candidate, estimate))
        except (TypeError, ValueError, KeyError) as error:
            issues.append(IngestionIssue("invalid_planning_estimate", str(error), candidate.vulnerability_id, "error"))
    package_ids = tuple(sorted({installed.package.key for installed in result.inventory}))
    try:
        approved = Dataset(package_ids, result.approved_dataset.dependencies if result.approved_dataset else (), tuple(actions))
        Dataset.from_dict({
            "packages": [{"id": package_id} for package_id in approved.packages],
            "dependencies": [{"from": source, "to": target} for source, target in approved.dependencies],
            "actions": [
                {**action.__dict__, "prerequisites": list(action.prerequisites)}
                for action in approved.actions
            ],
        })
    except ValueError as error:
        issues.append(IngestionIssue("invalid_approved_dataset", str(error), severity="error"))
        approved = None
    return IngestionResult(result.vulnerabilities, result.inventory, result.candidates, tuple(issues), approved, result.package_checks)


def _parse_inventory(payload: dict[str, Any], issues: list[IngestionIssue]) -> tuple[InstalledPackage, ...]:
    records = payload.get("packages") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise ValueError("Inventory payload must contain a packages array")
    if len(records) > MAX_INVENTORY_ROWS:
        raise ValueError(f"Inventory has {len(records)} rows; at most {MAX_INVENTORY_ROWS} are accepted per import")
    output: list[InstalledPackage] = []
    seen: set[tuple[str, str, str, str | None]] = set()
    for index, raw in enumerate(records):
        if not isinstance(raw, dict) or text_problem(raw.get("asset_id"), MAX_ASSET_IDENTIFIER):
            issues.append(IngestionIssue("invalid_inventory", f"Inventory entry {index}: asset_id is missing or invalid", str(index), "error"))
            continue
        ecosystem, name = raw.get("ecosystem"), raw.get("name")
        if text_problem(ecosystem, MAX_ECOSYSTEM) or text_problem(name, MAX_PACKAGE_NAME):
            issues.append(IngestionIssue("invalid_inventory", f"Inventory entry {index} ({raw['asset_id']}): package ecosystem or name is missing, too long or invalid", raw["asset_id"], "error"))
            continue
        version = raw.get("version")
        if version is not None and text_problem(version, MAX_VERSION):
            # Kept as an unknown version (REVIEW), never silently dropped.
            issues.append(IngestionIssue("invalid_inventory", f"Inventory entry {index} ({raw['asset_id']}): version {text_problem(version, MAX_VERSION)}", raw["asset_id"], "error"))
            version = None
        identity = (raw["asset_id"], ecosystem, name, version)
        if identity in seen:
            issues.append(
                IngestionIssue(
                    "duplicate_inventory",
                    f"Duplicate inventory entry for {raw['asset_id']} {ecosystem}:{name} {version or '<unknown>'}",
                    raw["asset_id"],
                    "error",
                )
            )
            continue
        seen.add(identity)
        output.append(InstalledPackage(raw["asset_id"], PackageIdentity(ecosystem, name), version))
    return tuple(output)


def _parse_record(raw: dict[str, Any], record_id: str, issues: list[IngestionIssue]) -> list[VulnerabilityRecord]:
    """Split one OSV record into one VulnerabilityRecord per affected package.

    OSV records may list several packages (and several entries for the same
    package); every package is kept with only its own ranges.
    """
    affected = raw.get("affected")
    if not isinstance(affected, list) or not affected:
        issues.append(IngestionIssue("malformed_record", f"{record_id} has no affected package entries", record_id, "error"))
        return []
    grouped: dict[tuple[str, str], tuple[PackageIdentity, list[tuple[str, tuple[dict[str, str], ...]]], set[str]]] = {}
    for item in affected:
        package = item.get("package") if isinstance(item, dict) else None
        if not isinstance(package, dict) or text_problem(package.get("ecosystem"), MAX_ECOSYSTEM) or text_problem(package.get("name"), MAX_PACKAGE_NAME):
            issues.append(IngestionIssue("malformed_record", f"{record_id} has an affected entry with invalid package identity", record_id, "error"))
            continue
        identity = PackageIdentity(package["ecosystem"], package["name"])
        _, ranges, fixed_versions = grouped.setdefault(match_key(identity), (identity, [], set()))
        raw_ranges = item.get("ranges", [])
        if not isinstance(raw_ranges, list):
            raw_ranges = []
        for raw_range in raw_ranges:
            if not isinstance(raw_range, dict):
                continue
            events = raw_range.get("events", [])
            if isinstance(events, list):
                range_type = raw_range.get("type", "")
                valid_events = tuple(event for event in events if isinstance(event, dict))
                if any(text_problem(value, MAX_VERSION) for event in valid_events for key, value in event.items() if key in {"introduced", "fixed", "last_affected"}):
                    # Over-long, blank or control-character versions cannot be
                    # compared or stored: drop the range and say so.
                    issues.append(IngestionIssue("malformed_range_events", f"{record_id} has an invalid version in a range", record_id, "error"))
                    continue
                ranges.append((range_type, valid_events))
                if range_type != "ECOSYSTEM":
                    issues.append(IngestionIssue("unsupported_version_range", f"{record_id} uses unsupported range type {range_type}", record_id))
                elif not any("introduced" in event for event in valid_events):
                    issues.append(IngestionIssue("malformed_range_events", f"{record_id} has a range without an introduced event", record_id, "error"))
                for event in valid_events:
                    if isinstance(event.get("fixed"), str):
                        fixed_versions.add(event["fixed"])
    severities = tuple(item for item in raw.get("severity", []) if isinstance(item, dict)) if isinstance(raw.get("severity", []), list) else ()
    aliases = tuple(alias for alias in raw.get("aliases", []) if not text_problem(alias, MAX_VULNERABILITY_ID)) if isinstance(raw.get("aliases", []), list) else ()
    records = []
    for identity, ranges, fixed_versions in grouped.values():
        if not ranges:
            issues.append(IngestionIssue("unsupported_version_range", f"{record_id} has no usable ranges for {identity.key}", record_id))
        records.append(VulnerabilityRecord(
            record_id, aliases, "osv", record_id, identity,
            tuple(AffectedRange(identity.ecosystem, range_type, tuple(dict(event) for event in events)) for range_type, events in ranges),
            tuple(sorted(fixed_versions)), severities, raw,
        ))
    return records


def _applicability(vulnerability: VulnerabilityRecord, installed: InstalledPackage) -> tuple[str, list[str], str | None]:
    checks = []
    issues: list[str] = []
    fixes: list[str] = []
    for affected_range in vulnerability.affected_ranges:
        check = version_in_range(installed.package.ecosystem, installed.version, {"type": affected_range.range_type, "events": list(affected_range.events)})
        if check.value is True:
            checks.append(True)
            if check.fixed_version is not None:
                fixes.append(check.fixed_version)
        elif check.value is False:
            checks.append(False)
        else:
            issues.append(check.issue or "unknown_applicability")
    if True in checks:
        return "affected", issues, _highest_version(installed.package.ecosystem, fixes)
    if checks and all(value is False for value in checks) and not issues:
        return "unaffected", [], None
    return "unknown", sorted(set(issues or ["unknown_applicability"])), None


def _highest_version(ecosystem: str, versions: list[str]) -> str | None:
    """Return the highest fix so that every affected range is remediated."""
    best: str | None = None
    for value in versions:
        if best is None:
            best = value
            continue
        comparison = compare_versions(ecosystem, value, best)
        if comparison is None:
            return None
        if comparison > 0:
            best = value
    return best


def _merge_candidates(left: RemediationCandidate, right: RemediationCandidate, issues: list[IngestionIssue]) -> RemediationCandidate:
    """Merge candidates for the same asset and vulnerability.

    This happens when one asset has several installed versions of a package.
    Upgrading the package remediates every installation, so one candidate is
    kept with the highest required fix. Unresolved issues are kept
    (conservative) so an unknown installation is never silently approved.
    """
    issues.append(IngestionIssue("multiple_installed_versions", f"{left.candidate_id} matches several installed versions", left.vulnerability_id))
    applicability = "affected" if "affected" in {left.applicability, right.applicability} else "unknown"
    fixes = [value for value in (left.recommended_fixed_version, right.recommended_fixed_version) if value is not None]
    fixed = _highest_version(left.package.ecosystem, fixes)
    unresolved = set(left.unresolved_issues) | set(right.unresolved_issues)
    if applicability == "affected" and fixed is not None:
        unresolved.discard("missing_fixed_version")
    return RemediationCandidate(
        left.candidate_id, left.asset_id, left.package, left.vulnerability_id, left.aliases,
        fixed, left.source, applicability, tuple(sorted(unresolved)), left.installed_version,
    )


def parse_inventory_strict(packages: list[Any]) -> tuple[InstalledPackage, ...]:
    """Validate an inventory for a direct import; reject it if any row is invalid.

    Used by POST /inventory, which is all-or-nothing: either every row is
    stored or none is. Exact duplicate rows are tolerated and stored once.
    """
    issues: list[IngestionIssue] = []
    records = _parse_inventory({"packages": packages}, issues)
    problems = [issue for issue in issues if issue.code == "invalid_inventory"]
    if problems:
        extra = f" (and {len(problems) - 1} more)" if len(problems) > 1 else ""
        raise ValueError(problems[0].message + extra)
    return records
