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
)
from .versioning import version_in_range


def ingest_osv(
    payload: dict[str, Any],
    inventory_payload: dict[str, Any],
    dependencies: tuple[tuple[str, str], ...] = (),
) -> IngestionResult:
    issues: list[IngestionIssue] = []
    vulnerabilities: list[VulnerabilityRecord] = []
    inventory = _parse_inventory(inventory_payload, issues)
    raw_records = payload.get("vulns") if isinstance(payload, dict) else None
    if not isinstance(raw_records, list):
        raise ValueError("OSV payload must contain a vulns array")
    seen_records: dict[tuple[str, str, str], VulnerabilityRecord] = {}
    for index, raw in enumerate(raw_records):
        record_id = raw.get("id") if isinstance(raw, dict) else None
        if not isinstance(record_id, str) or not record_id.strip():
            issues.append(IngestionIssue("malformed_record", f"Record {index} has no valid id", str(index), "error"))
            continue
        parsed = _parse_record(raw, record_id, issues)
        if parsed is None:
            continue
        key = (parsed.vulnerability_id, parsed.package.ecosystem, parsed.package.name)
        previous = seen_records.get(key)
        if previous is not None:
            if previous.fixed_versions != parsed.fixed_versions:
                issues.append(IngestionIssue("conflicting_fixed_versions", f"Conflicting fixes for {record_id}", record_id, "error"))
            else:
                issues.append(IngestionIssue("duplicate_record", f"Duplicate vulnerability record {record_id}", record_id))
            continue
        seen_records[key] = parsed
        vulnerabilities.append(parsed)
    candidates: list[RemediationCandidate] = []
    inventory_by_package: dict[str, list[InstalledPackage]] = defaultdict(list)
    for installed in inventory:
        inventory_by_package[installed.package.key].append(installed)
    for vulnerability in vulnerabilities:
        installed_items = inventory_by_package.get(vulnerability.package.key, [])
        if not installed_items:
            issues.append(IngestionIssue("package_not_in_inventory", f"{vulnerability.package.key} is not installed", vulnerability.source_record_id))
            continue
        for installed in installed_items:
            applicability, applicability_issues = _applicability(vulnerability, installed)
            if applicability == "unaffected":
                continue
            fixed_version = vulnerability.fixed_versions[0] if len(vulnerability.fixed_versions) == 1 else None
            unresolved = list(applicability_issues)
            if not vulnerability.fixed_versions:
                unresolved.append("missing_fixed_version")
                issues.append(IngestionIssue("missing_fixed_version", f"No fixed version for {vulnerability.vulnerability_id}", vulnerability.source_record_id))
            if len(vulnerability.fixed_versions) > 1:
                unresolved.append("conflicting_fixed_versions")
            candidates.append(RemediationCandidate(
                candidate_id=f"{installed.asset_id}:{vulnerability.vulnerability_id}",
                asset_id=installed.asset_id,
                package=vulnerability.package,
                vulnerability_id=vulnerability.vulnerability_id,
                aliases=vulnerability.aliases,
                recommended_fixed_version=fixed_version,
                source=vulnerability.source,
                applicability=applicability,
                unresolved_issues=tuple(sorted(set(unresolved))),
            ))
    if not dependencies and inventory:
        issues.append(IngestionIssue("incomplete_dependency_metadata", "No package dependency metadata was supplied"))
    package_ids = tuple(sorted({installed.package.key for installed in inventory}))
    return IngestionResult(tuple(vulnerabilities), inventory, tuple(candidates), tuple(issues), Dataset(package_ids, dependencies, ()))


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
    return IngestionResult(result.vulnerabilities, result.inventory, result.candidates, tuple(issues), approved)


def _parse_inventory(payload: dict[str, Any], issues: list[IngestionIssue]) -> tuple[InstalledPackage, ...]:
    records = payload.get("packages") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise ValueError("Inventory payload must contain a packages array")
    output: list[InstalledPackage] = []
    seen: set[tuple[str, str, str, str | None]] = set()
    for index, raw in enumerate(records):
        if not isinstance(raw, dict) or not isinstance(raw.get("asset_id"), str):
            issues.append(IngestionIssue("invalid_inventory", f"Inventory entry {index} is malformed", str(index), "error"))
            continue
        ecosystem, name = raw.get("ecosystem"), raw.get("name")
        if not isinstance(ecosystem, str) or not isinstance(name, str) or not ecosystem or not name:
            issues.append(IngestionIssue("invalid_inventory", f"Inventory entry {raw['asset_id']} lacks package identity", raw["asset_id"], "error"))
            continue
        version = raw.get("version")
        if version is not None and not isinstance(version, str):
            issues.append(IngestionIssue("invalid_inventory", f"Invalid version for {raw['asset_id']}", raw["asset_id"], "error"))
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


def _parse_record(raw: dict[str, Any], record_id: str, issues: list[IngestionIssue]) -> VulnerabilityRecord | None:
    affected = raw.get("affected")
    if not isinstance(affected, list) or not affected:
        issues.append(IngestionIssue("malformed_record", f"{record_id} has no affected package entries", record_id, "error"))
        return None
    package = affected[0].get("package") if isinstance(affected[0], dict) else None
    if not isinstance(package, dict) or not isinstance(package.get("ecosystem"), str) or not isinstance(package.get("name"), str):
        issues.append(IngestionIssue("malformed_record", f"{record_id} has invalid package identity", record_id, "error"))
        return None
    identity = PackageIdentity(package["ecosystem"], package["name"])
    ranges = []
    fixed_versions: set[str] = set()
    for item in affected:
        if not isinstance(item, dict):
            issues.append(IngestionIssue("malformed_record", f"{record_id} has malformed affected entry", record_id, "error"))
            continue
        raw_ranges = item.get("ranges", [])
        for raw_range in raw_ranges:
            if not isinstance(raw_range, dict):
                continue
            events = raw_range.get("events", [])
            if isinstance(events, list):
                range_type = raw_range.get("type", "")
                ranges.append((range_type, tuple(event for event in events if isinstance(event, dict))))
                if range_type != "ECOSYSTEM":
                    issues.append(IngestionIssue("unsupported_version_range", f"{record_id} uses unsupported range type {range_type}", record_id))
                for event in events:
                    if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                        fixed_versions.add(event["fixed"])
    if not ranges:
        issues.append(IngestionIssue("unsupported_version_range", f"{record_id} has no usable ranges", record_id))
    severities = tuple(item for item in raw.get("severity", []) if isinstance(item, dict))
    aliases = tuple(alias for alias in raw.get("aliases", []) if isinstance(alias, str))
    return VulnerabilityRecord(
        record_id, aliases, "osv", record_id, identity,
        tuple(AffectedRange(identity.ecosystem, range_type, tuple(dict(event) for event in events)) for range_type, events in ranges),
        tuple(sorted(fixed_versions)), severities, raw,
    )


def _applicability(vulnerability: VulnerabilityRecord, installed: InstalledPackage) -> tuple[str, list[str]]:
    checks = []
    issues: list[str] = []
    for affected_range in vulnerability.affected_ranges:
        check = version_in_range(installed.package.ecosystem, installed.version, {"type": affected_range.range_type, "events": list(affected_range.events)})
        if check.value is True:
            checks.append(True)
        elif check.value is False:
            checks.append(False)
        else:
            issues.append(check.issue or "unknown_applicability")
    if True in checks:
        return "affected", issues
    if checks and all(value is False for value in checks) and not issues:
        return "unaffected", []
    return "unknown", sorted(set(issues or ["unknown_applicability"]))
