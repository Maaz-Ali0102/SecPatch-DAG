from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from ..models import Dataset, PatchAction

Applicability = Literal["affected", "unaffected", "unknown"]


@dataclass(frozen=True)
class PackageIdentity:
    ecosystem: str
    name: str

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}"


_PYPI_NAME_SEPARATORS = re.compile(r"[-_.]+")


def match_key(package: PackageIdentity) -> tuple[str, str]:
    """Identity used to match OSV packages against installed packages.

    Ecosystem names are compared case-insensitively. PyPI project names are
    normalized as defined by PEP 503 (``Django`` == ``django``,
    ``PyYAML`` == ``pyyaml``, ``zope_interface`` == ``zope.interface``).
    """
    ecosystem = package.ecosystem.strip().lower()
    name = package.name.strip()
    if ecosystem == "pypi":
        name = _PYPI_NAME_SEPARATORS.sub("-", name).lower()
    return ecosystem, name


@dataclass(frozen=True)
class InstalledPackage:
    asset_id: str
    package: PackageIdentity
    version: str | None


@dataclass(frozen=True)
class AffectedRange:
    ecosystem: str
    range_type: str
    events: tuple[dict[str, str], ...]


@dataclass(frozen=True)
class VulnerabilityRecord:
    vulnerability_id: str
    aliases: tuple[str, ...]
    source: str
    source_record_id: str
    package: PackageIdentity
    affected_ranges: tuple[AffectedRange, ...]
    fixed_versions: tuple[str, ...]
    severities: tuple[dict[str, str], ...]
    raw: dict[str, Any]


@dataclass(frozen=True)
class RemediationCandidate:
    candidate_id: str
    asset_id: str
    package: PackageIdentity
    vulnerability_id: str
    aliases: tuple[str, ...]
    recommended_fixed_version: str | None
    source: str
    applicability: Applicability
    unresolved_issues: tuple[str, ...] = ()
    installed_version: str | None = None


@dataclass(frozen=True)
class IngestionIssue:
    code: str
    message: str
    source_record_id: str | None = None
    severity: Literal["warning", "error"] = "warning"


@dataclass(frozen=True)
class IngestionResult:
    vulnerabilities: tuple[VulnerabilityRecord, ...]
    inventory: tuple[InstalledPackage, ...]
    candidates: tuple[RemediationCandidate, ...]
    issues: tuple[IngestionIssue, ...]
    approved_dataset: Dataset | None = None

    package_checks: tuple[dict[str, Any], ...] = ()

    @property
    def supported_record_count(self) -> int:
        return len(self.vulnerabilities)

    def issue_dicts(self) -> list[dict[str, str | None]]:
        return [
            {
                "code": issue.code,
                "message": issue.message,
                "source_record_id": issue.source_record_id,
                "severity": issue.severity,
            }
            for issue in self.issues
        ]


def candidate_to_action(candidate: RemediationCandidate, estimate: dict[str, Any]) -> PatchAction:
    required = ("duration_minutes", "benefit")
    if any(key not in estimate for key in required):
        raise ValueError(f"Planning estimate for {candidate.candidate_id} must include duration_minutes and benefit")
    action_id = str(estimate.get("id", candidate.candidate_id))
    priority = estimate.get("priority", estimate["benefit"])
    prerequisites = estimate.get("prerequisites", [])
    return PatchAction(
        id=action_id,
        package_id=candidate.package.key,
        asset_id=candidate.asset_id,
        duration_minutes=estimate["duration_minutes"],
        benefit=estimate["benefit"],
        priority=priority,
        prerequisites=tuple(prerequisites),
        risk=str(estimate.get("risk", "medium")),
        mandatory=bool(estimate.get("mandatory", False)),
    )
