from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.ingestion.models import (
    IngestionResult,
    InstalledPackage as CoreInstalledPackage,
    RemediationCandidate as CoreCandidate,
    VulnerabilityRecord as CoreVulnerability,
)
from infrastructure.database.models import (
    AnalysisRun,
    Asset,
    Environment,
    InstalledPackage,
    Package,
    Project,
    RemediationCandidate,
    Vulnerability,
)


class ProjectRepository:
    def create(self, session: Session, name: str, description: str | None = None) -> Project:
        value = Project(name=name, description=description)
        session.add(value)
        session.flush()
        return value

    def get(self, session: Session, project_id: uuid.UUID) -> Project | None:
        return session.get(Project, project_id)

    def list(self, session: Session) -> list[Project]:
        return list(session.scalars(select(Project).order_by(Project.name)))

    def update(self, session: Session, value: Project, name: str | None, description: str | None) -> Project:
        if name is not None:
            value.name = name
        if description is not None:
            value.description = description
        session.flush()
        return value


class EnvironmentRepository:
    def create(self, session: Session, project_id: uuid.UUID, name: str, description: str | None = None) -> Environment:
        value = Environment(project_id=project_id, name=name, description=description)
        session.add(value)
        session.flush()
        return value

    def get(self, session: Session, environment_id: uuid.UUID) -> Environment | None:
        return session.get(Environment, environment_id)

    def list(self, session: Session, project_id: uuid.UUID) -> list[Environment]:
        return list(session.scalars(select(Environment).where(Environment.project_id == project_id).order_by(Environment.name)))

    def update(self, session: Session, value: Environment, name: str | None, description: str | None) -> Environment:
        if name is not None:
            value.name = name
        if description is not None:
            value.description = description
        session.flush()
        return value


class AssetRepository:
    def create(self, session: Session, environment_id: uuid.UUID, name: str, external_identifier: str | None = None, operating_system: str | None = None, metadata: dict[str, Any] | None = None) -> Asset:
        value = Asset(environment_id=environment_id, name=name, external_identifier=external_identifier, operating_system=operating_system, metadata_json=metadata or {})
        session.add(value)
        session.flush()
        return value

    def get(self, session: Session, asset_id: uuid.UUID) -> Asset | None:
        return session.get(Asset, asset_id)

    def list(self, session: Session, environment_id: uuid.UUID) -> list[Asset]:
        return list(session.scalars(select(Asset).where(Asset.environment_id == environment_id).order_by(Asset.name)))

    def update(self, session: Session, asset: Asset, **changes: Any) -> Asset:
        for key in ("name", "external_identifier", "operating_system", "metadata_json"):
            if key in changes and changes[key] is not None:
                setattr(asset, key, changes[key])
        session.flush()
        return asset


class InventoryRepository:
    def import_records(self, session: Session, assets: dict[str, Asset], records: Sequence[CoreInstalledPackage]) -> list[InstalledPackage]:
        stored: list[InstalledPackage] = []
        for record in records:
            asset = assets.get(record.asset_id)
            if asset is None:
                raise ValueError(f"Inventory references unknown asset identifier: {record.asset_id}")
            package = session.scalar(select(Package).where(Package.ecosystem == record.package.ecosystem, Package.package_name == record.package.name))
            if package is None:
                package = Package(ecosystem=record.package.ecosystem, package_name=record.package.name)
                session.add(package)
                session.flush()
            version_key = record.version or "<unknown>"
            existing = session.scalar(select(InstalledPackage).where(
                InstalledPackage.asset_id == asset.id,
                InstalledPackage.package_id == package.id,
                InstalledPackage.version_key == version_key,
            ))
            if existing is None:
                existing = InstalledPackage(
                    asset_id=asset.id,
                    package_id=package.id,
                    installed_version=record.version,
                    version_key=version_key,
                    inventory_source="offline",
                )
                session.add(existing)
                session.flush()
            stored.append(existing)
        return stored

    def list_for_asset(self, session: Session, asset_id: uuid.UUID) -> list[InstalledPackage]:
        return list(session.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == asset_id).order_by(InstalledPackage.package_id, InstalledPackage.version_key)))


class VulnerabilityRepository:
    def upsert_ingestion(self, session: Session, result: IngestionResult, asset_lookup: dict[str, Asset]) -> list[RemediationCandidate]:
        vulnerability_rows: dict[str, Vulnerability] = {}
        for record in result.vulnerabilities:
            row = session.scalar(select(Vulnerability).where(Vulnerability.source == record.source, Vulnerability.source_id == record.source_record_id))
            if row is None:
                row = Vulnerability(
                    source=record.source,
                    source_id=record.source_record_id,
                    aliases=list(record.aliases),
                    affected_ranges=[{"ecosystem": value.ecosystem, "range_type": value.range_type, "events": list(value.events)} for value in record.affected_ranges],
                    fixed_versions=list(record.fixed_versions),
                    severity_metadata={"severities": list(record.severities)},
                    raw_source_metadata=record.raw,
                )
                session.add(row)
                session.flush()
            vulnerability_rows[record.vulnerability_id] = row
        candidates: list[RemediationCandidate] = []
        for candidate in result.candidates:
            vulnerability = vulnerability_rows.get(candidate.vulnerability_id) or session.scalar(select(Vulnerability).where(Vulnerability.source_id == candidate.vulnerability_id))
            asset = asset_lookup.get(candidate.asset_id)
            if vulnerability is None or asset is None:
                continue
            package = session.scalar(select(Package).where(Package.ecosystem == candidate.package.ecosystem, Package.package_name == candidate.package.name))
            if package is None:
                continue
            installed = session.scalar(select(InstalledPackage).where(InstalledPackage.asset_id == asset.id, InstalledPackage.package_id == package.id))
            if installed is None:
                continue
            row = session.scalar(select(RemediationCandidate).where(
                RemediationCandidate.vulnerability_id == vulnerability.id,
                RemediationCandidate.installed_package_id == installed.id,
                RemediationCandidate.fixed_version == candidate.recommended_fixed_version,
            ))
            if row is None:
                row = RemediationCandidate(
                    vulnerability_id=vulnerability.id,
                    installed_package_id=installed.id,
                    fixed_version=candidate.recommended_fixed_version,
                    applicability=candidate.applicability,
                    status="candidate",
                    provenance={"source": candidate.source, "aliases": list(candidate.aliases)},
                    unresolved_issues=list(candidate.unresolved_issues),
                )
                session.add(row)
                session.flush()
            candidates.append(row)
        return candidates


class AnalysisRunRepository:
    def get(self, session: Session, run_id: uuid.UUID) -> AnalysisRun | None:
        return session.get(AnalysisRun, run_id)

    def list(self, session: Session, project_id: uuid.UUID, environment_id: uuid.UUID | None = None) -> list[AnalysisRun]:
        query = select(AnalysisRun).where(AnalysisRun.project_id == project_id)
        if environment_id is not None:
            query = query.where(AnalysisRun.environment_id == environment_id)
        return list(session.scalars(query.order_by(AnalysisRun.created_at.desc())))
