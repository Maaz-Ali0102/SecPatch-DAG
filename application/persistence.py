from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.engine import run_analysis
from core.ingestion.models import PackageIdentity, RemediationCandidate as CoreCandidate, candidate_to_action
from core.models import Dataset
from infrastructure.database.models import (
    AnalysisRun,
    Asset,
    Environment,
    InstalledPackage,
    Package,
    PackageDependency,
    PatchAction as DbPatchAction,
    PatchActionPrerequisite,
    PatchPlan,
    PatchPlanAction,
    Project,
    RemediationCandidate,
    Vulnerability,
)
from infrastructure.database.repositories import (
    AnalysisRunRepository,
    AssetRepository,
    EnvironmentRepository,
    InventoryRepository,
    ProjectRepository,
    VulnerabilityRepository,
)


projects = ProjectRepository()
environments = EnvironmentRepository()
assets = AssetRepository()
inventory = InventoryRepository()
vulnerabilities = VulnerabilityRepository()
analysis_runs = AnalysisRunRepository()


def create_project(session: Session, name: str, description: str | None = None) -> Project:
    value = projects.create(session, name, description)
    session.commit()
    return value


def create_environment(session: Session, project_id: uuid.UUID, name: str, description: str | None = None) -> Environment:
    if projects.get(session, project_id) is None:
        raise ValueError("Project not found")
    value = environments.create(session, project_id, name, description)
    session.commit()
    return value


def update_project(session: Session, project_id: uuid.UUID, name: str | None, description: str | None) -> Project:
    value = projects.get(session, project_id)
    if value is None:
        raise ValueError("Project not found")
    projects.update(session, value, name, description)
    session.commit()
    return value


def update_environment(session: Session, environment_id: uuid.UUID, name: str | None, description: str | None) -> Environment:
    value = environments.get(session, environment_id)
    if value is None:
        raise ValueError("Environment not found")
    environments.update(session, value, name, description)
    session.commit()
    return value


def register_asset(session: Session, environment_id: uuid.UUID, name: str, external_identifier: str | None = None, operating_system: str | None = None, metadata: dict[str, Any] | None = None) -> Asset:
    if environments.get(session, environment_id) is None:
        raise ValueError("Environment not found")
    value = assets.create(session, environment_id, name, external_identifier, operating_system, metadata)
    session.commit()
    return value


def update_asset(session: Session, asset_id: uuid.UUID, changes: dict[str, Any]) -> Asset:
    value = assets.get(session, asset_id)
    if value is None:
        raise ValueError("Asset not found")
    assets.update(session, value, **changes)
    session.commit()
    return value


def import_inventory(session: Session, environment_id: uuid.UUID, records: list[Any], asset_lookup: dict[str, Asset]) -> list[InstalledPackage]:
    if environments.get(session, environment_id) is None:
        raise ValueError("Environment not found")
    values = inventory.import_records(session, asset_lookup, records)
    session.commit()
    return values


def persist_ingestion(session: Session, result: Any, asset_lookup: dict[str, Asset]) -> list[RemediationCandidate]:
    values = vulnerabilities.upsert_ingestion(session, result, asset_lookup)
    session.commit()
    return values


def _result_input_snapshot(dataset: Dataset, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "packages": list(dataset.packages),
        "dependencies": [{"from": source, "to": target} for source, target in dataset.dependencies],
        "actions": [{**action.__dict__, "prerequisites": list(action.prerequisites)} for action in dataset.actions],
        "input_fingerprint": result["input_fingerprint"],
    }


def persist_analysis(
    session: Session,
    result: dict[str, Any],
    dataset: Dataset,
    project_id: uuid.UUID,
    environment_id: uuid.UUID,
) -> AnalysisRun:
    """Persist the complete immutable analysis result and normalized patch plan."""
    optimization = result["optimization"]
    validation = result.get("validation", {"valid": True, "violations": []})
    schedule = result.get("schedule", {"total_duration_minutes": 0, "entries": []})
    run = AnalysisRun(
        id=uuid.UUID(result["run_id"]),
        project_id=project_id,
        environment_id=environment_id,
        status=result["status"],
        optimization_method=optimization["method"],
        solver_status=optimization["solver_status"],
        objective_value=optimization["objective_value"],
        optimality_proven=optimization["optimality_proven"],
        maintenance_window_minutes=result["configuration"]["window_minutes"],
        input_snapshot=_result_input_snapshot(dataset, result),
        result_summary=result,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    session.add(run)
    session.flush()
    db_actions: dict[str, DbPatchAction] = {}
    package_rows: dict[str, Package] = {}
    for action in dataset.actions:
        ecosystem, _, name = action.package_id.partition(":")
        package = session.scalar(select(Package).where(Package.ecosystem == ecosystem, Package.package_name == name))
        if package is None:
            package = Package(ecosystem=ecosystem, package_name=name)
            session.add(package)
            session.flush()
        package_rows[action.package_id] = package
        db_action = DbPatchAction(
            id=uuid.uuid5(uuid.NAMESPACE_URL, f"{run.id}:{action.id}"),
            analysis_run_id=run.id,
            package_id=package.id,
            action_key=action.id,
            duration_minutes=action.duration_minutes,
            benefit=action.benefit,
            priority=action.priority,
            mandatory=action.mandatory,
            risk=action.risk,
        )
        session.add(db_action)
        db_actions[action.id] = db_action
    session.flush()
    for action in dataset.actions:
        for prerequisite in action.prerequisites:
            session.add(PatchActionPrerequisite(analysis_run_id=run.id, action_id=db_actions[action.id].id, prerequisite_action_id=db_actions[prerequisite].id))
    plan = PatchPlan(
        analysis_run_id=run.id,
        validation_valid=validation["valid"],
        validation_violations=validation["violations"],
        schedule_summary=schedule,
        optimization_metadata=result["optimization"],
    )
    session.add(plan)
    session.flush()
    for order, entry in enumerate(schedule["entries"], start=1):
        action = db_actions.get(entry["action_id"])
        if action is not None:
            session.add(PatchPlanAction(
                patch_plan_id=plan.id,
                analysis_run_id=run.id,
                patch_action_id=action.id,
                execution_order=order,
                start_offset_minutes=entry["start_minute"],
                finish_offset_minutes=entry["finish_minute"],
            ))
    session.commit()
    session.refresh(run)
    return run


def get_analysis(session: Session, run_id: uuid.UUID) -> dict[str, Any]:
    run = analysis_runs.get(session, run_id)
    if run is None:
        raise ValueError("Analysis run not found")
    plan = session.scalar(select(PatchPlan).where(PatchPlan.analysis_run_id == run.id))
    plan_actions = []
    if plan is not None:
        rows = session.scalars(select(PatchPlanAction).where(PatchPlanAction.patch_plan_id == plan.id).order_by(PatchPlanAction.execution_order))
        plan_actions = [
            {"patch_action_id": str(row.patch_action_id), "execution_order": row.execution_order, "start_offset_minutes": row.start_offset_minutes, "finish_offset_minutes": row.finish_offset_minutes}
            for row in rows
        ]
    result = dict(run.result_summary)
    result["persistence"] = {
        "analysis_run_id": str(run.id),
        "patch_plan_id": str(plan.id) if plan else None,
        "patch_plan_actions": plan_actions,
        "input_snapshot": run.input_snapshot,
    }
    return result


def list_analyses(session: Session, project_id: uuid.UUID, environment_id: uuid.UUID | None = None) -> list[AnalysisRun]:
    return analysis_runs.list(session, project_id, environment_id)


def execute_persisted_analysis(session: Session, project_id: uuid.UUID, environment_id: uuid.UUID, window_minutes: int, method: str, estimates: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Build planning inputs only from persisted inventory and explicit estimates."""
    environment = environments.get(session, environment_id)
    if environment is None or environment.project_id != project_id:
        raise ValueError("Environment does not belong to project")
    installed = list(session.scalars(select(InstalledPackage).join(Asset).where(Asset.environment_id == environment_id)))
    package_rows = {row.package_id: session.get(Package, row.package_id) for row in installed}
    package_ids = tuple(sorted(f"{row.ecosystem}:{row.package_name}" for row in package_rows.values() if row is not None))
    dependencies = tuple(
        (f"{dependent.ecosystem}:{dependent.package_name}", f"{prerequisite.ecosystem}:{prerequisite.package_name}")
        for edge in session.scalars(select(PackageDependency))
        for dependent in [session.get(Package, edge.dependent_package_id)]
        for prerequisite in [session.get(Package, edge.prerequisite_package_id)]
        if dependent is not None and prerequisite is not None
    )
    candidates = list(session.scalars(select(RemediationCandidate).join(InstalledPackage).join(Asset).where(Asset.environment_id == environment_id)))
    actions = []
    for row in candidates:
        vulnerability = session.get(Vulnerability, row.vulnerability_id)
        installed_row = session.get(InstalledPackage, row.installed_package_id)
        package = session.get(Package, installed_row.package_id) if installed_row else None
        asset = session.get(Asset, installed_row.asset_id) if installed_row else None
        if vulnerability is None or installed_row is None or package is None or asset is None:
            continue
        candidate_id = f"{asset.external_identifier or asset.id}:{vulnerability.source_id}"
        core_candidate = CoreCandidate(
            candidate_id,
            asset.external_identifier or str(asset.id),
            PackageIdentity(package.ecosystem, package.package_name),
            vulnerability.source_id,
            tuple(vulnerability.aliases),
            row.fixed_version,
            vulnerability.source,
            row.applicability,
            tuple(row.unresolved_issues),
        )
        estimate = estimates.get(candidate_id)
        if estimate is not None and not row.unresolved_issues:
            actions.append(candidate_to_action(core_candidate, estimate))
    dataset = Dataset(package_ids, dependencies, tuple(actions))
    result = run_analysis(dataset, window_minutes, method)
    persist_analysis(session, result, dataset, project_id, environment_id)
    return result
