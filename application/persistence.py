from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.engine import run_analysis
from core.ingestion.models import PackageIdentity, RemediationCandidate as CoreCandidate, candidate_to_action, match_key
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
    if _taken(session, Project, name=name):
        raise ConflictError(f"A project named '{name}' already exists")
    value = projects.create(session, name, description)
    session.commit()
    return value


class NotFoundError(ValueError):
    """Raised when a referenced project, environment or asset does not exist."""


class ConflictError(ValueError):
    """Raised when a name or identifier is already used where it must be unique."""


def _taken(session: Session, model: Any, exclude_id: uuid.UUID | None = None, **filters: Any) -> bool:
    query = select(model.id).where(*(getattr(model, key) == value for key, value in filters.items()))
    if exclude_id is not None:
        query = query.where(model.id != exclude_id)
    return session.scalar(query.limit(1)) is not None


def create_environment(session: Session, project_id: uuid.UUID, name: str, description: str | None = None) -> Environment:
    if projects.get(session, project_id) is None:
        raise NotFoundError("Project not found")
    if _taken(session, Environment, project_id=project_id, name=name):
        raise ConflictError(f"This project already has an environment named '{name}'")
    value = environments.create(session, project_id, name, description)
    session.commit()
    return value


def update_project(session: Session, project_id: uuid.UUID, name: str | None, description: str | None) -> Project:
    value = projects.get(session, project_id)
    if value is None:
        raise ValueError("Project not found")
    if name is not None and _taken(session, Project, exclude_id=project_id, name=name):
        raise ConflictError(f"A project named '{name}' already exists")
    projects.update(session, value, name, description)
    session.commit()
    return value


def update_environment(session: Session, environment_id: uuid.UUID, name: str | None, description: str | None) -> Environment:
    value = environments.get(session, environment_id)
    if value is None:
        raise ValueError("Environment not found")
    if name is not None and _taken(session, Environment, exclude_id=environment_id, project_id=value.project_id, name=name):
        raise ConflictError(f"This project already has an environment named '{name}'")
    environments.update(session, value, name, description)
    session.commit()
    return value


def register_asset(session: Session, environment_id: uuid.UUID, name: str, external_identifier: str | None = None, operating_system: str | None = None, metadata: dict[str, Any] | None = None) -> Asset:
    if environments.get(session, environment_id) is None:
        raise ValueError("Environment not found")
    # Inventory rows are matched to assets by external identifier, so two
    # assets with the same identifier would make every import ambiguous.
    if external_identifier and _taken(session, Asset, environment_id=environment_id, external_identifier=external_identifier):
        raise ConflictError(f"An asset with external identifier '{external_identifier}' is already registered in this environment")
    if _taken(session, Asset, environment_id=environment_id, name=name):
        raise ConflictError(f"An asset named '{name}' is already registered in this environment")
    value = assets.create(session, environment_id, name, external_identifier, operating_system, metadata)
    session.commit()
    return value


def _deleted_name(name: str, row_id: uuid.UUID, limit: int) -> str:
    """Rename a deleted row so its name can be reused (names are unique)."""
    suffix = f" (deleted {row_id.hex[:8]})"
    return name[: limit - len(suffix)] + suffix


def delete_asset(session: Session, asset_id: uuid.UUID) -> None:
    """Hide a server: it leaves lists, imports and new analyses, but saved
    plans that used it keep their history. Its identifier is released."""
    value = assets.get(session, asset_id)
    if value is None:
        raise NotFoundError("Asset not found")
    _archive_asset(value)
    session.commit()


def _archive_asset(value: Asset) -> None:
    value.archived_at = datetime.now(timezone.utc)
    value.name = _deleted_name(value.name, value.id, 200)
    value.external_identifier = None


def delete_environment(session: Session, environment_id: uuid.UUID) -> None:
    value = environments.get(session, environment_id)
    if value is None:
        raise NotFoundError("Environment not found")
    _archive_environment(session, value)
    session.commit()


def _archive_environment(session: Session, value: Environment) -> None:
    for asset in assets.list(session, value.id):
        _archive_asset(asset)
    value.archived_at = datetime.now(timezone.utc)
    value.name = _deleted_name(value.name, value.id, 120)


def delete_project(session: Session, project_id: uuid.UUID) -> None:
    value = projects.get(session, project_id)
    if value is None:
        raise NotFoundError("Project not found")
    for environment in environments.list(session, value.id):
        _archive_environment(session, environment)
    value.archived_at = datetime.now(timezone.utc)
    value.name = _deleted_name(value.name, value.id, 200)
    session.commit()


def update_asset(session: Session, asset_id: uuid.UUID, changes: dict[str, Any]) -> Asset:
    value = assets.get(session, asset_id)
    if value is None:
        raise ValueError("Asset not found")
    if changes.get("external_identifier") and _taken(session, Asset, exclude_id=asset_id, environment_id=value.environment_id, external_identifier=changes["external_identifier"]):
        raise ConflictError(f"An asset with external identifier '{changes['external_identifier']}' is already registered in this environment")
    if changes.get("name") and _taken(session, Asset, exclude_id=asset_id, environment_id=value.environment_id, name=changes["name"]):
        raise ConflictError(f"An asset named '{changes['name']}' is already registered in this environment")
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


MAX_DEPENDENCIES = 10_000


def _environment_packages(session: Session, environment_id: uuid.UUID) -> dict[str, Package]:
    """Packages installed on the environment's (not deleted) servers, by ``ecosystem:name``."""
    rows = session.scalars(
        select(Package).join(InstalledPackage, InstalledPackage.package_id == Package.id).join(Asset)
        .where(Asset.environment_id == environment_id, Asset.archived_at.is_(None))
    )
    return {f"{row.ecosystem}:{row.package_name}": row for row in rows}


def import_dependencies(session: Session, environment_id: uuid.UUID, edges: Any) -> int:
    """Replace the environment's package dependency edges.

    Each edge is ``{"from": "<dependent>", "to": "<prerequisite>"}`` using the
    ``ecosystem:name`` keys shown in the inventory, e.g. ``PyPI:requests`` ->
    ``PyPI:urllib3`` means requests depends on urllib3. Both packages must be
    installed in this environment. All-or-nothing: one bad edge rejects the file.
    """
    if environments.get(session, environment_id) is None:
        raise NotFoundError("Environment not found")
    if not isinstance(edges, list):
        raise ValueError("Dependencies file must contain a dependencies array")
    if len(edges) > MAX_DEPENDENCIES:
        raise ValueError(f"At most {MAX_DEPENDENCIES} dependencies are accepted per import")
    packages = _environment_packages(session, environment_id)
    if not packages:
        raise ValueError("This environment has no installed packages yet. Import the inventory first, then the dependencies.")
    # Match keys the same way inventory and OSV are matched (case, PEP 503).
    by_match = {match_key(PackageIdentity(row.ecosystem, row.package_name)): row for row in packages.values()}
    pairs: list[tuple[Package, Package]] = []
    problems: list[str] = []
    for index, edge in enumerate(edges):
        source = edge.get("from") if isinstance(edge, dict) else None
        target = edge.get("to") if isinstance(edge, dict) else None
        if not isinstance(source, str) or not isinstance(target, str) or ":" not in source or ":" not in target:
            problems.append(f"entry {index} needs \"from\" and \"to\" written as ecosystem:name")
            continue
        rows = []
        for key in (source, target):
            ecosystem, name = key.split(":", 1)
            row = by_match.get(match_key(PackageIdentity(ecosystem, name)))
            if row is None:
                problems.append(f"entry {index}: {key[:120]} is not installed in this environment")
            rows.append(row)
        if rows[0] is not None and rows[1] is not None:
            pairs.append((rows[0], rows[1]))
    if problems:
        more = f" (and {len(problems) - 1} more)" if len(problems) > 1 else ""
        raise ValueError(f"Dependency {problems[0]}{more}")
    for old in session.scalars(select(PackageDependency).where(PackageDependency.environment_id == environment_id)):
        session.delete(old)
    session.flush()
    unique = {(dependent.id, prerequisite.id) for dependent, prerequisite in pairs}
    for dependent_id, prerequisite_id in sorted(unique):
        session.add(PackageDependency(environment_id=environment_id, dependent_package_id=dependent_id, prerequisite_package_id=prerequisite_id, source="dashboard import"))
    session.commit()
    return len(unique)


def _environment_dependencies(session: Session, environment_id: uuid.UUID, package_ids: Any) -> tuple[tuple[str, str], ...]:
    edges = []
    for edge in session.scalars(select(PackageDependency).where(PackageDependency.environment_id == environment_id)):
        dependent = session.get(Package, edge.dependent_package_id)
        prerequisite = session.get(Package, edge.prerequisite_package_id)
        if dependent is None or prerequisite is None:
            continue
        pair = (f"{dependent.ecosystem}:{dependent.package_name}", f"{prerequisite.ecosystem}:{prerequisite.package_name}")
        if pair[0] in package_ids and pair[1] in package_ids:
            edges.append(pair)
    return tuple(sorted(edges))


def environment_graph(session: Session, environment_id: uuid.UUID) -> dict[str, Any]:
    """Tarjan SCC / topological analysis of the environment's packages, without planning."""
    if environments.get(session, environment_id) is None:
        raise NotFoundError("Environment not found")
    package_ids = tuple(sorted(_environment_packages(session, environment_id)))
    dependencies = _environment_dependencies(session, environment_id, set(package_ids))
    dataset = Dataset(packages=package_ids, dependencies=dependencies, actions=())
    result = run_analysis(dataset, 0, "precedence_greedy")
    return {"graph": result["graph"], "trace": result.get("trace", []), "statistics": result["statistics"]}


def execute_persisted_analysis(session: Session, project_id: uuid.UUID, environment_id: uuid.UUID, window_minutes: int, method: str, estimates: dict[str, dict[str, Any]], *, comparison_id: uuid.UUID | None = None, estimate_source: str | None = None) -> dict[str, Any]:
    """Build planning inputs only from persisted inventory and explicit estimates."""
    environment = environments.get(session, environment_id)
    if environment is None or environment.project_id != project_id:
        raise ValueError("Environment does not belong to project")
    installed = list(session.scalars(select(InstalledPackage).join(Asset).where(Asset.environment_id == environment_id, Asset.archived_at.is_(None))))
    package_rows = {row.package_id: session.get(Package, row.package_id) for row in installed}
    package_ids = tuple(sorted({f"{row.ecosystem}:{row.package_name}" for row in package_rows.values() if row is not None}))
    dependencies = _environment_dependencies(session, environment_id, set(package_ids))
    candidates = list(session.scalars(select(RemediationCandidate).join(InstalledPackage).join(Asset).where(Asset.environment_id == environment_id, Asset.archived_at.is_(None))))
    if not isinstance(estimates, dict):
        raise ValueError("estimates must be an object keyed by candidate key")
    actionable: dict[str, CoreCandidate] = {}
    not_actionable: dict[str, str] = {}
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
        # Only an affected candidate with a fixed version and no unresolved
        # issues may become an action (same rule as approve_candidates).
        if row.applicability != "affected":
            not_actionable.setdefault(candidate_id, f"applicability is {row.applicability}")
        elif row.fixed_version is None:
            not_actionable.setdefault(candidate_id, "no fixed version")
        elif row.unresolved_issues:
            not_actionable.setdefault(candidate_id, "unresolved issues: " + ", ".join(row.unresolved_issues))
        else:
            # Several rows can share a key (several installed versions on one
            # asset, or re-imports); one remediation action per key.
            previous = actionable.get(candidate_id)
            if previous is None or (row.fixed_version or "") > (previous.recommended_fixed_version or ""):
                actionable[candidate_id] = core_candidate
    actions = []
    estimate_review: dict[str, Any] = {"applied": [], "ignored": {}}
    for key, estimate in sorted(estimates.items()):
        if key not in actionable:
            estimate_review["ignored"][key] = not_actionable.get(key, "no remediation candidate with this key in the environment")
            continue
        if not isinstance(estimate, dict):
            raise ValueError(f"Estimate for {key} must be an object")
        try:
            actions.append(candidate_to_action(actionable[key], estimate))
        except (TypeError, ValueError, KeyError) as error:
            raise ValueError(str(error)) from error
        estimate_review["applied"].append(key)
    # Validate exactly like the JSON/CLI path: integer, positive durations,
    # non-negative integer benefits, known and acyclic prerequisites.
    dataset = Dataset.from_dict({
        "packages": list(package_ids),
        "dependencies": [{"from": source, "to": target} for source, target in dependencies if source in package_ids and target in package_ids],
        "actions": [{**action.__dict__, "prerequisites": list(action.prerequisites)} for action in actions],
    })
    result = run_analysis(dataset, window_minutes, method)
    if comparison_id is not None:
        result["comparison_id"] = str(comparison_id)
        result["estimate_source"] = estimate_source
    result["estimate_review"] = estimate_review
    persist_analysis(session, result, dataset, project_id, environment_id)
    return result
