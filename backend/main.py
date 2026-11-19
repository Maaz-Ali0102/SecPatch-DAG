from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DataError, IntegrityError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from application.persistence import (
    ConflictError,
    NotFoundError,
    create_environment,
    create_project,
    delete_asset,
    delete_environment,
    delete_project,
    environment_graph,
    execute_persisted_analysis,
    import_dependencies,
    get_analysis,
    import_inventory,
    list_analyses,
    persist_analysis,
    persist_ingestion,
    register_asset,
    update_environment,
    update_asset,
    update_project,
)
from core.engine import run_analysis
from core.ingestion import limits
from core.ingestion.limits import clean_text
from core.ingestion.osv import ingest_osv, parse_inventory_strict
from core.models import MAX_WINDOW_MINUTES, Dataset
from infrastructure.database.session import session_scope


logger = logging.getLogger("secpatch.api")


def _optional_text(value: str | None, field: str, max_length: int) -> str | None:
    return None if value is None else clean_text(value, field, max_length)


def _description(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    if len(value) > limits.MAX_DESCRIPTION:
        raise ValueError(f"Description must be at most {limits.MAX_DESCRIPTION} characters")
    return clean_text(value, "Description", limits.MAX_DESCRIPTION)


def _metadata(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is not None and len(json.dumps(value, default=str)) > limits.MAX_METADATA_BYTES:
        raise ValueError(f"Metadata must be at most {limits.MAX_METADATA_BYTES} bytes as JSON")
    return value


class AnalysisRequest(BaseModel):
    dataset: dict[str, Any]
    window_minutes: int = Field(ge=0, le=MAX_WINDOW_MINUTES)
    method: str = "precedence_greedy"
    project_id: uuid.UUID | None = None
    environment_id: uuid.UUID | None = None


app = FastAPI(title="SecPatch-DAG API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
_runs: dict[str, dict[str, Any]] = {}


@app.exception_handler(ConflictError)
def conflict_handler(_: Request, error: ConflictError) -> JSONResponse:
    return JSONResponse(status_code=409, content={"detail": str(error)})


@app.exception_handler(DataError)
def data_error_handler(_: Request, error: DataError) -> JSONResponse:
    # Safety net for values the database cannot store; never echo SQL.
    logger.warning("Rejected value the database cannot store: %s", error.orig)
    return JSONResponse(status_code=422, content={"detail": "A value is too long or contains characters that cannot be stored."})


@app.exception_handler(Exception)
def unexpected_error_handler(_: Request, error: Exception) -> JSONResponse:
    logger.exception("Unhandled error", exc_info=error)
    return JSONResponse(status_code=500, content={"detail": "Something went wrong on the server. The error has been logged."})


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    length = request.headers.get("content-length")
    if length is not None and length.isdigit() and int(length) > limits.MAX_REQUEST_BYTES:
        return JSONResponse(status_code=413, content={"detail": f"Request is larger than {limits.MAX_REQUEST_BYTES // (1024 * 1024)} MB."})
    return await call_next(request)


@app.exception_handler(IntegrityError)
def integrity_handler(_: Request, error: IntegrityError) -> JSONResponse:
    # Never echo SQL statements or constraint names back to the client.
    return JSONResponse(status_code=409, content={"detail": "That name or identifier is already in use."})


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/plans")
def create_plan(request: AnalysisRequest) -> dict[str, Any]:
    try:
        result = run_analysis(Dataset.from_dict(request.dataset), request.window_minutes, request.method)
    except (TypeError, ValueError, KeyError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    _runs[result["run_id"]] = result
    if os.getenv("PERSISTENCE_ENABLED", "").lower() in {"1", "true", "yes"}:
        if request.project_id is None or request.environment_id is None:
            raise HTTPException(status_code=422, detail="project_id and environment_id are required when persistence is enabled")
        try:
            with session_scope() as session:
                persist_analysis(session, result, Dataset.from_dict(request.dataset), request.project_id, request.environment_id)
        except Exception as error:
            logger.exception("Unable to persist analysis")
        raise HTTPException(status_code=503, detail="Unable to save the analysis right now. Check that the database is running.") from error
    return result


class ProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None

    _check_name = field_validator("name")(lambda v: clean_text(v, "Project name", limits.MAX_PROJECT_NAME))
    _check_description = field_validator("description")(lambda v: _description(v))


class ProjectUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None

    _check_name = field_validator("name")(lambda v: _optional_text(v, "Project name", limits.MAX_PROJECT_NAME))
    _check_description = field_validator("description")(lambda v: _description(v))


class EnvironmentRequest(BaseModel):
    project_id: uuid.UUID
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None

    _check_name = field_validator("name")(lambda v: clean_text(v, "Environment name", limits.MAX_ENVIRONMENT_NAME))
    _check_description = field_validator("description")(lambda v: _description(v))


class EnvironmentUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = None

    _check_name = field_validator("name")(lambda v: _optional_text(v, "Environment name", limits.MAX_ENVIRONMENT_NAME))
    _check_description = field_validator("description")(lambda v: _description(v))


class AssetRequest(BaseModel):
    environment_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    external_identifier: str | None = None
    operating_system: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    _check_name = field_validator("name")(lambda v: _optional_text(v, "Asset name", limits.MAX_ASSET_NAME))
    # Inventory rows are matched by this identifier, so it may be omitted
    # but never blank, too long or full of control characters.
    _check_identifier = field_validator("external_identifier")(lambda v: _optional_text(v, "External identifier", limits.MAX_ASSET_IDENTIFIER))
    _check_os = field_validator("operating_system")(lambda v: None if v is None or not v.strip() else clean_text(v, "Operating system", limits.MAX_OPERATING_SYSTEM))
    _check_metadata = field_validator("metadata")(lambda v: _metadata(v))


class AssetUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    external_identifier: str | None = None
    operating_system: str | None = None
    metadata: dict[str, Any] | None = None

    _check_name = field_validator("name")(lambda v: _optional_text(v, "Asset name", limits.MAX_ASSET_NAME))
    # Inventory rows are matched by this identifier, so it may be omitted
    # but never blank, too long or full of control characters.
    _check_identifier = field_validator("external_identifier")(lambda v: _optional_text(v, "External identifier", limits.MAX_ASSET_IDENTIFIER))
    _check_os = field_validator("operating_system")(lambda v: None if v is None or not v.strip() else clean_text(v, "Operating system", limits.MAX_OPERATING_SYSTEM))
    _check_metadata = field_validator("metadata")(lambda v: _metadata(v))


class InventoryImportRequest(BaseModel):
    environment_id: uuid.UUID
    packages: list[Any] = Field(max_length=limits.MAX_INVENTORY_ROWS)


class VulnerabilityImportRequest(BaseModel):
    environment_id: uuid.UUID
    osv: dict[str, Any]
    inventory: dict[str, Any]


class PersistedAnalysisRequest(BaseModel):
    comparison_id: uuid.UUID | None = None
    estimate_source: str | None = None
    project_id: uuid.UUID
    environment_id: uuid.UUID
    # One day. The DP table is (actions x window), so the dashboard path keeps
    # the window to realistic maintenance lengths; the CLI allows more.
    window_minutes: int = Field(ge=0, le=limits.MAX_DASHBOARD_WINDOW)
    method: str = "cp_sat"
    estimates: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @field_validator("estimates")
    @classmethod
    def _check_estimates(cls, value: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        if len(value) > limits.MAX_ESTIMATES:
            raise ValueError(f"At most {limits.MAX_ESTIMATES} estimates are accepted")
        for key in value:
            clean_text(key, "Estimate key", limits.MAX_ESTIMATE_KEY)
        return value


@app.post("/api/v1/projects")
def create_project_endpoint(request: ProjectRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            project = create_project(session, request.name, request.description)
            return {"id": str(project.id), "name": project.name, "description": project.description}
    except (ConflictError, IntegrityError, DataError):
        raise
    except Exception as error:
        logger.exception("Unable to persist project")
        raise HTTPException(status_code=503, detail="Unable to save the project right now. Check that the database is running.") from error


@app.post("/api/v1/environments")
def create_environment_endpoint(request: EnvironmentRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            environment = create_environment(session, request.project_id, request.name, request.description)
            return {"id": str(environment.id), "project_id": str(environment.project_id), "name": environment.name}
    except (ConflictError, IntegrityError, DataError):
        raise
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except Exception as error:
        logger.exception("Unable to persist environment")
        raise HTTPException(status_code=503, detail="Unable to save the environment right now. Check that the database is running.") from error


@app.get("/api/v1/projects")
def list_projects_endpoint() -> list[dict[str, Any]]:
    from infrastructure.database.repositories import ProjectRepository
    with session_scope() as session:
        return [{"id": str(item.id), "name": item.name, "description": item.description} for item in ProjectRepository().list(session)]


@app.patch("/api/v1/projects/{project_id}")
def update_project_endpoint(project_id: uuid.UUID, request: ProjectUpdateRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            project = update_project(session, project_id, request.name, request.description)
            return {"id": str(project.id), "name": project.name, "description": project.description}
    except (ConflictError, IntegrityError, DataError):
        raise
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.get("/api/v1/projects/{project_id}/environments")
def list_environments_endpoint(project_id: uuid.UUID) -> list[dict[str, Any]]:
    from infrastructure.database.repositories import EnvironmentRepository
    with session_scope() as session:
        return [{"id": str(item.id), "project_id": str(item.project_id), "name": item.name, "description": item.description} for item in EnvironmentRepository().list(session, project_id)]


@app.patch("/api/v1/environments/{environment_id}")
def update_environment_endpoint(environment_id: uuid.UUID, request: EnvironmentUpdateRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            environment = update_environment(session, environment_id, request.name, request.description)
            return {"id": str(environment.id), "project_id": str(environment.project_id), "name": environment.name, "description": environment.description}
    except (ConflictError, IntegrityError, DataError):
        raise
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.post("/api/v1/assets")
def create_asset_endpoint(request: AssetRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            asset = register_asset(session, request.environment_id, request.name, request.external_identifier, request.operating_system, request.metadata)
            return {"id": str(asset.id), "environment_id": str(asset.environment_id), "name": asset.name, "external_identifier": asset.external_identifier, "metadata": asset.metadata_json}
    except (ConflictError, IntegrityError, DataError):
        raise
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except Exception as error:
        logger.exception("Unable to persist asset")
        raise HTTPException(status_code=503, detail="Unable to save the asset right now. Check that the database is running.") from error


@app.get("/api/v1/environments/{environment_id}/assets")
def list_environment_assets_endpoint(environment_id: uuid.UUID) -> list[dict[str, Any]]:
    from infrastructure.database.repositories import AssetRepository
    with session_scope() as session:
        return [
            {
                "id": str(item.id),
                "environment_id": str(item.environment_id),
                "name": item.name,
                "external_identifier": item.external_identifier,
                "operating_system": item.operating_system,
                "metadata": item.metadata_json,
            }
            for item in AssetRepository().list(session, environment_id)
        ]


@app.get("/api/v1/assets/{asset_id}")
def get_asset_endpoint(asset_id: uuid.UUID) -> dict[str, Any]:
    from infrastructure.database.repositories import AssetRepository
    with session_scope() as session:
        asset = AssetRepository().get(session, asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        return {"id": str(asset.id), "environment_id": str(asset.environment_id), "name": asset.name, "external_identifier": asset.external_identifier, "operating_system": asset.operating_system, "metadata": asset.metadata_json}


@app.get("/api/v1/assets/{asset_id}/inventory")
def get_asset_inventory_endpoint(asset_id: uuid.UUID) -> list[dict[str, Any]]:
    from infrastructure.database.repositories import AssetRepository, InventoryRepository
    from infrastructure.database.models import Package
    with session_scope() as session:
        if AssetRepository().get(session, asset_id) is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        output = []
        for row in InventoryRepository().list_for_asset(session, asset_id):
            package = session.get(Package, row.package_id)
            output.append({
                "id": str(row.id),
                "asset_id": str(row.asset_id),
                "package_id": str(row.package_id),
                "package": package.package_name if package else None,
                "ecosystem": package.ecosystem if package else None,
                "version": row.installed_version,
                "source": row.inventory_source,
            })
        return output


@app.patch("/api/v1/assets/{asset_id}")
def update_asset_endpoint(asset_id: uuid.UUID, request: AssetUpdateRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            sent = request.model_dump(exclude_unset=True)
            changes = {("metadata_json" if key == "metadata" else key): value for key, value in sent.items()}
            asset = update_asset(session, asset_id, changes)
            return {"id": str(asset.id), "name": asset.name, "external_identifier": asset.external_identifier, "operating_system": asset.operating_system, "metadata": asset.metadata_json}
    except (ConflictError, IntegrityError, DataError):
        raise
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


class DependencyImportRequest(BaseModel):
    environment_id: uuid.UUID
    dependencies: list[Any] = Field(max_length=10_000)


def _delete(action: Any, row_id: uuid.UUID, what: str) -> dict[str, Any]:
    try:
        with session_scope() as session:
            action(session, row_id)
            return {"deleted": str(row_id)}
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except Exception as error:
        logger.exception("Unable to delete %s", what)
        raise HTTPException(status_code=503, detail=f"Unable to delete the {what} right now. Check that the database is running.") from error


@app.delete("/api/v1/projects/{project_id}")
def delete_project_endpoint(project_id: uuid.UUID) -> dict[str, Any]:
    return _delete(delete_project, project_id, "project")


@app.delete("/api/v1/environments/{environment_id}")
def delete_environment_endpoint(environment_id: uuid.UUID) -> dict[str, Any]:
    return _delete(delete_environment, environment_id, "environment")


@app.delete("/api/v1/assets/{asset_id}")
def delete_asset_endpoint(asset_id: uuid.UUID) -> dict[str, Any]:
    return _delete(delete_asset, asset_id, "asset")


@app.post("/api/v1/dependencies")
def import_dependencies_endpoint(request: DependencyImportRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            count = import_dependencies(session, request.environment_id, request.dependencies)
            return {"count": count, **environment_graph(session, request.environment_id)}
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.get("/api/v1/environments/{environment_id}/graph")
def environment_graph_endpoint(environment_id: uuid.UUID) -> dict[str, Any]:
    try:
        with session_scope() as session:
            return environment_graph(session, environment_id)
    except NotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.post("/api/v1/inventory")
def import_inventory_endpoint(request: InventoryImportRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            from infrastructure.database.repositories import AssetRepository
            asset_rows = AssetRepository().list(session, request.environment_id)
            lookup = {asset.external_identifier: asset for asset in asset_rows if asset.external_identifier}
            records = list(parse_inventory_strict(request.packages))
            rows = import_inventory(session, request.environment_id, records, lookup)
            return {"count": len(rows), "packages": [{"id": str(row.id), "version": row.installed_version} for row in rows]}
    except (KeyError, TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


def _candidate_detail(session: Any, candidate: Any) -> dict[str, Any]:
    from infrastructure.database.models import Asset, InstalledPackage, Package, Vulnerability
    vulnerability = session.get(Vulnerability, candidate.vulnerability_id)
    installed = session.get(InstalledPackage, candidate.installed_package_id)
    asset = session.get(Asset, installed.asset_id) if installed else None
    package = session.get(Package, installed.package_id) if installed else None
    return {
        "id": f"{candidate.id}",
        "candidate_key": f"{asset.external_identifier or asset.id}:{vulnerability.source_id}" if vulnerability and asset else None,
        "vulnerability_id": vulnerability.source_id if vulnerability else None,
        "aliases": vulnerability.aliases if vulnerability else [],
        "package": package.package_name if package else None,
        "ecosystem": package.ecosystem if package else None,
        "installed_version": installed.installed_version if installed else None,
        "fixed_version": candidate.fixed_version,
        "applicability": candidate.applicability,
        "unresolved_issues": candidate.unresolved_issues,
    }


@app.get("/api/v1/environments/{environment_id}/candidates")
def list_environment_candidates_endpoint(environment_id: uuid.UUID) -> dict[str, Any]:
    """Stored remediation candidates, so the dashboard can rebuild its
    vulnerability view after a page refresh or environment switch."""
    from sqlalchemy import select
    from infrastructure.database.models import Asset, InstalledPackage, RemediationCandidate, Vulnerability
    from infrastructure.database.repositories import EnvironmentRepository
    with session_scope() as session:
        environment = EnvironmentRepository().get(session, environment_id)
        if environment is None:
            raise HTTPException(status_code=404, detail="Environment not found")
        rows = list(session.scalars(
            select(RemediationCandidate).join(InstalledPackage).join(Asset)
            .where(Asset.environment_id == environment_id, Asset.archived_at.is_(None))
            .order_by(RemediationCandidate.created_at)
        ))
        details = [_candidate_detail(session, row) for row in rows]
        vulnerability_count = len({row.vulnerability_id for row in rows})
        return {"vulnerabilities": vulnerability_count, "candidates": len(details), "candidate_details": details, "issues": [], **(environment.advisory_check or {})}


@app.post("/api/v1/vulnerabilities/import")
def import_vulnerabilities_endpoint(request: VulnerabilityImportRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            from infrastructure.database.repositories import AssetRepository
            asset_rows = AssetRepository().list(session, request.environment_id)
            lookup = {asset.external_identifier: asset for asset in asset_rows if asset.external_identifier}
            result = ingest_osv(request.osv, request.inventory)
            inventory_records = list(result.inventory)
            import_inventory(session, request.environment_id, inventory_records, lookup)
            candidates = persist_ingestion(session, result, lookup)
            candidate_details = [_candidate_detail(session, candidate) for candidate in candidates]
            from infrastructure.database.models import Environment
            environment = session.get(Environment, request.environment_id)
            if environment is None:
                raise HTTPException(status_code=404, detail="Environment not found")
            report = {"vulnerabilities": len(result.vulnerabilities), "issues": result.issue_dicts(),
                      "package_checks": list(result.package_checks)}
            environment.advisory_check = report
            session.commit()
            return {**report, "candidates": len(candidates), "candidate_details": candidate_details}
    except (KeyError, TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.post("/api/v1/persisted-plans")
def create_persisted_plan_endpoint(request: PersistedAnalysisRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            return execute_persisted_analysis(session, request.project_id, request.environment_id, request.window_minutes, request.method, request.estimates, comparison_id=request.comparison_id, estimate_source=request.estimate_source)
    except (ValueError, TypeError, KeyError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception as error:
        logger.exception("Unable to execute persisted analysis")
        raise HTTPException(status_code=503, detail="Unable to run the analysis right now. Check that the database is running.") from error


@app.get("/api/v1/projects/{project_id}/analysis-runs")
def list_analysis_runs_endpoint(project_id: uuid.UUID, environment_id: uuid.UUID | None = None) -> list[dict[str, Any]]:
    with session_scope() as session:
        summaries = []
        for run in list_analyses(session, project_id, environment_id):
            result = run.result_summary or {}
            selected = result.get("optimization", {}).get("selected_actions")
            summaries.append({
                "comparison_id": result.get("comparison_id"), "estimate_source": result.get("estimate_source"),
                "id": str(run.id), "status": run.status, "method": run.optimization_method,
                "solver_status": run.solver_status, "objective_value": run.objective_value,
                "created_at": run.created_at.isoformat(), "window_minutes": run.maintenance_window_minutes,
                "selected_count": len(selected) if selected is not None else None,
                "used_minutes": result.get("schedule", {}).get("total_duration_minutes"),
            })
        return summaries


@app.get("/api/v1/analysis-runs/{run_id}")
def get_analysis_run_endpoint(run_id: uuid.UUID) -> dict[str, Any]:
    try:
        with session_scope() as session:
            return get_analysis(session, run_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.get("/api/v1/plans/{run_id}")
def get_plan(run_id: str) -> dict[str, Any]:
    if run_id not in _runs:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    return _runs[run_id]


@app.get("/api/v1/plans/{run_id}/trace")
def get_trace(run_id: str) -> dict[str, Any]:
    return {"run_id": run_id, "trace": get_plan(run_id)["trace"]}


@app.get("/api/v1/datasets")
def list_datasets() -> list[dict[str, str]]:
    sample_dir = Path(__file__).parents[1] / "datasets" / "samples"
    return [{"name": path.stem, "path": str(path)} for path in sorted(sample_dir.glob("*.json"))]


@app.get("/api/v1/datasets/{name}")
def get_dataset(name: str) -> dict[str, Any]:
    path = Path(__file__).parents[1] / "datasets" / "samples" / f"{name}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Dataset not found")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/api/v1/cep/experiment")
def cep_experiment(first: int = 18, second: int = 13) -> dict[str, Any]:
    from core.cep import experiment
    try:
        return experiment((first, second))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.get("/api/v1/analysis-runs/{run_id}/maintenance-windows")
def multiple_window_plan(run_id: uuid.UUID, first: int = 18, second: int = 13) -> dict[str, Any]:
    from core.maintenance import MaintenancePlanner
    with session_scope() as session:
        try:
            snapshot = get_analysis(session, run_id)["persistence"]["input_snapshot"]
        except ValueError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
    try:
        return MaintenancePlanner().plan(Dataset.from_dict(snapshot), (first, second))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
