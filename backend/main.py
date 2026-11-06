from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from application.persistence import (
    create_environment,
    create_project,
    execute_persisted_analysis,
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
from core.ingestion.models import InstalledPackage, PackageIdentity
from core.ingestion.osv import ingest_osv
from core.models import Dataset
from infrastructure.database.session import session_scope


class AnalysisRequest(BaseModel):
    dataset: dict[str, Any]
    window_minutes: int = Field(ge=0)
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
            raise HTTPException(status_code=503, detail=f"Unable to persist analysis: {error}") from error
    return result


class ProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None


class ProjectUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None


class EnvironmentRequest(BaseModel):
    project_id: uuid.UUID
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None


class EnvironmentUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = None


class AssetRequest(BaseModel):
    environment_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    external_identifier: str | None = None
    operating_system: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    external_identifier: str | None = None
    operating_system: str | None = None
    metadata: dict[str, Any] | None = None


class InventoryImportRequest(BaseModel):
    environment_id: uuid.UUID
    packages: list[dict[str, Any]]


class VulnerabilityImportRequest(BaseModel):
    environment_id: uuid.UUID
    osv: dict[str, Any]
    inventory: dict[str, Any]


class PersistedAnalysisRequest(BaseModel):
    project_id: uuid.UUID
    environment_id: uuid.UUID
    window_minutes: int = Field(ge=0)
    method: str = "cp_sat"
    estimates: dict[str, dict[str, Any]] = Field(default_factory=dict)


@app.post("/api/v1/projects")
def create_project_endpoint(request: ProjectRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            project = create_project(session, request.name, request.description)
            return {"id": str(project.id), "name": project.name, "description": project.description}
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"Unable to persist project: {error}") from error


@app.post("/api/v1/environments")
def create_environment_endpoint(request: EnvironmentRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            environment = create_environment(session, request.project_id, request.name, request.description)
            return {"id": str(environment.id), "project_id": str(environment.project_id), "name": environment.name}
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"Unable to persist environment: {error}") from error


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
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.post("/api/v1/assets")
def create_asset_endpoint(request: AssetRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            asset = register_asset(session, request.environment_id, request.name, request.external_identifier, request.operating_system, request.metadata)
            return {"id": str(asset.id), "environment_id": str(asset.environment_id), "name": asset.name, "external_identifier": asset.external_identifier, "metadata": asset.metadata_json}
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"Unable to persist asset: {error}") from error


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
            asset = update_asset(session, asset_id, {"name": request.name, "external_identifier": request.external_identifier, "operating_system": request.operating_system, "metadata_json": request.metadata})
            return {"id": str(asset.id), "name": asset.name, "external_identifier": asset.external_identifier, "operating_system": asset.operating_system, "metadata": asset.metadata_json}
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.post("/api/v1/inventory")
def import_inventory_endpoint(request: InventoryImportRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            from infrastructure.database.repositories import AssetRepository
            asset_rows = AssetRepository().list(session, request.environment_id)
            lookup = {asset.external_identifier: asset for asset in asset_rows if asset.external_identifier}
            records = [InstalledPackage(str(item["asset_id"]), PackageIdentity(str(item["ecosystem"]), str(item["name"])), item.get("version")) for item in request.packages]
            rows = import_inventory(session, request.environment_id, records, lookup)
            return {"count": len(rows), "packages": [{"id": str(row.id), "version": row.installed_version} for row in rows]}
    except (KeyError, TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


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
            from infrastructure.database.models import Asset, InstalledPackage, Package, Vulnerability
            candidate_details = []
            for candidate in candidates:
                vulnerability = session.get(Vulnerability, candidate.vulnerability_id)
                installed = session.get(InstalledPackage, candidate.installed_package_id)
                asset = session.get(Asset, installed.asset_id) if installed else None
                package = session.get(Package, installed.package_id) if installed else None
                candidate_details.append({
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
                })
            return {"vulnerabilities": len(result.vulnerabilities), "candidates": len(candidates), "candidate_details": candidate_details, "issues": result.issue_dicts()}
    except (KeyError, TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.post("/api/v1/persisted-plans")
def create_persisted_plan_endpoint(request: PersistedAnalysisRequest) -> dict[str, Any]:
    try:
        with session_scope() as session:
            return execute_persisted_analysis(session, request.project_id, request.environment_id, request.window_minutes, request.method, request.estimates)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"Unable to execute persisted analysis: {error}") from error


@app.get("/api/v1/projects/{project_id}/analysis-runs")
def list_analysis_runs_endpoint(project_id: uuid.UUID, environment_id: uuid.UUID | None = None) -> list[dict[str, Any]]:
    with session_scope() as session:
        return [{"id": str(run.id), "status": run.status, "method": run.optimization_method, "solver_status": run.solver_status, "objective_value": run.objective_value, "created_at": run.created_at.isoformat()} for run in list_analyses(session, project_id, environment_id)]


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
