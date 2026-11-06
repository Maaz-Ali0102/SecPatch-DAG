from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from postgresql_support import load_project_environment, managed_engine

load_project_environment()

from backend.main import app


@pytest.fixture
def api_database():
    yield from managed_engine()


def test_postgresql_backed_api_workflow(api_database) -> None:
    _, prefix = api_database
    client = TestClient(app)
    project = client.post("/api/v1/projects", json={"name": prefix + "api-project"})
    assert project.status_code == 200, project.text
    project_data = project.json()
    project_id = project_data["id"]
    assert any(item["id"] == project_id for item in client.get("/api/v1/projects").json())

    environment = client.post("/api/v1/environments", json={
        "project_id": project_id,
        "name": prefix + "api-environment",
    })
    assert environment.status_code == 200, environment.text
    environment_id = environment.json()["id"]
    assert any(item["id"] == environment_id for item in client.get(f"/api/v1/projects/{project_id}/environments").json())

    asset = client.post("/api/v1/assets", json={
        "environment_id": environment_id,
        "name": prefix + "api-asset",
        "external_identifier": prefix + "api-host",
        "operating_system": "linux",
    })
    assert asset.status_code == 200, asset.text

    inventory = client.post("/api/v1/inventory", json={
        "environment_id": environment_id,
        "packages": [{
            "asset_id": prefix + "api-host",
            "ecosystem": "PyPI",
            "name": prefix + "api-package",
            "version": "1.0",
        }],
    })
    assert inventory.status_code == 200, inventory.text
    asset_inventory = client.get(f"/api/v1/assets/{asset.json()['id']}/inventory")
    assert asset_inventory.status_code == 200
    assert asset_inventory.json()[0]["version"] == "1.0"

    vulnerability_id = prefix + "api-vulnerability"
    vulnerability = client.post("/api/v1/vulnerabilities/import", json={
        "environment_id": environment_id,
        "osv": {"vulns": [{
            "id": vulnerability_id,
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": prefix + "api-package"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
            }],
        }]},
        "inventory": {"packages": [{
            "asset_id": prefix + "api-host",
            "ecosystem": "PyPI",
            "name": prefix + "api-package",
            "version": "1.0",
        }]},
    })
    assert vulnerability.status_code == 200, vulnerability.text
    assert vulnerability.json()["candidates"] == 1
    candidate_id = f"{prefix}api-host:{vulnerability_id}"

    plan = client.post("/api/v1/persisted-plans", json={
        "project_id": project_id,
        "environment_id": environment_id,
        "window_minutes": 20,
        "method": "cp_sat",
        "estimates": {candidate_id: {"duration_minutes": 5, "benefit": 10}},
    })
    assert plan.status_code == 200, plan.text
    assert plan.json()["optimization"]["selected_actions"][0]["id"] == candidate_id

    runs = client.get(f"/api/v1/projects/{project_id}/analysis-runs", params={"environment_id": environment_id})
    assert runs.status_code == 200
    assert len(runs.json()) == 1
    run_id = runs.json()[0]["id"]
    historical = client.get(f"/api/v1/analysis-runs/{run_id}")
    assert historical.status_code == 200
    assert historical.json()["persistence"]["analysis_run_id"] == run_id
