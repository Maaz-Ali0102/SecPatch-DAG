from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from application.persistence import create_environment, create_project, get_analysis, persist_analysis, register_asset
from core.models import Dataset
from infrastructure.database.base import Base
from infrastructure.database.models import AnalysisRun, Package, PatchAction, PatchActionPrerequisite


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        Base.metadata.create_all(connection)
        with Session(bind=connection) as value:
            yield value


def test_persistence_maps_analysis_snapshot_without_core_dependency_on_database(session: Session) -> None:
    project = create_project(session, "demo")
    environment = create_environment(session, project.id, "production")
    dataset = Dataset.from_dict({
        "packages": [{"id": "app"}],
        "dependencies": [],
        "actions": [{"id": "patch-app", "package_id": "app", "duration_minutes": 5, "benefit": 10}],
    })
    result = {
        "run_id": str(uuid.uuid4()),
        "status": "completed",
        "configuration": {"window_minutes": 10},
        "input_fingerprint": "fingerprint",
        "optimization": {"method": "cp_sat", "solver_status": "OPTIMAL", "objective_value": 10, "optimality_proven": True},
    }
    run = persist_analysis(session, result, dataset, project.id, environment.id)
    assert run.project_id == project.id
    assert run.result_summary["optimization"]["solver_status"] == "OPTIMAL"
    assert run.input_snapshot["actions"][0]["id"] == "patch-app"


def test_analysis_environment_must_belong_to_project(session: Session) -> None:
    first = create_project(session, "first")
    second = create_project(session, "second")
    environment = create_environment(session, first.id, "prod")
    session.add(AnalysisRun(
        project_id=second.id, environment_id=environment.id, status="completed",
        optimization_method="cp_sat", optimality_proven=False, maintenance_window_minutes=0,
    ))
    with pytest.raises(IntegrityError):
        session.commit()


def test_patch_action_prerequisite_is_scoped_to_same_analysis_run(session: Session) -> None:
    project = create_project(session, "project")
    environment = create_environment(session, project.id, "prod")
    run_one = AnalysisRun(project_id=project.id, environment_id=environment.id, status="completed", optimization_method="cp_sat", optimality_proven=False, maintenance_window_minutes=1)
    run_two = AnalysisRun(project_id=project.id, environment_id=environment.id, status="completed", optimization_method="cp_sat", optimality_proven=False, maintenance_window_minutes=1)
    package = Package(ecosystem="pypi", package_name="demo")
    session.add_all([run_one, run_two, package])
    session.commit()
    action_one = PatchAction(analysis_run_id=run_one.id, package_id=package.id, action_key="one", duration_minutes=1, benefit=1, priority=1)
    action_two = PatchAction(analysis_run_id=run_two.id, package_id=package.id, action_key="two", duration_minutes=1, benefit=1, priority=1)
    session.add_all([action_one, action_two])
    session.commit()
    session.add(PatchActionPrerequisite(analysis_run_id=run_one.id, action_id=action_one.id, prerequisite_action_id=action_two.id))
    with pytest.raises(IntegrityError):
        session.commit()


def test_normalized_patch_plan_and_historical_retrieval(session: Session) -> None:
    project = create_project(session, "history")
    environment = create_environment(session, project.id, "prod")
    dataset = Dataset.from_dict({
        "packages": [{"id": "pypi:demo"}],
        "dependencies": [],
        "actions": [{"id": "patch-demo", "package_id": "pypi:demo", "duration_minutes": 5, "benefit": 10}],
    })
    result = {
        "run_id": str(uuid.uuid4()), "status": "completed",
        "configuration": {"window_minutes": 10}, "input_fingerprint": "history",
        "optimization": {"method": "cp_sat", "solver_status": "OPTIMAL", "objective_value": 10, "optimality_proven": True},
        "validation": {"valid": True, "violations": []},
        "schedule": {"total_duration_minutes": 5, "entries": [{"action_id": "patch-demo", "start_minute": 0, "finish_minute": 5}]},
    }
    run = persist_analysis(session, result, dataset, project.id, environment.id)
    persisted = get_analysis(session, run.id)
    assert persisted["persistence"]["patch_plan_id"] is not None
    assert persisted["persistence"]["patch_plan_actions"][0]["execution_order"] == 1
    assert persisted["persistence"]["patch_plan_actions"][0]["finish_offset_minutes"] == 5


def test_multiple_versions_are_valid_for_one_asset(session: Session) -> None:
    project = create_project(session, "inventory")
    environment = create_environment(session, project.id, "prod")
    asset = register_asset(session, environment.id, "host", "host-1")
    from core.ingestion.models import InstalledPackage, PackageIdentity
    rows = [
        InstalledPackage("host-1", PackageIdentity("pypi", "demo"), "1.9"),
        InstalledPackage("host-1", PackageIdentity("pypi", "demo"), "1.10"),
    ]
    from application.persistence import import_inventory
    stored = import_inventory(session, environment.id, rows, {"host-1": asset})
    assert {row.installed_version for row in stored} == {"1.9", "1.10"}
