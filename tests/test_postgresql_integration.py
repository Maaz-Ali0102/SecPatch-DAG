from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from application.persistence import (
    create_environment,
    create_project,
    get_analysis,
    import_inventory,
    persist_analysis,
    persist_ingestion,
    register_asset,
)
from core.ingestion.models import InstalledPackage, PackageIdentity
from core.ingestion.osv import ingest_osv
from core.models import Dataset
from infrastructure.database.models import (
    AnalysisRun,
    InstalledPackage as DbInstalledPackage,
    Package,
    PatchAction,
    PatchActionPrerequisite,
    PatchPlanAction,
    Project,
    RemediationCandidate,
    Vulnerability,
)

from postgresql_support import managed_engine


@pytest.fixture
def database():
    yield from managed_engine()


def _result(run_id: str, fingerprint: str, benefit: int, action_id: str = "patch-demo") -> dict:
    return {
        "run_id": run_id,
        "status": "completed",
        "configuration": {"window_minutes": 20},
        "input_fingerprint": fingerprint,
        "optimization": {
            "method": "cp_sat",
            "solver_status": "OPTIMAL",
            "objective_value": benefit,
            "optimality_proven": True,
            "selected_actions": [{"id": action_id, "benefit": benefit}],
        },
        "validation": {"valid": True, "violations": []},
        "schedule": {
            "total_duration_minutes": 5,
            "entries": [{"action_id": action_id, "start_minute": 0, "finish_minute": 5}],
        },
    }


def _dataset(package_id: str, benefit: int = 10) -> Dataset:
    return Dataset.from_dict({
        "packages": [{"id": package_id}],
        "dependencies": [],
        "actions": [{
            "id": "patch-demo",
            "package_id": package_id,
            "duration_minutes": 5,
            "benefit": benefit,
        }],
    })


def test_database_is_secpatch_test_and_jsonb_round_trip(database) -> None:
    engine, prefix = database
    with engine.connect() as connection:
        assert connection.execute(text("SELECT current_database()")).scalar_one() == "secpatch_test"
        jsonb_columns = connection.execute(text(
            "SELECT column_name, udt_name FROM information_schema.columns "
            "WHERE table_name = 'analysis_runs' AND column_name IN ('input_snapshot', 'result_summary')"
        )).all()
        assert {(row[0], row[1]) for row in jsonb_columns} == {
            ("input_snapshot", "jsonb"),
            ("result_summary", "jsonb"),
        }

    with Session(engine) as session:
        project = create_project(session, prefix + "jsonb")
        environment = create_environment(session, project.id, prefix + "env")
        run = persist_analysis(
            session,
            _result(str(uuid.uuid4()), prefix, 10),
            _dataset("pypi:" + prefix + "package"),
            project.id,
            environment.id,
        )
        stored = get_analysis(session, run.id)
        assert stored["persistence"]["input_snapshot"]["input_fingerprint"] == prefix
        assert stored["optimization"]["selected_actions"][0]["id"] == "patch-demo"


def test_inventory_versions_and_duplicate_prevention(database) -> None:
    engine, prefix = database
    with Session(engine) as session:
        project = create_project(session, prefix + "inventory")
        environment = create_environment(session, project.id, prefix + "env")
        asset = register_asset(session, environment.id, prefix + "asset", prefix + "host")
        records = [
            InstalledPackage(prefix + "host", PackageIdentity("pypi", prefix + "package"), "1.0"),
            InstalledPackage(prefix + "host", PackageIdentity("pypi", prefix + "package"), "2.0"),
        ]
        first = import_inventory(session, environment.id, records, {prefix + "host": asset})
        second = import_inventory(session, environment.id, records, {prefix + "host": asset})
        assert {row.installed_version for row in first} == {"1.0", "2.0"}
        assert [row.id for row in first] == [row.id for row in second]
        assert session.query(DbInstalledPackage).filter_by(asset_id=asset.id).count() == 2


def _osv_payload(prefix: str) -> tuple[dict, dict]:
    package = prefix + "package"
    vulnerability_id = prefix + "vulnerability"
    record = {
        "id": vulnerability_id,
        "aliases": ["CVE-" + prefix[:8]],
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": package},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
        }],
    }
    return {"vulns": [record, record]}, {
        "packages": [{"asset_id": prefix + "host", "ecosystem": "PyPI", "name": package, "version": "1.0"}],
    }


def test_osv_deduplication_and_remediation_candidate_persistence(database) -> None:
    engine, prefix = database
    osv, inventory = _osv_payload(prefix)
    with Session(engine) as session:
        project = create_project(session, prefix + "osv")
        environment = create_environment(session, project.id, prefix + "env")
        asset = register_asset(session, environment.id, prefix + "asset", prefix + "host")
        result = ingest_osv(osv, inventory)
        assert len(result.vulnerabilities) == 1
        assert any(issue.code == "duplicate_record" for issue in result.issues)
        import_inventory(session, environment.id, list(result.inventory), {prefix + "host": asset})
        stored = persist_ingestion(session, result, {prefix + "host": asset})
        stored_again = persist_ingestion(session, result, {prefix + "host": asset})
        assert len(stored) == len(stored_again) == 1
        assert session.query(Vulnerability).filter_by(source_id=prefix + "vulnerability").count() == 1
        assert session.query(RemediationCandidate).join(Vulnerability).filter(
            Vulnerability.source_id == prefix + "vulnerability"
        ).count() == 1


def test_cross_analysis_prerequisite_and_plan_run_consistency(database) -> None:
    engine, prefix = database
    with Session(engine) as session:
        project = create_project(session, prefix + "constraints")
        environment = create_environment(session, project.id, prefix + "env")
        package = Package(ecosystem="pypi", package_name=prefix + "package")
        run_one = AnalysisRun(project_id=project.id, environment_id=environment.id, status="completed", optimization_method="cp_sat", maintenance_window_minutes=1)
        run_two = AnalysisRun(project_id=project.id, environment_id=environment.id, status="completed", optimization_method="cp_sat", maintenance_window_minutes=1)
        session.add_all([package, run_one, run_two])
        session.commit()
        action_one = PatchAction(analysis_run_id=run_one.id, package_id=package.id, action_key="one", duration_minutes=1, benefit=1, priority=1)
        action_two = PatchAction(analysis_run_id=run_two.id, package_id=package.id, action_key="two", duration_minutes=1, benefit=1, priority=1)
        session.add_all([action_one, action_two])
        session.commit()
        session.add(PatchActionPrerequisite(analysis_run_id=run_one.id, action_id=action_one.id, prerequisite_action_id=action_two.id))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        dataset = _dataset("pypi:" + prefix + "plan")
        persisted = persist_analysis(session, _result(str(uuid.uuid4()), prefix, 10), dataset, project.id, environment.id)
        rows = session.scalars(select(PatchPlanAction).where(PatchPlanAction.analysis_run_id == persisted.id)).all()
        assert rows
        assert all(row.analysis_run_id == persisted.id for row in rows)


def test_historical_analysis_is_immutable_and_rollback_is_safe(database) -> None:
    engine, prefix = database
    with Session(engine) as session:
        project = create_project(session, prefix + "history")
        environment = create_environment(session, project.id, prefix + "env")
        first = persist_analysis(session, _result(str(uuid.uuid4()), "first-" + prefix, 10), _dataset("pypi:" + prefix + "first", 10), project.id, environment.id)
        first_snapshot = get_analysis(session, first.id)
        second = persist_analysis(session, _result(str(uuid.uuid4()), "second-" + prefix, 30), _dataset("pypi:" + prefix + "second", 30), project.id, environment.id)
        assert second.id != first.id
        unchanged = get_analysis(session, first.id)
        assert unchanged["persistence"]["input_snapshot"] == first_snapshot["persistence"]["input_snapshot"]
        assert unchanged["optimization"] == first_snapshot["optimization"]
        assert unchanged["persistence"]["patch_plan_actions"] == first_snapshot["persistence"]["patch_plan_actions"]

        rollback_name = prefix + "rollback"
        try:
            session.add(Project(name=rollback_name))
            session.add(Project(name=rollback_name))
            session.commit()
        except IntegrityError:
            session.rollback()
        assert session.query(Project).filter_by(name=rollback_name).count() == 0
