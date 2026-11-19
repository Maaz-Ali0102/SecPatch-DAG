"""Regression tests for defects found during the November 2026 QA pass.

Each test fails on the code as it was before the fix.
"""
from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from application.persistence import (
    NotFoundError,
    create_environment,
    create_project,
    execute_persisted_analysis,
    import_inventory,
    persist_ingestion,
    register_asset,
)
from core.engine import run_analysis
from core.graph import analyze_graph
from core.ingestion.models import InstalledPackage as CoreInstalled, PackageIdentity
from core.ingestion.osv import approve_candidates, ingest_osv
from core.ingestion.versioning import compare_versions, version_in_range
from core.models import MAX_ESTIMATE_VALUE, Dataset
from infrastructure.database.base import Base
from infrastructure.database.models import InstalledPackage, RemediationCandidate


def vuln(vuln_id: str, *affected: tuple[str, str, list[dict[str, str]]]) -> dict:
    return {"id": vuln_id, "affected": [
        {"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}
        for eco, name, events in affected
    ]}


def inventory(*rows: tuple[str, str, str, str | None]) -> dict:
    return {"packages": [
        {"asset_id": asset, "ecosystem": eco, "name": name, **({"version": version} if version else {})}
        for asset, eco, name, version in rows
    ]}


# --- Version matching -----------------------------------------------------

def test_range_with_two_branches_does_not_hide_the_first_branch() -> None:
    events = [{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"fixed": "2.3"}]
    assert version_in_range("PyPI", "1.2", {"type": "ECOSYSTEM", "events": events}).value is True
    assert version_in_range("PyPI", "1.7", {"type": "ECOSYSTEM", "events": events}).value is False
    assert version_in_range("PyPI", "2.1", {"type": "ECOSYSTEM", "events": events}).fixed_version == "2.3"
    assert version_in_range("PyPI", "2.3", {"type": "ECOSYSTEM", "events": events}).value is False


def test_unsorted_events_are_evaluated_in_version_order() -> None:
    events = [{"fixed": "2.3"}, {"introduced": "2.0"}, {"fixed": "1.5"}, {"introduced": "1.0"}]
    check = version_in_range("PyPI", "1.2", {"type": "ECOSYSTEM", "events": events})
    assert (check.value, check.fixed_version) == (True, "1.5")


def test_last_affected_is_inclusive() -> None:
    events = [{"introduced": "0"}, {"last_affected": "1.4.0"}]
    assert version_in_range("npm", "1.4.0", {"type": "ECOSYSTEM", "events": events}).value is True
    assert version_in_range("npm", "1.4.1", {"type": "ECOSYSTEM", "events": events}).value is False


def test_range_without_introduced_is_unknown_not_unaffected() -> None:
    result = ingest_osv({"vulns": [vuln("X", ("PyPI", "requests", [{"fixed": "2.28.0"}]))]}, inventory(("a", "PyPI", "requests", "2.27.0")))
    assert [(c.applicability, c.unresolved_issues) for c in result.candidates] == [("unknown", ("range_missing_introduced",))]
    assert any(issue.code == "malformed_range_events" for issue in result.issues)


def test_semver_prerelease_numeric_identifiers_compare_numerically() -> None:
    assert compare_versions("npm", "1.0.0-rc.10", "1.0.0-rc.2") == 1
    assert compare_versions("npm", "1.0.0-alpha", "1.0.0-alpha.1") == -1
    assert compare_versions("npm", "1.0.0-alpha.1", "1.0.0-alpha.beta") == -1
    assert compare_versions("npm", "1.0.0-beta.11", "1.0.0-rc.1") == -1


def test_osv_record_with_several_packages_matches_every_package() -> None:
    payload = {"vulns": [vuln("X", ("PyPI", "pkga", [{"introduced": "0"}, {"fixed": "1.0"}]), ("npm", "pkgb", [{"introduced": "0"}, {"fixed": "3.0.0"}]))]}
    result = ingest_osv(payload, inventory(("a", "npm", "pkgb", "2.0.0"), ("b", "PyPI", "pkga", "0.5")))
    found = {(c.asset_id, c.package.key, c.recommended_fixed_version) for c in result.candidates}
    assert found == {("a", "npm:pkgb", "3.0.0"), ("b", "PyPI:pkga", "1.0")}


def test_pypi_names_and_ecosystem_case_are_normalized_for_matching() -> None:
    payload = {"vulns": [vuln("X", ("PyPI", "Django", [{"introduced": "0"}, {"fixed": "4.0"}])), vuln("Y", ("PyPI", "zope.interface", [{"introduced": "0"}, {"fixed": "6.0"}]))]}
    result = ingest_osv(payload, inventory(("a", "pypi", "django", "3.0"), ("a", "PyPI", "Zope_Interface", "5.0")))
    assert {(c.vulnerability_id, c.applicability) for c in result.candidates} == {("X", "affected"), ("Y", "affected")}
    # Candidates carry the installed spelling so persistence finds the row.
    assert {c.package.name for c in result.candidates} == {"django", "Zope_Interface"}


def test_several_installed_versions_on_one_asset_give_one_action() -> None:
    payload = {"vulns": [vuln("X", ("PyPI", "requests", [{"introduced": "0"}, {"fixed": "2.28.0"}]))]}
    result = ingest_osv(payload, inventory(("a", "PyPI", "requests", "2.20.0"), ("a", "PyPI", "requests", "2.25.0")))
    assert len(result.candidates) == 1
    approved = approve_candidates(result, {"a:X": {"duration_minutes": 5, "benefit": 5}})
    assert [action.id for action in approved.approved_dataset.actions] == ["a:X"]


# --- Core planning ---------------------------------------------------------

def test_long_prerequisite_chain_does_not_hit_recursion_limit() -> None:
    actions = [{"id": f"a{i}", "package_id": "p", "duration_minutes": 1, "benefit": 1, "prerequisites": [f"a{i - 1}"] if i else []} for i in range(3000)]
    dataset = Dataset.from_dict({"packages": ["p"], "actions": actions})
    result = run_analysis(dataset, 5000, "precedence_greedy")
    assert result["optimization"]["objective_value"] == 3000
    assert result["validation"]["valid"]


def test_long_dependency_chain_does_not_hit_recursion_limit() -> None:
    nodes = tuple(f"p{i:05d}" for i in range(5000))
    edges = tuple((nodes[i], nodes[i + 1]) for i in range(len(nodes) - 1))
    graph = analyze_graph(nodes, edges)
    assert len(graph.components) == 5000 and not graph.cyclic_components


def test_out_of_range_numbers_are_rejected_not_crashing_the_solver() -> None:
    with pytest.raises(ValueError):
        Dataset.from_dict({"packages": ["p"], "actions": [{"id": "a", "package_id": "p", "duration_minutes": 1, "benefit": MAX_ESTIMATE_VALUE + 1}]})
    dataset = Dataset.from_dict({"packages": ["p"], "actions": [{"id": "a", "package_id": "p", "duration_minutes": 1, "benefit": 1}]})
    with pytest.raises(ValueError):
        run_analysis(dataset, 2**63, "cp_sat")


def test_mandatory_must_be_a_real_boolean() -> None:
    with pytest.raises(ValueError):
        Dataset.from_dict({"packages": ["p"], "actions": [{"id": "a", "package_id": "p", "duration_minutes": 1, "benefit": 1, "mandatory": "false"}]})


# --- Persisted workflow (SQLite) ---------------------------------------------

@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        Base.metadata.create_all(connection)
        with Session(bind=connection) as value:
            yield value


def _workspace(session: Session, osv: dict, inv: dict):
    project = create_project(session, "qa")
    environment = create_environment(session, project.id, "prod")
    lookup = {}
    for asset_id in sorted({row["asset_id"] for row in inv["packages"]}):
        lookup[asset_id] = register_asset(session, environment.id, asset_id, asset_id)
    result = ingest_osv(osv, inv)
    import_inventory(session, environment.id, list(result.inventory), lookup)
    persist_ingestion(session, result, lookup)
    return project, environment


BASIC_OSV = {"vulns": [vuln("X", ("PyPI", "requests", [{"introduced": "0"}, {"fixed": "2.28.0"}]))]}
BASIC_INV = inventory(("a", "PyPI", "requests", "2.27.0"), ("legacy", "PyPI", "requests", None))


@pytest.mark.parametrize("estimate", [
    {"duration_minutes": 10, "benefit": 10.5},
    {"duration_minutes": "10", "benefit": 5},
    {"duration_minutes": 0, "benefit": 5},
    {"duration_minutes": 10, "benefit": -1},
    {"duration_minutes": 10, "benefit": 5, "prerequisites": ["missing"]},
    {"duration_minutes": 10},
])
def test_persisted_analysis_rejects_invalid_estimates(session: Session, estimate: dict) -> None:
    project, environment = _workspace(session, BASIC_OSV, BASIC_INV)
    with pytest.raises(ValueError):
        execute_persisted_analysis(session, project.id, environment.id, 60, "cp_sat", {"a:X": estimate})


def test_persisted_analysis_reports_ignored_estimates(session: Session) -> None:
    project, environment = _workspace(session, BASIC_OSV, BASIC_INV)
    result = execute_persisted_analysis(session, project.id, environment.id, 60, "cp_sat", {
        "a:X": {"duration_minutes": 10, "benefit": 5},
        "legacy:X": {"duration_minutes": 10, "benefit": 5},
        "typo:X": {"duration_minutes": 10, "benefit": 5},
    })
    assert result["estimate_review"]["applied"] == ["a:X"]
    assert set(result["estimate_review"]["ignored"]) == {"legacy:X", "typo:X"}
    assert result["optimization"]["objective_value"] == 5


def test_candidate_is_linked_to_the_affected_installed_version(session: Session) -> None:
    inv = inventory(("a", "PyPI", "requests", "2.31.0"), ("a", "PyPI", "requests", "2.27.0"))
    _workspace(session, BASIC_OSV, inv)
    candidate = session.query(RemediationCandidate).one()
    assert session.get(InstalledPackage, candidate.installed_package_id).installed_version == "2.27.0"


def test_two_affected_versions_on_one_asset_do_not_crash_analysis(session: Session) -> None:
    inv = inventory(("a", "PyPI", "requests", "2.20.0"), ("a", "PyPI", "requests", "2.25.0"))
    project, environment = _workspace(session, BASIC_OSV, inv)
    result = execute_persisted_analysis(session, project.id, environment.id, 60, "cp_sat", {"a:X": {"duration_minutes": 10, "benefit": 5}})
    assert [action["id"] for action in result["optimization"]["selected_actions"]] == ["a:X"]


def test_dependency_edges_from_other_environments_do_not_break_analysis(session: Session) -> None:
    from infrastructure.database.models import Package, PackageDependency
    project, environment = _workspace(session, BASIC_OSV, BASIC_INV)
    other = [Package(ecosystem="npm", package_name="left"), Package(ecosystem="npm", package_name="right")]
    session.add_all(other)
    session.flush()
    other_environment = create_environment(session, project.id, "other")
    session.add(PackageDependency(environment_id=other_environment.id, dependent_package_id=other[0].id, prerequisite_package_id=other[1].id))
    session.commit()
    result = execute_persisted_analysis(session, project.id, environment.id, 60, "cp_sat", {"a:X": {"duration_minutes": 10, "benefit": 5}})
    assert result["optimization"]["objective_value"] == 5


def test_environment_for_unknown_project_is_not_found(session: Session) -> None:
    import uuid
    with pytest.raises(NotFoundError):
        create_environment(session, uuid.uuid4(), "prod")


# --- Configuration ------------------------------------------------------------

def test_database_url_is_read_from_dotenv(tmp_path, monkeypatch) -> None:
    from infrastructure.database import session as session_module
    env_file = tmp_path / ".env"
    env_file.write_text('# comment\nDATABASE_URL="postgresql+psycopg://u:p@db:5432/x"\n', encoding="utf-8")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    session_module.load_dotenv(env_file)
    assert os.environ["DATABASE_URL"] == "postgresql+psycopg://u:p@db:5432/x"


# --- Duplicate names / identifiers (found in user-style UI testing) ---------

def test_duplicate_asset_external_identifier_is_rejected(session: Session) -> None:
    from application.persistence import ConflictError
    project = create_project(session, "dup")
    environment = create_environment(session, project.id, "prod")
    register_asset(session, environment.id, "Host A", "host-1")
    with pytest.raises(ConflictError):
        register_asset(session, environment.id, "Host B", "host-1")
    with pytest.raises(ConflictError):
        register_asset(session, environment.id, "Host A", "host-2")
    other = create_environment(session, project.id, "staging")
    register_asset(session, other.id, "Host A", "host-1")  # same ID in another environment is fine


def test_duplicate_project_and_environment_names_are_conflicts(session: Session) -> None:
    from application.persistence import ConflictError
    project = create_project(session, "same")
    with pytest.raises(ConflictError):
        create_project(session, "same")
    create_environment(session, project.id, "prod")
    with pytest.raises(ConflictError):
        create_environment(session, project.id, "prod")


def test_asset_can_be_edited_and_keeps_its_inventory(session: Session) -> None:
    from application.persistence import update_asset
    project, environment = _workspace(session, BASIC_OSV, BASIC_INV)
    from infrastructure.database.models import Asset
    asset = session.get(Asset, session.query(InstalledPackage).first().asset_id)
    updated = update_asset(session, asset.id, {"name": "Renamed", "external_identifier": "renamed-1", "operating_system": "ubuntu"})
    assert (updated.name, updated.external_identifier, updated.operating_system) == ("Renamed", "renamed-1", "ubuntu")
    assert session.query(InstalledPackage).filter_by(asset_id=asset.id).count() >= 1


# --- Delete, dependencies, re-import (2026-11-17) ------------------------------

TWO_OSV = {"vulns": [
    vuln("X", ("PyPI", "requests", [{"introduced": "0"}, {"fixed": "2.28.0"}])),
    vuln("Y", ("PyPI", "urllib3", [{"introduced": "0"}, {"fixed": "1.26.5"}])),
]}
TWO_INV = inventory(("a", "PyPI", "requests", "2.27.0"), ("a", "PyPI", "urllib3", "1.26.0"))
TWO_ESTIMATES = {"a:X": {"duration_minutes": 10, "benefit": 5}, "a:Y": {"duration_minutes": 10, "benefit": 7}}


def test_dependency_cycle_blocks_its_patches_and_clearing_it_unblocks(session: Session) -> None:
    from application.persistence import environment_graph, import_dependencies
    project, environment = _workspace(session, TWO_OSV, TWO_INV)
    assert import_dependencies(session, environment.id, [{"from": "PyPI:requests", "to": "PyPI:urllib3"}]) == 1
    graph = environment_graph(session, environment.id)["graph"]
    assert graph["edges"] and graph["cyclic_components"] == []
    assert graph["topological_order"].index("PyPI:urllib3") < graph["topological_order"].index("PyPI:requests")
    assert execute_persisted_analysis(session, project.id, environment.id, 60, "dynamic_programming", TWO_ESTIMATES)["optimization"]["objective_value"] == 12
    import_dependencies(session, environment.id, [{"from": "PyPI:requests", "to": "PyPI:urllib3"}, {"from": "PyPI:urllib3", "to": "PyPI:requests"}])
    result = execute_persisted_analysis(session, project.id, environment.id, 60, "dynamic_programming", TWO_ESTIMATES)
    assert result["optimization"]["objective_value"] == 0
    assert result["graph"]["cyclic_components"] == [["PyPI:requests", "PyPI:urllib3"]]
    import_dependencies(session, environment.id, [])
    assert execute_persisted_analysis(session, project.id, environment.id, 60, "dynamic_programming", TWO_ESTIMATES)["optimization"]["objective_value"] == 12


def test_dependency_names_match_like_inventory_and_unknown_packages_are_rejected(session: Session) -> None:
    from application.persistence import import_dependencies
    _, environment = _workspace(session, TWO_OSV, TWO_INV)
    assert import_dependencies(session, environment.id, [{"from": "pypi:Requests", "to": "PyPI:urllib3"}]) == 1
    with pytest.raises(ValueError, match="not installed"):
        import_dependencies(session, environment.id, [{"from": "PyPI:requests", "to": "PyPI:nope"}])
    with pytest.raises(ValueError, match="ecosystem:name"):
        import_dependencies(session, environment.id, [{"from": "requests"}])


def test_dependencies_do_not_leak_into_other_environments(session: Session) -> None:
    from application.persistence import environment_graph, import_dependencies
    project, environment = _workspace(session, TWO_OSV, TWO_INV)
    import_dependencies(session, environment.id, [{"from": "PyPI:requests", "to": "PyPI:urllib3"}, {"from": "PyPI:urllib3", "to": "PyPI:requests"}])
    other = create_environment(session, project.id, "staging")
    asset = register_asset(session, other.id, "a", "a")
    result = ingest_osv(TWO_OSV, TWO_INV)
    import_inventory(session, other.id, list(result.inventory), {"a": asset})
    persist_ingestion(session, result, {"a": asset})
    assert environment_graph(session, other.id)["graph"]["edges"] == []
    assert execute_persisted_analysis(session, project.id, other.id, 60, "cp_sat", TWO_ESTIMATES)["optimization"]["objective_value"] == 12


def test_deleted_server_leaves_analysis_and_frees_its_identifier(session: Session) -> None:
    from application.persistence import delete_asset, list_analyses
    from infrastructure.database.repositories import AssetRepository
    project, environment = _workspace(session, TWO_OSV, TWO_INV)
    execute_persisted_analysis(session, project.id, environment.id, 60, "cp_sat", TWO_ESTIMATES)
    asset = AssetRepository().list(session, environment.id)[0]
    delete_asset(session, asset.id)
    assert AssetRepository().list(session, environment.id) == []
    result = execute_persisted_analysis(session, project.id, environment.id, 60, "cp_sat", TWO_ESTIMATES)
    assert result["optimization"]["objective_value"] == 0
    assert set(result["estimate_review"]["ignored"]) == {"a:X", "a:Y"}
    assert register_asset(session, environment.id, "a", "a").external_identifier == "a"
    assert len(list_analyses(session, project.id)) == 2  # history kept


def test_deleted_project_is_hidden_and_its_name_can_be_reused(session: Session) -> None:
    from application.persistence import delete_project
    from infrastructure.database.repositories import EnvironmentRepository, ProjectRepository
    project, environment = _workspace(session, TWO_OSV, TWO_INV)
    delete_project(session, project.id)
    assert ProjectRepository().list(session) == []
    assert EnvironmentRepository().get(session, environment.id) is None
    with pytest.raises(NotFoundError):
        delete_project(session, project.id)
    assert create_project(session, "qa").name == "qa"


def test_reimporting_the_same_osv_file_does_not_duplicate_candidates(session: Session) -> None:
    from sqlalchemy import func, select
    project, environment = _workspace(session, TWO_OSV, TWO_INV)
    lookup = {"a": __import__("infrastructure.database.repositories", fromlist=["AssetRepository"]).AssetRepository().list(session, environment.id)[0]}
    before = session.scalar(select(func.count()).select_from(RemediationCandidate))
    persist_ingestion(session, ingest_osv(TWO_OSV, TWO_INV), lookup)
    assert session.scalar(select(func.count()).select_from(RemediationCandidate)) == before
