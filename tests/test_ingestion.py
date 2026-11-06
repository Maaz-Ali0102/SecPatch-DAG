import json
from pathlib import Path

import pytest

from core.engine import run_analysis
from core.ingestion.osv import approve_candidates, ingest_osv
from core.ingestion.versioning import compare_versions, version_in_range


ROOT = Path(__file__).parents[1]
DIAGNOSTIC_DATA_ROOT = ROOT.parent / "secpatch_dag_diagnostic_data" / "secpatch_dag_diagnostic_data" / "datasets"


def fixture(name: str) -> dict:
    return json.loads((ROOT / "datasets" / "samples" / name).read_text(encoding="utf-8"))


def test_offline_osv_inventory_to_cp_sat_pipeline() -> None:
    result = ingest_osv(fixture("osv_offline.json"), fixture("inventory_offline.json"))
    approved = approve_candidates(result, fixture("approved_estimates.json"))
    assert result.vulnerabilities[0].vulnerability_id == "OSV-DEMO-2026-0001"
    assert result.vulnerabilities[0].aliases == ("CVE-2026-0001", "GHSA-demo-0001")
    candidate = next(item for item in approved.candidates if item.asset_id == "asset-api")
    assert candidate.applicability == "affected"
    assert candidate.recommended_fixed_version == "1.10.0"
    assert approved.approved_dataset is not None
    analysis = run_analysis(approved.approved_dataset, 30, "cp_sat")
    assert analysis["optimization"]["solver_status"] == "OPTIMAL"
    assert analysis["validation"]["valid"]
    assert analysis["schedule"]["entries"][0]["action_id"] == "patch-demo-lib-1-10"


def test_affected_unaffected_and_unknown_inventory_versions() -> None:
    result = ingest_osv(fixture("osv_offline.json"), fixture("inventory_offline.json"))
    candidates = {candidate.asset_id: candidate for candidate in result.candidates if candidate.vulnerability_id == "OSV-DEMO-2026-0001"}
    assert candidates["asset-api"].applicability == "affected"
    assert "asset-worker" not in candidates
    assert candidates["asset-unknown"].applicability == "unknown"
    assert "missing_installed_version" in candidates["asset-unknown"].unresolved_issues


def test_missing_fixed_version_is_preserved_and_not_approved() -> None:
    result = ingest_osv(fixture("osv_offline.json"), fixture("inventory_offline.json"))
    candidate = next(item for item in result.candidates if item.vulnerability_id == "OSV-DEMO-2026-0002")
    assert candidate.recommended_fixed_version is None
    assert "missing_fixed_version" in candidate.unresolved_issues
    approved = approve_candidates(result, {"asset-api:OSV-DEMO-2026-0002": {"duration_minutes": 5, "benefit": 5}})
    assert approved.approved_dataset is not None
    assert approved.approved_dataset.actions == ()
    assert any(issue.code == "missing_fixed_version" for issue in approved.issues)


def test_malformed_unsupported_duplicate_and_conflict_records_are_reported() -> None:
    payload = {
        "vulns": [
            {"id": "OSV-1", "affected": [{"package": {"ecosystem": "PyPI", "name": "demo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]},
            {"id": "OSV-1", "affected": [{"package": {"ecosystem": "PyPI", "name": "demo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]},
            {"id": "OSV-1", "affected": [{"package": {"ecosystem": "PyPI", "name": "demo"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "3.0.0"}]}]}]},
            {"id": "OSV-BAD", "affected": []},
            {"id": "OSV-UNSUPPORTED", "affected": [{"package": {"ecosystem": "Unknown", "name": "demo"}, "ranges": [{"type": "GIT", "events": []}]}]},
        ]
    }
    result = ingest_osv(payload, {"packages": [{"asset_id": "a", "ecosystem": "PyPI", "name": "demo", "version": "1.5.0"}]})
    codes = {issue.code for issue in result.issues}
    assert {"duplicate_record", "conflicting_fixed_versions", "malformed_record", "unsupported_version_range"} <= codes
    assert len(result.vulnerabilities) == 2


def test_invalid_inventory_is_reported_without_silent_discard() -> None:
    result = ingest_osv({"vulns": []}, {"packages": [
        {"asset_id": "bad"},
        {"asset_id": "bad", "ecosystem": "PyPI", "name": "x", "version": "1.0"},
        {"asset_id": "good", "ecosystem": "PyPI", "name": "x", "version": 1.0},
    ]})
    assert sum(issue.code == "invalid_inventory" for issue in result.issues) == 2


def test_baseline_inventory_preserves_multiple_packages_per_asset() -> None:
    baseline = DIAGNOSTIC_DATA_ROOT / "baseline"
    if not baseline.exists():
        pytest.skip("Supplied diagnostic baseline dataset is not available")

    result = ingest_osv(
        json.loads((baseline / "osv_offline.json").read_text(encoding="utf-8")),
        json.loads((baseline / "inventory_offline.json").read_text(encoding="utf-8")),
    )

    assert len(result.inventory) == 10
    assert not any(issue.code == "duplicate_inventory" for issue in result.issues)
    assert {
        (item.asset_id, item.package.key, item.version)
        for item in result.inventory
    } == {
        ("asset-api-prod", "PyPI:requests", "2.27.0"),
        ("asset-api-prod", "PyPI:urllib3", "1.26.5"),
        ("asset-api-prod", "PyPI:certifi", "2022.6.15"),
        ("asset-worker-prod", "PyPI:requests", "2.31.0"),
        ("asset-worker-prod", "PyPI:cryptography", "38.0.0"),
        ("asset-admin", "npm:lodash", "4.17.15"),
        ("asset-admin", "npm:express", "4.18.2"),
        ("asset-batch", "PyPI:pyyaml", "5.3.1"),
        ("asset-batch", "PyPI:jinja2", "3.1.3"),
        ("asset-legacy", "PyPI:requests", None),
    }
    assert {
        candidate.vulnerability_id
        for candidate in result.candidates
    } == {
        "OSV-TEST-BASE-0001",
        "OSV-TEST-BASE-0002",
        "OSV-TEST-BASE-0003",
        "OSV-TEST-BASE-0004",
        "OSV-TEST-BASE-0005",
    }


def test_exact_duplicate_inventory_entry_is_reported() -> None:
    result = ingest_osv(
        {"vulns": []},
        {"packages": [
            {"asset_id": "asset", "ecosystem": "PyPI", "name": "demo", "version": "1.0.0"},
            {"asset_id": "asset", "ecosystem": "PyPI", "name": "demo", "version": "1.0.0"},
        ]},
    )

    assert len(result.inventory) == 1
    assert sum(issue.code == "duplicate_inventory" for issue in result.issues) == 1


def test_valid_estimates_create_one_action_per_eligible_candidate() -> None:
    result = ingest_osv({
        "vulns": [
            {"id": "OSV-A", "affected": [{"package": {"ecosystem": "npm", "name": "a"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]},
            {"id": "OSV-B", "affected": [{"package": {"ecosystem": "npm", "name": "b"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]},
        ]
    }, {"packages": [
        {"asset_id": "a1", "ecosystem": "npm", "name": "a", "version": "1.5.0"},
        {"asset_id": "b1", "ecosystem": "npm", "name": "b", "version": "1.5.0"},
    ]})

    approved = approve_candidates(result, {
        "a1:OSV-A": {"id": "patch-a", "duration_minutes": 5, "benefit": 10},
        "b1:OSV-B": {"id": "patch-b", "duration_minutes": 7, "benefit": 20},
    })

    assert approved.approved_dataset is not None
    assert [(action.id, action.package_id) for action in approved.approved_dataset.actions] == [
        ("patch-a", "npm:a"),
        ("patch-b", "npm:b"),
    ]


def test_missing_or_mismatched_estimates_do_not_create_actions() -> None:
    result = ingest_osv({
        "vulns": [{"id": "OSV-A", "affected": [{"package": {"ecosystem": "npm", "name": "a"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]}]
    }, {"packages": [{"asset_id": "a1", "ecosystem": "npm", "name": "a", "version": "1.5.0"}]})

    approved = approve_candidates(result, {"wrong-asset:OSV-A": {"duration_minutes": 5, "benefit": 10}})

    assert approved.approved_dataset is not None
    assert approved.approved_dataset.actions == ()


def test_invalid_estimate_is_reported_without_fabricating_action() -> None:
    result = ingest_osv({
        "vulns": [{"id": "OSV-A", "affected": [{"package": {"ecosystem": "npm", "name": "a"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]}]
    }, {"packages": [{"asset_id": "a1", "ecosystem": "npm", "name": "a", "version": "1.5.0"}]})

    approved = approve_candidates(result, {"a1:OSV-A": {"duration_minutes": "five", "benefit": 10}})

    assert approved.approved_dataset is None
    assert any(issue.code in {"invalid_planning_estimate", "invalid_approved_dataset"} for issue in approved.issues)


def test_unknown_applicability_remains_unapproved_even_with_estimate() -> None:
    result = ingest_osv({
        "vulns": [{"id": "OSV-A", "affected": [{"package": {"ecosystem": "npm", "name": "a"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]}]
    }, {"packages": [{"asset_id": "a1", "ecosystem": "npm", "name": "a"}]})

    approved = approve_candidates(result, {"a1:OSV-A": {"duration_minutes": 5, "benefit": 10}})

    assert approved.approved_dataset is not None
    assert approved.approved_dataset.actions == ()
    assert next(iter(approved.candidates)).applicability == "unknown"


def test_version_boundaries_and_supported_schemes() -> None:
    assert compare_versions("npm", "1.9.0", "1.10.0") < 0
    assert compare_versions("npm", "1.10.0-beta.1", "1.10.0") < 0
    assert compare_versions("npm", "1.10.0", "1.10.0") == 0
    assert compare_versions("Unknown", "1.0", "2.0") is None
    assert version_in_range("npm", "1.9.0", {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.10.0"}]}).value is True
    assert version_in_range("npm", "1.10.0", {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.10.0"}]}).value is False
    assert version_in_range("npm", "bad", {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}).value is None


def test_package_dependencies_do_not_create_patch_prerequisites() -> None:
    result = ingest_osv({
        "vulns": [
            {"id": "OSV-A", "affected": [{"package": {"ecosystem": "npm", "name": "a"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]},
            {"id": "OSV-B", "affected": [{"package": {"ecosystem": "npm", "name": "b"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]},
        ]
    }, {"packages": [
        {"asset_id": "a1", "ecosystem": "npm", "name": "a", "version": "1.5.0"},
        {"asset_id": "b1", "ecosystem": "npm", "name": "b", "version": "1.5.0"},
    ]}, dependencies=(("npm:b", "npm:a"),))
    approved = approve_candidates(result, {
        "a1:OSV-A": {"duration_minutes": 1, "benefit": 1},
        "b1:OSV-B": {"duration_minutes": 1, "benefit": 1},
    })
    assert approved.approved_dataset is not None
    assert all(not action.prerequisites for action in approved.approved_dataset.actions)
    assert approved.approved_dataset.dependencies == (("npm:b", "npm:a"),)


def test_conflicting_fixed_versions_are_not_approved() -> None:
    result = ingest_osv({
        "vulns": [{"id": "OSV-C", "affected": [{"package": {"ecosystem": "npm", "name": "c"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "3.0.0"}, {"fixed": "4.0.0"}]},
        ]}]}]
    }, {"packages": [{"asset_id": "c1", "ecosystem": "npm", "name": "c", "version": "1.5.0"}]})
    approved = approve_candidates(result, {"c1:OSV-C": {"duration_minutes": 1, "benefit": 1}})
    assert approved.approved_dataset is not None
    assert approved.approved_dataset.actions == ()
    assert "conflicting_fixed_versions" in next(iter(approved.candidates)).unresolved_issues
