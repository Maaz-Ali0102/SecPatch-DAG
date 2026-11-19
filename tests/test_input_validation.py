"""Input validation regressions found in the QA probe (QA_REPORT.md, bugs 32-41).

These run without a database: every bad request here must be rejected by
request validation before anything reaches PostgreSQL.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.main import AssetRequest, AssetUpdateRequest, PersistedAnalysisRequest, ProjectRequest, app
from core.ingestion import limits
from core.ingestion.osv import ingest_osv, parse_inventory_strict

client = TestClient(app)
ENV = uuid.uuid4()


def _inventory(**overrides: object) -> dict:
    row = {"asset_id": "srv", "ecosystem": "PyPI", "name": "flask", "version": "1.0"}
    row.update(overrides)
    return {"packages": [row]}


@pytest.mark.parametrize("name", ["   ", "", "a\x00b", "x" * 201])
def test_bad_project_names_are_rejected(name: str) -> None:
    with pytest.raises(ValidationError):
        ProjectRequest(name=name)


def test_names_are_trimmed_so_trailing_spaces_cannot_make_duplicates() -> None:
    assert ProjectRequest(name="  Demo Bank  ").name == "Demo Bank"
    assert AssetRequest(environment_id=ENV, name=" web ", external_identifier=" srv-1 ").external_identifier == "srv-1"


def test_blank_description_becomes_none_and_huge_one_is_rejected() -> None:
    assert ProjectRequest(name="x", description="   ").description is None
    with pytest.raises(ValidationError):
        ProjectRequest(name="x", description="d" * (limits.MAX_DESCRIPTION + 1))


@pytest.mark.parametrize(
    "fields",
    [
        {"external_identifier": "   "},
        {"external_identifier": "x" * 256},
        {"external_identifier": "a", "operating_system": "o" * 121},
        {"external_identifier": "a", "operating_system": "linux\x00"},
        {"external_identifier": "a", "metadata": {"k": "x" * 20_000}},
    ],
)
def test_bad_asset_fields_are_rejected(fields: dict) -> None:
    with pytest.raises(ValidationError):
        AssetRequest(environment_id=ENV, name="a", **fields)


def test_asset_edit_only_sends_the_fields_given() -> None:
    assert AssetUpdateRequest(name="New").model_dump(exclude_unset=True) == {"name": "New"}
    assert AssetUpdateRequest(operating_system="").model_dump(exclude_unset=True) == {"operating_system": None}
    with pytest.raises(ValidationError):
        AssetUpdateRequest(name="   ")


def test_estimate_keys_and_counts_are_limited() -> None:
    with pytest.raises(ValidationError):
        PersistedAnalysisRequest(project_id=ENV, environment_id=ENV, window_minutes=60, estimates={"k" * 1000: {}})


@pytest.mark.parametrize(
    "row",
    [
        {"version": "9" * 201},
        {"version": 1.0},
        {"version": "1.0\x00"},
        {"ecosystem": "E" * 81},
        {"name": "n" * 301},
        {"asset_id": "   "},
    ],
)
def test_strict_inventory_rejects_bad_rows_with_a_clear_message(row: dict) -> None:
    with pytest.raises(ValueError, match="Inventory entry 0"):
        list(parse_inventory_strict(_inventory(**row)["packages"]))


def test_osv_record_count_is_capped() -> None:
    vulns = {"vulns": [{"id": f"V{i}"} for i in range(limits.MAX_OSV_RECORDS + 1)]}
    with pytest.raises(ValueError, match="at most"):
        ingest_osv(vulns, _inventory())


def test_oversized_osv_id_is_reported_not_stored() -> None:
    result = ingest_osv({"vulns": [{"id": "V" * 300, "affected": []}]}, _inventory())
    assert result.vulnerabilities == () or len(result.vulnerabilities) == 0
    assert any(issue.code == "malformed_record" for issue in result.issues)


def test_invalid_fixed_version_goes_to_review_instead_of_guessing() -> None:
    vulns = {"vulns": [{"id": "V1", "affected": [{"package": {"ecosystem": "PyPI", "name": "flask"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9" * 300}]}]}]}]}
    result = ingest_osv(vulns, _inventory())
    (candidate,) = result.candidates
    assert candidate.recommended_fixed_version is None
    assert candidate.unresolved_issues
    assert any(issue.code == "malformed_range_events" for issue in result.issues)


def test_inventory_endpoint_rejects_too_many_rows_before_touching_the_database() -> None:
    rows = [{"asset_id": "srv", "ecosystem": "PyPI", "name": "p", "version": "1"}] * (limits.MAX_INVENTORY_ROWS + 1)
    response = client.post("/api/v1/inventory", json={"environment_id": str(ENV), "packages": rows})
    assert response.status_code == 422


def test_oversized_request_body_gets_413() -> None:
    response = client.post(
        "/api/v1/projects",
        content=b"{}",
        headers={"content-type": "application/json", "content-length": str(limits.MAX_REQUEST_BYTES + 1)},
    )
    assert response.status_code == 413
