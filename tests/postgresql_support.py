from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, text


def load_project_environment() -> None:
    if os.getenv("DATABASE_URL"):
        return
    env_path = Path(__file__).parents[1] / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() and not key.lstrip().startswith("#"):
            os.environ.setdefault(key.strip(), value.strip())


def postgres_engine() -> Engine:
    load_project_environment()
    url = os.getenv("DATABASE_URL")
    if not url:
        pytest.skip("PostgreSQL tests skipped: DATABASE_URL is not configured")
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with engine.connect() as connection:
            database = connection.execute(text("SELECT current_database()")).scalar_one()
            if database != "secpatch_test":
                pytest.fail(f"PostgreSQL tests require database secpatch_test, connected to {database!r}")
        return engine
    except pytest.SkipTest:
        raise
    except Exception as error:
        pytest.skip(f"PostgreSQL tests skipped: unable to connect ({type(error).__name__})")


def cleanup_prefix(engine: Engine, prefix: str) -> None:
    with engine.begin() as connection:
        project_ids = connection.execute(
            text("SELECT id FROM projects WHERE name LIKE :prefix"),
            {"prefix": f"{prefix}%"},
        ).scalars().all()
        if project_ids:
            params = {"project_ids": project_ids}
            connection.execute(text(
                "DELETE FROM patch_plan_actions "
                "WHERE analysis_run_id IN (SELECT id FROM analysis_runs WHERE project_id = ANY(:project_ids))"
            ), params)
            connection.execute(text(
                "DELETE FROM patch_plans "
                "WHERE analysis_run_id IN (SELECT id FROM analysis_runs WHERE project_id = ANY(:project_ids))"
            ), params)
            connection.execute(text(
                "DELETE FROM patch_action_prerequisites "
                "WHERE analysis_run_id IN (SELECT id FROM analysis_runs WHERE project_id = ANY(:project_ids))"
            ), params)
            connection.execute(text(
                "DELETE FROM patch_actions "
                "WHERE analysis_run_id IN (SELECT id FROM analysis_runs WHERE project_id = ANY(:project_ids))"
            ), params)
            connection.execute(text("DELETE FROM analysis_runs WHERE project_id = ANY(:project_ids)"), params)
            connection.execute(text(
                "DELETE FROM remediation_candidates "
                "WHERE installed_package_id IN ("
                "SELECT ip.id FROM installed_packages ip "
                "JOIN assets a ON a.id = ip.asset_id "
                "JOIN environments e ON e.id = a.environment_id "
                "WHERE e.project_id = ANY(:project_ids))"
            ), params)
            connection.execute(text(
                "DELETE FROM installed_packages WHERE asset_id IN "
                "(SELECT a.id FROM assets a JOIN environments e ON e.id = a.environment_id "
                "WHERE e.project_id = ANY(:project_ids))"
            ), params)
            connection.execute(text(
                "DELETE FROM assets WHERE environment_id IN "
                "(SELECT id FROM environments WHERE project_id = ANY(:project_ids))"
            ), params)
            connection.execute(text("DELETE FROM environments WHERE project_id = ANY(:project_ids)"), params)
            connection.execute(text("DELETE FROM projects WHERE id = ANY(:project_ids)"), params)
        connection.execute(text(
            "DELETE FROM vulnerabilities WHERE source = 'osv' AND source_id LIKE :prefix"
        ), {"prefix": f"{prefix}%"})
        connection.execute(text(
            "DELETE FROM packages WHERE package_name LIKE :prefix"
        ), {"prefix": f"{prefix}%"})


def isolated_prefix() -> str:
    import uuid

    return f"phase5c_test_{uuid.uuid4().hex[:12]}_"


def managed_engine() -> Iterator[tuple[Engine, str]]:
    engine = postgres_engine()
    prefix = isolated_prefix()
    try:
        yield engine, prefix
    finally:
        cleanup_prefix(engine, prefix)
        engine.dispose()
