"""Input limits shared by the API and the ingestion parsers.

Lengths match the database column sizes, so a value that passes here can
always be stored. Counts keep a single request bounded in time and memory.
"""
from __future__ import annotations

import unicodedata

# Text lengths (characters), mirroring infrastructure/database/models.py
MAX_PROJECT_NAME = 200
MAX_ENVIRONMENT_NAME = 120
MAX_ASSET_NAME = 200
MAX_ASSET_IDENTIFIER = 255
MAX_OPERATING_SYSTEM = 120
MAX_DESCRIPTION = 2_000
MAX_METADATA_BYTES = 10_000
MAX_ECOSYSTEM = 80
MAX_PACKAGE_NAME = 300
MAX_VERSION = 200
MAX_VULNERABILITY_ID = 255
MAX_ESTIMATE_KEY = 600

# Counts per request
MAX_INVENTORY_ROWS = 20_000
MAX_OSV_RECORDS = 5_000
MAX_ESTIMATES = 10_000
MAX_DASHBOARD_WINDOW = 1_440  # minutes (24 hours)
MAX_REQUEST_BYTES = 25 * 1024 * 1024


def text_problem(value: object, max_length: int) -> str | None:
    """Return why a text value is unacceptable, or None if it is fine.

    Rejects non-strings, blank values, values longer than the column, and
    control characters (for example NUL, which PostgreSQL cannot store and
    which can hide content in logs and reports).
    """
    if not isinstance(value, str):
        return "must be text"
    if not value.strip():
        return "cannot be blank"
    if len(value) > max_length:
        return f"must be at most {max_length} characters"
    if any(unicodedata.category(character) == "Cc" for character in value):
        return "contains control characters"
    return None


def clean_text(value: str, field: str, max_length: int) -> str:
    """Trim surrounding spaces and validate; raise ValueError with a plain message."""
    stripped = value.strip() if isinstance(value, str) else value
    problem = text_problem(stripped, max_length)
    if problem:
        raise ValueError(f"{field} {problem}")
    return stripped
