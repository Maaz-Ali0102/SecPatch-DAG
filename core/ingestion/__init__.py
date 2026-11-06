"""Offline vulnerability intelligence ingestion and normalization."""

from .models import (
    AffectedRange,
    IngestionIssue,
    IngestionResult,
    InstalledPackage,
    PackageIdentity,
    RemediationCandidate,
    VulnerabilityRecord,
)
from .osv import ingest_osv, approve_candidates

__all__ = [
    "AffectedRange",
    "IngestionIssue",
    "IngestionResult",
    "InstalledPackage",
    "PackageIdentity",
    "RemediationCandidate",
    "VulnerabilityRecord",
    "approve_candidates",
    "ingest_osv",
]
