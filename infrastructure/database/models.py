from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base

JSON_TYPE = JSON().with_variant(JSONB, "postgresql")
UUID_TYPE = UUID(as_uuid=True)


def new_id() -> uuid.UUID:
    return uuid.uuid4()


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class Project(TimestampMixin, Base):
    __tablename__ = "projects"
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (UniqueConstraint("name", name="uq_projects_name"),)


class Environment(TimestampMixin, Base):
    __tablename__ = "environments"
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (UniqueConstraint("project_id", "id", name="uq_environments_project_id_id"),
                      UniqueConstraint("project_id", "name", name="uq_environments_project_name"))


class Asset(TimestampMixin, Base):
    __tablename__ = "assets"
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=new_id)
    environment_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("environments.id", ondelete="RESTRICT"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    external_identifier: Mapped[str | None] = mapped_column(String(255))
    operating_system: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON_TYPE, default=dict, nullable=False)
    __table_args__ = (UniqueConstraint("environment_id", "name", name="uq_assets_environment_name"),
                      Index("ix_assets_external_identifier", "external_identifier"))


class Package(TimestampMixin, Base):
    __tablename__ = "packages"
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=new_id)
    ecosystem: Mapped[str] = mapped_column(String(80), nullable=False)
    package_name: Mapped[str] = mapped_column(String(300), nullable=False)
    __table_args__ = (UniqueConstraint("ecosystem", "package_name", name="uq_packages_identity"),)


class InstalledPackage(TimestampMixin, Base):
    __tablename__ = "installed_packages"
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=new_id)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False)
    package_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("packages.id", ondelete="RESTRICT"), nullable=False)
    installed_version: Mapped[str | None] = mapped_column(String(200))
    version_key: Mapped[str] = mapped_column(String(200), nullable=False)
    inventory_source: Mapped[str | None] = mapped_column(String(120))
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("asset_id", "package_id", "version_key", name="uq_installed_asset_package_version"),)


class PackageDependency(Base):
    __tablename__ = "package_dependencies"
    dependent_package_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("packages.id", ondelete="RESTRICT"), primary_key=True)
    prerequisite_package_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("packages.id", ondelete="RESTRICT"), primary_key=True)
    source: Mapped[str | None] = mapped_column(String(120))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON_TYPE, default=dict, nullable=False)


class Vulnerability(TimestampMixin, Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=new_id)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(JSON_TYPE, default=list, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    severity_metadata: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)
    affected_ranges: Mapped[list[dict[str, Any]]] = mapped_column(JSON_TYPE, default=list, nullable=False)
    fixed_versions: Mapped[list[str]] = mapped_column(JSON_TYPE, default=list, nullable=False)
    raw_source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)
    __table_args__ = (UniqueConstraint("source", "source_id", name="uq_vulnerabilities_source_id"),
                      Index("ix_vulnerabilities_source", "source", "source_id"))


class RemediationCandidate(TimestampMixin, Base):
    __tablename__ = "remediation_candidates"
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=new_id)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False)
    installed_package_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("installed_packages.id", ondelete="RESTRICT"), nullable=False)
    fixed_version: Mapped[str | None] = mapped_column(String(200))
    applicability: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="candidate")
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)
    unresolved_issues: Mapped[list[str]] = mapped_column(JSON_TYPE, default=list, nullable=False)
    __table_args__ = (CheckConstraint("applicability IN ('affected', 'unaffected', 'unknown')", name="ck_candidates_applicability"),
                      UniqueConstraint("vulnerability_id", "installed_package_id", "fixed_version", name="uq_candidate_identity"))


class AnalysisRun(TimestampMixin, Base):
    __tablename__ = "analysis_runs"
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=new_id)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    environment_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    optimization_method: Mapped[str] = mapped_column(String(50), nullable=False)
    solver_status: Mapped[str | None] = mapped_column(String(30))
    objective_value: Mapped[int | None] = mapped_column(Integer)
    optimality_proven: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    maintenance_window_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    input_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)
    error_details: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        ForeignKeyConstraint(["environment_id", "project_id"], ["environments.id", "environments.project_id"], ondelete="RESTRICT", name="fk_analysis_environment_project"),
        CheckConstraint("maintenance_window_minutes >= 0", name="ck_analysis_window_nonnegative"),
        Index("ix_analysis_runs_project_created", "project_id", "created_at"),
    )


class PatchAction(TimestampMixin, Base):
    __tablename__ = "patch_actions"
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=new_id)
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("analysis_runs.id", ondelete="RESTRICT"), nullable=False)
    remediation_candidate_id: Mapped[uuid.UUID | None] = mapped_column(UUID_TYPE, ForeignKey("remediation_candidates.id", ondelete="RESTRICT"))
    package_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("packages.id", ondelete="RESTRICT"), nullable=False)
    action_key: Mapped[str] = mapped_column(String(200), nullable=False)
    duration_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    benefit: Mapped[int] = mapped_column(Integer, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    mandatory: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk: Mapped[str] = mapped_column(String(30), nullable=False, default="medium")
    __table_args__ = (
        UniqueConstraint("analysis_run_id", "id", name="uq_patch_actions_run_id"),
        UniqueConstraint("analysis_run_id", "action_key", name="uq_patch_actions_run_key"),
        CheckConstraint("duration_minutes > 0", name="ck_patch_action_duration_positive"),
        CheckConstraint("benefit >= 0 AND priority >= 0", name="ck_patch_action_nonnegative"),
    )


class PatchActionPrerequisite(Base):
    __tablename__ = "patch_action_prerequisites"
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True)
    action_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True)
    prerequisite_action_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True)
    __table_args__ = (
        ForeignKeyConstraint(["analysis_run_id", "action_id"], ["patch_actions.analysis_run_id", "patch_actions.id"], ondelete="RESTRICT", name="fk_prereq_action_same_run"),
        ForeignKeyConstraint(["analysis_run_id", "prerequisite_action_id"], ["patch_actions.analysis_run_id", "patch_actions.id"], ondelete="RESTRICT", name="fk_prereq_target_same_run"),
        CheckConstraint("action_id <> prerequisite_action_id", name="ck_action_prerequisite_not_self"),
    )


class PatchPlan(TimestampMixin, Base):
    __tablename__ = "patch_plans"
    id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True, default=new_id)
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("analysis_runs.id", ondelete="RESTRICT"), nullable=False, unique=True)
    validation_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    validation_violations: Mapped[list[str]] = mapped_column(JSON_TYPE, default=list, nullable=False)
    schedule_summary: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)
    optimization_metadata: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)
    __table_args__ = (
        UniqueConstraint("id", "analysis_run_id", name="uq_patch_plans_id_run"),
    )


class PatchPlanAction(Base):
    __tablename__ = "patch_plan_actions"
    patch_plan_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("patch_plans.id", ondelete="RESTRICT"), primary_key=True)
    analysis_run_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, primary_key=True)
    patch_action_id: Mapped[uuid.UUID] = mapped_column(UUID_TYPE, ForeignKey("patch_actions.id", ondelete="RESTRICT"), primary_key=True)
    execution_order: Mapped[int] = mapped_column(Integer, nullable=False)
    start_offset_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    finish_offset_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    __table_args__ = (
                      ForeignKeyConstraint(["patch_plan_id", "analysis_run_id"], ["patch_plans.id", "patch_plans.analysis_run_id"], ondelete="RESTRICT", name="fk_plan_same_run"),
                      ForeignKeyConstraint(["analysis_run_id", "patch_action_id"], ["patch_actions.analysis_run_id", "patch_actions.id"], ondelete="RESTRICT", name="fk_plan_action_same_run"),
                      UniqueConstraint("patch_plan_id", "execution_order", name="uq_patch_plan_execution_order"),
                      CheckConstraint("start_offset_minutes >= 0 AND finish_offset_minutes >= start_offset_minutes", name="ck_patch_plan_offsets"))
