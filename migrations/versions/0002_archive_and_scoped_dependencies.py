"""Soft delete for projects, environments and assets; per-environment dependencies.

Before this revision there was no way to create package dependencies, so the
old global table is replaced rather than migrated.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_archive_scoped_deps"
down_revision = "0001_initial"
branch_labels = None
depends_on = None
UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB


def upgrade() -> None:
    for table in ("projects", "environments", "assets"):
        op.add_column(table, sa.Column("archived_at", sa.DateTime(timezone=True)))
    op.drop_table("package_dependencies")
    op.create_table(
        "package_dependencies",
        sa.Column("environment_id", UUID, sa.ForeignKey("environments.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("dependent_package_id", UUID, sa.ForeignKey("packages.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("prerequisite_package_id", UUID, sa.ForeignKey("packages.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("source", sa.String(120)),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )


def downgrade() -> None:
    op.drop_table("package_dependencies")
    op.create_table(
        "package_dependencies",
        sa.Column("dependent_package_id", UUID, sa.ForeignKey("packages.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("prerequisite_package_id", UUID, sa.ForeignKey("packages.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("source", sa.String(120)),
        sa.Column("metadata", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    for table in ("assets", "environments", "projects"):
        op.drop_column(table, "archived_at")
