"""Keep the latest advisory coverage report for each environment."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003_advisory_check"
down_revision = "0002_archive_scoped_deps"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("environments", sa.Column("advisory_check", sa.JSON().with_variant(JSONB, "postgresql"), nullable=True))


def downgrade():
    op.drop_column("environments", "advisory_check")
