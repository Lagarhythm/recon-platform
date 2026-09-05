"""add scan module coverage metadata

Revision ID: aa92f0d4b3c1
Revises: 480531f44b24
Create Date: 2026-09-05
"""

from alembic import op
import sqlalchemy as sa

revision = "aa92f0d4b3c1"
down_revision = "480531f44b24"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scan_module_run") as batch_op:
        batch_op.add_column(sa.Column("coverage_metadata", sa.JSON(), nullable=False, server_default="{}"))


def downgrade() -> None:
    with op.batch_alter_table("scan_module_run") as batch_op:
        batch_op.drop_column("coverage_metadata")
