"""add scan_module_run.skip_reason

Discriminates a benign resumed-run SKIPPED from a "zero eligible targets" /
"not configured" SKIPPED so the release gate can tell them apart.

Revision ID: c1a7e5d2f9b0
Revises: aa92f0d4b3c1
Create Date: 2026-09-05
"""

from alembic import op
import sqlalchemy as sa

revision = "c1a7e5d2f9b0"
down_revision = "aa92f0d4b3c1"
branch_labels = None
depends_on = None


_SKIP_REASON = sa.Enum(
    "resumed_prior_run",
    "zero_eligible_targets",
    "not_configured",
    "missing_binary",
    "capability_unavailable",
    "unverified_targets",
    name="skipreason",
    native_enum=False,
    create_constraint=False,
    length=32,
)


def upgrade() -> None:
    with op.batch_alter_table("scan_module_run") as batch_op:
        batch_op.add_column(sa.Column("skip_reason", _SKIP_REASON, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scan_module_run") as batch_op:
        batch_op.drop_column("skip_reason")
