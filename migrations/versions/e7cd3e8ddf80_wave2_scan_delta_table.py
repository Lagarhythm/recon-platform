"""wave2 scan_delta table

Revision ID: e7cd3e8ddf80
Revises: 54b620351190
Create Date: 2026-09-04 15:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e7cd3e8ddf80'
down_revision: Union[str, None] = '54b620351190'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('scan_delta',
    sa.Column('engagement_id', sa.String(length=36), nullable=False),
    sa.Column('scan_run_id', sa.String(length=36), nullable=False),
    sa.Column('base_snapshot_id', sa.String(length=36), nullable=True),
    sa.Column('computed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('added', sa.JSON(), nullable=False),
    sa.Column('removed', sa.JSON(), nullable=False),
    sa.Column('changed', sa.JSON(), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.ForeignKeyConstraint(['base_snapshot_id'], ['asset_snapshot.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['engagement_id'], ['engagement.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['scan_run_id'], ['scan_run.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('scan_delta', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_scan_delta_engagement'), ['engagement_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_scan_delta_scan_run'), ['scan_run_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('scan_delta', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_scan_delta_scan_run'))
        batch_op.drop_index(batch_op.f('ix_scan_delta_engagement'))

    op.drop_table('scan_delta')
