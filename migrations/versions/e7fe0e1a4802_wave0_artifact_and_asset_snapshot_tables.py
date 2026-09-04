"""wave0 artifact and asset_snapshot tables

Revision ID: e7fe0e1a4802
Revises: 480531f44b24
Create Date: 2026-09-03 18:18:43.951117

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e7fe0e1a4802'
down_revision: Union[str, None] = '480531f44b24'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('artifact',
    sa.Column('engagement_id', sa.String(length=36), nullable=False),
    sa.Column('asset_id', sa.String(length=36), nullable=True),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('path', sa.String(length=1024), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('content_type', sa.String(length=128), nullable=True),
    sa.Column('bytes', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['asset.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['engagement_id'], ['engagement.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('artifact', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_artifact_asset'), ['asset_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_artifact_engagement'), ['engagement_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_artifact_eng_sha'), ['engagement_id', 'sha256'], unique=False)

    op.create_table('asset_snapshot',
    sa.Column('engagement_id', sa.String(length=36), nullable=False),
    sa.Column('scan_run_id', sa.String(length=36), nullable=False),
    sa.Column('taken_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('signature_set', sa.JSON(), nullable=False),
    sa.Column('summary', sa.JSON(), nullable=False),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.ForeignKeyConstraint(['engagement_id'], ['engagement.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['scan_run_id'], ['scan_run.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('asset_snapshot', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_asset_snapshot_engagement'), ['engagement_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_asset_snapshot_scan_run'), ['scan_run_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('asset_snapshot', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_asset_snapshot_scan_run'))
        batch_op.drop_index(batch_op.f('ix_asset_snapshot_engagement'))

    op.drop_table('asset_snapshot')
    with op.batch_alter_table('artifact', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_artifact_eng_sha'))
        batch_op.drop_index(batch_op.f('ix_artifact_engagement'))
        batch_op.drop_index(batch_op.f('ix_artifact_asset'))

    op.drop_table('artifact')
