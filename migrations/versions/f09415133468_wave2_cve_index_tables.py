"""wave2 cve index tables (cve_record, cve_index_meta)

Revision ID: f09415133468
Revises: e7cd3e8ddf80
Create Date: 2026-09-04 16:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f09415133468'
down_revision: Union[str, None] = 'e7cd3e8ddf80'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('cve_record',
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('published', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_modified', sa.DateTime(timezone=True), nullable=True),
    sa.Column('cpe_matches', sa.JSON(), nullable=False),
    sa.Column('cvss_v31_score', sa.Float(), nullable=True),
    sa.Column('cvss_v31_severity', sa.String(length=16), nullable=True),
    sa.Column('cvss_vector', sa.String(length=128), nullable=True),
    sa.Column('in_kev', sa.Boolean(), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('references', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('cve_id')
    )

    op.create_table('cve_index_meta',
    sa.Column('id', sa.String(length=16), nullable=False),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('last_refreshed', sa.DateTime(timezone=True), nullable=False),
    sa.Column('record_count', sa.Integer(), nullable=False),
    sa.Column('feed_version', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('cve_index_meta')
    op.drop_table('cve_record')
