"""api_token table

Revision ID: 54b620351190
Revises: e7fe0e1a4802
Create Date: 2026-09-03 21:52:10.540863

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '54b620351190'
down_revision: Union[str, None] = 'e7fe0e1a4802'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'api_token',
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('last_used', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('api_token', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_api_token_token_hash'), ['token_hash'], unique=True
        )
        batch_op.create_index(
            batch_op.f('ix_api_token_user_id'), ['user_id'], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table('api_token', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_api_token_user_id'))
        batch_op.drop_index(batch_op.f('ix_api_token_token_hash'))

    op.drop_table('api_token')
