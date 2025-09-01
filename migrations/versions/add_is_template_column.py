"""add is_template column to challenge table

Revision ID: add_is_template_column
Revises: add_friend_system
Create Date: 2025-09-01 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_is_template_column'
down_revision = 'add_friend_system'
branch_labels = None
depends_on = None


def upgrade():
    # Add is_template column to challenge table
    op.add_column('challenge', sa.Column('is_template', sa.Boolean(), nullable=True, server_default='0'))


def downgrade():
    # Remove is_template column from challenge table
    op.drop_column('challenge', 'is_template')