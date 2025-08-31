"""add friend system and online status

Revision ID: add_friend_system
Revises: 5da182280c39
Create Date: 2024-01-01 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_friend_system'
down_revision = '5da182280c39'
branch_labels = None
depends_on = None


def upgrade():
    # Add online status columns to user table
    op.add_column('user', sa.Column('is_online', sa.Boolean(), nullable=True, default=False))
    op.add_column('user', sa.Column('last_seen', sa.DateTime(), nullable=True))
    
    # Create friend table
    op.create_table('friend',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('friend_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=True, default='pending'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('accepted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['friend_id'], ['user.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Add team_id column to chat_message table if it doesn't exist
    try:
        op.add_column('chat_message', sa.Column('team_id', sa.Integer(), nullable=True))
        op.create_foreign_key(None, 'chat_message', 'team', ['team_id'], ['id'])
    except:
        pass  # Column might already exist


def downgrade():
    # Remove friend table
    op.drop_table('friend')
    
    # Remove online status columns from user table
    op.drop_column('user', 'last_seen')
    op.drop_column('user', 'is_online')
    
    # Remove team_id column from chat_message table
    try:
        op.drop_constraint(None, 'chat_message', type_='foreignkey')
        op.drop_column('chat_message', 'team_id')
    except:
        pass
