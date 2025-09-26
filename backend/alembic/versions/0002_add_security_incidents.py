"""add security_incidents table

Revision ID: 0002_add_security_incidents
Revises: 0001_initial
Create Date: 2025-09-26 04:50:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0002_add_security_incidents'
down_revision = '0001_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'security_incidents',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table('security_incidents')
