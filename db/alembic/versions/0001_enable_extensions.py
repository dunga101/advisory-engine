"""enable extensions

Revision ID: 0001
Revises:
Create Date: 2026-07-01

"""
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")


def downgrade() -> None:
    op.execute("DROP EXTENSION IF EXISTS pgcrypto")
