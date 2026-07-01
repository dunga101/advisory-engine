"""create platform_reliability_notes, seed Windows Server 2019/2022

Revision ID: 0009
Revises: 0008
Create Date: 2026-07-01

"""
import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

platform_reliability_notes = sa.table(
    "platform_reliability_notes",
    sa.column("os_product", sa.Text),
    sa.column("notes", sa.Text),
)


def upgrade() -> None:
    op.create_table(
        "platform_reliability_notes",
        sa.Column("os_product", sa.Text, primary_key=True),
        sa.Column("notes", sa.Text),
    )
    op.bulk_insert(
        platform_reliability_notes,
        [
            {"os_product": "Windows Server 2019", "notes": "Clean history"},
            {"os_product": "Windows Server 2022", "notes": "Clean history"},
        ],
    )


def downgrade() -> None:
    op.drop_table("platform_reliability_notes")
