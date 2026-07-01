"""create windows_updates

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-01

"""
import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "windows_updates",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("advisory_id", sa.BigInteger, sa.ForeignKey("advisories.id"), nullable=False),
        sa.Column("kb_number", sa.Text),
        sa.Column("os_product", sa.Text),
        sa.Column("os_build", sa.Text),
        sa.Column("update_channel", sa.Text),
        sa.Column("cumulative", sa.Boolean),
        sa.Column("non_security_fixes", sa.ARRAY(sa.Text)),
        sa.Column("supersedes_kb", sa.Text),
        sa.Column("superseded_by_kb", sa.Text),
        sa.CheckConstraint(
            "update_channel IN ('b_release', 'c_d_preview', 'out_of_band')",
            name="ck_windows_updates_update_channel",
        ),
    )


def downgrade() -> None:
    op.drop_table("windows_updates")
