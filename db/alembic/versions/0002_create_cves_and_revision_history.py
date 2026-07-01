"""create cves and cve_revision_history

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-01

"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cves",
        sa.Column("cve_id", sa.Text, primary_key=True),
        sa.Column("cvss_score", sa.Numeric),
        sa.Column("cvss_vector", sa.Text),
        sa.Column("cwe_id", sa.Text),
        sa.Column("kev_listed", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("kev_date_added", sa.Date),
        sa.Column("kev_ransomware_use", sa.Boolean),
        sa.Column("description_raw", sa.Text),
    )
    op.create_table(
        "cve_revision_history",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("cve_id", sa.Text, sa.ForeignKey("cves.cve_id"), nullable=False),
        sa.Column(
            "captured_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column("field_changed", sa.Text, nullable=False),
        sa.Column("old_value", sa.Text),
        sa.Column("new_value", sa.Text),
    )
    op.create_index("ix_cve_revision_history_cve_id", "cve_revision_history", ["cve_id"])


def downgrade() -> None:
    op.drop_index("ix_cve_revision_history_cve_id", table_name="cve_revision_history")
    op.drop_table("cve_revision_history")
    op.drop_table("cves")
