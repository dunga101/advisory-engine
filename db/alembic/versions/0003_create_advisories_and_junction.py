"""create advisories and advisory_cve

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-01

"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "advisories",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("source_vendor", sa.Text, nullable=False),
        sa.Column("source_advisory_id", sa.Text, nullable=False),
        sa.Column("title", sa.Text),
        sa.Column("published_date", sa.Date),
        sa.Column("last_updated_date", sa.Date),
        sa.Column("source_url", sa.Text),
        sa.Column("severity_vendor", sa.Text),
        sa.UniqueConstraint("source_vendor", "source_advisory_id"),
    )
    op.create_table(
        "advisory_cve",
        sa.Column("advisory_id", sa.BigInteger, sa.ForeignKey("advisories.id"), primary_key=True),
        sa.Column("cve_id", sa.Text, sa.ForeignKey("cves.cve_id"), primary_key=True),
    )


def downgrade() -> None:
    op.drop_table("advisory_cve")
    op.drop_table("advisories")
