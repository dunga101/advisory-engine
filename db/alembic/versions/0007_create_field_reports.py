"""create field_reports

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-01

"""
import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "field_reports",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("windows_update_id", sa.BigInteger, sa.ForeignKey("windows_updates.id")),
        sa.Column("advisory_id", sa.BigInteger, sa.ForeignKey("advisories.id")),
        sa.Column("source_type", sa.Text),
        sa.Column("issue_description", sa.Text),
        sa.Column("affected_configuration", sa.Text),
        sa.Column("report_date", sa.Date),
        sa.Column("status", sa.Text),
        sa.CheckConstraint(
            "source_type IN ('microsoft_release_health', 'community', 'vendor_kb')",
            name="ck_field_reports_source_type",
        ),
        sa.CheckConstraint(
            "status IN ('unconfirmed', 'confirmed', 'workaround_available', 'resolved')",
            name="ck_field_reports_status",
        ),
    )


def downgrade() -> None:
    op.drop_table("field_reports")
