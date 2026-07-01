"""create patch_verdict_history (plain table; hypertable conversion deferred)

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-01

"""
import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # TimescaleDB is not installed on db-01 yet. This is a plain table for now;
    # a follow-up migration will run create_hypertable() once it is available.
    op.create_table(
        "patch_verdict_history",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("windows_update_id", sa.BigInteger, sa.ForeignKey("windows_updates.id"), nullable=False),
        sa.Column("as_of_date", sa.Date, nullable=False),
        sa.Column("recommendation", sa.Text),
        sa.Column("wait_days_estimate", sa.Integer),
        sa.Column("rationale", sa.Text),
        sa.Column("field_report_count_at_time", sa.Integer),
        sa.CheckConstraint(
            "recommendation IN ('deploy_now', 'pilot_ring', 'wait')",
            name="ck_patch_verdict_history_recommendation",
        ),
    )


def downgrade() -> None:
    op.drop_table("patch_verdict_history")
