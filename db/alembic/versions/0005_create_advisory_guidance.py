"""create advisory_guidance

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-01

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "advisory_guidance",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column(
            "advisory_id", sa.BigInteger, sa.ForeignKey("advisories.id"), nullable=False, unique=True
        ),
        sa.Column("plain_english_summary", sa.Text),
        sa.Column("what_to_backup", sa.Text),
        sa.Column("deployment_notes", sa.Text),
        sa.Column("known_issues_after_patch", sa.Text),
        sa.Column("rollback_procedure", sa.Text),
        sa.Column("post_patch_verification", sa.Text),
        sa.Column("publish_status", sa.Text, nullable=False, server_default="draft"),
        sa.Column("verification_status", sa.Text, nullable=False, server_default="ai_drafted"),
        sa.Column("reviewed_by", sa.Text),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("precheck_flags", postgresql.JSONB),
        sa.CheckConstraint(
            "publish_status IN ('draft', 'published', 'blocked_pending_review')",
            name="ck_advisory_guidance_publish_status",
        ),
        sa.CheckConstraint(
            "verification_status IN ('ai_drafted', 'human_verified', 'rejected')",
            name="ck_advisory_guidance_verification_status",
        ),
    )


def downgrade() -> None:
    op.drop_table("advisory_guidance")
