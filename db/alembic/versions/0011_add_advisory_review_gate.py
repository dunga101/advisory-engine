"""add review-gate columns to advisories; add rejection_reason to advisory_guidance

Revision ID: 0011
Revises: 0010
Create Date: 2026-07-01

Phase 4 (automated pre-check engine + CLI review tool) gates the raw
structured advisories record itself, ahead of any AI narrative. The build
brief's original design (Section 5/7) put the review gate on
advisory_guidance only, and explicitly auto-published "structured-fact-only"
rows with no gate at all ("Resolved Decisions"). This migration is a
deliberate, discussed departure from that stated decision: nothing reaches
the public site without passing through a gate now, and since the Gemini
narrative layer (Phase 6) doesn't exist yet, that gate has to live on
advisories in the meantime.

advisories.verification_status ('pending'/'approved'/'rejected') and
advisory_guidance.verification_status ('ai_drafted'/'human_verified'/
'rejected') use intentionally different enums — not an inconsistency. The
former tracks whether a raw structured-fact record has been reviewed at
all; the latter tracks whether AI-generated narrative text has been
human-verified. There's no "ai_drafted" concept for a raw fact record, and
no "pending" concept for narrative that doesn't exist until an AI drafts
it. They may get reconciled once Phase 6 wires an advisory_guidance row to
its advisory, but are deliberately separate today.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "advisories",
        sa.Column("publish_status", sa.Text, nullable=False, server_default="draft"),
    )
    op.add_column(
        "advisories",
        sa.Column("verification_status", sa.Text, nullable=False, server_default="pending"),
    )
    op.add_column("advisories", sa.Column("precheck_flags", postgresql.JSONB))
    op.add_column("advisories", sa.Column("reviewed_by", sa.Text))
    op.add_column("advisories", sa.Column("published_at", sa.DateTime(timezone=True)))
    op.add_column("advisories", sa.Column("rejection_reason", sa.Text))

    op.create_check_constraint(
        "ck_advisories_publish_status",
        "advisories",
        "publish_status IN ('draft', 'published', 'blocked_pending_review')",
    )
    op.create_check_constraint(
        "ck_advisories_verification_status",
        "advisories",
        "verification_status IN ('pending', 'approved', 'rejected')",
    )

    op.add_column("advisory_guidance", sa.Column("rejection_reason", sa.Text))


def downgrade() -> None:
    op.drop_column("advisory_guidance", "rejection_reason")

    op.drop_constraint("ck_advisories_verification_status", "advisories", type_="check")
    op.drop_constraint("ck_advisories_publish_status", "advisories", type_="check")

    op.drop_column("advisories", "rejection_reason")
    op.drop_column("advisories", "published_at")
    op.drop_column("advisories", "reviewed_by")
    op.drop_column("advisories", "precheck_flags")
    op.drop_column("advisories", "verification_status")
    op.drop_column("advisories", "publish_status")
