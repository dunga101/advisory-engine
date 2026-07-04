"""create advisory_revision_history

Revision ID: 0012
Revises: 0011
Create Date: 2026-07-02

Architecture review item 4 (narrowed review-gate reopening on
published/approved advisories): upsert_by_lookup writes to the advisories
table but, unlike upsert_and_diff/cves, had no revision-history table to
log changes to. This mirrors cve_revision_history's shape (migration
0002) so every field a collector rewrites on an existing advisories row
is now auditable, regardless of whether that change is significant enough
to also reopen the review gate.
"""
import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "advisory_revision_history",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("advisory_id", sa.Integer, sa.ForeignKey("advisories.id"), nullable=False),
        sa.Column(
            "captured_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column("field_changed", sa.Text, nullable=False),
        sa.Column("old_value", sa.Text),
        sa.Column("new_value", sa.Text),
    )
    op.create_index(
        "ix_advisory_revision_history_advisory_id", "advisory_revision_history", ["advisory_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_advisory_revision_history_advisory_id", table_name="advisory_revision_history")
    op.drop_table("advisory_revision_history")
