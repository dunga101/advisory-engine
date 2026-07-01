"""add unique constraint on windows_updates (kb_number, os_product)

Revision ID: 0010
Revises: 0009
Create Date: 2026-07-01

Rollback policy: if this breaks verification after being applied to db-01,
fix forward with a follow-up migration rather than `alembic downgrade`. Phase 1
never relied on downgrade in practice, live cves data already depends on
migrations layering forward, and downgrading here would just remove the
constraint without resolving whatever dedup/data issue triggered the failure.
Only downgrade if the constraint itself proves conceptually wrong (e.g.
os_product normalization can't actually make it a valid dedup key) — not as a
reflex response to a failed verification step.
"""
import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_windows_updates_kb_number_os_product",
        "windows_updates",
        ["kb_number", "os_product"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_windows_updates_kb_number_os_product", "windows_updates", type_="unique"
    )
