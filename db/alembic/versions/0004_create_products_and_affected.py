"""create products and advisory_product_affected

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-01

"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "products",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("vendor", sa.Text),
        sa.Column("product_name", sa.Text),
        sa.Column("product_family", sa.Text),
        sa.Column("exposure_check_method", sa.Text),
    )
    op.create_table(
        "advisory_product_affected",
        sa.Column("id", sa.BigInteger, primary_key=True),
        sa.Column("advisory_id", sa.BigInteger, sa.ForeignKey("advisories.id"), nullable=False),
        sa.Column("product_id", sa.BigInteger, sa.ForeignKey("products.id"), nullable=False),
        sa.Column("affected_version_range", sa.Text),
        sa.Column("fixed_version", sa.Text),
    )


def downgrade() -> None:
    op.drop_table("advisory_product_affected")
    op.drop_table("products")
