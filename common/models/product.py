from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from common.db import Base


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(primary_key=True)
    vendor: Mapped[str | None] = mapped_column(Text)
    product_name: Mapped[str | None] = mapped_column(Text)
    product_family: Mapped[str | None] = mapped_column(Text)
    exposure_check_method: Mapped[str | None] = mapped_column(Text)


class AdvisoryProductAffected(Base):
    __tablename__ = "advisory_product_affected"

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisories.id"), nullable=False)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), nullable=False)
    affected_version_range: Mapped[str | None] = mapped_column(Text)
    fixed_version: Mapped[str | None] = mapped_column(Text)
