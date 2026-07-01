from sqlalchemy import Text
from sqlalchemy.orm import Mapped, mapped_column

from common.db import Base


class PlatformReliabilityNote(Base):
    __tablename__ = "platform_reliability_notes"

    os_product: Mapped[str] = mapped_column(Text, primary_key=True)
    notes: Mapped[str | None] = mapped_column(Text)
