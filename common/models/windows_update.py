from sqlalchemy import ARRAY, Boolean, CheckConstraint, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from common.db import Base


class WindowsUpdate(Base):
    __tablename__ = "windows_updates"
    __table_args__ = (
        CheckConstraint(
            "update_channel IN ('b_release', 'c_d_preview', 'out_of_band')",
            name="ck_windows_updates_update_channel",
        ),
        UniqueConstraint("kb_number", "os_product", name="uq_windows_updates_kb_number_os_product"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisories.id"), nullable=False)
    kb_number: Mapped[str | None] = mapped_column(Text)
    os_product: Mapped[str | None] = mapped_column(Text)
    os_build: Mapped[str | None] = mapped_column(Text)
    update_channel: Mapped[str | None] = mapped_column(Text)
    cumulative: Mapped[bool | None] = mapped_column(Boolean)
    non_security_fixes: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    supersedes_kb: Mapped[str | None] = mapped_column(Text)
    superseded_by_kb: Mapped[str | None] = mapped_column(Text)
