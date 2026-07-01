from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Numeric, Text
from sqlalchemy.orm import Mapped, mapped_column

from common.db import Base


class Cve(Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    cvss_score: Mapped[float | None] = mapped_column(Numeric)
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    cwe_id: Mapped[str | None] = mapped_column(Text)
    kev_listed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_date_added: Mapped[date | None] = mapped_column(Date)
    kev_ransomware_use: Mapped[bool | None] = mapped_column(Boolean)
    description_raw: Mapped[str | None] = mapped_column(Text)


class CveRevisionHistory(Base):
    __tablename__ = "cve_revision_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(Text, ForeignKey("cves.cve_id"), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    field_changed: Mapped[str] = mapped_column(Text, nullable=False)
    old_value: Mapped[str | None] = mapped_column(Text)
    new_value: Mapped[str | None] = mapped_column(Text)
