from datetime import date

from sqlalchemy import CheckConstraint, Date, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from common.db import Base


class FieldReport(Base):
    __tablename__ = "field_reports"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('microsoft_release_health', 'community', 'vendor_kb')",
            name="ck_field_reports_source_type",
        ),
        CheckConstraint(
            "status IN ('unconfirmed', 'confirmed', 'workaround_available', 'resolved')",
            name="ck_field_reports_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    windows_update_id: Mapped[int | None] = mapped_column(ForeignKey("windows_updates.id"))
    advisory_id: Mapped[int | None] = mapped_column(ForeignKey("advisories.id"))
    source_type: Mapped[str | None] = mapped_column(Text)
    issue_description: Mapped[str | None] = mapped_column(Text)
    affected_configuration: Mapped[str | None] = mapped_column(Text)
    report_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str | None] = mapped_column(Text)
