from datetime import date

from sqlalchemy import CheckConstraint, Date, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from common.db import Base


class PatchVerdictHistory(Base):
    __tablename__ = "patch_verdict_history"
    __table_args__ = (
        CheckConstraint(
            "recommendation IN ('deploy_now', 'pilot_ring', 'wait')",
            name="ck_patch_verdict_history_recommendation",
        ),
    )

    # Plain table for now — TimescaleDB is not installed on db-01 yet. A follow-up
    # migration converts this to a hypertable on as_of_date once it is.
    id: Mapped[int] = mapped_column(primary_key=True)
    windows_update_id: Mapped[int] = mapped_column(ForeignKey("windows_updates.id"), nullable=False)
    as_of_date: Mapped[date] = mapped_column(Date, nullable=False)
    recommendation: Mapped[str | None] = mapped_column(Text)
    wait_days_estimate: Mapped[int | None] = mapped_column(Integer)
    rationale: Mapped[str | None] = mapped_column(Text)
    field_report_count_at_time: Mapped[int | None] = mapped_column(Integer)
