from datetime import date, datetime

from sqlalchemy import CheckConstraint, Date, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from common.db import Base


class Advisory(Base):
    __tablename__ = "advisories"
    __table_args__ = (UniqueConstraint("source_vendor", "source_advisory_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source_vendor: Mapped[str] = mapped_column(Text, nullable=False)
    source_advisory_id: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str | None] = mapped_column(Text)
    published_date: Mapped[date | None] = mapped_column(Date)
    last_updated_date: Mapped[date | None] = mapped_column(Date)
    source_url: Mapped[str | None] = mapped_column(Text)
    severity_vendor: Mapped[str | None] = mapped_column(Text)


class AdvisoryCve(Base):
    __tablename__ = "advisory_cve"

    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisories.id"), primary_key=True)
    cve_id: Mapped[str] = mapped_column(Text, ForeignKey("cves.cve_id"), primary_key=True)


class AdvisoryGuidance(Base):
    __tablename__ = "advisory_guidance"
    __table_args__ = (
        CheckConstraint(
            "publish_status IN ('draft', 'published', 'blocked_pending_review')",
            name="ck_advisory_guidance_publish_status",
        ),
        CheckConstraint(
            "verification_status IN ('ai_drafted', 'human_verified', 'rejected')",
            name="ck_advisory_guidance_verification_status",
        ),
        UniqueConstraint("advisory_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisories.id"), nullable=False)
    plain_english_summary: Mapped[str | None] = mapped_column(Text)
    what_to_backup: Mapped[str | None] = mapped_column(Text)
    deployment_notes: Mapped[str | None] = mapped_column(Text)
    known_issues_after_patch: Mapped[str | None] = mapped_column(Text)
    rollback_procedure: Mapped[str | None] = mapped_column(Text)
    post_patch_verification: Mapped[str | None] = mapped_column(Text)
    publish_status: Mapped[str] = mapped_column(Text, nullable=False, default="draft")
    verification_status: Mapped[str] = mapped_column(Text, nullable=False, default="ai_drafted")
    reviewed_by: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    precheck_flags: Mapped[dict | None] = mapped_column(JSONB)
