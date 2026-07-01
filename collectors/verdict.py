import logging
from datetime import date, timedelta

from sqlalchemy import select

from collectors.config import SOURCE_WEIGHT, WAIT_DAYS
from common.db import get_session_factory
from common.models import Advisory, AdvisoryCve, Cve, FieldReport, PatchVerdictHistory, WindowsUpdate

logger = logging.getLogger(__name__)


def _business_days_between(start: date, end: date) -> int:
    if end <= start:
        return 0
    days = 0
    current = start
    while current < end:
        current += timedelta(days=1)
        if current.weekday() < 5:
            days += 1
    return days


def _is_kev_listed(session, advisory_id: int) -> bool:
    return (
        session.execute(
            select(Cve.cve_id)
            .join(AdvisoryCve, AdvisoryCve.cve_id == Cve.cve_id)
            .where(AdvisoryCve.advisory_id == advisory_id, Cve.kev_listed.is_(True))
            .limit(1)
        ).first()
        is not None
    )


def _weighted_report_score(session, windows_update_id: int) -> tuple[int, int]:
    """Count and source-weight unresolved field reports. Resolved reports don't
    count — this is what lets the recommendation flip back as issues clear."""
    reports = (
        session.execute(
            select(FieldReport).where(
                FieldReport.windows_update_id == windows_update_id,
                FieldReport.status != "resolved",
            )
        )
        .scalars()
        .all()
    )
    count = len(reports)
    weighted = sum(SOURCE_WEIGHT.get(r.source_type, 1) for r in reports)
    return count, weighted


def _latest_verdict(session, windows_update_id: int) -> PatchVerdictHistory | None:
    return (
        session.execute(
            select(PatchVerdictHistory)
            .where(PatchVerdictHistory.windows_update_id == windows_update_id)
            .order_by(PatchVerdictHistory.as_of_date.desc(), PatchVerdictHistory.id.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )


def _evaluate(
    session, update: WindowsUpdate, advisory: Advisory, today: date
) -> tuple[str, int | None, str, int]:
    """Section 6 verdict rubric. Returns (recommendation, wait_days_estimate,
    rationale, field_report_count_at_time)."""
    if _is_kev_listed(session, update.advisory_id):
        return (
            "deploy_now",
            None,
            "KEV-listed / actively exploited — bypasses field reports and wait days. Always deploy_now, no exceptions.",
            0,
        )

    report_count, weighted_score = _weighted_report_score(session, update.id)

    if weighted_score > 0:
        wait_days_estimate = min(WAIT_DAYS * 3, max(WAIT_DAYS, weighted_score * 2))
        rationale = (
            f"{report_count} unresolved field report(s) (source-weighted score {weighted_score}) "
            f"held this back from broad rollout — re-evaluated daily, estimated ~{wait_days_estimate} "
            "business days until reports resolve."
        )
        return "wait", wait_days_estimate, rationale, report_count

    business_days_since = (
        _business_days_between(advisory.published_date, today) if advisory.published_date else 0
    )

    if update.update_channel == "c_d_preview":
        return (
            "pilot_ring",
            None,
            "C/D-week optional preview update — never recommended for broad rollout regardless of elapsed time.",
            report_count,
        )

    if business_days_since < WAIT_DAYS:
        return (
            "pilot_ring",
            None,
            f"No exploitation, zero field reports, only {business_days_since} of {WAIT_DAYS} "
            "business days elapsed since release.",
            report_count,
        )

    return (
        "deploy_now",
        None,
        f"No exploitation, zero field reports, {business_days_since} business days elapsed "
        f"(>= WAIT_DAYS={WAIT_DAYS}) — broad rollout.",
        report_count,
    )


def run_once(session=None) -> dict:
    """Evaluate the Section 6 verdict rubric for every windows_update row and write
    a new patch_verdict_history row only when the recommendation changes from the
    most recent row for that windows_update_id."""
    owns_session = session is None
    session = session or get_session_factory()()

    evaluated = 0
    written = 0

    try:
        today = date.today()
        updates = session.execute(select(WindowsUpdate)).scalars().all()

        for update in updates:
            advisory = session.get(Advisory, update.advisory_id)
            evaluated += 1

            recommendation, wait_days_estimate, rationale, report_count = _evaluate(
                session, update, advisory, today
            )

            latest = _latest_verdict(session, update.id)
            if latest is not None and latest.recommendation == recommendation:
                continue

            session.add(
                PatchVerdictHistory(
                    windows_update_id=update.id,
                    as_of_date=today,
                    recommendation=recommendation,
                    wait_days_estimate=wait_days_estimate,
                    rationale=rationale,
                    field_report_count_at_time=report_count,
                )
            )
            written += 1

        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        if owns_session:
            session.close()

    summary = {"windows_updates_evaluated": evaluated, "verdicts_written": written}
    logger.info("Verdict engine run complete: %s", summary)
    return summary
