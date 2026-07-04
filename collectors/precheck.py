import logging
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import select

from collectors.config import PRECHECK_AUTO_APPROVE
from collectors.sources.base import is_valid_cve_id
from common.db import get_session_factory
from common.models import Advisory, AdvisoryCve, AdvisoryProductAffected, Cve, Product

logger = logging.getLogger(__name__)

AUTO_APPROVED_REVIEWER = "auto-precheck"


def _validate_advisory_facts(
    *,
    title: str | None,
    source_url: str | None,
    cve_lookups: list[tuple[str, "Cve | None"]],
    product_ids_exist: list[tuple[int, bool]],
) -> list[str]:
    """Pure validation logic, no DB access — takes pre-fetched data so it's
    directly unit-testable. Returns a list of human-readable failure
    reasons; empty means the advisory passes every check.

    Zero linked CVEs (empty cve_lookups) is never itself a failure —
    advisories like Cisco's notice-only bulletins (cisco-sa-notice-vwL7b0S7)
    legitimately have none once _extract_valid_cve_ids filters Cisco's "NA"
    sentinel. What's checked instead: any CVE ID that IS linked must be
    real-shaped and resolvable, and its cvss_score must be null or a real
    Decimal — never a raw string/float that slipped past a collector's
    normalization (the exact class of bug the Cisco/MSRC diffing fixes
    targeted)."""
    reasons: list[str] = []

    if not title or not title.strip():
        reasons.append("missing title")
    if not source_url or not source_url.strip():
        reasons.append("missing source_url")

    for cve_id, cve_row in cve_lookups:
        if not is_valid_cve_id(cve_id):
            reasons.append(f"advisory_cve links malformed CVE ID: {cve_id!r}")
            continue

        if cve_row is None:
            # Structurally shouldn't happen — cves.cve_id FK on advisory_cve
            # prevents it — but checked rather than trusted blindly.
            reasons.append(f"advisory_cve references non-existent cve_id: {cve_id!r}")
            continue

        if cve_row.cvss_score is not None and not isinstance(cve_row.cvss_score, Decimal):
            reasons.append(
                f"{cve_id} cvss_score is {type(cve_row.cvss_score).__name__}, not Decimal/null"
            )

    for product_id, exists in product_ids_exist:
        if not exists:
            reasons.append(
                f"advisory_product_affected references non-existent product_id: {product_id}"
            )

    return reasons


def _check_advisory(session, advisory: Advisory) -> list[str]:
    """DB-touching wrapper around _validate_advisory_facts: fetches the
    linked CVE rows and product references for one advisory, then hands
    plain data to the pure validator."""
    cve_ids = (
        session.execute(
            select(AdvisoryCve.cve_id).where(AdvisoryCve.advisory_id == advisory.id)
        )
        .scalars()
        .all()
    )
    cve_lookups = [
        (cve_id, session.get(Cve, cve_id) if is_valid_cve_id(cve_id) else None)
        for cve_id in cve_ids
    ]

    product_ids = (
        session.execute(
            select(AdvisoryProductAffected.product_id).where(
                AdvisoryProductAffected.advisory_id == advisory.id
            )
        )
        .scalars()
        .all()
    )
    product_ids_exist = [(pid, session.get(Product, pid) is not None) for pid in product_ids]

    return _validate_advisory_facts(
        title=advisory.title,
        source_url=advisory.source_url,
        cve_lookups=cve_lookups,
        product_ids_exist=product_ids_exist,
    )


def run_once(session=None) -> dict:
    """Evaluate every advisory not yet in a terminal review state
    (verification_status='pending' — excludes already-approved/published
    and already-rejected rows). Advisories a human explicitly pulled into
    review via review_cli.py's --flag escape hatch
    (precheck_flags["source"] == "manual") are skipped entirely — this
    engine must never silently un-flag something a human asked to look at,
    even if it would otherwise pass every check.

    Previously blocked_pending_review advisories ARE re-evaluated each run
    (verification_status stays "pending" while blocked) so a fix in a later
    collector run can self-heal an advisory back to passing without a human
    having to intervene for a transient data issue.

    Passing advisories auto-publish when PRECHECK_AUTO_APPROVE is True
    (the current default); failing advisories always land in
    blocked_pending_review regardless of that setting."""
    owns_session = session is None
    session = session or get_session_factory()()

    evaluated = 0
    blocked = 0
    auto_approved = 0
    left_pending = 0

    try:
        candidates = (
            session.execute(select(Advisory).where(Advisory.verification_status == "pending"))
            .scalars()
            .all()
        )

        for advisory in candidates:
            # "manual" is a human's review_cli.py --flag; "auto-reopened" is
            # collectors.sources.base.reopen_review_gate pulling a
            # previously-published advisory back in after a significant
            # field change (architecture review item 4). Both must sit in
            # the queue until a human looks — re-evaluating either here
            # would let PRECHECK_AUTO_APPROVE silently re-publish the new
            # value the very next run, making the reopen a no-op.
            if advisory.precheck_flags and advisory.precheck_flags.get("source") in (
                "manual",
                "auto-reopened",
            ):
                continue

            evaluated += 1
            reasons = _check_advisory(session, advisory)

            if reasons:
                advisory.publish_status = "blocked_pending_review"
                advisory.precheck_flags = {"source": "precheck", "reasons": reasons}
                blocked += 1
                logger.info(
                    "Advisory %s (%s/%s) blocked_pending_review: %s",
                    advisory.id,
                    advisory.source_vendor,
                    advisory.source_advisory_id,
                    reasons,
                )
                continue

            advisory.precheck_flags = None
            advisory.publish_status = "draft"
            if PRECHECK_AUTO_APPROVE:
                advisory.publish_status = "published"
                advisory.verification_status = "approved"
                advisory.reviewed_by = AUTO_APPROVED_REVIEWER
                advisory.published_at = datetime.now(timezone.utc)
                auto_approved += 1
            else:
                left_pending += 1

        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        if owns_session:
            session.close()

    summary = {
        "evaluated": evaluated,
        "blocked_pending_review": blocked,
        "auto_approved": auto_approved,
        "left_pending": left_pending,
    }
    logger.info("Pre-check engine run complete: %s", summary)
    return summary
