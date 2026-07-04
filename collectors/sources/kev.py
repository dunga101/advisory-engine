import logging
from datetime import date, datetime, timezone

import requests
from sqlalchemy import select

from collectors.sources.base import cve_gate_hook, upsert_and_diff
from common.db import get_session_factory
from common.models import Cve, CveRevisionHistory

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

logger = logging.getLogger(__name__)


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%d").date()


def _normalize(entry: dict) -> dict:
    cwes = entry.get("cwes") or []
    return {
        "kev_listed": True,
        "kev_date_added": _parse_date(entry.get("dateAdded")),
        "kev_ransomware_use": entry.get("knownRansomwareCampaignUse") == "Known",
        "description_raw": entry.get("shortDescription"),
        "cwe_id": cwes[0] if cwes else None,
    }


def fetch_kev_feed() -> list[dict]:
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    return response.json()["vulnerabilities"]


def _unlist_removed_cves(session, current_ids: set[str]) -> int:
    """Architecture review item 5: CISA does periodically remove an entry
    from the KEV catalog (e.g. later analysis determines it wasn't
    actually exploited) — until now nothing detected that, so kev_listed
    stayed True forever once set. Anything in the DB as kev_listed=True
    that isn't in this run's current_ids gets flipped back, logged to
    cve_revision_history same as any other field change, and routed
    through cve_gate_hook so review reopens on linked advisories exactly
    like a listing does (is_gating_cve_change treats kev_listed as
    gating regardless of direction).

    Caller must never invoke this with an empty current_ids — see
    run_once's guard below."""
    assert current_ids, "must not run un-listing detection against an empty feed pull"

    now = datetime.now(timezone.utc)
    previously_listed = (
        session.execute(
            select(Cve).where(Cve.kev_listed.is_(True), Cve.cve_id.notin_(current_ids))
        )
        .scalars()
        .all()
    )

    unlisted = 0
    for cve in previously_listed:
        session.add(
            CveRevisionHistory(
                cve_id=cve.cve_id,
                captured_at=now,
                field_changed="kev_listed",
                old_value="True",
                new_value="False",
            )
        )
        cve.kev_listed = False
        cve_gate_hook(session, cve.cve_id)("kev_listed", True, False)
        unlisted += 1
    return unlisted


def run_once(session=None) -> dict:
    """Fetch the full KEV feed and upsert every entry into cves, writing a
    cve_revision_history row for every field that changed on an existing
    row, then detect un-listing (architecture review item 5): any
    kev_listed=True row absent from this pull gets flipped back to False.

    Un-listing detection is skipped entirely when the feed comes back
    empty — CISA's KEV catalog has held 1000+ entries every day since
    inception, so an empty response means something broke upstream
    (network/parsing), not that everything was actually delisted; treating
    it as real would mass-delist the whole catalog on a single bad fetch."""
    owns_session = session is None
    session = session or get_session_factory()()

    inserted = 0
    updated = 0
    field_changes = 0
    unlisted = 0

    try:
        entries = fetch_kev_feed()
        for entry in entries:
            cve_id = entry["cveID"]
            result = upsert_and_diff(
                session,
                model_cls=Cve,
                revision_cls=CveRevisionHistory,
                pk_column="cve_id",
                revision_fk_column="cve_id",
                pk_value=cve_id,
                fields=_normalize(entry),
                on_field_changed=cve_gate_hook(session, cve_id),
            )
            if result.inserted:
                inserted += 1
            elif result.changed_fields:
                updated += 1
                field_changes += len(result.changed_fields)

        if entries:
            current_ids = {entry["cveID"] for entry in entries}
            unlisted = _unlist_removed_cves(session, current_ids)
        else:
            logger.warning(
                "KEV feed returned zero entries; skipping un-listing detection "
                "to avoid mass false-delisting"
            )

        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        if owns_session:
            session.close()

    summary = {
        "feed_entry_count": len(entries),
        "inserted": inserted,
        "updated": updated,
        "field_changes": field_changes,
        "unlisted": unlisted,
    }
    logger.info("KEV collector run complete: %s", summary)
    return summary
