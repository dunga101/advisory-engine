import logging
from datetime import date, datetime

import requests

from collectors.sources.base import upsert_and_diff
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


def run_once(session=None) -> dict:
    """Fetch the full KEV feed and upsert every entry into cves, writing a
    cve_revision_history row for every field that changed on an existing row."""
    owns_session = session is None
    session = session or get_session_factory()()

    inserted = 0
    updated = 0
    field_changes = 0

    try:
        entries = fetch_kev_feed()
        for entry in entries:
            result = upsert_and_diff(
                session,
                model_cls=Cve,
                revision_cls=CveRevisionHistory,
                pk_column="cve_id",
                revision_fk_column="cve_id",
                pk_value=entry["cveID"],
                fields=_normalize(entry),
            )
            if result.inserted:
                inserted += 1
            elif result.changed_fields:
                updated += 1
                field_changes += len(result.changed_fields)
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
    }
    logger.info("KEV collector run complete: %s", summary)
    return summary
