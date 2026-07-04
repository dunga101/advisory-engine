import logging
import os
import time
from collections import deque
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation

import requests
from sqlalchemy import select

from collectors.config import (
    CISCO_BACKFILL_DAYS,
    CISCO_MAX_REQUESTS_PER_DAY,
    CISCO_MAX_REQUESTS_PER_MINUTE,
    CISCO_MAX_REQUESTS_PER_SECOND,
)
from collectors.sources.base import (
    advisory_gate_hook,
    cve_gate_hook,
    is_valid_cve_id,
    reopen_review_gate,
    upsert_and_diff,
    upsert_by_lookup,
)
from common.db import get_session_factory
from common.models import (
    Advisory,
    AdvisoryCve,
    AdvisoryProductAffected,
    AdvisoryRevisionHistory,
    Cve,
    CveRevisionHistory,
    Product,
)

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
API_BASE = "https://apix.cisco.com/security/advisories/v2"

logger = logging.getLogger(__name__)


class DailyQuotaExceeded(Exception):
    """Raised when another request would exceed Cisco's documented daily
    openVuln API quota (build brief Section 4: 5000/day). The caller should
    end this run cleanly rather than retry — the quota resets daily, and
    sleeping out the remainder of a day inside a cron job is not useful."""


class RateLimiter:
    """Sliding-window limiter enforcing Cisco's documented openVuln API
    quotas: 5 requests/sec, 30/min, 5000/day (build brief Section 4, values
    in collectors/config.py). Sleeps before a request would exceed the
    per-second/per-minute window; raises DailyQuotaExceeded rather than
    sleeping out a whole day. sleep_fn/time_fn are injectable for testing."""

    def __init__(
        self,
        per_second: int = CISCO_MAX_REQUESTS_PER_SECOND,
        per_minute: int = CISCO_MAX_REQUESTS_PER_MINUTE,
        per_day: int = CISCO_MAX_REQUESTS_PER_DAY,
        sleep_fn=time.sleep,
        time_fn=time.monotonic,
    ) -> None:
        self._per_second = per_second
        self._per_minute = per_minute
        self._per_day = per_day
        self._sleep = sleep_fn
        self._now = time_fn
        self._request_times: deque[float] = deque()

    def acquire(self) -> None:
        """Block (via sleep_fn) until a request is allowed under the
        per-second and per-minute windows, then record it. Call once
        immediately before every API request."""
        while True:
            now = self._now()
            self._evict_older_than(now - 86400)

            if len(self._request_times) >= self._per_day:
                raise DailyQuotaExceeded(
                    f"Cisco openVuln API daily quota reached ({self._per_day} requests)"
                )

            in_last_second = [t for t in self._request_times if t > now - 1]
            if len(in_last_second) >= self._per_second:
                self._sleep(max(0.0, 1.0 - (now - min(in_last_second))) + 0.01)
                continue

            in_last_minute = [t for t in self._request_times if t > now - 60]
            if len(in_last_minute) >= self._per_minute:
                self._sleep(max(0.0, 60.0 - (now - min(in_last_minute))) + 0.01)
                continue

            break

        self._request_times.append(self._now())

    def _evict_older_than(self, cutoff: float) -> None:
        while self._request_times and self._request_times[0] <= cutoff:
            self._request_times.popleft()


def fetch_access_token() -> str:
    """OAuth2 Client Credentials grant (build brief Section 4). Credentials
    come from the environment only — never hardcoded, never logged."""
    client_id = os.environ["CISCO_CLIENT_ID"]
    client_secret = os.environ["CISCO_CLIENT_SECRET"]
    response = requests.post(
        TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def _extract_advisories(payload) -> list[dict]:
    """Confirmed via live probe (2026-07-01): the real response is a dict
    envelope {"advisories": [...]}, not a bare array — Cisco's own DevNet
    docs didn't show a full example. The bare-array branch is kept as a
    defensive fallback, not because it's been observed."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return payload.get("advisories") or []
    return []


def fetch_advisories(
    access_token: str, rate_limiter: RateLimiter, start_date: date, end_date: date
) -> list[dict]:
    rate_limiter.acquire()
    response = requests.get(
        f"{API_BASE}/all/firstpublished",
        headers={"Authorization": f"Bearer {access_token}"},
        params={"startDate": start_date.isoformat(), "endDate": end_date.isoformat()},
        timeout=60,
    )
    response.raise_for_status()
    return _extract_advisories(response.json())


def _split_multi(value) -> list[str]:
    """Confirmed via live probe (2026-07-01): cves/productNames/bugIDs/cwe
    are real JSON arrays in practice — Cisco's own DevNet docs type them as
    bare strings and show an unbracketed single-value example, which turned
    out to be misleading. The comma-split fallback is kept in case an older
    API version or a differently-configured client ever hits the documented
    string shape; list entries are still .strip()'d since the live response
    had trailing whitespace on productNames values."""
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _extract_valid_cve_ids(entry: dict) -> list[str]:
    """cves entries that aren't real CVE IDs (Cisco's "NA" sentinel for "no
    CVE assigned yet" — confirmed live on cisco-sa-notice-vwL7b0S7 and
    cisco-sa-asaftd-persist-CISAED25-03) are filtered out entirely: not
    inserted into cves, not linked via advisory_cve. An advisory with zero
    valid CVEs after filtering still gets its own advisories row — a CVE
    link is optional, the advisory itself is not."""
    return [cve_id for cve_id in _split_multi(entry.get("cves")) if is_valid_cve_id(cve_id)]


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def _normalize_advisory(entry: dict) -> dict:
    first_published = _parse_datetime(entry.get("firstPublished"))
    last_updated = _parse_datetime(entry.get("lastUpdated"))
    return {
        "title": entry.get("advisoryTitle"),
        "published_date": first_published.date() if first_published else None,
        "last_updated_date": last_updated.date() if last_updated else None,
        "source_url": entry.get("publicationUrl"),
        "severity_vendor": entry.get("sir"),
    }


def _parse_cvss_score(value) -> Decimal | None:
    """Cisco's live API returns cvssBaseScore as a string ("7.5") despite
    the documented schema saying "number" (confirmed via a live probe) —
    cast straight to Decimal via str(value).strip() rather than through
    float(), which would round-trip through binary floating point and
    reintroduce the exact imprecision that caused the original MSRC/
    base.py Decimal-vs-float diffing bug. Missing/null/empty mirrors
    msrc.py's _highest_cvss, which returns None rather than crashing when
    no score is present."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return Decimal(text)
    except InvalidOperation:
        return None


def _normalize_cve(entry: dict) -> dict:
    """Never includes kev_listed/kev_date_added/kev_ransomware_use — CISA KEV
    is the sole source of truth for exploited-status (build brief Section 4).
    cvss_vector is omitted entirely (not cvssBaseScore-adjacent data in the
    openVuln response) rather than set to None, matching kev.py's convention
    of only including keys the source actually has an opinion on."""
    cwes = _split_multi(entry.get("cwe"))
    return {
        "cvss_score": _parse_cvss_score(entry.get("cvssBaseScore")),
        "cwe_id": cwes[0] if cwes else None,
        "description_raw": entry.get("summary"),
    }


def _process_advisory(session, entry: dict, advisory_source_id: str) -> tuple[int, int, int]:
    """Upsert one advisory plus its CVEs and products. Left to raise on any
    mapping/write failure — run_once catches it, rolls back just this
    advisory's uncommitted work, and moves on, rather than losing every
    advisory already committed this run."""
    cves_inserted = 0
    cves_updated = 0
    products_upserted = 0

    upsert_by_lookup(
        session,
        model_cls=Advisory,
        lookup={"source_vendor": "cisco", "source_advisory_id": advisory_source_id},
        fields=_normalize_advisory(entry),
        revision_cls=AdvisoryRevisionHistory,
        revision_fk_column="advisory_id",
        on_field_changed=advisory_gate_hook(session),
    )
    session.flush()
    advisory = session.execute(
        select(Advisory).filter_by(source_vendor="cisco", source_advisory_id=advisory_source_id)
    ).scalar_one()

    cve_fields = _normalize_cve(entry)
    for cve_id in _extract_valid_cve_ids(entry):
        diff_result = upsert_and_diff(
            session,
            model_cls=Cve,
            revision_cls=CveRevisionHistory,
            pk_column="cve_id",
            revision_fk_column="cve_id",
            pk_value=cve_id,
            fields=cve_fields,
            on_field_changed=cve_gate_hook(session, cve_id),
        )
        if diff_result.inserted:
            cves_inserted += 1
        elif diff_result.changed_fields:
            cves_updated += 1

        if session.get(AdvisoryCve, (advisory.id, cve_id)) is None:
            session.add(AdvisoryCve(advisory_id=advisory.id, cve_id=cve_id))

    for product_name in _split_multi(entry.get("productNames")):
        upsert_by_lookup(
            session,
            model_cls=Product,
            lookup={"vendor": "Cisco", "product_name": product_name},
            fields={},
        )
        products_upserted += 1
        session.flush()
        product = session.execute(
            select(Product).filter_by(vendor="Cisco", product_name=product_name)
        ).scalar_one()

        product_link_inserted = upsert_by_lookup(
            session,
            model_cls=AdvisoryProductAffected,
            lookup={"advisory_id": advisory.id, "product_id": product.id},
            fields={},
        )
        if product_link_inserted:
            reopen_review_gate(
                session, [advisory.id], reason=f"new product linked: {product_name}"
            )

    return cves_inserted, cves_updated, products_upserted


def run_once(session=None) -> dict:
    """Fetch Cisco PSIRT openVuln advisories first published in the last
    CISCO_BACKFILL_DAYS days and upsert into advisories, advisory_cve, cves,
    and advisory_product_affected. Cisco advisories reference IOS-XE/product
    versions generically — this never touches windows_updates, which is the
    Windows-only KB-chain model.

    Commits per advisory rather than once at the end: a single advisory
    with an unexpected shape must not roll back — and lose — every other
    advisory already processed in this run. Failures are logged and
    collected in the returned summary rather than raised."""
    owns_session = session is None
    session = session or get_session_factory()()

    advisories_upserted = 0
    cves_inserted = 0
    cves_updated = 0
    products_upserted = 0
    skipped_advisories: list[dict] = []

    rate_limiter = RateLimiter()

    try:
        access_token = fetch_access_token()

        end_date = date.today()
        start_date = end_date - timedelta(days=CISCO_BACKFILL_DAYS)

        try:
            entries = fetch_advisories(access_token, rate_limiter, start_date, end_date)
        except DailyQuotaExceeded:
            logger.warning(
                "Cisco collector stopped before fetching any advisories: daily API quota reached"
            )
            entries = []

        for entry in entries:
            advisory_source_id = entry.get("advisoryId")
            if not advisory_source_id:
                skipped_advisories.append(
                    {"advisoryId": None, "reason": "missing advisoryId field"}
                )
                continue

            try:
                entry_cves_inserted, entry_cves_updated, entry_products_upserted = (
                    _process_advisory(session, entry, advisory_source_id)
                )
                session.commit()
            except Exception as exc:
                session.rollback()
                logger.exception(
                    "Skipping Cisco advisory %s — failed to map/write", advisory_source_id
                )
                skipped_advisories.append(
                    {"advisoryId": advisory_source_id, "reason": f"{type(exc).__name__}: {exc}"}
                )
                continue

            advisories_upserted += 1
            cves_inserted += entry_cves_inserted
            cves_updated += entry_cves_updated
            products_upserted += entry_products_upserted
    except Exception:
        session.rollback()
        raise
    finally:
        if owns_session:
            session.close()

    summary = {
        "advisories_upserted": advisories_upserted,
        "cves_inserted": cves_inserted,
        "cves_updated": cves_updated,
        "products_upserted": products_upserted,
        "skipped_advisories": skipped_advisories,
    }
    logger.info("Cisco collector run complete: %s", summary)
    return summary
