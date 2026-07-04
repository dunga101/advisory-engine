import logging
from datetime import date, datetime, timedelta, timezone

import requests

from publisher.config import (
    FRESHNESS_THRESHOLD_HOURS,
    SITE_STATUS_URL,
    TOKEN_EXPIRES,
    TOKEN_EXPIRY_URGENT_DAYS,
    TOKEN_EXPIRY_WARN_DAYS,
    UPTIME_KUMA_PUSH_URL,
)

logger = logging.getLogger(__name__)


def check_token_expiry(today: date | None = None) -> str | None:
    """PAT-expiry preflight (architecture review item 3c). Returns a
    warning message once within TOKEN_EXPIRY_WARN_DAYS of TOKEN_EXPIRES,
    escalated in wording (not mechanism — the caller decides how to route
    it) inside TOKEN_EXPIRY_URGENT_DAYS. Returns None when there's nothing
    to report."""
    today = today or date.today()
    days_left = (TOKEN_EXPIRES - today).days

    if days_left > TOKEN_EXPIRY_WARN_DAYS:
        return None
    if days_left <= TOKEN_EXPIRY_URGENT_DAYS:
        return (
            f"URGENT: GITHUB_PUSH_TOKEN expires in {days_left} day(s) "
            f"({TOKEN_EXPIRES.isoformat()}) — rotate now, publishing will "
            "start failing once it expires."
        )
    return (
        f"WARNING: GITHUB_PUSH_TOKEN expires in {days_left} day(s) "
        f"({TOKEN_EXPIRES.isoformat()}) — schedule a rotation."
    )


def ping_dead_mans_switch(
    push_url: str | None = None, *, status: str = "up", message: str = "OK"
) -> None:
    """Ping the Uptime Kuma push monitor for this run (architecture review
    item 3a). status is 'up' or 'down'; message is shown in Kuma's monitor
    history. Never raises — a monitoring ping failing must never fail (or
    mask the outcome of) the publish run it's reporting on."""
    push_url = push_url if push_url is not None else UPTIME_KUMA_PUSH_URL
    if not push_url:
        logger.warning(
            "UPTIME_KUMA_PUSH_URL not configured — dead-man's-switch ping skipped "
            "(status=%s, message=%r)",
            status,
            message,
        )
        return
    try:
        requests.get(push_url, params={"status": status, "msg": message}, timeout=10)
    except requests.RequestException:
        logger.exception("Dead-man's-switch ping failed (status=%s)", status)


def check_site_freshness(
    site_status_url: str | None = None, *, now: datetime | None = None
) -> str | None:
    """Freshness check (architecture review item 3b): fetch the live
    site's status.json and compare its generated_at to now. Returns a
    warning message if stale beyond FRESHNESS_THRESHOLD_HOURS, or if the
    check itself fails (an unreachable site is itself a signal worth
    surfacing). Returns None when the site is fresh."""
    site_status_url = site_status_url if site_status_url is not None else SITE_STATUS_URL
    if not site_status_url:
        return "SITE_STATUS_URL not configured — freshness check skipped"

    now = now or datetime.now(timezone.utc)
    try:
        response = requests.get(site_status_url, timeout=15)
        response.raise_for_status()
        generated_at = datetime.fromisoformat(response.json()["generated_at"])
    except Exception as exc:
        return f"Site freshness check failed: {type(exc).__name__}: {exc}"

    age = now - generated_at
    threshold = timedelta(hours=FRESHNESS_THRESHOLD_HOURS)
    if age > threshold:
        return (
            f"Live site is stale: last generated {generated_at.isoformat()} "
            f"({age} ago, threshold {threshold})"
        )
    return None
