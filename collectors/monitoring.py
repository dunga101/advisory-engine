"""Architecture review item 3 (pipeline alerting): collectors' nightly
jobs (kev/msrc/cisco/fortinet/precheck/verdict) previously only ever
logged failures via logger.exception -- fine for an interactive session,
invisible for an unattended 03:00-03:45 cron run nobody is watching.
alert() gives every stage a single, always-on, grep-able sink: a
dedicated log file (zero extra infra required). An optional Uptime Kuma
push is also sent if COLLECTORS_PIPELINE_PUSH_URL is configured, same
opt-in pattern as publisher/monitoring.py's UPTIME_KUMA_PUSH_URL -- kept
as a *separate* env var/monitor rather than reusing publisher's, since
collectors (03:00-03:45) and publisher (04:00) run at different times and
pinging one shared monitor from both would let one job's "up" silently
clobber the other's "down" in Kuma's history.
"""
import logging
import os
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

ALERT_LOG_PATH = Path(os.environ.get("PIPELINE_ALERT_LOG_PATH", "logs/pipeline-alerts.log"))
PIPELINE_PUSH_URL = os.environ.get("COLLECTORS_PIPELINE_PUSH_URL") or None

_alert_logger = logging.getLogger("pipeline.alerts")


def _ensure_alert_handler() -> None:
    """Attaches the file handler lazily, on first real alert, rather than
    at import time -- importing this module (e.g. from a test) must never
    create logs/ as a side effect."""
    if any(isinstance(h, logging.FileHandler) for h in _alert_logger.handlers):
        return
    ALERT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(ALERT_LOG_PATH)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    _alert_logger.addHandler(handler)


def alert(stage: str, message: str) -> None:
    """The one thing every collectors job funnels a failure or an
    unexpected-zero-results signal through. Tail ALERT_LOG_PATH (or point
    PIPELINE_ALERT_LOG_PATH somewhere log-rotated) to see today's pipeline
    health without digging through the full INFO/DEBUG stream. Never
    raises -- an alerting failure must never take down the job it's
    reporting on, same rule publisher/monitoring.py's ping follows."""
    _ensure_alert_handler()
    _alert_logger.error("[%s] %s", stage, message)

    if not PIPELINE_PUSH_URL:
        return
    try:
        requests.get(
            PIPELINE_PUSH_URL,
            params={"status": "down", "msg": f"{stage}: {message}"[:200]},
            timeout=10,
        )
    except requests.RequestException:
        logger.exception("Pipeline alert push failed (stage=%s)", stage)
