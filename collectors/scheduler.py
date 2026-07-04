import logging

from apscheduler.schedulers.blocking import BlockingScheduler

from collectors.monitoring import alert
from collectors.precheck import run_once as run_precheck
from collectors.sources.cisco import run_once as run_cisco
from collectors.sources.fortinet import run_once as run_fortinet
from collectors.sources.kev import run_once as run_kev
from collectors.sources.msrc import run_once as run_msrc
from collectors.verdict import run_once as run_verdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_kev_job() -> None:
    try:
        result = run_kev()
    except Exception as exc:
        logger.exception("KEV collector run failed")
        alert("kev", f"run failed: {type(exc).__name__}: {exc}")
        return
    # Unlike MSRC/Cisco/Fortinet (backfill-windowed, legitimately empty on
    # most days), KEV always fetches CISA's *entire* current catalog —
    # it has held 1000+ entries every day since inception, so zero is
    # essentially always a fetch/parse failure, not a real empty feed.
    # Also matters for kev.py's un-listing detection (architecture review
    # item 5): a spurious empty response there would otherwise look like
    # every listed CVE just got delisted at once.
    if result.get("feed_entry_count") == 0:
        alert("kev", "feed returned zero entries — treating as a fetch/parse failure, not a real empty catalog")


def run_msrc_job() -> None:
    try:
        run_msrc()
    except Exception as exc:
        logger.exception("MSRC collector run failed")
        alert("msrc", f"run failed: {type(exc).__name__}: {exc}")


def run_cisco_job() -> None:
    try:
        run_cisco()
    except Exception as exc:
        logger.exception("Cisco collector run failed")
        alert("cisco", f"run failed: {type(exc).__name__}: {exc}")


def run_fortinet_job() -> None:
    try:
        run_fortinet()
    except Exception as exc:
        logger.exception("Fortinet collector run failed")
        alert("fortinet", f"run failed: {type(exc).__name__}: {exc}")


def run_precheck_job() -> None:
    try:
        run_precheck()
    except Exception as exc:
        logger.exception("Pre-check engine run failed")
        alert("precheck", f"run failed: {type(exc).__name__}: {exc}")


def run_verdict_job() -> None:
    try:
        run_verdict()
    except Exception as exc:
        logger.exception("Verdict engine run failed")
        alert("verdict", f"run failed: {type(exc).__name__}: {exc}")


def main() -> None:
    scheduler = BlockingScheduler()
    # Staggered so MSRC/Cisco/Fortinet/verdict run after KEV lands fresh
    # kev_listed data, precheck runs after Fortinet so the day's newly
    # ingested advisories get gated automatically, and verdict runs last so
    # Cisco/Fortinet data is available when it computes. Publisher is
    # scheduled separately, from its own container (publisher/main.py) —
    # collectors has no reason to hold GitHub push credentials.
    scheduler.add_job(run_kev_job, "cron", hour=3, minute=0, id="kev_daily")
    scheduler.add_job(run_msrc_job, "cron", hour=3, minute=15, id="msrc_daily")
    scheduler.add_job(run_cisco_job, "cron", hour=3, minute=30, id="cisco_daily")
    scheduler.add_job(run_fortinet_job, "cron", hour=3, minute=35, id="fortinet_daily")
    scheduler.add_job(run_precheck_job, "cron", hour=3, minute=40, id="precheck_daily")
    scheduler.add_job(run_verdict_job, "cron", hour=3, minute=45, id="verdict_daily")
    logger.info(
        "collectors scheduler starting; KEV 03:00, MSRC 03:15, Cisco 03:30, "
        "Fortinet 03:35, precheck 03:40, verdict 03:45 daily"
    )
    scheduler.start()


if __name__ == "__main__":
    main()
