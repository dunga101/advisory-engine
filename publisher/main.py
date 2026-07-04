import logging

from apscheduler.schedulers.blocking import BlockingScheduler

from publisher.monitoring import check_site_freshness, check_token_expiry, ping_dead_mans_switch
from publisher.publish import run_once

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_publisher_job() -> None:
    """Runs the publish, then closes the monitoring loop (architecture
    review item 3): a PAT-expiry preflight before the run, a dead-man's-
    switch ping reporting the run's outcome, and (on success) a freshness
    check against the live site so a publish that "succeeded" but didn't
    actually land is still caught."""
    token_warning = check_token_expiry()
    if token_warning:
        logger.warning(token_warning)

    try:
        run_once()
    except Exception:
        logger.exception("Publisher run failed")
        message = "Publisher run failed"
        if token_warning:
            message = f"{message}; {token_warning}"
        ping_dead_mans_switch(status="down", message=message[:200])
        return

    freshness_warning = check_site_freshness()
    if freshness_warning:
        logger.warning(freshness_warning)

    if freshness_warning:
        message = freshness_warning
        status = "down"
    elif token_warning:
        message = token_warning
        status = "up"
    else:
        message = "OK"
        status = "up"
    ping_dead_mans_switch(status=status, message=message[:200])


def main() -> None:
    """Publisher owns its own schedule (separate container/image from
    collectors, which has no reason to hold GITHUB_PUSH_TOKEN). 04:00
    daily — matches the staggering collectors/scheduler.py uses, running
    after its 03:45 verdict job so the day's pipeline has settled."""
    scheduler = BlockingScheduler()
    scheduler.add_job(run_publisher_job, "cron", hour=4, minute=0, id="publisher_daily")
    logger.info("publisher scheduler starting; publish 04:00 daily")
    scheduler.start()


if __name__ == "__main__":
    main()
