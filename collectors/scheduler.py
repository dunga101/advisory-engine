import logging

from apscheduler.schedulers.blocking import BlockingScheduler

from collectors.sources.kev import run_once as run_kev
from collectors.sources.msrc import run_once as run_msrc
from collectors.verdict import run_once as run_verdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_kev_job() -> None:
    try:
        run_kev()
    except Exception:
        logger.exception("KEV collector run failed")


def run_msrc_job() -> None:
    try:
        run_msrc()
    except Exception:
        logger.exception("MSRC collector run failed")


def run_verdict_job() -> None:
    try:
        run_verdict()
    except Exception:
        logger.exception("Verdict engine run failed")


def main() -> None:
    scheduler = BlockingScheduler()
    # Staggered so MSRC/verdict run after KEV lands fresh kev_listed data.
    scheduler.add_job(run_kev_job, "cron", hour=3, minute=0, id="kev_daily")
    scheduler.add_job(run_msrc_job, "cron", hour=3, minute=15, id="msrc_daily")
    scheduler.add_job(run_verdict_job, "cron", hour=3, minute=45, id="verdict_daily")
    logger.info(
        "collectors scheduler starting; KEV 03:00, MSRC 03:15, verdict 03:45 daily"
    )
    scheduler.start()


if __name__ == "__main__":
    main()
