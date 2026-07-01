import logging

from apscheduler.schedulers.blocking import BlockingScheduler

from collectors.sources.kev import run_once as run_kev

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_kev_job() -> None:
    try:
        run_kev()
    except Exception:
        logger.exception("KEV collector run failed")


def main() -> None:
    scheduler = BlockingScheduler()
    scheduler.add_job(run_kev_job, "cron", hour=3, minute=0, id="kev_daily")
    logger.info("collectors scheduler starting; KEV job scheduled daily at 03:00")
    scheduler.start()


if __name__ == "__main__":
    main()
