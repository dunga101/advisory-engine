import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main() -> None:
    logger.info("publisher skeleton started — export/git-push logic lands in Phase 5")
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
