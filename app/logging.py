import logging
import sys

from app.settings import settings


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("lightspeed")
    logger.setLevel(getattr(logging, settings.log_level.upper()))
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


logger = setup_logging()
