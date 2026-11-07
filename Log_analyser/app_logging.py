import logging
from pathlib import Path


LOG_DIRECTORY = Path(__file__).resolve().parent / "logs"


def get_logger(module_name):
    """Create one UTF-8 log file per application module."""
    logger = logging.getLogger(module_name)
    if logger.handlers:
        return logger

    LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)
    filename = f"{module_name.rsplit('.', 1)[-1]}.log"
    handler = logging.FileHandler(LOG_DIRECTORY / filename, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"
        )
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger
