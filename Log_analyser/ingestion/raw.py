import gzip
import os

from app_logging import get_logger


logger = get_logger(__name__)


def iter_log_rows(path, filenames=None):
    """Yield selected logs as (filename, line number, text)."""
    if not os.path.isdir(path):
        error = FileNotFoundError(f"Directory not found: {path}")
        logger.error("Unable to read log directory %s: %s", path, error)
        raise error

    try:
        files = os.listdir(path) if filenames is None else filenames
        for file in sorted(files):
            if file.startswith("."):
                continue

            file_path = os.path.join(path, file)
            if not os.path.isfile(file_path):
                continue

            opener = (
                gzip.open(file_path, mode="rt", encoding="utf-8", errors="replace")
                if file.endswith(".gz")
                else open(file_path, mode="rt", encoding="utf-8", errors="replace")
            )

            with opener as source:
                for line_number, row in enumerate(source, start=1):
                    yield file, line_number, row
    except Exception:
        logger.exception("Unable to read log files in %s", path)
        raise


def toRows(path):
    """Return all lines from every text or gzip-compressed log file in a directory."""
    return [row for _, _, row in iter_log_rows(path)]


if __name__ == "__main__":
    print(toRows("./data")[:10])