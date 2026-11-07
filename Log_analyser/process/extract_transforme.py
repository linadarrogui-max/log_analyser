import re
import ipaddress

from app_logging import get_logger


logger = get_logger(__name__)

LOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<process>[^\s:]+(?:\[[^\]]+\])?):\s(?P<message>.*)$"
)
FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?:(invalid user) )?(?P<user>\S+) from (?P<ip>\S+)"
)
ACCEPTED_LOGIN_PATTERN = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)"
)
REPEATED_MESSAGE_PATTERN = re.compile(
    r"^message repeated (?P<count>\d+) times: \[ (?P<message>.*)\]$"
)


def extract_from_row(row):
    """Extract the timestamp metadata and message from a single auth log line."""
    if not row or not isinstance(row, str):
        return {}

    try:
        match = LOG_PATTERN.match(row.strip())
        if not match:
            return {}

        return match.groupdict()
    except Exception:
        logger.exception("Unable to parse authentication log row")
        raise


def parse_auth_event(row):
    """Extract a successful or failed SSH password authentication event."""
    try:
        parsed_row = extract_from_row(row)
        if not parsed_row:
            return {}

        message = parsed_row["message"]
        repeated_message = REPEATED_MESSAGE_PATTERN.match(message)
        repeat_count = 1
        if repeated_message:
            repeat_count = int(repeated_message.group("count"))
            message = repeated_message.group("message")

        match = FAILED_PASSWORD_PATTERN.search(message)
        status = "failed"
        invalid_user = False
        if match:
            username = match.group("user")
            ip = match.group("ip")
            invalid_user = match.group(1) is not None
        else:
            match = ACCEPTED_LOGIN_PATTERN.search(message)
            if not match:
                return {}
            status = "successful"
            username = match.group("user")
            ip = match.group("ip")

        ipaddress.ip_address(ip)
        return {
            "status": status,
            "user": username,
            "ip": ip,
            "invalid_user": invalid_user,
            "repeat_count": repeat_count,
            "month": parsed_row["month"],
            "day": int(parsed_row["day"]),
            "time": parsed_row["time"],
            "host": parsed_row["host"],
            "process": parsed_row["process"],
            "message": message,
            "raw_message": row.rstrip("\r\n"),
        }
    except Exception:
        logger.exception("Unable to parse authentication event")
        raise


def extract(rows):
    """Parse a sequence of raw log rows into dictionaries."""
    try:
        return [extract_from_row(row) for row in rows if row]
    except Exception:
        logger.exception("Unable to extract authentication log rows")
        raise
