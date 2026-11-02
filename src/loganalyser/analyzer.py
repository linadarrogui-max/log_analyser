from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from loganalyser.logs import iter_log_lines

EventType = Literal[
    "failed_password",
    "accepted_login",
    "invalid_user",
    "authentication_failure",
    "other",
]

_LOG_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<process>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+)"
)
_ACCEPTED_LOGIN = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+)"
)
_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
_AUTH_FAILURE = re.compile(r"\bauthentication failure;.*?\brhost=(?P<ip>\S+)")


@dataclass(frozen=True)
class LogEvent:
    month: str
    day: int
    time: str
    host: str
    process: str
    pid: int | None
    message: str
    event_type: EventType
    ip: str | None = None
    user: str | None = None


@dataclass(frozen=True)
class AnalysisReport:
    total_lines: int
    parsed_lines: int
    event_counts: dict[str, int]
    failed_passwords_by_ip: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def parse_log_line(line: str) -> LogEvent | None:
    match = _LOG_LINE.match(line.rstrip("\r\n"))
    if match is None:
        return None

    message = match["message"]
    event_type: EventType = "other"
    ip: str | None = None
    user: str | None = None

    for pattern, kind in (
        (_FAILED_PASSWORD, "failed_password"),
        (_ACCEPTED_LOGIN, "accepted_login"),
        (_INVALID_USER, "invalid_user"),
        (_AUTH_FAILURE, "authentication_failure"),
    ):
        event_match = pattern.search(message)
        if event_match is not None:
            event_type = kind
            ip = event_match["ip"]
            user = event_match.groupdict().get("user")
            break

    return LogEvent(
        month=match["month"],
        day=int(match["day"]),
        time=match["time"],
        host=match["host"],
        process=match["process"],
        pid=int(match["pid"]) if match["pid"] else None,
        message=message,
        event_type=event_type,
        ip=ip,
        user=user,
    )


def analyze_logs(path: str | Path) -> AnalysisReport:
    total_lines = 0
    parsed_lines = 0
    event_counts: Counter[str] = Counter()
    failed_passwords_by_ip: Counter[str] = Counter()

    for line in iter_log_lines(path):
        total_lines += 1
        event = parse_log_line(line)
        if event is None:
            continue
        parsed_lines += 1
        event_counts[event.event_type] += 1
        if event.event_type == "failed_password" and event.ip is not None:
            failed_passwords_by_ip[event.ip] += 1

    return AnalysisReport(
        total_lines=total_lines,
        parsed_lines=parsed_lines,
        event_counts=dict(sorted(event_counts.items())),
        failed_passwords_by_ip=dict(
            sorted(failed_passwords_by_ip.items(), key=lambda item: (-item[1], item[0]))
        ),
    )
