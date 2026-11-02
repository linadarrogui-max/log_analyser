from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from loganalyser.analyzer import AnalysisReport, analyze_logs


def _format_report(report: AnalysisReport) -> str:
    counts = report.event_counts
    lines = [
        f"Lines analyzed: {report.total_lines}",
        f"Lines parsed: {report.parsed_lines}",
        f"Failed passwords: {counts.get('failed_password', 0)}",
        f"Accepted logins: {counts.get('accepted_login', 0)}",
        f"Invalid users: {counts.get('invalid_user', 0)}",
        f"Authentication failures: {counts.get('authentication_failure', 0)}",
    ]
    if report.failed_passwords_by_ip:
        lines.append("Top IPs by failed passwords:")
        lines.extend(
            f"  {ip}: {attempts}"
            for ip, attempts in list(report.failed_passwords_by_ip.items())[:10]
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze Linux authentication logs.")
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path("data"),
        help="log file or directory to analyze (default: data)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the report as JSON",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="open the graphical dashboard",
    )
    args = parser.parse_args(argv)

    if args.gui:
        from loganalyser.gui import main as gui_main

        return gui_main()

    report = analyze_logs(args.path)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_format_report(report))
    return 0
