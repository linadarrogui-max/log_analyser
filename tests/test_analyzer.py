from __future__ import annotations

import gzip
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from loganalyser.analyzer import AnalysisReport, analyze_logs, parse_log_line
from loganalyser.charts import build_dashboard_figure
from loganalyser.logs import iter_log_lines


class ParseLogLineTests(unittest.TestCase):
    def test_parses_failed_password(self) -> None:
        event = parse_log_line(
            "May  3 00:02:48 ns sshd[1098645]: "
            "Failed password for root from 203.171.18.62 port 3549 ssh2"
        )

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.month, "May")
        self.assertEqual(event.day, 3)
        self.assertEqual(event.process, "sshd")
        self.assertEqual(event.pid, 1098645)
        self.assertEqual(event.event_type, "failed_password")
        self.assertEqual(event.ip, "203.171.18.62")
        self.assertEqual(event.user, "root")

    def test_parses_accepted_login_and_ignores_unstructured_lines(self) -> None:
        event = parse_log_line(
            "Jun 12 10:11:12 host sshd[42]: "
            "Accepted publickey for alice from 2001:db8::1 port 22 ssh2"
        )

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.event_type, "accepted_login")
        self.assertEqual(event.ip, "2001:db8::1")
        self.assertEqual(event.user, "alice")
        self.assertIsNone(parse_log_line("not a syslog line"))


class LogReaderTests(unittest.TestCase):
    def test_reads_text_and_gzip_files_in_a_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            (directory / "auth.log").write_text("plain\n", encoding="utf-8")
            with gzip.open(directory / "auth.log.1.gz", "wt", encoding="utf-8") as stream:
                stream.write("compressed\n")

            self.assertEqual(list(iter_log_lines(directory)), ["plain\n", "compressed\n"])

    def test_reads_gzip_content_without_gzip_extension(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            log_path = Path(temporary_directory) / "auth.log"
            with gzip.open(log_path, "wt", encoding="utf-8") as stream:
                stream.write(
                    "May  3 00:02:48 ns sshd[42]: "
                    "Failed password for root from 1.2.3.4\n"
                )

            self.assertEqual(
                len(list(iter_log_lines(log_path))),
                1,
            )
            report = analyze_logs(log_path)
            self.assertEqual(report.event_counts["failed_password"], 1)

    def test_reads_tar_gzip_members_without_recounting_sibling_copies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            duplicate = b"May  3 00:02:48 ns sshd[42]: Failed password for root from 1.2.3.4\n"
            compressed_line = (
                b"May  4 00:02:48 ns sshd[43]: "
                b"Failed password for root from 5.6.7.8\n"
            )
            compressed_log = io.BytesIO()
            with gzip.GzipFile(fileobj=compressed_log, mode="wb") as stream:
                stream.write(compressed_line)
            (directory / "auth.log.1").write_bytes(duplicate)
            archive_path = directory / "auth.log"
            with tarfile.open(archive_path, "w:gz") as archive:
                member = tarfile.TarInfo("auth.log.1")
                member.size = len(duplicate)
                archive.addfile(member, io.BytesIO(duplicate))
                compressed_member = tarfile.TarInfo("extra.log.gz")
                compressed_member.size = len(compressed_log.getvalue())
                archive.addfile(compressed_member, io.BytesIO(compressed_log.getvalue()))

            self.assertEqual(
                list(iter_log_lines(archive_path)),
                [
                    duplicate.decode(),
                    compressed_line.decode(),
                ],
            )
            self.assertEqual(
                list(iter_log_lines(directory)),
                [
                    compressed_line.decode(),
                    duplicate.decode(),
                ],
            )


class AnalyzeLogsTests(unittest.TestCase):
    def test_reports_counts_and_failed_passwords_by_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            log_path = Path(temporary_directory) / "auth.log"
            log_path.write_text(
                "\n".join(
                    (
                        "May  3 00:02:48 ns sshd[42]: Failed password for root from 1.2.3.4",
                        "May  3 00:02:49 ns sshd[43]: Failed password for root from 1.2.3.4",
                        "May  3 00:03:00 ns sshd[44]: Accepted password for alice from 5.6.7.8",
                        "invalid row",
                    )
                )
                + "\n",
                encoding="utf-8",
            )

            report = analyze_logs(log_path)

            self.assertEqual(report.total_lines, 4)
            self.assertEqual(report.parsed_lines, 3)
            self.assertEqual(report.event_counts["failed_password"], 2)
            self.assertEqual(report.event_counts["accepted_login"], 1)
            self.assertEqual(report.failed_passwords_by_ip, {"1.2.3.4": 2})


class DashboardChartTests(unittest.TestCase):
    def test_builds_event_and_top_ip_charts(self) -> None:
        report = AnalysisReport(
            total_lines=3,
            parsed_lines=3,
            event_counts={"failed_password": 2, "accepted_login": 1},
            failed_passwords_by_ip={"1.2.3.4": 2},
        )

        figure = build_dashboard_figure(report)

        self.assertEqual(len(figure.axes), 2)
        self.assertEqual(len(figure.axes[0].patches), 2)
        self.assertEqual(len(figure.axes[1].patches), 1)
        self.assertIn(
            "Événements détectés",
            figure.axes[0].get_title(loc="left"),
        )
        self.assertIn(
            "Mot de passe refusé",
            [label.get_text() for label in figure.axes[0].get_xticklabels()],
        )
        self.assertEqual(
            [label.get_text() for label in figure.axes[0].texts],
            ["2\n66.7%", "1\n33.3%"],
        )
        self.assertEqual(
            [label.get_text() for label in figure.axes[1].texts],
            ["2"],
        )

if __name__ == "__main__":
    unittest.main()
