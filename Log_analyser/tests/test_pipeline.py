import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import matplotlib

from ingestion.raw import iter_log_rows
from process.extract_transforme import parse_auth_event
from process import geolocation
from serving.dashboard import render
from storage.postgres import get_dashboard_data


matplotlib.use("Agg")


class AuthenticationParsingTests(unittest.TestCase):
    def test_repeated_invalid_user_attempts_are_counted(self):
        row = (
            "Oct  7 11:22:33 host sshd[123]: message repeated 3 times: "
            "[ Failed password for invalid user guest from 203.0.113.10 "
            "port 22 ssh2]"
        )

        event = parse_auth_event(row)

        self.assertEqual(event["status"], "failed")
        self.assertEqual(event["user"], "guest")
        self.assertTrue(event["invalid_user"])
        self.assertEqual(event["repeat_count"], 3)

    def test_successful_login_is_parsed(self):
        row = (
            "Oct  7 11:22:33 host sshd[123]: Accepted password for alice "
            "from 8.8.8.8 port 22 ssh2"
        )

        event = parse_auth_event(row)

        self.assertEqual(event["status"], "successful")
        self.assertEqual(event["user"], "alice")
        self.assertFalse(event["invalid_user"])
        self.assertEqual(event["repeat_count"], 1)


class IngestionTests(unittest.TestCase):
    def test_selected_logs_exclude_country_and_cache_files(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "auth.log.1").write_text("ssh log\n", encoding="utf-8")
            (folder / "ip_country.csv").write_text(
                "network,country\n", encoding="utf-8"
            )
            (folder / "ip_country_cache.json").write_text(
                "{}\n", encoding="utf-8"
            )

            rows = list(iter_log_rows(folder, ["auth.log.1"]))

        self.assertEqual(rows, [("auth.log.1", 1, "ssh log\n")])


class GeolocationTests(unittest.TestCase):
    def test_most_specific_local_network_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "ip_country.csv"
            csv_path.write_text(
                "network,country\n"
                "8.8.0.0/16,Country A\n"
                "8.8.8.0/24,Country B\n",
                encoding="utf-8",
            )
            with patch.object(geolocation, "COUNTRY_RANGE_FILE", csv_path):
                with patch.object(geolocation, "_COUNTRY_TRIES", None):
                    country = geolocation._local_country(
                        ipaddress.ip_address("8.8.8.8")
                    )

        self.assertEqual(country, "Country B")

    def test_cache_save_retries_temporary_windows_permission_error(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "ip_country_cache.json"
            cache_path.write_text('{"previous": true}', encoding="utf-8")
            real_replace = geolocation.os.replace
            calls = []

            def replace_with_transient_lock(source, destination):
                calls.append((source, destination))
                if len(calls) == 1:
                    raise PermissionError("temporary file lock")
                real_replace(source, destination)

            with patch.object(geolocation, "COUNTRY_CACHE_FILE", cache_path):
                with patch.object(
                    geolocation.os, "replace", side_effect=replace_with_transient_lock
                ):
                    with patch.object(geolocation.time, "sleep"):
                        geolocation._save_country_cache()

            self.assertEqual(len(calls), 2)
            self.assertTrue(cache_path.is_file())
            self.assertEqual(list(Path(directory).glob("*.tmp")), [])


class DashboardQueryTests(unittest.TestCase):
    def test_dashboard_uses_all_three_postgresql_aggregations(self):
        expected = [
            [{"country": "Country A", "attempts": 2}],
            [{"username": "alice", "attempts": 1}],
            [{"username": "guest", "attempts": 3}],
        ]
        with patch(
            "storage.postgres._query_rows",
            side_effect=expected,
        ) as query:
            report = get_dashboard_data()

        self.assertEqual(report["failed_by_country"], expected[0])
        self.assertEqual(report["successful_by_user"], expected[1])
        self.assertEqual(report["failed_invalid_users"], expected[2])
        self.assertEqual(query.call_count, 3)
        queries = " ".join(call.args[0] for call in query.call_args_list)
        self.assertIn("status = 'failed'", queries)
        self.assertIn("status = 'successful'", queries)
        self.assertIn("invalid_user = TRUE", queries)


class DashboardRenderingTests(unittest.TestCase):
    def test_dashboard_saves_all_three_requested_charts(self):
        report = {
            "failed_by_country": [{"country": "Country A", "attempts": 2}],
            "successful_by_user": [{"username": "alice", "attempts": 1}],
            "failed_invalid_users": [{"username": "guest", "attempts": 3}],
        }
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "dashboard.png"
            with patch("matplotlib.pyplot.show"):
                render(report, output_path)

            self.assertTrue(output_path.is_file())
            self.assertGreater(output_path.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
