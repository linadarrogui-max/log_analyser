from __future__ import annotations

import json
from dataclasses import dataclass

import mysql.connector
from mysql.connector.connection import MySQLConnection

from loganalyser.analyzer import AnalysisReport, LogEvent

_EVENT_COLUMNS = (
    "run_id, month, day, event_time, host, process, pid, message, "
    "event_type, ip, username"
)


@dataclass(frozen=True)
class DatabaseConfig:
    host: str
    port: int
    database: str
    user: str
    password: str


@dataclass(frozen=True)
class StoredRun:
    run_id: int
    source_path: str
    analyzed_at: str
    report: AnalysisReport


class MySQLStore:
    def __init__(self, config: DatabaseConfig) -> None:
        self._config = config

    def _connect(self) -> MySQLConnection:
        return mysql.connector.connect(
            host=self._config.host,
            port=self._config.port,
            database=self._config.database,
            user=self._config.user,
            password=self._config.password,
            connection_timeout=5,
        )

    def initialize(self) -> None:
        connection = self._connect()
        try:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS analysis_runs (
                        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                        source_path TEXT NOT NULL,
                        analyzed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        total_lines BIGINT UNSIGNED NOT NULL,
                        parsed_lines BIGINT UNSIGNED NOT NULL,
                        event_counts JSON NOT NULL,
                        failed_passwords_by_ip JSON NOT NULL
                    ) ENGINE=InnoDB
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS auth_events (
                        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                        run_id BIGINT UNSIGNED NOT NULL,
                        month CHAR(3) NOT NULL,
                        day TINYINT UNSIGNED NOT NULL,
                        event_time TIME NOT NULL,
                        host VARCHAR(255) NOT NULL,
                        process VARCHAR(255) NOT NULL,
                        pid BIGINT UNSIGNED NULL,
                        message TEXT NOT NULL,
                        event_type VARCHAR(40) NOT NULL,
                        ip VARCHAR(45) NULL,
                        username VARCHAR(255) NULL,
                        INDEX idx_auth_events_run_type (run_id, event_type),
                        INDEX idx_auth_events_ip (run_id, ip),
                        CONSTRAINT fk_auth_events_run
                            FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
                            ON DELETE CASCADE
                    ) ENGINE=InnoDB
                    """
                )
                connection.commit()
            finally:
                cursor.close()
        finally:
            connection.close()

    def save_analysis(
        self,
        source_path: str,
        report: AnalysisReport,
        events: list[LogEvent],
    ) -> int:
        connection = self._connect()
        try:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    """
                    INSERT INTO analysis_runs (
                        source_path, total_lines, parsed_lines,
                        event_counts, failed_passwords_by_ip
                    ) VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        source_path,
                        report.total_lines,
                        report.parsed_lines,
                        json.dumps(report.event_counts),
                        json.dumps(report.failed_passwords_by_ip),
                    ),
                )
                run_id = cursor.lastrowid
                if run_id is None:
                    raise RuntimeError("MySQL n'a pas retourné l'identifiant de l'analyse.")

                insert_event = f"""
                    INSERT INTO auth_events ({_EVENT_COLUMNS})
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                for start in range(0, len(events), 1000):
                    cursor.executemany(
                        insert_event,
                        [
                            (
                                run_id,
                                event.month,
                                event.day,
                                event.time,
                                event.host,
                                event.process,
                                event.pid,
                                event.message,
                                event.event_type,
                                event.ip,
                                event.user,
                            )
                            for event in events[start : start + 1000]
                        ],
                    )
                connection.commit()
                return int(run_id)
            except mysql.connector.Error:
                connection.rollback()
                raise
            finally:
                cursor.close()
        finally:
            connection.close()

    def list_runs(self) -> list[StoredRun]:
        connection = self._connect()
        try:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    """
                    SELECT id, source_path, analyzed_at, total_lines, parsed_lines,
                           event_counts, failed_passwords_by_ip
                    FROM analysis_runs
                    ORDER BY analyzed_at DESC, id DESC
                    """
                )
                return [
                    StoredRun(
                        run_id=int(row[0]),
                        source_path=str(row[1]),
                        analyzed_at=str(row[2]),
                        report=AnalysisReport(
                            total_lines=int(row[3]),
                            parsed_lines=int(row[4]),
                            event_counts=_json_counts(row[5]),
                            failed_passwords_by_ip=_json_counts(row[6]),
                        ),
                    )
                    for row in cursor.fetchall()
                ]
            finally:
                cursor.close()
        finally:
            connection.close()

    def load_events(
        self,
        run_id: int,
        event_type: str | None = None,
        search: str = "",
        limit: int = 1000,
    ) -> list[LogEvent]:
        conditions = ["run_id = %s"]
        parameters: list[object] = [run_id]
        if event_type:
            conditions.append("event_type = %s")
            parameters.append(event_type)
        if search:
            conditions.append(
                "LOWER(CONCAT_WS(' ', username, ip, host, message)) LIKE %s"
            )
            parameters.append(f"%{search.lower()}%")
        parameters.append(limit)

        connection = self._connect()
        try:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    f"""
                    SELECT month, day, event_time, host, process, pid, message,
                           event_type, ip, username
                    FROM auth_events
                    WHERE {" AND ".join(conditions)}
                    ORDER BY id DESC
                    LIMIT %s
                    """,
                    parameters,
                )
                return [
                    LogEvent(
                        month=str(row[0]),
                        day=int(row[1]),
                        time=str(row[2]),
                        host=str(row[3]),
                        process=str(row[4]),
                        pid=int(row[5]) if row[5] is not None else None,
                        message=str(row[6]),
                        event_type=row[7],
                        ip=str(row[8]) if row[8] is not None else None,
                        user=str(row[9]) if row[9] is not None else None,
                    )
                    for row in cursor.fetchall()
                ]
            finally:
                cursor.close()
        finally:
            connection.close()

    def delete_run(self, run_id: int) -> None:
        connection = self._connect()
        try:
            cursor = connection.cursor()
            try:
                cursor.execute("DELETE FROM analysis_runs WHERE id = %s", (run_id,))
                if cursor.rowcount == 0:
                    raise ValueError("Cette analyse n'existe plus dans la base.")
                connection.commit()
            except mysql.connector.Error:
                connection.rollback()
                raise
            finally:
                cursor.close()
        finally:
            connection.close()


def _json_counts(value: object) -> dict[str, int]:
    decoded = json.loads(value) if isinstance(value, str) else value
    if not isinstance(decoded, dict):
        raise ValueError("Les statistiques enregistrées dans MySQL sont invalides.")
    return {str(key): int(count) for key, count in decoded.items()}
