import csv
import getpass
import ipaddress
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from app_logging import get_logger


logger = get_logger(__name__)
SCHEMA_FILE = Path(__file__).with_name("schema.sql")
BATCH_SIZE = 250
_SESSION_PASSWORD = None
DATABASE_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _psql_command():
    executable = os.environ.get("PSQL_PATH") or shutil.which("psql")
    if not executable and os.name == "nt":
        install_directory = Path(
            os.environ.get("ProgramFiles", r"C:\Program Files")
        ) / "PostgreSQL"
        candidates = sorted(
            install_directory.glob("*/bin/psql.exe"),
            reverse=True,
        )
        if candidates:
            executable = str(candidates[0])
    if not executable:
        raise FileNotFoundError(
            "PostgreSQL client psql not found; install PostgreSQL or set PSQL_PATH"
        )

    command = [
        executable,
        "--no-psqlrc",
        "--no-password",
        "--set=ON_ERROR_STOP=1",
        "--quiet",
        "--tuples-only",
        "--no-align",
    ]
    for option, variable, default in (
        ("--host", "PGHOST", "localhost"),
        ("--port", "PGPORT", "5432"),
        ("--username", "PGUSER", "postgres"),
        ("--dbname", "PGDATABASE", "log_analyser"),
    ):
        command.extend((option, os.environ.get(variable, default)))
    return command


def _run_sql(script):
    """Run SQL through psql, prompting securely if PostgreSQL requests a password."""
    global _SESSION_PASSWORD
    command = _psql_command()
    environment = os.environ.copy()
    environment["PGCLIENTENCODING"] = "UTF8"
    if _SESSION_PASSWORD:
        environment["PGPASSWORD"] = _SESSION_PASSWORD

    try:
        result = subprocess.run(
            command,
            input="SET standard_conforming_strings = on;\n" + script,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=120,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        logger.exception("Could not execute PostgreSQL client")
        raise

    authentication_error = (result.stderr or "").lower()
    password_required = any(
        marker in authentication_error
        for marker in (
            "no password supplied",
            "password authentication failed",
            "mot de passe",
        )
    )
    if result.returncode and password_required and not environment.get(
        "PGPASSWORD"
    ):
        try:
            password = getpass.getpass("Mot de passe PostgreSQL (saisie masquée) : ")
        except (EOFError, OSError):
            logger.exception("Unable to read PostgreSQL password from terminal")
            raise RuntimeError(
                "PostgreSQL requires a password. Run the application from a "
                "terminal or configure pgpass.conf."
            ) from None

        if not password:
            raise RuntimeError(
                "PostgreSQL password was empty. Configure pgpass.conf or retry."
            )

        _SESSION_PASSWORD = password
        environment["PGPASSWORD"] = password
        try:
            result = subprocess.run(
                command,
                input="SET standard_conforming_strings = on;\n" + script,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
                timeout=120,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError):
            logger.exception("Could not retry PostgreSQL connection")
            raise

    missing_database = any(
        marker in (result.stderr or "").lower()
        for marker in (
            "does not exist",
            "n'existe pas",
            "no existe",
            "existiert nicht",
        )
    )
    if result.returncode and missing_database:
        _create_database(command, environment)
        try:
            result = subprocess.run(
                command,
                input="SET standard_conforming_strings = on;\n" + script,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
                timeout=120,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError):
            logger.exception("Could not retry after creating PostgreSQL database")
            raise

    if result.returncode:
        error = RuntimeError(
            "PostgreSQL command failed. Verify the database, user, password, "
            "and connection settings."
        )
        logger.error("psql failed: %s", (result.stderr or "").strip())
        raise error
    return result.stdout


def _create_database(command, environment):
    """Create the configured application database after an explicit missing-db error."""
    database_name = os.environ.get("PGDATABASE", "log_analyser")
    if not DATABASE_NAME_PATTERN.fullmatch(database_name):
        raise ValueError(
            "PGDATABASE must contain only letters, digits, or underscores "
            "and must not start with a digit"
        )

    maintenance_command = list(command)
    database_option = maintenance_command.index("--dbname")
    maintenance_command[database_option + 1] = "postgres"
    exists_query = (
        "SELECT 1 FROM pg_database "
        f"WHERE datname = '{database_name}';"
    )
    try:
        check = subprocess.run(
            maintenance_command,
            input=exists_query,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=120,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        logger.exception("Unable to check for the PostgreSQL application database")
        raise

    if check.returncode:
        logger.error(
            "Unable to check PostgreSQL databases: %s",
            (check.stderr or "").strip(),
        )
        raise RuntimeError(
            "Could not connect to the PostgreSQL maintenance database 'postgres'."
        )

    if check.stdout.strip():
        return

    create_script = f'CREATE DATABASE "{database_name}";'
    try:
        created = subprocess.run(
            maintenance_command,
            input=create_script,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=120,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        logger.exception("Unable to create PostgreSQL database %s", database_name)
        raise

    if created.returncode:
        logger.error(
            "Unable to create PostgreSQL database: %s",
            (created.stderr or "").strip(),
        )
        raise RuntimeError(
            f"Could not create database '{database_name}'. "
            "The PostgreSQL user may need CREATEDB permission."
        )
    logger.info("Created PostgreSQL database %s", database_name)


def _sql_literal(value):
    """Quote a value as a PostgreSQL string literal."""
    if value is None:
        return "NULL"
    text = str(value)
    if "\x00" in text:
        raise ValueError("PostgreSQL text values cannot contain NUL characters")
    return "'" + text.replace("'", "''") + "'"


def initialize_schema():
    try:
        script = SCHEMA_FILE.read_text(encoding="utf-8")
        _run_sql(script)
    except Exception:
        logger.exception("Unable to initialize PostgreSQL schema")
        raise


def import_country_ranges(csv_path):
    """Import an optional local network,country CSV into PostgreSQL."""
    path = Path(csv_path)
    try:
        with path.open(mode="r", encoding="utf-8", newline="") as source:
            reader = csv.DictReader(source)
            if not reader.fieldnames or not {"network", "country"}.issubset(
                reader.fieldnames
            ):
                raise ValueError(
                    "Country CSV must contain network and country columns"
                )

            batch = []
            imported = 0
            for line_number, row in enumerate(reader, start=2):
                network_text = (row.get("network") or "").strip()
                country = (row.get("country") or "").strip()
                if not network_text or not country:
                    raise ValueError(
                        f"Empty network or country on CSV line {line_number}"
                    )
                network = ipaddress.ip_network(network_text, strict=False)
                batch.append(
                    "INSERT INTO ip_country_ranges (network, country) VALUES "
                    f"({_sql_literal(str(network))}::cidr, {_sql_literal(country)}) "
                    "ON CONFLICT (network) DO UPDATE SET country = EXCLUDED.country;"
                )
                if len(batch) == BATCH_SIZE:
                    _run_sql("BEGIN;\n" + "\n".join(batch) + "\nCOMMIT;\n")
                    imported += len(batch)
                    batch = []

        if batch:
            _run_sql("BEGIN;\n" + "\n".join(batch) + "\nCOMMIT;\n")
            imported += len(batch)
        logger.info("Imported %d IP country ranges from %s", imported, path)
        return imported
    except Exception:
        logger.exception("Unable to import country ranges from %s", path)
        raise


def _country_expression(ip, fallback_country):
    address = ipaddress.ip_address(ip)
    return (
        "COALESCE((SELECT country FROM ip_country_ranges "
        f"WHERE {_sql_literal(str(address))}::inet <<= network "
        "ORDER BY masklen(network) DESC LIMIT 1), "
        f"{_sql_literal(fallback_country)})"
    )


def _event_insert(event):
    columns = (
        "source_file, line_number, month, day, log_time, host, process, "
        "username, ip_address, status, invalid_user, attempt_count, country, "
        "message, raw_message"
    )
    values = (
        _sql_literal(event["source_file"]),
        str(event["line_number"]),
        _sql_literal(event["month"]),
        str(event["day"]),
        _sql_literal(event["time"]),
        _sql_literal(event["host"]),
        _sql_literal(event["process"]),
        _sql_literal(event["user"]),
        f"{_sql_literal(event['ip'])}::inet",
        _sql_literal(event["status"]),
        "TRUE" if event["invalid_user"] else "FALSE",
        str(event["repeat_count"]),
        _country_expression(event["ip"], event["country"]),
        _sql_literal(event["message"]),
        _sql_literal(event["raw_message"]),
    )
    update_columns = (
        "month, day, log_time, host, process, username, ip_address, status, "
        "invalid_user, attempt_count, country, message, raw_message"
    )
    assignments = ", ".join(
        f"{column} = EXCLUDED.{column}" for column in update_columns.split(", ")
    )
    return (
        f"INSERT INTO authentication_events ({columns}) VALUES "
        f"({', '.join(values)}) "
        "ON CONFLICT (source_file, line_number) DO UPDATE SET "
        f"{assignments};"
    )


def import_events(events):
    """Insert parsed events in idempotent, bounded PostgreSQL transactions."""
    imported = 0
    try:
        batch = []
        for event in events:
            batch.append(_event_insert(event))
            if len(batch) == BATCH_SIZE:
                _run_sql("BEGIN;\n" + "\n".join(batch) + "\nCOMMIT;\n")
                imported += len(batch)
                batch = []
        if batch:
            _run_sql("BEGIN;\n" + "\n".join(batch) + "\nCOMMIT;\n")
            imported += len(batch)
        logger.info("Imported or updated %d authentication events", imported)
        return imported
    except Exception:
        logger.exception("Unable to import authentication events")
        raise


def _query_rows(query):
    try:
        output = _run_sql(query)
        return [json.loads(line) for line in output.splitlines() if line.strip()]
    except Exception:
        logger.exception("Unable to query PostgreSQL dashboard data")
        raise


def get_dashboard_data():
    """Read the three dashboard aggregations from PostgreSQL."""
    return {
        "failed_by_country": _query_rows(
            "SELECT row_to_json(report)::text FROM ("
            "SELECT country, SUM(attempt_count) AS attempts "
            "FROM authentication_events WHERE status = 'failed' "
            "GROUP BY country ORDER BY attempts DESC, country"
            ") AS report;"
        ),
        "successful_by_user": _query_rows(
            "SELECT row_to_json(report)::text FROM ("
            "SELECT username, SUM(attempt_count) AS attempts "
            "FROM authentication_events WHERE status = 'successful' "
            "GROUP BY username ORDER BY attempts DESC, username"
            ") AS report;"
        ),
        "failed_invalid_users": _query_rows(
            "SELECT row_to_json(report)::text FROM ("
            "SELECT username, SUM(attempt_count) AS attempts "
            "FROM authentication_events "
            "WHERE status = 'failed' AND invalid_user = TRUE "
            "GROUP BY username ORDER BY attempts DESC, username"
            ") AS report;"
        ),
    }
