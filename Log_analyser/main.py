from pathlib import Path

from app_logging import get_logger
from ingestion.raw import iter_log_rows
from process.extract_transforme import parse_auth_event
from serving.dashboard import render
from storage.postgres import (
    get_dashboard_data,
    import_country_ranges,
    import_events,
    initialize_schema,
)


logger = get_logger("main")


def main() -> None:
    """Read authentication logs and display their dashboard."""
    project_directory = Path(__file__).resolve().parent
    data_directory = project_directory / "data"
    try:
        initialize_schema()
        country_database = data_directory / "ip_country.csv"
        if country_database.is_file():
            import_country_ranges(country_database)

        events = []
        for source_file, line_number, row in iter_log_rows(data_directory):
            event = parse_auth_event(row)
            if event:
                event["source_file"] = source_file
                event["line_number"] = line_number
                events.append(event)

        imported = import_events(events)
        logger.info("Processed %d authentication events", imported)
        report = get_dashboard_data()
        render(report, project_directory / "dashboard.png")
    except Exception:
        logger.exception("Log analyser failed")
        raise


if __name__ == "__main__":
    main()
