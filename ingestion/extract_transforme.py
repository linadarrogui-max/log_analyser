from pathlib import Path
import argparse
import sys
import argparse

# Make the src-layout package importable when this file is run with plain Python.
_SOURCE_ROOT = str(Path(__file__).resolve().parents[1] / "src")
if _SOURCE_ROOT not in sys.path:
    sys.path.insert(0, _SOURCE_ROOT)

from loganalyser.analyzer import LogEvent, parse_log_line
from loganalyser.analyzer import analyze_logs
from loganalyser.charts import build_dashboard_figure
from loganalyser.logs import iter_log_lines


def extract(path: str | Path = "data") -> list[LogEvent]:
    return [
        event
        for line in iter_log_lines(path)
        if (event := parse_log_line(line)) is not None
    ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extraire et afficher les statistiques des journaux Linux."
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path("data"),
        help="fichier ou dossier de journaux (défaut : data)",
    )
    args = parser.parse_args()
    report = analyze_logs(args.path)
    print(f"{report.parsed_lines:,} lignes structurées dans {report.total_lines:,}.")

    import tkinter as tk
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    window = tk.Tk()
    window.title(f"Loganalyser — {args.path}")
    canvas = FigureCanvasTkAgg(build_dashboard_figure(report), master=window)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)
    window.mainloop()