from pathlib import Path

from app_logging import get_logger


logger = get_logger(__name__)
CHART_LIMIT = 12


def render(report, output_path):
    """Save and display a three-chart Matplotlib authentication dashboard."""
    try:
        import matplotlib.pyplot as plt

        figure, axes = plt.subplots(1, 3, figsize=(18, 8))
        charts = (
            (
                axes[0],
                report["failed_by_country"],
                "Échecs par pays",
                "country",
                "#c0392b",
            ),
            (
                axes[1],
                report["successful_by_user"],
                "Réussites par utilisateur",
                "username",
                "#2980b9",
            ),
            (
                axes[2],
                report["failed_invalid_users"],
                "Échecs : utilisateur invalide",
                "username",
                "#e67e22",
            ),
        )

        for axis, rows, title, label_key, color in charts:
            top_rows = sorted(
                rows,
                key=lambda row: (-row["attempts"], row[label_key]),
            )[:CHART_LIMIT]
            labels = [row[label_key] for row in reversed(top_rows)]
            values = [row["attempts"] for row in reversed(top_rows)]
            if values:
                axis.barh(labels, values, color=color)
            else:
                axis.text(
                    0.5,
                    0.5,
                    "Aucune donnée",
                    ha="center",
                    va="center",
                    transform=axis.transAxes,
                )
            axis.set_title(title)
            axis.set_xlabel("Nombre de tentatives")
            axis.grid(axis="x", linestyle=":", alpha=0.4)
            axis.set_axisbelow(True)

        figure.suptitle("Analyse des tentatives d’authentification SSH")
        figure.tight_layout()
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        figure.savefig(destination, dpi=150, bbox_inches="tight")
        print(f"Dashboard enregistré : {destination}")
        plt.show()
        plt.close(figure)
    except Exception:
        logger.exception("Unable to create or display Matplotlib dashboard")
        raise
