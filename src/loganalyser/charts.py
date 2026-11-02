from __future__ import annotations

from matplotlib.figure import Figure

from loganalyser.analyzer import AnalysisReport

_COLORS = ("#e76f51", "#2a9d8f", "#e9c46a", "#457b9d", "#8d6eaa")
_EVENT_LABELS = {
    "failed_password": "Mot de passe refusé",
    "accepted_login": "Connexion acceptée",
    "invalid_user": "Utilisateur invalide",
    "authentication_failure": "Échec d'authentification",
    "other": "Autre",
}


def _format_event_share(count: int, total: int) -> str:
    if not total:
        return "0%"
    share = count / total
    return "<0.1%" if 0 < share < 0.001 else f"{share:.1%}"


def build_dashboard_figure(report: AnalysisReport) -> Figure:
    figure = Figure(figsize=(12, 5.2), dpi=100, facecolor="#ffffff")
    event_axis, ip_axis = figure.subplots(1, 2)
    for axis in (event_axis, ip_axis):
        axis.set_facecolor("#ffffff")
        axis.tick_params(colors="#64748b", labelsize=8)
        axis.spines[["top", "right"]].set_visible(False)
        axis.spines[["left", "bottom"]].set_color("#dbe3ee")

    labels = [
        _EVENT_LABELS.get(name, name.replace("_", " ").title())
        for name in report.event_counts
    ]
    counts = list(report.event_counts.values())
    bars = event_axis.bar(labels, counts, color=_COLORS[: len(labels)])
    event_axis.set_title(
        "Événements détectés", loc="left", fontweight="bold", pad=14
    )
    event_axis.set_ylabel("Nombre d'événements")
    event_axis.tick_params(axis="x", labelrotation=25, labelsize=8)
    event_axis.set_ylim(0, max(counts, default=0) * 1.18 or 1)
    event_axis.set_axisbelow(True)
    event_axis.yaxis.grid(color="#e9eef5", linewidth=0.8)
    event_axis.bar_label(
        bars,
        labels=[
            f"{count:,}\n{_format_event_share(count, report.parsed_lines)}"
            for count in counts
        ],
        padding=4,
        fontsize=8,
    )

    top_ips = list(report.failed_passwords_by_ip.items())[:10]
    if top_ips:
        ips, attempts = zip(*reversed(top_ips))
        ip_bars = ip_axis.barh(ips, attempts, color="#e76f51")
        ip_axis.bar_label(
            ip_bars,
            labels=[f"{count:,}" for count in attempts],
            padding=4,
            fontsize=8,
            color="#475569",
        )
        ip_axis.set_xlim(0, max(attempts) * 1.18 or 1)
        ip_axis.set_axisbelow(True)
        ip_axis.xaxis.grid(color="#e9eef5", linewidth=0.8)
    else:
        ip_axis.text(
            0.5,
            0.5,
            "Aucune tentative échouée",
            ha="center",
            va="center",
            transform=ip_axis.transAxes,
        )
    ip_axis.set_title(
        "Top IP — mots de passe échoués", loc="left", fontweight="bold", pad=14
    )
    ip_axis.set_xlabel("Nombre de tentatives")
    ip_axis.tick_params(axis="y", labelsize=8)
    figure.tight_layout(pad=2.4)
    return figure
