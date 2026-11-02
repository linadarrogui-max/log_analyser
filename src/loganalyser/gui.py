from __future__ import annotations

import csv
import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import mysql.connector
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from loganalyser.analyzer import AnalysisReport, LogEvent, analyze_logs, parse_log_line
from loganalyser.charts import build_dashboard_figure
from loganalyser.database import DatabaseConfig, MySQLStore, StoredRun
from loganalyser.logs import iter_log_lines

_EVENT_LABELS = {
    "failed_password": "Mot de passe refusé",
    "accepted_login": "Connexion acceptée",
    "invalid_user": "Utilisateur invalide",
    "authentication_failure": "Échec d'authentification",
    "other": "Autre",
}


class LogAnalyserApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Loganalyser — Sécurité SSH")
        self.root.geometry("1360x880")
        self.root.minsize(1050, 720)
        self.store: MySQLStore | None = None
        self.saved_runs: list[StoredRun] = []
        self.selected_run_id: int | None = None
        self.current_report = AnalysisReport(0, 0, {}, {})
        self.local_report = self.current_report
        self.local_source_path: str | None = None
        self.local_events: list[LogEvent] = []
        self.displayed_events: list[LogEvent] = []
        self.chart_canvas: FigureCanvasTkAgg | None = None
        self.status_text = tk.StringVar(value="Choisissez un fichier ou un dossier de journaux.")
        self.source_text = tk.StringVar(value="Aucune source sélectionnée")
        self.database_text = tk.StringVar(value="MySQL non connecté")
        self.metric_details = {
            "Lignes lues": tk.StringVar(value="En attente d’un journal"),
            "Lignes reconnues": tk.StringVar(value="0 % du journal"),
            "Échecs de mot de passe": tk.StringVar(value="Tentatives refusées"),
            "Connexions acceptées": tk.StringVar(value="Accès réussis"),
        }
        self.run_selection = tk.StringVar()
        self.event_filter = tk.StringVar(value="Tous les types")
        self.search_text = tk.StringVar()
        self.metric_values = {
            "Lignes lues": tk.StringVar(value="0"),
            "Lignes reconnues": tk.StringVar(value="0"),
            "Échecs de mot de passe": tk.StringVar(value="0"),
            "Connexions acceptées": tk.StringVar(value="0"),
        }

        self._configure_style()
        self._build_layout()
        self._update_report(self.current_report)
        default_logs = Path(__file__).resolve().parents[2] / "data"
        if default_logs.is_dir() and any(default_logs.iterdir()):
            self._analyze_path(default_logs)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background="#f3f6fb")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("TLabel", background="#f3f6fb", foreground="#243247")
        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 23, "bold"),
            foreground="#15243a",
        )
        style.configure(
            "Subtitle.TLabel",
            font=("Segoe UI", 10),
            foreground="#718096",
        )
        style.configure("TButton", font=("Segoe UI", 9), padding=(12, 9))
        style.configure(
            "Primary.TButton",
            background="#2563eb",
            foreground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            padding=(14, 10),
        )
        style.map(
            "Primary.TButton",
            background=[("active", "#1d4ed8"), ("pressed", "#1e40af")],
            foreground=[("disabled", "#dbeafe")],
        )
        style.configure(
            "Secondary.TButton",
            background="#ffffff",
            foreground="#243247",
            padding=(12, 10),
        )
        style.map("Secondary.TButton", background=[("active", "#eaf0f8")])
        style.configure(
            "TNotebook",
            background="#f3f6fb",
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            background="#e8edf5",
            foreground="#526176",
            padding=(18, 11),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#ffffff"), ("active", "#f8fafc")],
            foreground=[("selected", "#1d4ed8")],
        )
        style.configure(
            "Treeview",
            background="#ffffff",
            fieldbackground="#ffffff",
            foreground="#344256",
            rowheight=34,
            font=("Segoe UI", 9),
            borderwidth=0,
        )
        style.map(
            "Treeview",
            background=[("selected", "#dbeafe")],
            foreground=[("selected", "#17243a")],
        )
        style.configure(
            "Treeview.Heading",
            background="#f1f5f9",
            foreground="#526176",
            font=("Segoe UI", 9, "bold"),
            padding=(8, 10),
            relief="flat",
        )
        style.map("Treeview.Heading", background=[("active", "#e8edf5")])
        style.configure(
            "TCombobox",
            padding=7,
            fieldbackground="#ffffff",
            background="#ffffff",
        )

    def _build_layout(self) -> None:
        page = ttk.Frame(self.root, padding=(26, 22))
        page.pack(fill="both", expand=True)

        header = ttk.Frame(page)
        header.pack(fill="x", pady=(0, 20))
        title_block = ttk.Frame(header)
        title_block.pack(side="left", fill="x", expand=True)
        tk.Label(
            title_block,
            text="LOG ANALYTICS  /  SÉCURITÉ SSH",
            font=("Segoe UI", 8, "bold"),
            fg="#2563eb",
            bg="#f3f6fb",
        ).pack(anchor="w", pady=(0, 5))
        ttk.Label(title_block, text="Loganalyser", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            title_block,
            text="Surveillez les connexions et repérez les activités suspectes.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        actions = ttk.Frame(header)
        actions.pack(side="right", anchor="e")
        ttk.Button(
            actions,
            text="＋  Ouvrir un fichier",
            style="Primary.TButton",
            command=self._browse_file,
        ).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(
            actions,
            text="Ouvrir un dossier",
            style="Secondary.TButton",
            command=self._browse_directory,
        ).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(
            actions,
            text="Base de données",
            style="Secondary.TButton",
            command=self._open_database_dialog,
        ).pack(side="left")

        source_card = tk.Frame(
            page,
            bg="#ffffff",
            highlightbackground="#e2e8f0",
            highlightthickness=1,
            padx=14,
            pady=11,
        )
        source_card.pack(fill="x", pady=(0, 14))
        source_text_block = tk.Frame(source_card, bg="#ffffff")
        source_text_block.pack(side="left", fill="x", expand=True)
        tk.Label(
            source_text_block,
            text="SOURCE ANALYSÉE",
            font=("Segoe UI", 8, "bold"),
            fg="#8390a3",
            bg="#ffffff",
        ).pack(anchor="w")
        tk.Label(
            source_text_block,
            textvariable=self.source_text,
            font=("Segoe UI", 10, "bold"),
            fg="#243247",
            bg="#ffffff",
            anchor="w",
        ).pack(anchor="w", pady=(3, 0))
        ttk.Separator(source_card, orient="vertical").pack(
            side="left", fill="y", padx=16
        )
        tk.Label(
            source_card,
            textvariable=self.database_text,
            font=("Segoe UI", 9),
            fg="#64748b",
            bg="#ffffff",
        ).pack(side="left")

        run_bar = ttk.Frame(page)
        run_bar.pack(fill="x", pady=(0, 14))
        ttk.Label(
            run_bar,
            text="Historique des analyses",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(0, 12))
        self.run_combo = ttk.Combobox(
            run_bar,
            textvariable=self.run_selection,
            values=["Analyse locale"],
            state="readonly",
            width=68,
        )
        self.run_combo.pack(side="left", fill="x", expand=True)
        self.run_combo.bind("<<ComboboxSelected>>", self._select_saved_run)
        self.delete_run_button = ttk.Button(
            run_bar,
            text="Supprimer l’analyse",
            command=self._delete_selected_run,
            state="disabled",
        )
        self.delete_run_button.pack(side="left", padx=(10, 0))

        self.notebook = ttk.Notebook(page)
        self.notebook.pack(fill="both", expand=True)
        self.dashboard_tab = ttk.Frame(self.notebook, padding=(18, 18))
        self.events_tab = ttk.Frame(self.notebook, padding=(18, 18))
        self.notebook.add(self.dashboard_tab, text="Vue d’ensemble")
        self.notebook.add(self.events_tab, text="Journal des événements")
        self._build_dashboard()
        self._build_events()

        footer = tk.Frame(page, bg="#f3f6fb")
        footer.pack(fill="x", pady=(10, 0))
        tk.Label(
            footer,
            text="●",
            font=("Segoe UI", 9),
            fg="#16a37b",
            bg="#f3f6fb",
        ).pack(side="left", padx=(1, 7))
        tk.Label(
            footer,
            textvariable=self.status_text,
            font=("Segoe UI", 9),
            fg="#64748b",
            bg="#f3f6fb",
            anchor="w",
        ).pack(side="left", fill="x", expand=True)

    def _build_dashboard(self) -> None:
        cards = ttk.Frame(self.dashboard_tab)
        cards.pack(fill="x", pady=(0, 18))
        accents = ("#2563eb", "#0f9f83", "#e5484d", "#8b5cf6")
        for column, ((name, value), accent) in enumerate(
            zip(self.metric_values.items(), accents)
        ):
            card = tk.Frame(
                cards,
                bg="#ffffff",
                highlightbackground="#e2e8f0",
                highlightthickness=1,
                padx=16,
                pady=13,
            )
            card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 8, 0))
            tk.Frame(card, bg=accent, height=3).pack(fill="x", pady=(0, 10))
            tk.Label(
                card,
                text=name.upper(),
                font=("Segoe UI", 8, "bold"),
                fg="#718096",
                bg="#ffffff",
            ).pack(anchor="w")
            tk.Label(
                card,
                textvariable=value,
                font=("Segoe UI", 25, "bold"),
                fg="#17243a",
                bg="#ffffff",
            ).pack(anchor="w", pady=(4, 0))
            tk.Label(
                card,
                textvariable=self.metric_details[name],
                font=("Segoe UI", 8),
                fg="#8a97a9",
                bg="#ffffff",
            ).pack(anchor="w", pady=(2, 0))
            cards.columnconfigure(column, weight=1)

        chart_card = tk.Frame(
            self.dashboard_tab,
            bg="#ffffff",
            highlightbackground="#e2e8f0",
            highlightthickness=1,
        )
        chart_card.pack(fill="both", expand=True)
        chart_header = tk.Frame(chart_card, bg="#ffffff")
        chart_header.pack(fill="x", padx=18, pady=(14, 0))
        tk.Label(
            chart_header,
            text="Activité d’authentification",
            font=("Segoe UI", 12, "bold"),
            fg="#17243a",
            bg="#ffffff",
        ).pack(anchor="w")
        tk.Label(
            chart_header,
            text="Répartition des événements et adresses IP avec le plus d’échecs",
            font=("Segoe UI", 9),
            fg="#718096",
            bg="#ffffff",
        ).pack(anchor="w", pady=(3, 0))
        self.chart_frame = tk.Frame(chart_card, bg="#ffffff")
        self.chart_frame.pack(fill="both", expand=True, padx=10, pady=(4, 10))

    def _build_events(self) -> None:
        heading = ttk.Frame(self.events_tab)
        heading.pack(fill="x", pady=(0, 14))
        ttk.Label(
            heading,
            text="Événements détectés",
            font=("Segoe UI", 15, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            heading,
            text="Filtrez les lignes pour examiner les connexions et tentatives suspectes.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(3, 0))

        controls = ttk.Frame(self.events_tab)
        controls.pack(fill="x", pady=(0, 10))
        filter_options = ["Tous les types", *_EVENT_LABELS.values()]
        self.filter_combo = ttk.Combobox(
            controls,
            textvariable=self.event_filter,
            values=filter_options,
            state="readonly",
            width=27,
        )
        self.filter_combo.pack(side="left", padx=(0, 9))
        self.filter_combo.bind("<<ComboboxSelected>>", self._refresh_events)
        search_entry = ttk.Entry(controls, textvariable=self.search_text, width=38)
        search_entry.pack(side="left", padx=(0, 8), ipady=5)
        search_entry.bind("<Return>", self._refresh_events)
        ttk.Button(
            controls,
            text="Rechercher",
            style="Primary.TButton",
            command=self._refresh_events,
        ).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(
            controls,
            text="Effacer les filtres",
            style="Secondary.TButton",
            command=self._clear_event_filters,
        ).pack(side="left")
        ttk.Button(
            controls,
            text="Exporter CSV",
            style="Secondary.TButton",
            command=self._export_csv,
        ).pack(
            side="right"
        )

        table_frame = tk.Frame(
            self.events_tab,
            bg="#ffffff",
            highlightbackground="#e2e8f0",
            highlightthickness=1,
        )
        table_frame.pack(fill="both", expand=True)
        columns = ("timestamp", "type", "user", "ip", "host", "message")
        self.event_table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=20,
        )
        headings = {
            "timestamp": ("DATE / HEURE", 150),
            "type": ("TYPE D’ÉVÉNEMENT", 205),
            "user": ("UTILISATEUR", 145),
            "ip": ("ADRESSE IP", 155),
            "host": ("HÔTE", 150),
            "message": ("MESSAGE", 450),
        }
        for column, (heading, width) in headings.items():
            self.event_table.heading(column, text=heading)
            self.event_table.column(
                column,
                width=width,
                minwidth=90,
                anchor="w",
                stretch=column == "message",
            )
        self.event_table.tag_configure("failed_password", background="#fff4f3")
        self.event_table.tag_configure("accepted_login", background="#effaf5")
        self.event_table.tag_configure("invalid_user", background="#fff9ed")
        self.event_table.tag_configure("authentication_failure", background="#f5f3ff")
        scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.event_table.yview
        )
        self.event_table.configure(yscrollcommand=scrollbar.set)
        self.event_table.pack(
            side="left", fill="both", expand=True, padx=(1, 0), pady=1
        )
        scrollbar.pack(side="right", fill="y")
        horizontal_scrollbar = ttk.Scrollbar(
            self.events_tab,
            orient="horizontal",
            command=self.event_table.xview,
        )
        horizontal_scrollbar.pack(fill="x", pady=(0, 2))
        self.event_table.configure(xscrollcommand=horizontal_scrollbar.set)
        self.event_count_label = ttk.Label(
            self.events_tab,
            text="Aucun événement affiché.",
            style="Subtitle.TLabel",
        )
        self.event_count_label.pack(anchor="w", pady=(8, 0))

    def _browse_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="Choisir un journal",
            filetypes=[
                ("Journaux et archives", "*.log *.gz *.tar *.tgz"),
                ("Tous les fichiers", "*.*"),
            ],
        )
        if filename:
            self._analyze_path(Path(filename))

    def _browse_directory(self) -> None:
        directory = filedialog.askdirectory(title="Choisir le dossier des journaux")
        if directory:
            self._analyze_path(Path(directory))

    def _analyze_path(self, path: Path) -> None:
        self.status_text.set(f"Analyse de {path}…")
        self.root.update_idletasks()
        try:
            report = analyze_logs(path)
            events = [
                event
                for line in iter_log_lines(path)
                if (event := parse_log_line(line)) is not None
            ]
        except (OSError, ValueError) as error:
            messagebox.showerror("Analyse impossible", str(error), parent=self.root)
            self.status_text.set("L’analyse a échoué.")
            return

        self.selected_run_id = None
        self.local_report = report
        self.local_source_path = str(path)
        self.local_events = events
        self.source_text.set(str(path))
        self._update_report(report)
        self._refresh_events()
        self.notebook.select(self.dashboard_tab)
        self.status_text.set(
            f"Analyse terminée : {report.total_lines:,} lignes lues depuis {path}."
        )
        self._set_run_combo_to_local()

        if self.store is not None:
            try:
                run_id = self.store.save_analysis(str(path), report, events)
                self._refresh_saved_runs(selected_run_id=run_id)
                self.status_text.set(
                    f"Analyse terminée et enregistrée dans MySQL (analyse #{run_id})."
                )
            except mysql.connector.Error as error:
                messagebox.showerror(
                    "Enregistrement MySQL impossible",
                    str(error),
                    parent=self.root,
                )

    def _update_report(self, report: AnalysisReport) -> None:
        self.current_report = report
        counts = report.event_counts
        self.metric_values["Lignes lues"].set(f"{report.total_lines:,}")
        self.metric_values["Lignes reconnues"].set(f"{report.parsed_lines:,}")
        self.metric_values["Échecs de mot de passe"].set(
            f"{counts.get('failed_password', 0):,}"
        )
        self.metric_values["Connexions acceptées"].set(
            f"{counts.get('accepted_login', 0):,}"
        )
        recognized_ratio = (
            report.parsed_lines / report.total_lines if report.total_lines else 0
        )
        self.metric_details["Lignes lues"].set("Lignes parcourues dans la source")
        self.metric_details["Lignes reconnues"].set(
            f"{recognized_ratio:.1%} des lignes analysées"
        )
        self.metric_details["Échecs de mot de passe"].set(
            f"{counts.get('invalid_user', 0):,} utilisateurs invalides"
        )
        self.metric_details["Connexions acceptées"].set(
            f"{counts.get('authentication_failure', 0):,} échecs d’authentification"
        )

        for child in self.chart_frame.winfo_children():
            child.destroy()
        self.chart_canvas = FigureCanvasTkAgg(
            build_dashboard_figure(report),
            master=self.chart_frame,
        )
        self.chart_canvas.draw()
        self.chart_canvas.get_tk_widget().pack(fill="both", expand=True)

    def _event_type_value(self) -> str | None:
        label = self.event_filter.get()
        if label == "Tous les types":
            return None
        return next(
            (event_type for event_type, text in _EVENT_LABELS.items() if text == label),
            None,
        )

    def _refresh_events(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        if self.selected_run_id is not None and self.store is not None:
            try:
                events = self.store.load_events(
                    self.selected_run_id,
                    self._event_type_value(),
                    self.search_text.get().strip(),
                )
            except mysql.connector.Error as error:
                messagebox.showerror("Lecture MySQL impossible", str(error), parent=self.root)
                return
        else:
            event_type = self._event_type_value()
            search = self.search_text.get().strip().casefold()
            events = [
                event
                for event in self.local_events
                if (event_type is None or event.event_type == event_type)
                and (
                    not search
                    or search
                    in " ".join(
                        (
                            event.user or "",
                            event.ip or "",
                            event.host,
                            event.message,
                        )
                    ).casefold()
                )
            ][:1000]

        self.displayed_events = events
        self.event_table.delete(*self.event_table.get_children())
        for event in events:
            self.event_table.insert(
                "",
                "end",
                values=(
                    f"{event.month} {event.day:02} {event.time}",
                    _EVENT_LABELS.get(event.event_type, event.event_type),
                    event.user or "—",
                    event.ip or "—",
                    event.host,
                    event.message[:180],
                ),
                tags=(event.event_type,),
            )
        count_text = f"{len(events):,} résultat(s) affiché(s)"
        if len(events) == 1000:
            count_text += "  •  Affinez les filtres pour réduire la liste."
        self.event_count_label.configure(text=count_text)

    def _clear_event_filters(self) -> None:
        self.event_filter.set("Tous les types")
        self.search_text.set("")
        self._refresh_events()

    def _export_csv(self) -> None:
        if not self.displayed_events:
            messagebox.showinfo(
                "Export CSV",
                "Aucun événement à exporter. Appliquez d’abord vos filtres.",
                parent=self.root,
            )
            return
        filename = filedialog.asksaveasfilename(
            title="Exporter les événements affichés",
            defaultextension=".csv",
            filetypes=[("Fichier CSV", "*.csv")],
        )
        if not filename:
            return
        try:
            with Path(filename).open("w", newline="", encoding="utf-8-sig") as stream:
                writer = csv.writer(stream)
                writer.writerow(
                    ["date_heure", "type", "utilisateur", "ip", "hote", "message"]
                )
                for event in self.displayed_events:
                    writer.writerow(
                        [
                            f"{event.month} {event.day:02} {event.time}",
                            event.event_type,
                            event.user or "",
                            event.ip or "",
                            event.host,
                            event.message,
                        ]
                    )
        except OSError as error:
            messagebox.showerror("Export impossible", str(error), parent=self.root)
            return
        self.status_text.set(f"Export CSV créé : {filename}")

    def _open_database_dialog(self) -> None:
        window = tk.Toplevel(self.root)
        window.title("Connexion à MySQL")
        window.transient(self.root)
        window.resizable(False, False)
        form = ttk.Frame(window, padding=18)
        form.pack(fill="both", expand=True)

        fields: dict[str, tk.StringVar] = {
            "Hôte": tk.StringVar(value=os.getenv("LOGANALYSER_DB_HOST", "localhost")),
            "Port": tk.StringVar(value=os.getenv("LOGANALYSER_DB_PORT", "3306")),
            "Base de données": tk.StringVar(
                value=os.getenv("LOGANALYSER_DB_NAME", "loganalyser")
            ),
            "Utilisateur": tk.StringVar(value=os.getenv("LOGANALYSER_DB_USER", "root")),
            "Mot de passe": tk.StringVar(value=os.getenv("LOGANALYSER_DB_PASSWORD", "")),
        }
        for row, (label, variable) in enumerate(fields.items()):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=5)
            entry = ttk.Entry(
                form,
                textvariable=variable,
                width=34,
                show="*" if label == "Mot de passe" else "",
            )
            entry.grid(row=row, column=1, sticky="ew", padx=(12, 0), pady=5)

        ttk.Label(
            form,
            text="Les identifiants ne sont pas enregistrés par l’application.",
            style="Subtitle.TLabel",
        ).grid(row=len(fields), column=0, columnspan=2, sticky="w", pady=(6, 12))

        def connect() -> None:
            try:
                port = int(fields["Port"].get())
                if not 1 <= port <= 65535:
                    raise ValueError("Le port doit être compris entre 1 et 65535.")
                config = DatabaseConfig(
                    host=fields["Hôte"].get().strip(),
                    port=port,
                    database=fields["Base de données"].get().strip(),
                    user=fields["Utilisateur"].get().strip(),
                    password=fields["Mot de passe"].get(),
                )
                if not config.host or not config.database or not config.user:
                    raise ValueError("L’hôte, la base et l’utilisateur sont obligatoires.")
                store = MySQLStore(config)
                store.initialize()
                runs = store.list_runs()
            except ValueError as error:
                messagebox.showerror("Configuration invalide", str(error), parent=window)
                return
            except mysql.connector.Error as error:
                messagebox.showerror("Connexion MySQL impossible", str(error), parent=window)
                return

            self.store = store
            self.saved_runs = runs
            self.database_text.set(f"MySQL connecté  •  {config.database}")
            self._populate_run_combo()
            self.status_text.set(
                f"Connecté à MySQL : {config.host}:{config.port}/{config.database}."
            )
            window.destroy()

        ttk.Button(form, text="Tester et connecter", command=connect).grid(
            row=len(fields) + 1,
            column=0,
            columnspan=2,
            sticky="e",
        )
        form.columnconfigure(1, weight=1)
        window.grab_set()

    def _run_label(self, run: StoredRun) -> str:
        return f"#{run.run_id} — {Path(run.source_path).name} — {run.analyzed_at}"

    def _populate_run_combo(self) -> None:
        options = [self._run_label(run) for run in self.saved_runs]
        self.run_combo.configure(values=["Analyse locale", *options])
        selected_index = next(
            (
                index + 1
                for index, run in enumerate(self.saved_runs)
                if run.run_id == self.selected_run_id
            ),
            0,
        )
        self.run_combo.current(selected_index)
        self.delete_run_button.configure(
            state="normal" if self.selected_run_id is not None else "disabled"
        )

    def _set_run_combo_to_local(self) -> None:
        self.run_combo.current(0)
        self.run_selection.set("Analyse locale")
        self.delete_run_button.configure(state="disabled")

    def _refresh_saved_runs(self, selected_run_id: int | None = None) -> None:
        if self.store is None:
            return
        self.saved_runs = self.store.list_runs()
        if selected_run_id is not None:
            self.selected_run_id = selected_run_id
            selected = next(
                (run for run in self.saved_runs if run.run_id == selected_run_id),
                None,
            )
            if selected is not None:
                self.source_text.set(selected.source_path)
                self._update_report(selected.report)
        self._populate_run_combo()
        self._refresh_events()

    def _select_saved_run(self, _event: tk.Event[tk.Misc]) -> None:
        index = self.run_combo.current()
        if index <= 0 or index - 1 >= len(self.saved_runs):
            self.selected_run_id = None
            self.delete_run_button.configure(state="disabled")
            self.source_text.set(
                self.local_source_path or "Aucune source sélectionnée"
            )
            self._update_report(self.local_report)
            self._refresh_events()
            return
        run = self.saved_runs[index - 1]
        self.selected_run_id = run.run_id
        self.source_text.set(run.source_path)
        self._update_report(run.report)
        self.delete_run_button.configure(state="normal")
        self._refresh_events()
        self.status_text.set(
            f"Analyse #{run.run_id} chargée depuis MySQL : {run.source_path}."
        )

    def _delete_selected_run(self) -> None:
        if self.store is None or self.selected_run_id is None:
            return
        if not messagebox.askyesno(
            "Supprimer l’analyse",
            "Supprimer cette analyse et tous ses événements de MySQL ?",
            parent=self.root,
        ):
            return
        try:
            self.store.delete_run(self.selected_run_id)
            self.selected_run_id = None
            self.current_report = AnalysisReport(0, 0, {}, {})
            self.local_report = self.current_report
            self.local_source_path = None
            self.local_events = []
            self.source_text.set("Aucune source sélectionnée")
            self._update_report(self.current_report)
            self.saved_runs = self.store.list_runs()
            self._populate_run_combo()
            self._refresh_events()
            self.status_text.set("Analyse supprimée de MySQL.")
        except (mysql.connector.Error, ValueError) as error:
            messagebox.showerror("Suppression impossible", str(error), parent=self.root)


def main() -> int:
    root = tk.Tk()
    LogAnalyserApp(root)
    root.mainloop()
    return 0
