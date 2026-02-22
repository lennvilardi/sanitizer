#! /usr/bin/env python3
"""Tkinter GUI for the sanitizer tool."""

from __future__ import annotations

import locale
import os
import queue
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from sanitizer_core import RedactionConfig, sanitize_single_file, suggested_output_file


UI_COLORS = {
    "app_bg": "#0b1220",
    "card_bg": "#111827",
    "card_border": "#253347",
    "header_bg": "#020817",
    "header_text": "#f8fafc",
    "header_muted": "#a5b4c7",
    "chip_bg": "#1e293b",
    "chip_border": "#41556f",
    "text_primary": "#e2e8f0",
    "text_muted": "#94a3b8",
    "input_bg": "#0f172a",
    "input_border": "#334155",
    "table_bg": "#0f172a",
    "table_heading": "#1e293b",
    "button_soft_bg": "#243041",
    "button_soft_active": "#334155",
    "accent": "#2563eb",
    "accent_active": "#1d4ed8",
}


TRANSLATIONS = {
    "fr": {
        "app_title": "Sanitizer",
        "brand_name": "Sanitizer",
        "brand_subtitle": "Caviardage sécurisé des configurations",
        "brand_chip": "Mode fichier unique",
        "ready": "Prêt",
        "running": "Exécution...",
        "source_file": "Fichier source",
        "browse": "Parcourir",
        "domains": "Domaines à caviarder",
        "domains_hint": "séparés par des virgules",
        "dry_run": "Dry-run (analyse uniquement)",
        "redact_certs": "Caviarder les certificats",
        "redact_pubkeys": "Caviarder les clés SSH publiques",
        "run": "Lancer",
        "open_output": "Ouvrir le dossier de sortie",
        "logs_tab": "Journal",
        "replacements_tab": "Remplacements",
        "logs_section": "Journal d'exécution",
        "replacements_section": "Remplacements détectés",
        "progress_value": "Progression: {percent}%",
        "running_progress": "Exécution... {percent}%",
        "line_col": "Ligne",
        "rule_col": "Règle",
        "before_col": "Avant (masqué)",
        "after_col": "Après",
        "busy_msg": "Une exécution est déjà en cours.",
        "invalid_source_title": "Source invalide",
        "invalid_source_msg": "Fichier source invalide :\n{path}",
        "invalid_config_title": "Configuration invalide",
        "overwrite_title": "Confirmation",
        "overwrite_msg": "Le fichier de sortie existe déjà :\n{path}\n\nÉcraser ?",
        "run_error_title": "Erreur Sanitizer",
        "no_output_yet": "Aucune sortie disponible. Lancez d'abord un traitement.",
        "start_log": "Démarrage: source={source} domaines={domains} dry_run={dry_run}",
        "status_completed": "Terminé",
        "status_skipped": "Statut: ignoré ({reason})",
        "status_done": "Statut: {status}",
        "replacement_count": "Remplacements: {count}",
        "output_line": "Sortie: {path}",
        "no_replacements": "Aucun remplacement détecté.",
        "status_modified": "modifié",
        "status_unchanged": "inchangé",
        "status_dry_run": "dry-run",
    },
    "en": {
        "app_title": "Sanitizer",
        "brand_name": "Sanitizer",
        "brand_subtitle": "Secure configuration redaction",
        "brand_chip": "Single-file mode",
        "ready": "Ready",
        "running": "Running...",
        "source_file": "Source file",
        "browse": "Browse",
        "domains": "Domains to redact",
        "domains_hint": "comma separated",
        "dry_run": "Dry-run (analyze only)",
        "redact_certs": "Redact certificates",
        "redact_pubkeys": "Redact SSH public keys",
        "run": "Run",
        "open_output": "Open output folder",
        "logs_tab": "Logs",
        "replacements_tab": "Replacements",
        "logs_section": "Execution logs",
        "replacements_section": "Detected replacements",
        "progress_value": "Progress: {percent}%",
        "running_progress": "Running... {percent}%",
        "line_col": "Line",
        "rule_col": "Rule",
        "before_col": "Before (masked)",
        "after_col": "After",
        "busy_msg": "A run is already in progress.",
        "invalid_source_title": "Invalid source",
        "invalid_source_msg": "Invalid source file:\n{path}",
        "invalid_config_title": "Invalid configuration",
        "overwrite_title": "Confirmation",
        "overwrite_msg": "Output file already exists:\n{path}\n\nOverwrite?",
        "run_error_title": "Sanitizer error",
        "no_output_yet": "No output yet. Run sanitizer first.",
        "start_log": "Starting: source={source} domains={domains} dry_run={dry_run}",
        "status_completed": "Completed",
        "status_skipped": "Status: skipped ({reason})",
        "status_done": "Status: {status}",
        "replacement_count": "Replacements: {count}",
        "output_line": "Output: {path}",
        "no_replacements": "No replacements detected.",
        "status_modified": "modified",
        "status_unchanged": "unchanged",
        "status_dry_run": "dry-run",
    },
}


def detect_system_language() -> str:
    candidates = [locale.getlocale()[0], os.environ.get("LANG")]
    for candidate in candidates:
        if candidate and candidate.lower().startswith("fr"):
            return "fr"
    return "en"


def resource_path(*parts: str) -> Path:
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    else:
        base = Path(__file__).resolve().parent
    return base.joinpath(*parts)


class SanitizerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.lang = detect_system_language()
        self.title(self.t("app_title"))
        self.geometry("1020x700")
        self.minsize(900, 620)
        self.configure(bg=UI_COLORS["app_bg"])

        self.source_var = tk.StringVar(value="")
        self.domains_var = tk.StringVar(value="")
        self.dry_run_var = tk.BooleanVar(value=False)
        self.redact_certs_var = tk.BooleanVar(value=True)
        self.redact_public_keys_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value=self.t("ready"))
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_text_var = tk.StringVar(value=self.t("progress_value").format(percent=0))

        self.run_thread: Optional[threading.Thread] = None
        self.event_queue: queue.Queue[tuple] = queue.Queue()
        self.last_output_file: Optional[Path] = None
        self.header_logo: Optional[tk.PhotoImage] = None
        self.window_icon: Optional[tk.PhotoImage] = None
        self.active_tab: str = "logs"

        base_font = tkfont.nametofont("TkDefaultFont")
        base_size = abs(int(base_font.cget("size")))
        self.brand_title_font = base_font.copy()
        self.brand_title_font.configure(size=base_size + 8, weight="bold")
        self.brand_subtitle_font = base_font.copy()
        self.brand_subtitle_font.configure(size=max(base_size, 10))
        self.brand_chip_font = base_font.copy()
        self.brand_chip_font.configure(size=max(base_size - 1, 9), weight="bold")

        self._configure_styles()
        self._apply_window_icon()

        self._build_layout()
        self.after(150, self._poll_events)

    def t(self, key: str) -> str:
        return TRANSLATIONS[self.lang].get(key, key)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=UI_COLORS["app_bg"])
        style.configure("TLabel", background=UI_COLORS["app_bg"], foreground=UI_COLORS["text_primary"])

        style.configure("Card.TFrame", background=UI_COLORS["card_bg"])
        style.configure("Card.TLabel", background=UI_COLORS["card_bg"], foreground=UI_COLORS["text_primary"])
        style.configure("Muted.Card.TLabel", background=UI_COLORS["card_bg"], foreground=UI_COLORS["text_muted"])
        style.configure("Card.TCheckbutton", background=UI_COLORS["card_bg"], foreground=UI_COLORS["text_primary"])
        style.map("Card.TCheckbutton", background=[("active", UI_COLORS["card_bg"])])
        style.configure("Card.TSeparator", background=UI_COLORS["card_border"])

        style.configure(
            "Accent.TButton",
            foreground="#ffffff",
            background=UI_COLORS["accent"],
            padding=(14, 9),
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "Accent.TButton",
            background=[("pressed", UI_COLORS["accent_active"]), ("active", UI_COLORS["accent_active"])],
            foreground=[("disabled", "#9ca3af"), ("!disabled", "#ffffff")],
        )
        style.configure(
            "Soft.TButton",
            foreground=UI_COLORS["text_primary"],
            background=UI_COLORS["button_soft_bg"],
            padding=(12, 9),
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "Soft.TButton",
            background=[("pressed", UI_COLORS["button_soft_active"]), ("active", UI_COLORS["button_soft_active"])],
        )

        style.configure(
            "Dark.TEntry",
            fieldbackground=UI_COLORS["input_bg"],
            foreground=UI_COLORS["text_primary"],
            bordercolor=UI_COLORS["input_border"],
            insertcolor=UI_COLORS["text_primary"],
        )
        style.map("Dark.TEntry", fieldbackground=[("readonly", UI_COLORS["input_bg"])], foreground=[("readonly", UI_COLORS["text_muted"])])
        style.configure(
            "Processing.Horizontal.TProgressbar",
            troughcolor=UI_COLORS["input_bg"],
            bordercolor=UI_COLORS["card_border"],
            background=UI_COLORS["accent"],
            lightcolor=UI_COLORS["accent"],
            darkcolor=UI_COLORS["accent"],
        )
        style.configure(
            "Tab.Active.TButton",
            foreground="#ffffff",
            background=UI_COLORS["accent"],
            padding=(14, 8),
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "Tab.Active.TButton",
            background=[("pressed", UI_COLORS["accent_active"]), ("active", UI_COLORS["accent_active"])],
        )
        style.configure(
            "Tab.Inactive.TButton",
            foreground=UI_COLORS["text_muted"],
            background=UI_COLORS["button_soft_bg"],
            padding=(14, 8),
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "Tab.Inactive.TButton",
            foreground=[("active", UI_COLORS["text_primary"])],
            background=[("pressed", UI_COLORS["button_soft_active"]), ("active", UI_COLORS["button_soft_active"])],
        )

        style.configure(
            "Premium.Treeview",
            rowheight=28,
            background=UI_COLORS["table_bg"],
            fieldbackground=UI_COLORS["table_bg"],
            foreground=UI_COLORS["text_primary"],
            bordercolor=UI_COLORS["card_border"],
            borderwidth=1,
        )
        style.configure(
            "Premium.Treeview.Heading",
            background=UI_COLORS["table_heading"],
            foreground=UI_COLORS["text_primary"],
            relief="flat",
        )
        style.map("Premium.Treeview.Heading", background=[("active", UI_COLORS["chip_bg"])])

    def _build_layout(self) -> None:
        main = tk.Frame(self, bg=UI_COLORS["app_bg"], padx=18, pady=18)
        main.pack(fill=tk.BOTH, expand=True)

        header = tk.Frame(main, bg=UI_COLORS["header_bg"], padx=16, pady=14, highlightthickness=1, highlightbackground=UI_COLORS["card_border"])
        header.pack(fill=tk.X, pady=(0, 12))

        self.header_logo = self._load_logo(
            (
                ("assets", "logo", "png", "light", "sanitize-logo-light-64.png"),
                ("assets", "logo", "png", "minimal", "sanitize-logo-minimal-64.png"),
            )
        )
        if self.header_logo is not None:
            tk.Label(header, image=self.header_logo, bg=UI_COLORS["header_bg"]).pack(side=tk.LEFT, padx=(0, 12))

        brand = tk.Frame(header, bg=UI_COLORS["header_bg"])
        brand.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(
            brand,
            text=self.t("brand_name"),
            fg=UI_COLORS["header_text"],
            bg=UI_COLORS["header_bg"],
            font=self.brand_title_font,
            anchor=tk.W,
        ).pack(anchor=tk.W)
        tk.Label(
            brand,
            text=self.t("brand_subtitle"),
            fg=UI_COLORS["header_muted"],
            bg=UI_COLORS["header_bg"],
            font=self.brand_subtitle_font,
            anchor=tk.W,
        ).pack(anchor=tk.W, pady=(1, 0))

        chip = tk.Frame(
            header,
            bg=UI_COLORS["chip_bg"],
            padx=12,
            pady=6,
            bd=0,
            highlightthickness=0,
        )
        chip.pack(side=tk.RIGHT)
        tk.Label(
            chip,
            text=self.t("brand_chip"),
            fg=UI_COLORS["header_text"],
            bg=UI_COLORS["chip_bg"],
            font=self.brand_chip_font,
            borderwidth=0,
        ).pack()

        controls_card = tk.Frame(
            main,
            bg=UI_COLORS["card_bg"],
            highlightthickness=1,
            highlightbackground=UI_COLORS["card_border"],
        )
        controls_card.pack(fill=tk.X, pady=(0, 12))

        controls = ttk.Frame(controls_card, padding=14, style="Card.TFrame")
        controls.pack(fill=tk.X)

        form = ttk.Frame(controls, style="Card.TFrame")
        form.pack(fill=tk.X)
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text=self.t("source_file"), style="Card.TLabel").grid(row=0, column=0, sticky=tk.W, pady=6)
        ttk.Entry(form, textvariable=self.source_var, style="Dark.TEntry").grid(row=0, column=1, sticky=tk.EW, pady=6, padx=(10, 8))
        ttk.Button(form, text=self.t("browse"), command=self._browse_source, style="Soft.TButton").grid(row=0, column=2, sticky=tk.E, pady=6)

        ttk.Label(form, text=self.t("domains"), style="Card.TLabel").grid(row=1, column=0, sticky=tk.W, pady=6)
        ttk.Entry(form, textvariable=self.domains_var, style="Dark.TEntry").grid(row=1, column=1, sticky=tk.EW, pady=6, padx=(10, 8))
        ttk.Label(form, text=self.t("domains_hint"), style="Muted.Card.TLabel").grid(row=1, column=2, sticky=tk.W, pady=6)

        options = ttk.Frame(controls, style="Card.TFrame")
        options.pack(fill=tk.X, pady=(12, 8))
        ttk.Checkbutton(options, text=self.t("dry_run"), variable=self.dry_run_var, style="Card.TCheckbutton").pack(side=tk.LEFT, padx=(0, 16))
        ttk.Checkbutton(options, text=self.t("redact_certs"), variable=self.redact_certs_var, style="Card.TCheckbutton").pack(side=tk.LEFT, padx=(0, 16))
        ttk.Checkbutton(options, text=self.t("redact_pubkeys"), variable=self.redact_public_keys_var, style="Card.TCheckbutton").pack(side=tk.LEFT)

        actions = ttk.Frame(controls, style="Card.TFrame")
        actions.pack(fill=tk.X, pady=(2, 2))
        self.run_button = ttk.Button(actions, text=self.t("run"), command=self._on_run, style="Accent.TButton")
        self.run_button.pack(side=tk.LEFT)
        ttk.Button(actions, text=self.t("open_output"), command=self._open_output_folder, style="Soft.TButton").pack(side=tk.LEFT, padx=(10, 0))

        progress_row = ttk.Frame(controls, style="Card.TFrame")
        progress_row.pack(fill=tk.X, pady=(10, 2))
        ttk.Label(progress_row, textvariable=self.progress_text_var, style="Muted.Card.TLabel").pack(side=tk.LEFT)
        self.progress_bar = ttk.Progressbar(
            progress_row,
            variable=self.progress_var,
            maximum=100.0,
            mode="determinate",
            style="Processing.Horizontal.TProgressbar",
        )
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(14, 0))

        notebook_card = tk.Frame(
            main,
            bg=UI_COLORS["card_bg"],
            highlightthickness=1,
            highlightbackground=UI_COLORS["card_border"],
        )
        notebook_card.pack(fill=tk.BOTH, expand=True)

        tabs_shell = ttk.Frame(notebook_card, style="Card.TFrame", padding=(12, 10, 12, 0))
        tabs_shell.pack(fill=tk.X)
        self.logs_tab_button = ttk.Button(
            tabs_shell,
            text=self.t("logs_tab"),
            command=lambda: self._select_tab("logs"),
            style="Tab.Active.TButton",
        )
        self.logs_tab_button.pack(side=tk.LEFT)
        self.replacements_tab_button = ttk.Button(
            tabs_shell,
            text=self.t("replacements_tab"),
            command=lambda: self._select_tab("replacements"),
            style="Tab.Inactive.TButton",
        )
        self.replacements_tab_button.pack(side=tk.LEFT, padx=(10, 0))

        content_host = ttk.Frame(notebook_card, style="Card.TFrame", padding=12)
        content_host.pack(fill=tk.BOTH, expand=True)

        self.replacements_view = ttk.Frame(content_host, style="Card.TFrame")
        self.logs_view = ttk.Frame(content_host, style="Card.TFrame")

        ttk.Label(self.replacements_view, text=self.t("replacements_section"), style="Card.TLabel").pack(anchor=tk.W, pady=(0, 8))

        replacement_frame = ttk.Frame(self.replacements_view, style="Card.TFrame")
        replacement_frame.pack(fill=tk.BOTH, expand=True)

        self.replacement_tree = ttk.Treeview(
            replacement_frame,
            columns=("line", "rule", "before", "after"),
            show="headings",
            height=14,
            style="Premium.Treeview",
        )
        self.replacement_tree.heading("line", text=self.t("line_col"))
        self.replacement_tree.heading("rule", text=self.t("rule_col"))
        self.replacement_tree.heading("before", text=self.t("before_col"))
        self.replacement_tree.heading("after", text=self.t("after_col"))

        self.replacement_tree.column("line", width=90, minwidth=70, anchor=tk.W)
        self.replacement_tree.column("rule", width=220, minwidth=160, anchor=tk.W)
        self.replacement_tree.column("before", width=340, minwidth=240, anchor=tk.W)
        self.replacement_tree.column("after", width=340, minwidth=240, anchor=tk.W)

        self.replacement_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll = ttk.Scrollbar(replacement_frame, orient=tk.VERTICAL, command=self.replacement_tree.yview)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.replacement_tree.configure(yscrollcommand=tree_scroll.set)
        replacement_frame.bind("<Configure>", self._on_replacement_frame_resize)

        ttk.Label(self.logs_view, text=self.t("logs_section"), style="Card.TLabel").pack(anchor=tk.W, pady=(0, 8))

        log_frame = ttk.Frame(self.logs_view, style="Card.TFrame")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(
            log_frame,
            wrap=tk.WORD,
            height=18,
            font="TkFixedFont",
            bg=UI_COLORS["table_bg"],
            fg=UI_COLORS["text_primary"],
            relief=tk.FLAT,
            borderwidth=0,
            padx=10,
            pady=10,
            insertbackground=UI_COLORS["text_primary"],
        )
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self._select_tab("logs")

        status_wrap = tk.Frame(main, bg=UI_COLORS["app_bg"])
        status_wrap.pack(fill=tk.X, pady=(10, 0))
        status_bar = ttk.Label(status_wrap, textvariable=self.status_var, anchor=tk.W)
        status_bar.pack(fill=tk.X)

    def _load_logo(self, candidates: tuple[tuple[str, ...], ...]) -> Optional[tk.PhotoImage]:
        for candidate in candidates:
            logo_path = resource_path(*candidate)
            if not logo_path.exists():
                continue
            try:
                return tk.PhotoImage(file=str(logo_path))
            except tk.TclError:
                continue
        return None

    def _apply_window_icon(self) -> None:
        self.window_icon = self._load_logo(
            (
                ("assets", "logo", "png", "minimal", "sanitize-logo-minimal-32.png"),
                ("assets", "logo", "png", "light", "sanitize-logo-light-32.png"),
            )
        )
        if self.window_icon is not None:
            self.iconphoto(True, self.window_icon)

    def _browse_source(self) -> None:
        selected = filedialog.askopenfilename(title=self.t("source_file"))
        if selected:
            self.source_var.set(selected)

    def _on_replacement_frame_resize(self, event: tk.Event) -> None:
        total_width = max(int(getattr(event, "width", 0)) - 22, 520)
        line_width = max(70, int(total_width * 0.08))
        rule_width = max(170, int(total_width * 0.2))
        remaining = max(280, total_width - line_width - rule_width)
        before_width = max(220, int(remaining * 0.5))
        after_width = max(220, remaining - before_width)

        self.replacement_tree.column("line", width=line_width, minwidth=70)
        self.replacement_tree.column("rule", width=rule_width, minwidth=160)
        self.replacement_tree.column("before", width=before_width, minwidth=220)
        self.replacement_tree.column("after", width=after_width, minwidth=220)

    def _select_tab(self, tab_name: str) -> None:
        self.active_tab = tab_name
        if tab_name == "logs":
            self.replacements_view.pack_forget()
            self.logs_view.pack(fill=tk.BOTH, expand=True)
            self.logs_tab_button.configure(style="Tab.Active.TButton")
            self.replacements_tab_button.configure(style="Tab.Inactive.TButton")
        else:
            self.logs_view.pack_forget()
            self.replacements_view.pack(fill=tk.BOTH, expand=True)
            self.logs_tab_button.configure(style="Tab.Inactive.TButton")
            self.replacements_tab_button.configure(style="Tab.Active.TButton")

    def _update_progress(self, percent: int) -> None:
        bounded = max(0, min(100, int(percent)))
        self.progress_var.set(float(bounded))
        self.progress_text_var.set(self.t("progress_value").format(percent=bounded))
        if self.run_thread and self.run_thread.is_alive():
            self.status_var.set(self.t("running_progress").format(percent=bounded))

    def _set_running(self, is_running: bool) -> None:
        self.run_button.configure(state=(tk.DISABLED if is_running else tk.NORMAL))
        self.status_var.set(self.t("running") if is_running else self.t("ready"))

    def _log(self, message: str) -> None:
        self.log_text.insert(tk.END, message.rstrip() + "\n")
        self.log_text.see(tk.END)

    def _clear_replacement_rows(self) -> None:
        for item_id in self.replacement_tree.get_children():
            self.replacement_tree.delete(item_id)

    def _on_run(self) -> None:
        if self.run_thread and self.run_thread.is_alive():
            messagebox.showinfo(self.t("app_title"), self.t("busy_msg"))
            return

        source_file = Path(self.source_var.get()).expanduser()
        if not source_file.exists() or not source_file.is_file():
            messagebox.showerror(
                self.t("invalid_source_title"),
                self.t("invalid_source_msg").format(path=source_file),
            )
            return

        try:
            config = RedactionConfig(
                domains=[self.domains_var.get()],
                redact_certs=self.redact_certs_var.get(),
                redact_public_keys=self.redact_public_keys_var.get(),
            )
        except ValueError as exc:
            messagebox.showerror(self.t("invalid_config_title"), str(exc))
            return

        output_file = suggested_output_file(source_file)
        if output_file.exists() and not self.dry_run_var.get():
            confirmed = messagebox.askyesno(
                self.t("overwrite_title"),
                self.t("overwrite_msg").format(path=output_file),
            )
            if not confirmed:
                return

        self._set_running(True)
        self._update_progress(0)
        self._clear_replacement_rows()
        self._log(
            self.t("start_log").format(
                source=source_file,
                domains=",".join(config.domains) if config.domains else "(none)",
                dry_run=self.dry_run_var.get(),
            )
        )

        self.run_thread = threading.Thread(
            target=self._run_worker,
            kwargs={
                "source_file": source_file,
                "config": config,
                "dry_run": self.dry_run_var.get(),
            },
            daemon=True,
        )
        self.run_thread.start()

    def _run_worker(
        self,
        *,
        source_file: Path,
        config: RedactionConfig,
        dry_run: bool,
    ) -> None:
        try:
            last_progress = -1

            def progress_callback(ratio: float) -> None:
                nonlocal last_progress
                percent = int(round(max(0.0, min(1.0, ratio)) * 100))
                if percent == last_progress:
                    return
                last_progress = percent
                self.event_queue.put(("progress", percent))

            result = sanitize_single_file(
                source_file=source_file,
                config=config,
                dry_run=dry_run,
                progress_callback=progress_callback,
            )
            self.event_queue.put(("done", result))
        except Exception as exc:  # defensive: keeps UI responsive on unexpected failures
            self.event_queue.put(("error", str(exc)))

    def _poll_events(self) -> None:
        try:
            while True:
                event = self.event_queue.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        self.after(150, self._poll_events)

    def _handle_event(self, event: tuple) -> None:
        kind = event[0]
        if kind == "progress":
            self._update_progress(event[1])
            return
        if kind == "error":
            self._set_running(False)
            self._log(f"ERROR: {event[1]}")
            messagebox.showerror(self.t("run_error_title"), event[1])
            return

        if kind == "done":
            result = event[1]
            self.last_output_file = result.output_file
            self._update_progress(100)
            if result.report.skipped:
                self._log(self.t("status_skipped").format(reason=result.report.skipped))
            else:
                if result.dry_run:
                    status_label = self.t("status_dry_run")
                elif result.report.modified:
                    status_label = self.t("status_modified")
                else:
                    status_label = self.t("status_unchanged")
                self._log(self.t("status_done").format(status=status_label))
            self._log(self.t("replacement_count").format(count=result.report.replacements))
            self._log(self.t("output_line").format(path=result.output_file))

            if result.report.logs:
                for entry in result.report.logs:
                    self.replacement_tree.insert(
                        "",
                        tk.END,
                        values=(entry.line, entry.rule, entry.before, entry.after),
                    )
            else:
                self._log(self.t("no_replacements"))

            self._set_running(False)
            self.status_var.set(self.t("status_completed"))

    def _open_output_folder(self) -> None:
        if not self.last_output_file:
            messagebox.showinfo(self.t("app_title"), self.t("no_output_yet"))
            return
        webbrowser.open(self.last_output_file.parent.resolve().as_uri())


def main() -> int:
    app = SanitizerApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
