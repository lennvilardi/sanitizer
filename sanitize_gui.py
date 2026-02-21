#! /usr/bin/env python3
"""Tkinter GUI for the sanitizer tool."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from sanitizer_core import DEFAULT_EXTS, DEFAULT_MAX_SIZE_MB, RedactionConfig, parse_exts, sanitize_directory


class SanitizerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Config Sanitizer")
        self.geometry("900x620")
        self.minsize(780, 520)

        self.source_var = tk.StringVar(value=str(Path.cwd()))
        self.output_var = tk.StringVar(value="")
        self.domains_var = tk.StringVar(value="")
        self.exts_var = tk.StringVar(value=",".join(sorted(DEFAULT_EXTS)))
        self.max_size_var = tk.StringVar(value=str(DEFAULT_MAX_SIZE_MB))
        self.dry_run_var = tk.BooleanVar(value=False)
        self.redact_certs_var = tk.BooleanVar(value=False)
        self.redact_public_keys_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Ready")

        self.run_thread: Optional[threading.Thread] = None
        self.event_queue: queue.Queue[tuple] = queue.Queue()
        self.last_output_dir: Optional[Path] = None
        self.last_report_path: Optional[Path] = None

        self._build_layout()
        self.after(150, self._poll_events)

    def _build_layout(self) -> None:
        main = ttk.Frame(self, padding=14)
        main.pack(fill=tk.BOTH, expand=True)

        form = ttk.Frame(main)
        form.pack(fill=tk.X)
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Source directory").grid(row=0, column=0, sticky=tk.W, pady=4)
        ttk.Entry(form, textvariable=self.source_var).grid(row=0, column=1, sticky=tk.EW, pady=4, padx=(10, 8))
        ttk.Button(form, text="Browse", command=self._browse_source).grid(row=0, column=2, sticky=tk.E, pady=4)

        ttk.Label(form, text="Output directory").grid(row=1, column=0, sticky=tk.W, pady=4)
        ttk.Entry(form, textvariable=self.output_var).grid(row=1, column=1, sticky=tk.EW, pady=4, padx=(10, 8))
        ttk.Button(form, text="Browse", command=self._browse_output).grid(row=1, column=2, sticky=tk.E, pady=4)

        ttk.Label(form, text="Domains to redact").grid(row=2, column=0, sticky=tk.W, pady=4)
        ttk.Entry(form, textvariable=self.domains_var).grid(row=2, column=1, sticky=tk.EW, pady=4, padx=(10, 8))
        ttk.Label(form, text="comma separated").grid(row=2, column=2, sticky=tk.W, pady=4)

        ttk.Label(form, text="Extensions").grid(row=3, column=0, sticky=tk.W, pady=4)
        ttk.Entry(form, textvariable=self.exts_var).grid(row=3, column=1, sticky=tk.EW, pady=4, padx=(10, 8))
        ttk.Label(form, text="ex: .yml,.yaml,.env").grid(row=3, column=2, sticky=tk.W, pady=4)

        ttk.Label(form, text="Max file size (MB)").grid(row=4, column=0, sticky=tk.W, pady=4)
        ttk.Entry(form, textvariable=self.max_size_var).grid(row=4, column=1, sticky=tk.W, pady=4, padx=(10, 8))

        options = ttk.Frame(main)
        options.pack(fill=tk.X, pady=(12, 8))
        ttk.Checkbutton(options, text="Dry-run (write report only)", variable=self.dry_run_var).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(options, text="Redact certificates", variable=self.redact_certs_var).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(options, text="Redact SSH public keys", variable=self.redact_public_keys_var).pack(side=tk.LEFT)

        actions = ttk.Frame(main)
        actions.pack(fill=tk.X, pady=(2, 8))
        self.run_button = ttk.Button(actions, text="Run sanitizer", command=self._on_run)
        self.run_button.pack(side=tk.LEFT)
        ttk.Button(actions, text="Open output folder", command=self._open_output_folder).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(actions, text="Open JSON report", command=self._open_report).pack(side=tk.LEFT, padx=(8, 0))

        log_frame = ttk.LabelFrame(main, text="Logs", padding=8)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(log_frame, wrap=tk.WORD, height=18)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=scrollbar.set)

        status_bar = ttk.Label(main, textvariable=self.status_var, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=(8, 0))

    def _browse_source(self) -> None:
        selected = filedialog.askdirectory(title="Choose source directory")
        if selected:
            self.source_var.set(selected)

    def _browse_output(self) -> None:
        selected = filedialog.askdirectory(title="Choose output directory")
        if selected:
            self.output_var.set(selected)

    def _set_running(self, is_running: bool) -> None:
        self.run_button.configure(state=(tk.DISABLED if is_running else tk.NORMAL))
        self.status_var.set("Running..." if is_running else "Ready")

    def _log(self, message: str) -> None:
        self.log_text.insert(tk.END, message.rstrip() + "\n")
        self.log_text.see(tk.END)

    def _on_run(self) -> None:
        if self.run_thread and self.run_thread.is_alive():
            messagebox.showinfo("Sanitizer", "A run is already in progress.")
            return

        source_dir = Path(self.source_var.get()).expanduser()
        if not source_dir.exists() or not source_dir.is_dir():
            messagebox.showerror("Invalid source", f"Invalid source directory:\n{source_dir}")
            return

        out_text = self.output_var.get().strip()
        out_dir = Path(out_text).expanduser() if out_text else None

        try:
            max_size_mb = float(self.max_size_var.get().strip())
            if max_size_mb <= 0:
                raise ValueError("max-size must be > 0")
        except ValueError as exc:
            messagebox.showerror("Invalid size", f"Invalid max size value: {exc}")
            return

        try:
            config = RedactionConfig(
                domains=[self.domains_var.get()],
                redact_certs=self.redact_certs_var.get(),
                redact_public_keys=self.redact_public_keys_var.get(),
            )
            extensions = parse_exts(self.exts_var.get().strip())
        except ValueError as exc:
            messagebox.showerror("Invalid configuration", str(exc))
            return

        self._set_running(True)
        self._log(
            "Starting run: "
            f"source={source_dir} domains={','.join(config.domains) if config.domains else '(none)'} "
            f"dry_run={self.dry_run_var.get()}"
        )

        self.run_thread = threading.Thread(
            target=self._run_worker,
            kwargs={
                "source_dir": source_dir,
                "out_dir": out_dir,
                "config": config,
                "extensions": extensions,
                "max_size_mb": max_size_mb,
            },
            daemon=True,
        )
        self.run_thread.start()

    def _run_worker(
        self,
        *,
        source_dir: Path,
        out_dir: Optional[Path],
        config: RedactionConfig,
        extensions: set[str],
        max_size_mb: float,
    ) -> None:
        try:
            def progress_callback(relative: Path, report) -> None:
                if report.modified:
                    status = "modified"
                elif report.skipped:
                    status = f"skipped:{report.skipped}"
                else:
                    status = "unchanged"
                self.event_queue.put(("log", f"[{status}] {relative}"))

            result = sanitize_directory(
                source_dir=source_dir,
                out_dir=out_dir,
                config=config,
                exts=extensions,
                dry_run=self.dry_run_var.get(),
                max_size_mb=max_size_mb,
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
        if kind == "log":
            self._log(event[1])
            return
        if kind == "error":
            self._set_running(False)
            self._log(f"ERROR: {event[1]}")
            messagebox.showerror("Sanitizer error", event[1])
            return
        if kind == "done":
            result = event[1]
            self.last_output_dir = result.out_dir
            self.last_report_path = result.report_path
            self._log(f"Files processed: {result.stats.files_processed}")
            self._log(f"Files modified:  {result.stats.files_modified}")
            self._log(f"Replacements:    {result.stats.replacements}")
            self._log(f"Report:          {result.report_path}")
            self._set_running(False)
            self.status_var.set("Completed")
            return

    def _open_output_folder(self) -> None:
        if not self.last_output_dir:
            messagebox.showinfo("Sanitizer", "No output folder yet. Run the sanitizer first.")
            return
        webbrowser.open(self.last_output_dir.resolve().as_uri())

    def _open_report(self) -> None:
        if not self.last_report_path:
            messagebox.showinfo("Sanitizer", "No report yet. Run the sanitizer first.")
            return
        webbrowser.open(self.last_report_path.resolve().as_uri())


def main() -> int:
    app = SanitizerApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
