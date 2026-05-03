"""Tkinter desktop GUI.

Layout overview:

    +--------------------------------------------------------------+
    | [logo]  VoIP Health Check                                    |
    |--------------------------------------------------------------|
    | [ Quick Scan ]      [ Start Packet Capture ]                 |
    |                                                              |
    | +-- Optional: --------------------------------------------+  |
    | | Problem Experienced: [dropdown]                         |  |
    | | Do you have a different problem?  [text]                |  |
    | | v Advanced                                              |  |
    | |    Hosted Platform: ( ) On-Prem ( ) Cloud Only ...      |  |
    | |    Gateway IP: [...]  Firewall IP: [...]                |  |
    | |    Starbox IP: [...]                                    |  |
    | | [ Scan Now ]                                            |  |
    | +---------------------------------------------------------+  |
    |                                                              |
    | Results / Log                                                |
    | +---------------------------------------------------------+  |
    | |                                                         |  |
    | +---------------------------------------------------------+  |
    | [ Download Results ]                            [ Clear ]    |
    +--------------------------------------------------------------+

The widgets, labels and dropdown options are easy to tweak — they live
near the top of ``VoipScanApp.__init__``.
"""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from . import __app_name__, __version__, capture, logger, paths, scanner
from .logger import get_logger, log_exception

# ---- Theme ---------------------------------------------------------------
# Mirrors the web app's dark theme so the desktop client feels related.
BG = "#0f1115"
SURFACE = "#181b22"
SURFACE_2 = "#1f232c"
BORDER = "#2a2f3a"
TEXT = "#e6e8ec"
TEXT_MUTED = "#9aa3b2"
ACCENT = "#d9534f"
ACCENT_HOVER = "#ff7a73"
SUCCESS = "#2ecc71"
WARN = "#f5a623"

# Editable dropdown choices for "Problem Experienced".
PROBLEM_OPTIONS = [
    "",
    "choppy calls",
    "one-way audio",
    "delayed audio",
    "no inbound calls",
    "no outbound calls",
    "phone lost registration",
]

HOSTED_PLATFORMS = ["On-Prem", "Cloud Only", "Remote Phone"]


class VoipScanApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.log = get_logger()
        self._ui_queue: "queue.Queue[str]" = queue.Queue()
        self._scan_thread: Optional[threading.Thread] = None
        self._cancel_event = threading.Event()
        self._last_results: list[dict] = []

        self._configure_root()
        self._build_styles()
        self._build_header()
        self._build_primary_actions()
        self._build_optional_section()
        self._build_results()
        self._build_footer()

        # Stream log messages into the results panel.
        logger.register_gui_sink(self._enqueue)
        self.root.after(100, self._drain_queue)
        self._enqueue(f"{__app_name__} v{__version__} ready.")
        self._enqueue(f"Logs: {paths.logs_dir()}")
        nmap_path = scanner.find_nmap()
        if nmap_path:
            self._enqueue(f"nmap: {nmap_path}")
        else:
            self._enqueue(
                "[warn] nmap not found yet — drop a portable nmap build "
                "into LocalScanner/nmap/ before scanning."
            )

    # -- Window / styling -------------------------------------------------
    def _configure_root(self) -> None:
        self.root.title(__app_name__)
        self.root.geometry("900x720")
        self.root.minsize(780, 600)
        self.root.configure(bg=BG)

        # Try to set the window icon from the logo.
        try:
            logo = paths.logo_path()
            if logo.exists():
                # PhotoImage works for PNGs in modern Tk. Keep a ref on
                # the root so it isn't GC'd.
                self._icon_img = tk.PhotoImage(file=str(logo))
                self.root.iconphoto(True, self._icon_img)
        except Exception:
            log_exception("Could not load window icon")

    def _build_styles(self) -> None:
        style = ttk.Style(self.root)
        # 'clam' is the most theme-friendly built-in for custom colors.
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "TFrame", background=BG,
        )
        style.configure(
            "Surface.TFrame", background=SURFACE,
        )
        style.configure(
            "Card.TLabelframe",
            background=SURFACE,
            foreground=TEXT,
            bordercolor=BORDER,
            relief="solid",
        )
        style.configure(
            "Card.TLabelframe.Label",
            background=SURFACE,
            foreground=TEXT_MUTED,
            font=("Segoe UI", 10, "bold"),
        )
        style.configure(
            "TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10)
        )
        style.configure(
            "Surface.TLabel",
            background=SURFACE,
            foreground=TEXT,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Muted.TLabel",
            background=SURFACE,
            foreground=TEXT_MUTED,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Header.TLabel",
            background=BG,
            foreground=TEXT,
            font=("Segoe UI", 18, "bold"),
        )
        style.configure(
            "Subheader.TLabel",
            background=BG,
            foreground=TEXT_MUTED,
            font=("Segoe UI", 10),
        )
        style.configure(
            "TButton",
            background=SURFACE_2,
            foreground=TEXT,
            bordercolor=BORDER,
            focusthickness=0,
            padding=(14, 8),
            font=("Segoe UI", 10),
        )
        style.map(
            "TButton",
            background=[("active", BORDER)],
            foreground=[("disabled", TEXT_MUTED)],
        )
        style.configure(
            "Primary.TButton",
            background=ACCENT,
            foreground="#ffffff",
            font=("Segoe UI", 11, "bold"),
            padding=(18, 10),
        )
        style.map(
            "Primary.TButton",
            background=[("active", ACCENT_HOVER), ("disabled", BORDER)],
        )
        style.configure(
            "Secondary.TButton",
            background=SURFACE_2,
            foreground=TEXT,
            padding=(16, 9),
            font=("Segoe UI", 10, "bold"),
        )
        style.configure(
            "TEntry",
            fieldbackground=SURFACE_2,
            background=SURFACE_2,
            foreground=TEXT,
            bordercolor=BORDER,
            insertcolor=TEXT,
        )
        style.configure(
            "TCombobox",
            fieldbackground=SURFACE_2,
            background=SURFACE_2,
            foreground=TEXT,
            arrowcolor=TEXT,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", SURFACE_2)],
            foreground=[("readonly", TEXT)],
        )
        style.configure(
            "TRadiobutton",
            background=SURFACE,
            foreground=TEXT,
            indicatorcolor=SURFACE_2,
            font=("Segoe UI", 10),
        )
        style.map(
            "TRadiobutton",
            background=[("active", SURFACE)],
        )

    # -- Header -----------------------------------------------------------
    def _build_header(self) -> None:
        header = ttk.Frame(self.root, style="TFrame")
        header.pack(fill="x", padx=18, pady=(16, 8))

        # Logo (PhotoImage handles PNG natively).
        try:
            logo_file = paths.logo_path()
            if logo_file.exists():
                raw = tk.PhotoImage(file=str(logo_file))
                # Subsample to a sensible header height (~56px tall).
                # Pick a factor that keeps aspect.
                ratio = max(1, raw.height() // 56)
                self._header_logo = raw.subsample(ratio, ratio)
                tk.Label(
                    header,
                    image=self._header_logo,
                    bg=BG,
                    bd=0,
                ).pack(side="left", padx=(0, 14))
        except Exception:
            log_exception("Could not load header logo")

        text_col = ttk.Frame(header, style="TFrame")
        text_col.pack(side="left", fill="x", expand=True)
        ttk.Label(text_col, text=__app_name__, style="Header.TLabel").pack(
            anchor="w"
        )
        ttk.Label(
            text_col,
            text="Local network diagnostics for VoIP health.",
            style="Subheader.TLabel",
        ).pack(anchor="w")

    # -- Primary actions --------------------------------------------------
    def _build_primary_actions(self) -> None:
        row = ttk.Frame(self.root, style="TFrame")
        row.pack(fill="x", padx=18, pady=(4, 12))

        self.btn_quick = ttk.Button(
            row,
            text="Quick Scan",
            style="Primary.TButton",
            command=self._on_quick_scan,
        )
        self.btn_quick.pack(side="left", padx=(0, 10))

        self.btn_capture = ttk.Button(
            row,
            text="Start Packet Capture",
            style="Secondary.TButton",
            command=self._on_packet_capture,
        )
        self.btn_capture.pack(side="left")

    # -- Optional section -------------------------------------------------
    def _build_optional_section(self) -> None:
        card = ttk.Labelframe(
            self.root, text=" Optional: ", style="Card.TLabelframe", padding=14
        )
        card.pack(fill="x", padx=18, pady=(0, 12))

        # Problem Experienced
        row1 = ttk.Frame(card, style="Surface.TFrame")
        row1.pack(fill="x", pady=(0, 8))
        ttk.Label(
            row1, text="Problem Experienced:", style="Surface.TLabel"
        ).pack(side="left")
        self.var_problem = tk.StringVar(value="")
        self.cmb_problem = ttk.Combobox(
            row1,
            textvariable=self.var_problem,
            values=PROBLEM_OPTIONS,
            state="readonly",
            width=32,
        )
        self.cmb_problem.pack(side="left", padx=(8, 0))

        # Different problem text box
        row2 = ttk.Frame(card, style="Surface.TFrame")
        row2.pack(fill="x", pady=(0, 8))
        ttk.Label(
            row2,
            text="Do you have a different problem?",
            style="Surface.TLabel",
        ).pack(side="left")
        self.var_other = tk.StringVar()
        self.ent_other = ttk.Entry(row2, textvariable=self.var_other, width=40)
        self.ent_other.pack(side="left", padx=(8, 0), fill="x", expand=True)

        # Advanced expand toggle
        adv_row = ttk.Frame(card, style="Surface.TFrame")
        adv_row.pack(fill="x", pady=(6, 4))
        self._advanced_open = False
        self.btn_advanced = ttk.Button(
            adv_row,
            text="▼  Advanced",  # ▼
            style="TButton",
            command=self._toggle_advanced,
        )
        self.btn_advanced.pack(side="left")

        # Advanced container (collapsed by default)
        self.frm_advanced = ttk.Frame(card, style="Surface.TFrame")
        # Hosted Platform
        hp = ttk.Frame(self.frm_advanced, style="Surface.TFrame")
        hp.pack(fill="x", pady=(8, 6))
        ttk.Label(hp, text="Hosted Platform:", style="Surface.TLabel").pack(
            side="left"
        )
        self.var_hosted = tk.StringVar(value=HOSTED_PLATFORMS[0])
        for label in HOSTED_PLATFORMS:
            ttk.Radiobutton(
                hp,
                text=label,
                value=label,
                variable=self.var_hosted,
                style="TRadiobutton",
            ).pack(side="left", padx=(10, 0))

        # IP fields
        ips = ttk.Frame(self.frm_advanced, style="Surface.TFrame")
        ips.pack(fill="x", pady=(2, 4))
        self.var_gw = tk.StringVar()
        self.var_fw = tk.StringVar()
        self.var_sb = tk.StringVar()
        self._ip_field(ips, "Gateway IP:", self.var_gw, 0)
        self._ip_field(ips, "Firewall IP:", self.var_fw, 1)
        self._ip_field(ips, "Starbox IP:", self.var_sb, 2)

        # Scan Now
        scan_row = ttk.Frame(card, style="Surface.TFrame")
        scan_row.pack(fill="x", pady=(10, 0))
        self.btn_scan_now = ttk.Button(
            scan_row,
            text="Scan Now",
            style="Primary.TButton",
            command=self._on_scan_now,
        )
        self.btn_scan_now.pack(side="left")

    def _ip_field(
        self, parent: ttk.Frame, label: str, var: tk.StringVar, row: int
    ) -> None:
        ttk.Label(parent, text=label, style="Surface.TLabel").grid(
            row=row, column=0, sticky="w", pady=2, padx=(0, 8)
        )
        ttk.Entry(parent, textvariable=var, width=22).grid(
            row=row, column=1, sticky="w", pady=2
        )

    def _toggle_advanced(self) -> None:
        self._advanced_open = not self._advanced_open
        if self._advanced_open:
            self.frm_advanced.pack(fill="x", pady=(4, 0))
            self.btn_advanced.config(text="▲  Advanced")  # ▲
        else:
            self.frm_advanced.forget()
            self.btn_advanced.config(text="▼  Advanced")  # ▼

    # -- Results ----------------------------------------------------------
    def _build_results(self) -> None:
        card = ttk.Labelframe(
            self.root,
            text=" Scan Results / Log ",
            style="Card.TLabelframe",
            padding=10,
        )
        card.pack(fill="both", expand=True, padx=18, pady=(0, 8))

        text_frame = tk.Frame(card, bg=SURFACE_2, highlightthickness=1,
                              highlightbackground=BORDER)
        text_frame.pack(fill="both", expand=True)

        self.txt_results = tk.Text(
            text_frame,
            bg=SURFACE_2,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            wrap="word",
            font=("Consolas", 10),
            padx=10,
            pady=8,
        )
        self.txt_results.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(text_frame, command=self.txt_results.yview)
        scroll.pack(side="right", fill="y")
        self.txt_results.configure(yscrollcommand=scroll.set, state="disabled")

    def _build_footer(self) -> None:
        row = ttk.Frame(self.root, style="TFrame")
        row.pack(fill="x", padx=18, pady=(0, 16))

        self.btn_download = ttk.Button(
            row,
            text="Download Results",
            style="Secondary.TButton",
            command=self._on_download,
        )
        self.btn_download.pack(side="left")

        self.btn_clear = ttk.Button(
            row,
            text="Clear",
            style="TButton",
            command=self._on_clear,
        )
        self.btn_clear.pack(side="right")

        self.lbl_status = ttk.Label(
            row, text="Idle.", style="Subheader.TLabel"
        )
        self.lbl_status.pack(side="right", padx=(0, 12))

    # -- GUI plumbing -----------------------------------------------------
    def _enqueue(self, msg: str) -> None:
        self._ui_queue.put(msg)

    def _drain_queue(self) -> None:
        try:
            while True:
                msg = self._ui_queue.get_nowait()
                self._append_text(msg)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def _append_text(self, msg: str) -> None:
        self.txt_results.configure(state="normal")
        self.txt_results.insert("end", msg + "\n")
        self.txt_results.see("end")
        self.txt_results.configure(state="disabled")

    def _set_busy(self, busy: bool, status: str = "") -> None:
        state = "disabled" if busy else "normal"
        for btn in (
            self.btn_quick,
            self.btn_capture,
            self.btn_scan_now,
        ):
            btn.configure(state=state)
        if status:
            self.lbl_status.configure(text=status)
        elif not busy:
            self.lbl_status.configure(text="Idle.")

    # -- Action handlers --------------------------------------------------
    def _on_quick_scan(self) -> None:
        profile = scanner.build_quick_profile()
        self._run_scan(profile, "Running quick scan...")

    def _on_scan_now(self) -> None:
        targets = [
            self.var_gw.get(),
            self.var_fw.get(),
            self.var_sb.get(),
        ]
        cleaned = [t.strip() for t in targets if t and t.strip()]
        if not cleaned:
            messagebox.showwarning(
                __app_name__,
                "Enter at least one IP under Advanced (Gateway, Firewall or "
                "Starbox) before running Scan Now.",
            )
            return
        profile = scanner.build_targeted_profile(cleaned)
        self._run_scan(profile, "Running targeted scan...")

    def _on_packet_capture(self) -> None:
        # Stub-only — see voipscan/capture.py.
        self._enqueue(capture.start_capture_stub())
        status = capture.detect_capture_engine()
        if not status.available:
            messagebox.showinfo(
                __app_name__,
                status.detail,
            )

    def _run_scan(self, profile: scanner.ScanProfile, status: str) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showinfo(
                __app_name__, "A scan is already running. Please wait."
            )
            return
        self._set_busy(True, status)
        self._cancel_event = threading.Event()

        def worker() -> None:
            try:
                result = scanner.run_profile(
                    profile,
                    on_line=self._enqueue,
                    cancel_event=self._cancel_event,
                )
                result["finished_at"] = datetime.utcnow().isoformat() + "Z"
                result["form"] = self._collect_form()
                self._last_results.append(result)
                self._enqueue(
                    f"[{profile.name}] complete (rc={result['returncode']})."
                )
            except scanner.ScanError as e:
                self._enqueue(f"[error] {e}")
                messagebox.showerror(__app_name__, str(e))
            except Exception as e:
                log_exception(f"Unexpected error during {profile.name}")
                self._enqueue(f"[error] Unexpected: {e}")
                messagebox.showerror(
                    __app_name__,
                    f"Unexpected error during {profile.name}. See logs/voipscan.log.",
                )
            finally:
                self.root.after(0, lambda: self._set_busy(False))

        self._scan_thread = threading.Thread(
            target=worker, name="voipscan-worker", daemon=True
        )
        self._scan_thread.start()

    def _collect_form(self) -> dict:
        return {
            "problem_experienced": self.var_problem.get(),
            "other_problem": self.var_other.get().strip(),
            "hosted_platform": self.var_hosted.get(),
            "gateway_ip": self.var_gw.get().strip(),
            "firewall_ip": self.var_fw.get().strip(),
            "starbox_ip": self.var_sb.get().strip(),
        }

    def _on_download(self) -> None:
        if not self._last_results and not self._buffer_text():
            messagebox.showinfo(
                __app_name__, "Nothing to save yet — run a scan first."
            )
            return
        default = f"voipscan_report_{logger.session_id()}.json"
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=default,
            initialdir=str(paths.reports_dir()),
            filetypes=[
                ("JSON report", "*.json"),
                ("Text log", "*.txt"),
                ("All files", "*.*"),
            ],
            title="Save Scan Report",
        )
        if not path:
            return
        try:
            self._write_report(Path(path))
            self._enqueue(f"Saved report -> {path}")
        except Exception as e:
            log_exception("Failed to save report")
            messagebox.showerror(__app_name__, f"Failed to save: {e}")

    def _write_report(self, path: Path) -> None:
        if path.suffix.lower() == ".txt":
            with path.open("w", encoding="utf-8") as f:
                f.write(f"{__app_name__} report\n")
                f.write(f"Generated: {datetime.utcnow().isoformat()}Z\n\n")
                f.write("--- Form ---\n")
                form = self._last_results[-1]["form"] if self._last_results else {}
                for k, v in form.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n--- Results ---\n")
                for r in self._last_results:
                    f.write(f"\n# {r['profile']} (rc={r['returncode']})\n")
                    f.write(f"command: {' '.join(r['command'])}\n")
                    f.write(r["stdout"])
                    f.write("\n")
                f.write("\n--- Console buffer ---\n")
                f.write(self._buffer_text())
            return

        payload = {
            "app": __app_name__,
            "version": __version__,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "form": self._last_results[-1]["form"] if self._last_results else {},
            "results": self._last_results,
            "console": self._buffer_text(),
        }
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def _buffer_text(self) -> str:
        self.txt_results.configure(state="normal")
        text = self.txt_results.get("1.0", "end").rstrip()
        self.txt_results.configure(state="disabled")
        return text

    def _on_clear(self) -> None:
        self.txt_results.configure(state="normal")
        self.txt_results.delete("1.0", "end")
        self.txt_results.configure(state="disabled")


def run() -> None:
    logger.init_logging()
    root = tk.Tk()
    VoipScanApp(root)
    root.mainloop()
