"""Tkinter desktop GUI.

Two phases:

* **During scan** — the Results / Log box streams technical log lines
  the same way the legacy build did.
* **After scan completes** — the raw log is saved to disk, the box is
  cleared, and a plain-English interpretation of the structured
  ``ScanReport`` is rendered in its place. Each section has a colored
  status badge drawn with a Tk Canvas (no external assets required).

Editable bits live near the top of ``VoipScanApp.__init__`` and inside
the small ``ICONS`` / ``STATUS_COLORS`` tables below.
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

from . import (
    __app_name__,
    __version__,
    capture,
    interpret,
    logger,
    paths,
    scanner,
    upload as upload_mod,
)
from .logger import get_logger, log_exception
from .report import FormInputs, ScanReport

# ---- Theme ---------------------------------------------------------------
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
DANGER = "#e74c3c"
INFO_BLUE = "#3aa0ff"
GREY = "#6b7280"

# Status badge colors used in the post-scan summary view.
STATUS_COLORS = {
    "OK": SUCCESS,
    "WARN": WARN,
    "BAD": DANGER,
    "INFO": INFO_BLUE,
    "UNK": GREY,
}

# Section icon mapping — purely visual, picked to be readable on a dark
# theme without external image assets.
ICONS = {
    "summary": "≡",
    "sipalg": "S",
    "ports": "#",
    "vlan": "V",
    "attribution": "A",
    "net": "N",
    "capture": "C",
    "latency": "L",
    "dhcp": "D",
}

PROBLEM_OPTIONS = [
    "",
    "choppy calls",
    "one-way audio",
    "delayed audio",
    "no inbound calls",
    "no outbound calls",
    "phone lost registration",
]

# "Auto / unknown" is the default — it tells the scanner to infer the
# hosted-platform context from scan data instead of forcing a value.
HOSTED_PLATFORMS = ["Auto / unknown", "On-Prem", "Cloud Only", "Remote Phone"]
HOSTED_AUTO = HOSTED_PLATFORMS[0]


class VoipScanApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.log = get_logger()
        self._ui_queue: "queue.Queue[str]" = queue.Queue()
        self._scan_thread: Optional[threading.Thread] = None
        self._cancel_event = threading.Event()
        self._last_report: Optional[ScanReport] = None
        self._last_log_path: Optional[Path] = None
        self._last_results: list[dict] = []  # legacy nmap dicts (kept for compat)

        self._capture_session: Optional[capture.CaptureSession] = None
        # Server-assigned scan session id (set after a successful upload).
        # Used to attach the next capture artifact to the same scan.
        self._server_session_id: Optional[str] = None

        self._configure_root()
        self._build_styles()
        self._build_header()
        self._build_primary_actions()
        self._build_optional_section()
        self._build_results()
        self._build_footer()

        logger.register_gui_sink(self._enqueue)
        self.root.after(100, self._drain_queue)
        self._enqueue(f"{__app_name__} v{__version__} ready.")
        self._enqueue(f"Logs: {paths.logs_dir()}")
        nmap_path = scanner.find_nmap()
        if nmap_path:
            self._enqueue(f"nmap: {nmap_path}")
        else:
            self._enqueue(
                "[info] nmap not found — evidence scan still works using "
                "Python sockets and Windows commands. Drop a portable "
                "nmap into LocalScanner/nmap/ for the optional nmap pass."
            )

    # -- Window / styling -------------------------------------------------
    def _configure_root(self) -> None:
        self.root.title(__app_name__)
        self.root.geometry("960x780")
        self.root.minsize(820, 640)
        self.root.configure(bg=BG)

        try:
            logo = paths.logo_path()
            if logo.exists():
                self._icon_img = tk.PhotoImage(file=str(logo))
                self.root.iconphoto(True, self._icon_img)
        except Exception:
            log_exception("Could not load window icon")

    def _build_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=BG)
        style.configure("Surface.TFrame", background=SURFACE)
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
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
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
        style.map("TRadiobutton", background=[("active", SURFACE)])

    # -- Header -----------------------------------------------------------
    def _build_header(self) -> None:
        header = ttk.Frame(self.root, style="TFrame")
        header.pack(fill="x", padx=18, pady=(16, 8))

        try:
            logo_file = paths.logo_path()
            if logo_file.exists():
                raw = tk.PhotoImage(file=str(logo_file))
                ratio = max(1, raw.height() // 56)
                self._header_logo = raw.subsample(ratio, ratio)
                tk.Label(
                    header, image=self._header_logo, bg=BG, bd=0
                ).pack(side="left", padx=(0, 14))
        except Exception:
            log_exception("Could not load header logo")

        text_col = ttk.Frame(header, style="TFrame")
        text_col.pack(side="left", fill="x", expand=True)
        ttk.Label(text_col, text=__app_name__, style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            text_col,
            text="Evidence-focused VoIP network diagnostics for Windows.",
            style="Subheader.TLabel",
        ).pack(anchor="w")

    # -- Primary actions --------------------------------------------------
    def _build_primary_actions(self) -> None:
        row = ttk.Frame(self.root, style="TFrame")
        row.pack(fill="x", padx=18, pady=(4, 12))

        # All buttons on this row share equal sizing and spacing so the
        # layout stays balanced even as labels change ("Start" vs "Stop").
        self.btn_quick = ttk.Button(
            row,
            text="Run Evidence Scan",
            style="Primary.TButton",
            command=self._on_evidence_scan,
            width=22,
        )
        self.btn_quick.pack(side="left", padx=(0, 10))

        self.btn_capture = ttk.Button(
            row,
            text="Start Packet Capture",
            style="Secondary.TButton",
            command=self._start_packet_capture,
            width=22,
        )
        self.btn_capture.pack(side="left", padx=(0, 10))

        self.btn_capture_stop = ttk.Button(
            row,
            text="Stop Packet Capture",
            style="Secondary.TButton",
            command=self._stop_packet_capture,
            width=22,
            state="disabled",
        )
        self.btn_capture_stop.pack(side="left")

    # -- Optional section -------------------------------------------------
    def _build_optional_section(self) -> None:
        card = ttk.Labelframe(
            self.root, text=" Optional: ", style="Card.TLabelframe", padding=14
        )
        card.pack(fill="x", padx=18, pady=(0, 12))

        row1 = ttk.Frame(card, style="Surface.TFrame")
        row1.pack(fill="x", pady=(0, 8))
        ttk.Label(row1, text="Problem Experienced:", style="Surface.TLabel").pack(side="left")
        self.var_problem = tk.StringVar(value="")
        self.cmb_problem = ttk.Combobox(
            row1,
            textvariable=self.var_problem,
            values=PROBLEM_OPTIONS,
            state="readonly",
            width=32,
        )
        self.cmb_problem.pack(side="left", padx=(8, 0))

        row2 = ttk.Frame(card, style="Surface.TFrame")
        row2.pack(fill="x", pady=(0, 8))
        ttk.Label(
            row2, text="Do you have a different problem?", style="Surface.TLabel"
        ).pack(side="left")
        self.var_other = tk.StringVar()
        self.ent_other = ttk.Entry(row2, textvariable=self.var_other, width=40)
        self.ent_other.pack(side="left", padx=(8, 0), fill="x", expand=True)

        adv_row = ttk.Frame(card, style="Surface.TFrame")
        adv_row.pack(fill="x", pady=(6, 4))
        self._advanced_open = False
        self.btn_advanced = ttk.Button(
            adv_row,
            text="▼  Advanced (optional)",
            style="TButton",
            command=self._toggle_advanced,
        )
        self.btn_advanced.pack(side="left")
        ttk.Label(
            adv_row,
            text="Optional — leave blank to auto-detect where possible.",
            style="Muted.TLabel",
        ).pack(side="left", padx=(10, 0))

        self.frm_advanced = ttk.Frame(card, style="Surface.TFrame")

        ttk.Label(
            self.frm_advanced,
            text=(
                "All Advanced fields are optional. Blank fields will be "
                "auto-detected from the OS where possible (gateway), or "
                "skipped cleanly (Starbox, SIP endpoint) — they will not "
                "create warnings, fake targets, or failed scans."
            ),
            style="Muted.TLabel",
            wraplength=820,
            justify="left",
        ).pack(fill="x", pady=(8, 4))

        hp = ttk.Frame(self.frm_advanced, style="Surface.TFrame")
        hp.pack(fill="x", pady=(2, 2))
        ttk.Label(hp, text="Hosted Platform:", style="Surface.TLabel").pack(side="left")
        self.var_hosted = tk.StringVar(value=HOSTED_AUTO)
        for label in HOSTED_PLATFORMS:
            ttk.Radiobutton(
                hp,
                text=label,
                value=label,
                variable=self.var_hosted,
                style="TRadiobutton",
            ).pack(side="left", padx=(10, 0))
        ttk.Label(
            self.frm_advanced,
            text=(
                "  Leave on 'Auto / unknown' to let the scanner infer "
                "context from scan data instead of forcing a platform."
            ),
            style="Muted.TLabel",
        ).pack(fill="x", pady=(0, 6))

        ips = ttk.Frame(self.frm_advanced, style="Surface.TFrame")
        ips.pack(fill="x", pady=(2, 4))
        self.var_gw = tk.StringVar()
        self.var_fw = tk.StringVar()
        self.var_sb = tk.StringVar()
        self.var_sip_endpoint = tk.StringVar()
        self._ip_field(
            ips,
            "Gateway IP:",
            self.var_gw,
            0,
            hint="auto-detected from OS routes if blank",
        )
        self._ip_field(
            ips,
            "Firewall IP:",
            self.var_fw,
            1,
            hint="leave blank if you don't have one — not assumed to equal gateway",
        )
        self._ip_field(
            ips,
            "Starbox IP:",
            self.var_sb,
            2,
            hint="leave blank to skip Starbox-specific checks cleanly",
        )
        self._ip_field(
            ips,
            "SIP test endpoint (host:port):",
            self.var_sip_endpoint,
            3,
            width=28,
            hint="leave blank to skip external SIP probes; ALG proof will be limited",
        )

        scan_row = ttk.Frame(card, style="Surface.TFrame")
        scan_row.pack(fill="x", pady=(10, 0))
        self.btn_scan_now = ttk.Button(
            scan_row,
            text="Scan Now (Advanced is optional)",
            style="Primary.TButton",
            command=self._on_scan_now,
        )
        self.btn_scan_now.pack(side="left")

    def _ip_field(
        self,
        parent: ttk.Frame,
        label: str,
        var: tk.StringVar,
        row: int,
        width: int = 22,
        hint: str = "",
    ) -> None:
        ttk.Label(parent, text=label, style="Surface.TLabel").grid(
            row=row, column=0, sticky="w", pady=2, padx=(0, 8)
        )
        ttk.Entry(parent, textvariable=var, width=width).grid(
            row=row, column=1, sticky="w", pady=2
        )
        if hint:
            ttk.Label(
                parent,
                text=f"({hint})",
                style="Muted.TLabel",
            ).grid(row=row, column=2, sticky="w", pady=2, padx=(8, 0))

    def _toggle_advanced(self) -> None:
        self._advanced_open = not self._advanced_open
        if self._advanced_open:
            self.frm_advanced.pack(fill="x", pady=(4, 0))
            self.btn_advanced.config(text="▲  Advanced (optional)")
        else:
            self.frm_advanced.forget()
            self.btn_advanced.config(text="▼  Advanced (optional)")

    # -- Results ----------------------------------------------------------
    def _build_results(self) -> None:
        card = ttk.Labelframe(
            self.root,
            text=" Scan Results / Log ",
            style="Card.TLabelframe",
            padding=10,
        )
        card.pack(fill="both", expand=True, padx=18, pady=(0, 8))
        self._results_card = card

        # Container that swaps between the streaming text and the
        # post-scan summary view.
        self.results_container = tk.Frame(card, bg=SURFACE_2, highlightthickness=1,
                                          highlightbackground=BORDER)
        self.results_container.pack(fill="both", expand=True)

        self._build_text_view()
        self._build_summary_view()
        self._show_text_view()

    def _build_text_view(self) -> None:
        self.text_view = tk.Frame(self.results_container, bg=SURFACE_2)
        self.txt_results = tk.Text(
            self.text_view,
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
        scroll = ttk.Scrollbar(self.text_view, command=self.txt_results.yview)
        scroll.pack(side="right", fill="y")
        self.txt_results.configure(yscrollcommand=scroll.set, state="disabled")

    def _build_summary_view(self) -> None:
        # Scrollable canvas containing per-section frames.
        self.summary_view = tk.Frame(self.results_container, bg=SURFACE_2)
        self.summary_canvas = tk.Canvas(
            self.summary_view, bg=SURFACE_2, highlightthickness=0
        )
        self.summary_canvas.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(
            self.summary_view, orient="vertical", command=self.summary_canvas.yview
        )
        scroll.pack(side="right", fill="y")
        self.summary_canvas.configure(yscrollcommand=scroll.set)

        self.summary_inner = tk.Frame(self.summary_canvas, bg=SURFACE_2)
        self._summary_window = self.summary_canvas.create_window(
            (0, 0), window=self.summary_inner, anchor="nw"
        )
        self.summary_inner.bind(
            "<Configure>",
            lambda e: self.summary_canvas.configure(
                scrollregion=self.summary_canvas.bbox("all")
            ),
        )
        self.summary_canvas.bind(
            "<Configure>",
            lambda e: self.summary_canvas.itemconfigure(
                self._summary_window, width=e.width
            ),
        )

    def _show_text_view(self) -> None:
        try:
            self.summary_view.pack_forget()
        except Exception:
            pass
        self.text_view.pack(fill="both", expand=True)

    def _show_summary_view(self) -> None:
        try:
            self.text_view.pack_forget()
        except Exception:
            pass
        self.summary_view.pack(fill="both", expand=True)

    def _build_footer(self) -> None:
        row = ttk.Frame(self.root, style="TFrame")
        row.pack(fill="x", padx=18, pady=(0, 16))

        self.btn_download = ttk.Button(
            row, text="Download Results", style="Secondary.TButton", command=self._on_download
        )
        self.btn_download.pack(side="left")

        self.btn_show_log = ttk.Button(
            row, text="Show Raw Log", style="TButton", command=self._show_text_view
        )
        self.btn_show_log.pack(side="left", padx=(8, 0))

        self.btn_show_summary = ttk.Button(
            row, text="Show Summary", style="TButton",
            command=lambda: self._show_summary_view() if self._last_report else None,
        )
        self.btn_show_summary.pack(side="left", padx=(8, 0))

        self.btn_clear = ttk.Button(
            row, text="Clear", style="TButton", command=self._on_clear
        )
        self.btn_clear.pack(side="right")

        self.lbl_status = ttk.Label(row, text="Idle.", style="Subheader.TLabel")
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
        # Capture button intentionally stays enabled so the user can
        # start/stop a packet capture while a scan is running.
        state = "disabled" if busy else "normal"
        for btn in (self.btn_quick, self.btn_scan_now):
            btn.configure(state=state)
        if status:
            self.lbl_status.configure(text=status)
        elif not busy:
            session = self._capture_session
            if session is not None and session.is_running:
                self.lbl_status.configure(text=f"Capturing packets ({session.engine})...")
            else:
                self.lbl_status.configure(text="Idle.")

    # -- Action handlers --------------------------------------------------
    def _on_evidence_scan(self) -> None:
        self._run_evidence(self._collect_form())

    def _on_scan_now(self) -> None:
        self._run_evidence(self._collect_form())

    def _set_capture_buttons(self, running: bool) -> None:
        """Toggle Start/Stop button enabled-state based on capture status."""
        self.btn_capture.configure(state=("disabled" if running else "normal"))
        self.btn_capture_stop.configure(state=("normal" if running else "disabled"))

    def _start_packet_capture(self) -> None:
        # Guard against double-clicks while a session is already running.
        session = self._capture_session
        if session is not None and session.is_running:
            self._enqueue("[capture] A capture is already running — Stop it first.")
            return
        try:
            session = capture.CaptureSession(on_log=self._enqueue)
            status = session.start()
        except capture.CaptureUnavailable as e:
            self._enqueue(f"[capture] {e}")
            messagebox.showinfo(__app_name__, str(e))
            return
        except Exception as e:
            log_exception("Packet capture failed to start")
            self._enqueue(f"[capture] Failed to start: {e}")
            messagebox.showerror(
                __app_name__,
                f"Packet capture could not start: {e}\n\n"
                "If this looks like a permissions issue, try running the "
                "app as Administrator. dumpcap also requires Npcap.",
            )
            return
        self._capture_session = session
        self._enqueue(f"[capture] Engine: {status.engine}. {status.detail}")
        self._set_capture_buttons(running=True)
        self.lbl_status.configure(text=f"Capturing packets ({status.engine})...")

    def _stop_packet_capture(self) -> None:
        session = self._capture_session
        if session is None:
            self._enqueue("[capture] No capture is currently running.")
            self._set_capture_buttons(running=False)
            return
        try:
            result = session.stop()
        except Exception as e:
            log_exception("Packet capture stop failed")
            self._enqueue(f"[capture] Stop error: {e}")
            result = None
        self._set_capture_buttons(running=False)
        self.lbl_status.configure(text="Idle.")
        self._capture_session = None
        if result is None:
            return
        for note in result.notes:
            self._enqueue(f"[capture] {note}")
        if result.output_files:
            files = ", ".join(p.name for p in result.output_files)
            self._enqueue(
                f"[capture] Capture stopped — saved file(s): {files} "
                f"in {result.output_files[0].parent}"
            )
            self._upload_capture(result)
        else:
            self._enqueue(
                "[capture] Capture stopped — no output file was produced. "
                "Check that the app has permission to capture packets."
            )

    def _run_evidence(self, form: FormInputs) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showinfo(__app_name__, "A scan is already running. Please wait.")
            return
        # Switch to streaming text view for the duration of the scan.
        self._show_text_view()
        self._set_busy(True, "Running evidence scan...")
        self._cancel_event = threading.Event()

        def worker() -> None:
            report: Optional[ScanReport] = None
            try:
                report = scanner.run_evidence_scan(
                    form=form,
                    on_log=self._enqueue,
                    use_nmap=True,
                    cancel_event=self._cancel_event,
                )
                report.app_version = __version__
                self._last_report = report
                self._enqueue("[scan] Saving raw log to disk...")
                log_path = self._save_raw_log(report)
                self._last_log_path = log_path
                self._enqueue(f"[scan] Log saved -> {log_path}")
                self._upload_scan(report, log_path)
                self._enqueue("[scan] Switching to plain-English summary view.")
                self.root.after(0, lambda: self._render_summary(report))
            except Exception as e:
                log_exception("Evidence scan failed")
                self._enqueue(f"[error] {e}")
                messagebox.showerror(
                    __app_name__,
                    f"Unexpected error during scan. See logs/voipscan.log.",
                )
            finally:
                self.root.after(0, lambda: self._set_busy(False))

        self._scan_thread = threading.Thread(
            target=worker, name="voipscan-evidence", daemon=True
        )
        self._scan_thread.start()

    def _collect_form(self) -> FormInputs:
        # "Auto / unknown" is the GUI default for Hosted Platform; pass it
        # through as an empty string so the scanner treats it as auto/infer
        # rather than forcing one of the explicit platform values.
        hosted = self.var_hosted.get()
        if hosted == HOSTED_AUTO:
            hosted = ""
        return FormInputs(
            problem_experienced=self.var_problem.get(),
            other_problem=self.var_other.get().strip(),
            hosted_platform=hosted,
            gateway_ip=self.var_gw.get().strip(),
            firewall_ip=self.var_fw.get().strip(),
            starbox_ip=self.var_sb.get().strip(),
            sip_test_endpoint=self.var_sip_endpoint.get().strip(),
        )

    # -- Saving / rendering ----------------------------------------------
    def _save_raw_log(self, report: ScanReport) -> Path:
        log_dir = paths.logs_dir()
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        log_path = log_dir / f"voipscan_evidence_{ts}.log"
        text = self._buffer_text()
        with log_path.open("w", encoding="utf-8") as f:
            f.write(f"{__app_name__} v{__version__}\n")
            f.write(f"Scan started: {report.started_at}\n")
            f.write(f"Scan finished: {report.finished_at}\n")
            f.write(f"Duration: {report.duration_seconds:.1f}s\n\n")
            f.write("=== STREAMING LOG ===\n")
            f.write(text)
            f.write("\n\n=== JSON REPORT ===\n")
            f.write(report.to_json())
        return log_path

    def _render_summary(self, report: ScanReport) -> None:
        # Replace the streaming view with the plain-English summary.
        self._clear_summary_inner()
        sections = interpret.build_sections(report)

        # Top header with metadata.
        meta = tk.Frame(self.summary_inner, bg=SURFACE_2, padx=14, pady=10)
        meta.pack(fill="x")
        tk.Label(
            meta,
            text="Plain-English Scan Results",
            bg=SURFACE_2,
            fg=TEXT,
            font=("Segoe UI", 14, "bold"),
            anchor="w",
        ).pack(anchor="w")
        finished = report.finished_at or "(unknown)"
        tk.Label(
            meta,
            text=f"Generated {finished} • {report.duration_seconds:.1f}s • "
                 f"v{report.app_version or __version__}",
            bg=SURFACE_2,
            fg=TEXT_MUTED,
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(anchor="w")
        if self._last_log_path is not None:
            tk.Label(
                meta,
                text=f"Raw log: {self._last_log_path}",
                bg=SURFACE_2,
                fg=TEXT_MUTED,
                font=("Segoe UI", 9),
                anchor="w",
            ).pack(anchor="w")

        ttk.Separator(self.summary_inner).pack(fill="x", padx=14, pady=(6, 0))

        for sec in sections:
            self._render_section(self.summary_inner, sec)

        self._show_summary_view()

    def _clear_summary_inner(self) -> None:
        for w in self.summary_inner.winfo_children():
            w.destroy()

    def _render_section(self, parent: tk.Frame, sec: "interpret.Section") -> None:
        color = STATUS_COLORS.get(sec.status, GREY)
        icon_text = ICONS.get(sec.key, "?")

        outer = tk.Frame(parent, bg=SURFACE_2, padx=12, pady=8)
        outer.pack(fill="x", padx=4, pady=(8, 0))

        # A row containing the colored badge canvas + the section header.
        head = tk.Frame(outer, bg=SURFACE_2)
        head.pack(fill="x")

        badge = tk.Canvas(
            head, width=44, height=44, bg=SURFACE_2, highlightthickness=0
        )
        badge.pack(side="left", padx=(0, 10))
        badge.create_oval(2, 2, 42, 42, fill=color, outline=color)
        badge.create_text(22, 22, text=icon_text, fill="#0f1115",
                          font=("Segoe UI", 16, "bold"))

        title_col = tk.Frame(head, bg=SURFACE_2)
        title_col.pack(side="left", fill="x", expand=True)
        tk.Label(
            title_col,
            text=sec.title,
            bg=SURFACE_2,
            fg=TEXT,
            font=("Segoe UI", 12, "bold"),
            anchor="w",
        ).pack(anchor="w")

        status_label = tk.Label(
            title_col,
            text=f"  {sec.status} — {sec.summary}",
            bg=SURFACE_2,
            fg=color,
            font=("Segoe UI", 10, "bold"),
            anchor="w",
            justify="left",
            wraplength=720,
        )
        status_label.pack(anchor="w")

        # Bullets
        if sec.bullets:
            body = tk.Frame(outer, bg=SURFACE_2)
            body.pack(fill="x", padx=(54, 0), pady=(4, 0))
            for line in sec.bullets:
                tk.Label(
                    body,
                    text=line,
                    bg=SURFACE_2,
                    fg=TEXT,
                    font=("Segoe UI", 10),
                    anchor="w",
                    justify="left",
                    wraplength=720,
                ).pack(anchor="w", pady=1)

        # Fixes
        if sec.fixes:
            fbox = tk.Frame(outer, bg=SURFACE_2)
            fbox.pack(fill="x", padx=(54, 0), pady=(6, 0))
            tk.Label(
                fbox,
                text="Suggested fixes",
                bg=SURFACE_2,
                fg=TEXT_MUTED,
                font=("Segoe UI", 9, "bold"),
                anchor="w",
            ).pack(anchor="w")
            for f in sec.fixes:
                tk.Label(
                    fbox,
                    text=f"• {f}",
                    bg=SURFACE_2,
                    fg=TEXT,
                    font=("Segoe UI", 10),
                    anchor="w",
                    justify="left",
                    wraplength=720,
                ).pack(anchor="w", pady=1)

        ttk.Separator(parent).pack(fill="x", padx=14, pady=(4, 0))

    # -- Download / clear -------------------------------------------------
    def _on_download(self) -> None:
        if self._last_report is None and not self._buffer_text():
            messagebox.showinfo(__app_name__, "Nothing to save yet — run a scan first.")
            return
        default = f"voipscan_report_{logger.session_id()}.json"
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=default,
            initialdir=str(paths.reports_dir()),
            filetypes=[
                ("JSON report", "*.json"),
                ("Text report", "*.txt"),
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
                f.write(f"{__app_name__} v{__version__}\n")
                f.write(f"Generated: {datetime.utcnow().isoformat()}Z\n\n")
                if self._last_report is not None:
                    f.write(interpret.render_plain_text(self._last_report))
                    f.write("\n\n=== Streaming log ===\n")
                f.write(self._buffer_text())
            return

        # JSON: full ScanReport plus a copy of the streaming log.
        if self._last_report is not None:
            payload = self._last_report.to_dict()
        else:
            payload = {}
        payload["console"] = self._buffer_text()
        payload["app"] = __app_name__
        payload["version"] = __version__
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)

    def _buffer_text(self) -> str:
        self.txt_results.configure(state="normal")
        text = self.txt_results.get("1.0", "end").rstrip()
        self.txt_results.configure(state="disabled")
        return text

    # -- VPS upload -------------------------------------------------------
    def _upload_scan(self, report: ScanReport, log_path: Optional[Path]) -> None:
        """Best-effort: send the structured scan + log to the dashboard.

        Failures never break the local scan; the user still has the JSON
        and the raw log on disk regardless of network state.
        """
        try:
            url = upload_mod.get_vps_url()
            self._enqueue(f"[upload] Sending scan report to {url} ...")
            result = upload_mod.upload_scan_session(report, log_path)
        except Exception as e:
            log_exception("upload_scan_session crashed")
            self._enqueue(f"[upload] failed: {e}")
            return
        if result.get("ok"):
            sid = result.get("session_id") or ""
            self._server_session_id = sid or None
            self._enqueue(
                f"[upload] Scan uploaded successfully (server session "
                f"{sid or '?'})."
            )
        else:
            msg = result.get("message") or result.get("server") or "upload failed"
            self._enqueue(f"[upload] Scan upload skipped/failed: {msg}")

    def _upload_capture(self, result: "capture.CaptureResult") -> None:
        try:
            url = upload_mod.get_vps_url()
            for f in result.output_files:
                self._enqueue(
                    f"[upload] Sending capture {f.name} to {url} ..."
                )
                resp = upload_mod.upload_capture_artifact(
                    f,
                    session_id=self._server_session_id,
                    engine=result.engine,
                    notes="; ".join(result.notes)[:500],
                )
                if resp.get("ok"):
                    self._enqueue(f"[upload] Capture {f.name} uploaded.")
                else:
                    self._enqueue(
                        f"[upload] Capture {f.name} not uploaded: "
                        f"{resp.get('message') or resp.get('server')}"
                    )
        except Exception as e:
            log_exception("capture upload crashed")
            self._enqueue(f"[upload] capture upload failed: {e}")

    def _on_clear(self) -> None:
        self.txt_results.configure(state="normal")
        self.txt_results.delete("1.0", "end")
        self.txt_results.configure(state="disabled")
        self._clear_summary_inner()
        self._show_text_view()


def run() -> None:
    logger.init_logging()
    root = tk.Tk()
    app = VoipScanApp(root)

    def _on_close() -> None:
        # Make sure a running packet capture is stopped cleanly so the
        # output file is finalized before the process exits.
        try:
            session = app._capture_session
            if session is not None and session.is_running:
                app._stop_packet_capture()
        except Exception:
            log_exception("Error stopping capture on close")
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", _on_close)
    root.mainloop()
