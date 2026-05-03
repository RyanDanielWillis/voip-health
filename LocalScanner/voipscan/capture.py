"""Packet capture engine.

The GUI's "Start Packet Capture" button hooks into ``CaptureSession`` here.
We support two engines on Windows, picked in this order:

1. **Wireshark dumpcap** — preferred. Writes a real ``.pcapng`` to
   ``captures/`` and applies a BPF filter that focuses on VoIP/SIP/RTP
   traffic without being so strict that nothing is captured.
2. **Windows pktmon** — built-in fallback. Starts a packet capture, and
   on stop converts the resulting ``.etl`` to ``.pcapng`` if the host
   supports it (pktmon 10.0.20H1+ does), otherwise emits a text dump
   alongside the raw ``.etl``.

If neither tool is available, ``CaptureSession.start()`` raises
``CaptureUnavailable`` and the GUI surfaces the install instructions.

All paths and the BPF filter are defined as module-level constants so
they can be tweaked without restructuring the file.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from . import paths
from .logger import get_logger, log_exception


# --- Tunables -------------------------------------------------------------

# BPF filter applied when dumpcap is the engine. Kept loose enough that we
# still catch traffic on non-default ports, but selective enough that the
# capture file stays manageable on a busy network.
DUMPCAP_BPF_FILTER = (
    "udp port 5060 or udp port 5061 or "
    "tcp port 5060 or tcp port 5061 or "
    "tcp port 5160 or tcp port 5161 or "
    "tcp port 8088 or tcp port 8089 or "
    "tcp port 2160 or "
    "(udp portrange 10000-20000)"
)

# Soft cap on capture duration as a safety net. The user can stop earlier;
# this just prevents the capture from running forever if the user closes
# the app without stopping.
DUMPCAP_AUTOSTOP_SECONDS = 1800  # 30 minutes
DUMPCAP_AUTOSTOP_MEGABYTES = 200

PKTMON_AUTOSTOP_SECONDS = 600  # pktmon defaults to a circular buffer; bound it.


# --- Status dataclass -----------------------------------------------------

@dataclass
class CaptureStatus:
    available: bool
    engine: str  # "dumpcap" | "pktmon" | "none"
    detail: str
    tool_path: str = ""


@dataclass
class CaptureResult:
    engine: str
    output_files: list[Path] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class CaptureUnavailable(RuntimeError):
    """Raised when no packet capture engine is usable on this host."""


# --- Engine detection -----------------------------------------------------

def _find_dumpcap() -> Optional[Path]:
    """Locate dumpcap.exe (ships with Wireshark)."""
    on_path = shutil.which("dumpcap")
    if on_path:
        return Path(on_path)
    if not paths.is_windows():
        return None
    candidates = [
        Path(r"C:\Program Files\Wireshark\dumpcap.exe"),
        Path(r"C:\Program Files (x86)\Wireshark\dumpcap.exe"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _find_pktmon() -> Optional[Path]:
    """Locate pktmon.exe (built-in on Windows 10 1809+)."""
    on_path = shutil.which("pktmon")
    if on_path:
        return Path(on_path)
    if not paths.is_windows():
        return None
    candidate = Path(r"C:\Windows\System32\pktmon.exe")
    if candidate.exists():
        return candidate
    return None


def _has_npcap() -> bool:
    """Best-effort Npcap presence check — required for dumpcap to actually
    capture on Windows."""
    if not paths.is_windows():
        return False
    for d in (
        Path(r"C:\Windows\System32\Npcap"),
        Path(r"C:\Program Files\Npcap"),
    ):
        if d.exists():
            return True
    return False


def detect_capture_engine() -> CaptureStatus:
    """Pick the best available capture engine. Never raises."""
    log = get_logger()

    dumpcap = _find_dumpcap()
    if dumpcap is not None:
        # Even if dumpcap is found we still note the Npcap dependency for
        # Windows operators, since dumpcap relies on it for live capture.
        npcap_note = ""
        if paths.is_windows() and not _has_npcap():
            npcap_note = (
                " Note: Npcap was not detected. Install Npcap "
                "(https://npcap.com/) so dumpcap can attach to interfaces."
            )
        return CaptureStatus(
            available=True,
            engine="dumpcap",
            detail=f"Wireshark dumpcap found at {dumpcap}.{npcap_note}",
            tool_path=str(dumpcap),
        )

    pktmon = _find_pktmon()
    if pktmon is not None:
        return CaptureStatus(
            available=True,
            engine="pktmon",
            detail=(
                f"Using built-in Windows pktmon at {pktmon}. "
                "Capture must be started from an Administrator shell — "
                "if pktmon refuses to start, re-run the app as Administrator."
            ),
            tool_path=str(pktmon),
        )

    if paths.is_windows():
        detail = (
            "No packet capture tool detected. Install Wireshark "
            "(https://www.wireshark.org/, includes dumpcap.exe and Npcap) "
            "or use the built-in Windows pktmon (Win10 1809+) as a fallback."
        )
    else:
        detail = (
            "Packet capture is wired for Windows in this build. "
            "On non-Windows hosts, install Wireshark/dumpcap to enable it."
        )
    log.info("No capture engine detected: %s", detail)
    return CaptureStatus(available=False, engine="none", detail=detail)


# --- Capture session ------------------------------------------------------

class CaptureSession:
    """Manages a single packet capture run.

    Use ``start()`` to begin the capture, ``stop()`` to end it (or wait
    for the soft auto-stop). The session exposes ``is_running`` and
    ``output_files`` for the GUI to surface.
    """

    def __init__(self, on_log: Callable[[str], None]) -> None:
        self._on_log = on_log
        self._log = get_logger()
        self._proc: Optional[subprocess.Popen[str]] = None
        self._engine: str = "none"
        self._tool_path: str = ""
        self._started_at: Optional[datetime] = None
        self._lock = threading.Lock()
        self._reader_thread: Optional[threading.Thread] = None
        self._pktmon_etl: Optional[Path] = None
        self._pktmon_pcapng: Optional[Path] = None
        self._pktmon_text: Optional[Path] = None
        self.output_files: list[Path] = []

    # -- public API ------------------------------------------------------

    @property
    def is_running(self) -> bool:
        with self._lock:
            if self._engine == "dumpcap":
                return self._proc is not None and self._proc.poll() is None
            if self._engine == "pktmon":
                return self._started_at is not None
            return False

    @property
    def engine(self) -> str:
        return self._engine

    def start(self) -> CaptureStatus:
        status = detect_capture_engine()
        if not status.available:
            raise CaptureUnavailable(status.detail)

        captures = paths.captures_dir()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if status.engine == "dumpcap":
            self._start_dumpcap(status, captures, ts)
        elif status.engine == "pktmon":
            self._start_pktmon(status, captures, ts)
        else:  # pragma: no cover — detect_capture_engine guards this
            raise CaptureUnavailable(status.detail)
        self._engine = status.engine
        self._tool_path = status.tool_path
        self._started_at = datetime.now()
        return status

    def stop(self) -> CaptureResult:
        if self._engine == "dumpcap":
            return self._stop_dumpcap()
        if self._engine == "pktmon":
            return self._stop_pktmon()
        return CaptureResult(engine="none", notes=["No capture was running."])

    # -- dumpcap engine --------------------------------------------------

    def _start_dumpcap(
        self, status: CaptureStatus, captures: Path, ts: str
    ) -> None:
        out_path = captures / f"voipscan_capture_{ts}.pcapng"
        cmd = [
            status.tool_path,
            "-w", str(out_path),
            "-f", DUMPCAP_BPF_FILTER,
            "-a", f"duration:{DUMPCAP_AUTOSTOP_SECONDS}",
            "-a", f"filesize:{DUMPCAP_AUTOSTOP_MEGABYTES * 1024}",  # KB
            "-q",  # quiet (no per-packet count spam)
        ]
        self._on_log(
            f"[capture] Starting dumpcap -> {out_path.name} "
            f"(filter: {DUMPCAP_BPF_FILTER})"
        )
        self._log.info("dumpcap command: %s", " ".join(cmd))
        try:
            creationflags = 0
            if paths.is_windows():
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=creationflags,
            )
        except FileNotFoundError as e:
            raise CaptureUnavailable(f"Could not launch dumpcap: {e}") from e
        except PermissionError as e:
            raise CaptureUnavailable(
                "dumpcap could not be started — this usually means Npcap "
                "is missing or the app is not running with sufficient "
                "privileges. Install Npcap or run as Administrator."
            ) from e

        self._proc = proc
        self.output_files = [out_path]

        # Stream dumpcap stderr/stdout into the GUI/logs so the user sees
        # if it actually started capturing or hit a permission error.
        def reader() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip("\n")
                if not line:
                    continue
                self._on_log(f"[capture] {line}")
            rc = proc.wait()
            self._on_log(f"[capture] dumpcap exited rc={rc}")

        self._reader_thread = threading.Thread(
            target=reader, name="voipscan-capture-reader", daemon=True
        )
        self._reader_thread.start()

    def _stop_dumpcap(self) -> CaptureResult:
        proc = self._proc
        if proc is None:
            return CaptureResult(engine="dumpcap", notes=["dumpcap was not running."])
        if proc.poll() is None:
            self._on_log("[capture] Stopping dumpcap...")
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._log.warning("dumpcap did not exit on terminate; killing.")
                proc.kill()
                proc.wait(timeout=5)
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=5)
        notes: list[str] = []
        out_files = [p for p in self.output_files if p.exists() and p.stat().st_size > 0]
        if not out_files:
            notes.append(
                "Capture file is empty or missing — dumpcap may have failed "
                "to attach to an interface. Verify Npcap is installed and "
                "try running the app as Administrator."
            )
        else:
            for p in out_files:
                self._on_log(f"[capture] Saved {p}")
        self._engine = "none"
        self._proc = None
        return CaptureResult(engine="dumpcap", output_files=out_files, notes=notes)

    # -- pktmon engine ---------------------------------------------------

    def _start_pktmon(
        self, status: CaptureStatus, captures: Path, ts: str
    ) -> None:
        # pktmon doesn't expose BPF filters; instead we install per-port
        # filters before starting the capture. The set is cleared first so
        # we don't accumulate filters across runs.
        self._pktmon_etl = captures / f"voipscan_capture_{ts}.etl"
        self._pktmon_pcapng = captures / f"voipscan_capture_{ts}.pcapng"
        self._pktmon_text = captures / f"voipscan_capture_{ts}.txt"

        self._on_log("[capture] Configuring pktmon filters (SIP/RTP ports)...")
        try:
            self._run_pktmon([status.tool_path, "filter", "remove"])
            for port in (5060, 5061, 5160, 5161, 8088, 8089, 2160):
                self._run_pktmon(
                    [status.tool_path, "filter", "add", "-p", str(port)]
                )
        except subprocess.CalledProcessError as e:
            raise CaptureUnavailable(
                f"pktmon refused to install filters (rc={e.returncode}). "
                "This usually means the app is not running as Administrator."
            ) from e

        cmd = [
            status.tool_path,
            "start",
            "--capture",
            "--file-name", str(self._pktmon_etl),
            "--file-size", "200",  # MB cap on the rolling buffer
        ]
        self._on_log(f"[capture] Starting pktmon -> {self._pktmon_etl.name}")
        self._log.info("pktmon command: %s", " ".join(cmd))
        try:
            self._run_pktmon(cmd)
        except subprocess.CalledProcessError as e:
            raise CaptureUnavailable(
                f"pktmon failed to start (rc={e.returncode}). "
                "Run the app as Administrator and retry."
            ) from e
        self.output_files = [self._pktmon_etl]

    def _stop_pktmon(self) -> CaptureResult:
        notes: list[str] = []
        produced: list[Path] = []
        tool = self._tool_path
        self._on_log("[capture] Stopping pktmon...")
        try:
            self._run_pktmon([tool, "stop"])
        except subprocess.CalledProcessError as e:
            notes.append(f"pktmon stop returned rc={e.returncode}")

        etl = self._pktmon_etl
        if etl is not None and etl.exists():
            produced.append(etl)
            # Try pcapng conversion first (Win11 / recent pktmon).
            try:
                self._run_pktmon(
                    [tool, "etl2pcap", str(etl), "-o", str(self._pktmon_pcapng)]
                )
                if self._pktmon_pcapng and self._pktmon_pcapng.exists():
                    produced.append(self._pktmon_pcapng)
                    self._on_log(f"[capture] Converted to {self._pktmon_pcapng.name}")
            except (subprocess.CalledProcessError, FileNotFoundError):
                notes.append(
                    "pktmon etl2pcap is unavailable on this build of Windows. "
                    "Falling back to a text dump alongside the raw .etl."
                )
                try:
                    text_path = self._pktmon_text
                    assert text_path is not None
                    with text_path.open("w", encoding="utf-8") as f:
                        subprocess.run(
                            [tool, "format", str(etl)],
                            stdout=f,
                            stderr=subprocess.STDOUT,
                            check=False,
                            creationflags=getattr(
                                subprocess, "CREATE_NO_WINDOW", 0
                            ) if paths.is_windows() else 0,
                        )
                    if text_path.exists() and text_path.stat().st_size > 0:
                        produced.append(text_path)
                        self._on_log(f"[capture] Wrote text dump {text_path.name}")
                except Exception:
                    log_exception("pktmon format failed")
        else:
            notes.append(
                "pktmon ETL file was not produced — the capture may have "
                "failed to start. Confirm the app is running as Administrator."
            )

        for p in produced:
            self._on_log(f"[capture] Saved {p}")
        self.output_files = produced
        self._engine = "none"
        self._started_at = None
        return CaptureResult(engine="pktmon", output_files=produced, notes=notes)

    def _run_pktmon(self, cmd: list[str]) -> None:
        creationflags = 0
        if paths.is_windows():
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            creationflags=creationflags,
        )
        out = (result.stdout or "").strip()
        if out:
            for line in out.splitlines():
                self._on_log(f"[capture] {line}")


# --- Backwards-compatible helpers ----------------------------------------

def start_capture_stub() -> str:
    """Legacy helper retained for compatibility.

    Returns a status string so any caller still using the old API gets
    something useful instead of crashing.
    """
    status = detect_capture_engine()
    if status.available:
        return (
            f"[capture] Capture engine ready: {status.engine}. "
            "Use the GUI to start/stop capture."
        )
    return f"[capture] {status.detail}"
