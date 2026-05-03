"""Packet capture engine.

The GUI's "Start Packet Capture" button hooks into ``CaptureSession`` here.
We try, in order:

1. **Wireshark dumpcap** — preferred. Writes a real ``.pcapng`` to
   ``captures/`` and applies a BPF filter that focuses on VoIP/SIP/RTP
   traffic without being so strict that nothing is captured.
2. **Windows pktmon** — built-in fallback. Starts a packet capture, and
   on stop converts the resulting ``.etl`` to ``.pcapng`` if the host
   supports it (pktmon 10.0.20H1+ does), otherwise emits a text dump
   alongside the raw ``.etl``.
3. **Connection-evidence fallback** — when no PCAP engine is available
   AND/OR the user is not running the app as Administrator. Gathers a
   timestamped text artifact of netstat, the route table, DNS/adapter
   config, ping snapshots and PowerShell ``Test-NetConnection`` results
   for the relevant SIP/RTP ports. Saved into ``captures/`` and uploaded
   like any other artifact. This is the workaround the operator asked
   for: useful evidence without requiring Administrator rights.

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


def is_admin() -> bool:
    """Best-effort 'is the current process Administrator?' check.

    Used by ``CaptureSession.start`` to decide whether the dumpcap /
    pktmon attempt is even worth making, and to surface a clear plain
    English message in the evidence-only fallback. Never raises.
    """
    if not paths.is_windows():
        # On Unix-like systems the GUI build doesn't capture at all, but
        # we still answer the question for completeness.
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        import ctypes  # imported lazily so non-Windows imports don't pay

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
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
        self._evidence_path: Optional[Path] = None
        self._evidence_started: Optional[datetime] = None
        self.output_files: list[Path] = []

    # -- public API ------------------------------------------------------

    @property
    def is_running(self) -> bool:
        with self._lock:
            if self._engine == "dumpcap":
                return self._proc is not None and self._proc.poll() is None
            if self._engine == "pktmon":
                return self._started_at is not None
            if self._engine == "evidence":
                return self._evidence_started is not None
            return False

    @property
    def engine(self) -> str:
        return self._engine

    def start(self) -> CaptureStatus:
        """Start the best capture engine that this host can run.

        Order:
          1. dumpcap (Wireshark) when present + Administrator.
          2. pktmon when present + Administrator.
          3. Connection-evidence fallback (no admin, always works).

        The fallback is the operator's explicit ask: full PCAP capture
        on Windows requires Administrator + Npcap, which most field
        operators won't have. The evidence fallback is non-PCAP but
        captures the most useful network state we can read without
        admin rights.
        """
        status = detect_capture_engine()
        captures = paths.captures_dir()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        admin = is_admin()
        if status.available and admin:
            try:
                if status.engine == "dumpcap":
                    self._start_dumpcap(status, captures, ts)
                elif status.engine == "pktmon":
                    self._start_pktmon(status, captures, ts)
                else:
                    raise CaptureUnavailable(status.detail)
                self._engine = status.engine
                self._tool_path = status.tool_path
                self._started_at = datetime.now()
                return status
            except CaptureUnavailable as e:
                self._on_log(
                    f"[capture] {status.engine} could not start ({e}). "
                    "Falling back to non-admin connection evidence."
                )

        # Non-admin / no-engine path: evidence capture.
        if not admin:
            self._on_log(
                "[capture] Full packet capture needs Administrator + a "
                "preinstalled capture driver (Npcap / pktmon). This "
                "process is NOT running as Administrator, so we'll "
                "collect a non-admin connection-evidence file instead."
            )
        elif not status.available:
            self._on_log(
                f"[capture] No PCAP engine detected ({status.detail}). "
                "Collecting a connection-evidence file instead."
            )
        return self._start_evidence(captures, ts)

    def stop(self) -> CaptureResult:
        if self._engine == "dumpcap":
            return self._stop_dumpcap()
        if self._engine == "pktmon":
            return self._stop_pktmon()
        if self._engine == "evidence":
            return self._stop_evidence()
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

    # -- Evidence engine (no admin required) ----------------------------

    # Ports we sample with Test-NetConnection / port-test in the
    # evidence fallback. Kept short — these are the ports that matter
    # for Sangoma SIP/RTP and HTTP provisioning.
    EVIDENCE_TCP_PORTS = (5060, 5061, 5160, 5161, 8088, 8089, 2160, 443, 80)
    EVIDENCE_HOSTS = ("199.15.180.1", "8.8.8.8")
    EVIDENCE_AUTOSTOP_SECONDS = 600  # 10 minute soft cap

    def _start_evidence(
        self, captures: Path, ts: str
    ) -> CaptureStatus:
        """Begin a non-admin evidence capture.

        We immediately snapshot the network state — netstat, route
        table, adapter config — then leave the file open for ``stop()``
        to append a final snapshot (so the operator can compare before
        and after the issue they're trying to reproduce).
        """
        self._evidence_path = captures / f"voipscan_evidence_{ts}.txt"
        self._evidence_started = datetime.now()
        self._engine = "evidence"
        self._tool_path = ""
        self.output_files = [self._evidence_path]

        header = (
            "VoIP Health Check — connection evidence (non-admin fallback)\n"
            f"Started: {self._evidence_started.isoformat()}\n"
            f"Host: {os.environ.get('COMPUTERNAME', '')}\n"
            f"User: {os.environ.get('USERNAME', '')}\n"
            "Purpose: This file is collected when full packet capture\n"
            "(Wireshark dumpcap or pktmon) is not available, usually\n"
            "because the app is not running as Administrator. It is\n"
            "NOT a packet capture — it's a textual snapshot of the\n"
            "network state useful for diagnosing VoIP connectivity.\n"
            "=" * 70 + "\n"
        )
        try:
            with self._evidence_path.open("w", encoding="utf-8") as f:
                f.write(header)
                f.write("\n--- INITIAL SNAPSHOT ---\n")
            self._append_evidence_snapshot("INITIAL")
        except Exception:
            log_exception("evidence snapshot (initial) failed")
        self._on_log(
            f"[capture] Evidence capture started -> {self._evidence_path.name}. "
            "Run a few test calls now; press Stop when finished."
        )
        return CaptureStatus(
            available=True,
            engine="evidence",
            detail=(
                "Connection-evidence mode (no Administrator rights "
                "required). Collecting netstat, routes, adapter info, "
                "ping snapshots and Test-NetConnection results. Stop "
                "when finished."
            ),
            tool_path="",
        )

    def _stop_evidence(self) -> CaptureResult:
        """Finalize the evidence file and surface it for upload."""
        notes: list[str] = []
        path = self._evidence_path
        if path is None:
            return CaptureResult(
                engine="evidence",
                notes=["evidence capture was not running"],
            )
        try:
            self._append_evidence_snapshot("FINAL")
            with path.open("a", encoding="utf-8") as f:
                f.write("\n--- END ---\n")
                f.write(f"Stopped: {datetime.now().isoformat()}\n")
        except Exception:
            log_exception("evidence snapshot (final) failed")
            notes.append("final snapshot could not be written")

        produced: list[Path] = []
        if path.exists() and path.stat().st_size > 0:
            produced.append(path)
            self._on_log(f"[capture] Saved {path}")
        else:
            notes.append(
                "evidence file is empty — nothing was readable from the "
                "OS without admin"
            )
        notes.append(
            "Non-admin evidence capture: this is NOT a packet capture. "
            "For true PCAP, install Wireshark + Npcap and run the app "
            "as Administrator."
        )
        self._engine = "none"
        self._evidence_started = None
        self.output_files = produced
        return CaptureResult(engine="evidence", output_files=produced, notes=notes)

    def _append_evidence_snapshot(self, label: str) -> None:
        path = self._evidence_path
        if path is None:
            return
        sections: list[tuple[str, list[str]]] = []
        if paths.is_windows():
            sections.append(("ipconfig /all", ["ipconfig", "/all"]))
            sections.append(("route print -4", ["route", "print", "-4"]))
            sections.append(
                ("netstat -ano (TCP+UDP, listening + active)",
                 ["netstat", "-ano"])
            )
            sections.append(("arp -a", ["arp", "-a"]))
            sections.append(("nslookup voipscan host", ["nslookup", "199.15.180.1"]))
        else:
            sections.append(("ip addr", ["ip", "addr"]))
            sections.append(("ip route", ["ip", "route"]))
            sections.append(("ss -tunap", ["ss", "-tunap"]))
            sections.append(("arp -a", ["arp", "-a"]))

        with path.open("a", encoding="utf-8") as f:
            f.write(f"\n=== {label} @ {datetime.now().isoformat()} ===\n")
            for title, cmd in sections:
                f.write(f"\n# {title}\n")
                f.write(self._safe_run(cmd))
                f.write("\n")

            # Connectivity probes — ping each anchor + Test-NetConnection
            # (Windows only) for the SIP/RTP-relevant ports. Both are
            # non-admin and always safe to run.
            f.write("\n# ping snapshots (4 packets each)\n")
            for host in self.EVIDENCE_HOSTS:
                if paths.is_windows():
                    cmd = ["ping", "-n", "4", "-w", "1000", host]
                else:
                    cmd = ["ping", "-c", "4", "-W", "1", host]
                f.write(f"\n## ping {host}\n")
                f.write(self._safe_run(cmd))

            if paths.is_windows():
                f.write("\n# PowerShell Test-NetConnection (TCP only — UDP needs other tools)\n")
                for host in self.EVIDENCE_HOSTS:
                    for port in self.EVIDENCE_TCP_PORTS:
                        ps_cmd = (
                            "powershell.exe", "-NoProfile", "-Command",
                            f"Test-NetConnection -ComputerName {host} -Port {port} "
                            "-WarningAction SilentlyContinue | "
                            "Select-Object ComputerName,RemotePort,TcpTestSucceeded,"
                            "PingSucceeded,RemoteAddress | Format-List",
                        )
                        f.write(f"\n## Test-NetConnection {host}:{port}\n")
                        f.write(self._safe_run(list(ps_cmd)))

    def _safe_run(self, cmd: list[str]) -> str:
        """Run a diagnostic command and return its combined output.

        Any failure is captured as text rather than raising — the whole
        point of evidence capture is "best effort, never blow up".
        """
        try:
            creationflags = (
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                if paths.is_windows() else 0
            )
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=creationflags,
                check=False,
            )
            out = (res.stdout or "") + (
                f"\n[stderr]\n{res.stderr}" if res.stderr else ""
            )
            return out or "(no output)"
        except FileNotFoundError as e:
            return f"[not available on this host: {e}]"
        except subprocess.TimeoutExpired:
            return "[command timed out after 30s]"
        except Exception as e:
            return f"[command failed: {e}]"

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
