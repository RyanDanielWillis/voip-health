"""Packet-capture foundation.

Real packet capture on Windows requires Npcap (or WinPcap) to be
installed and a privileged process. We do **not** silently pretend to
capture — instead we detect what's available and surface a clear status
message. When a capture engine is present, the hook below is the place
to wire it up (e.g. shell out to ``dumpcap.exe`` or use ``pyshark``).
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from . import paths
from .logger import get_logger


@dataclass
class CaptureStatus:
    available: bool
    engine: str  # "npcap" | "wireshark" | "none"
    detail: str


def detect_capture_engine() -> CaptureStatus:
    """Best-effort detection — never raises."""
    log = get_logger()

    if not paths.is_windows():
        return CaptureStatus(
            available=False,
            engine="none",
            detail=(
                "Packet capture is only wired for Windows in this build. "
                "Run on a Windows machine with Npcap installed."
            ),
        )

    # Npcap install footprint.
    npcap_dirs = [
        Path(r"C:\\Windows\\System32\\Npcap"),
        Path(r"C:\\Program Files\\Npcap"),
    ]
    for d in npcap_dirs:
        if d.exists():
            log.info("Npcap detected at %s", d)
            return CaptureStatus(
                available=False,  # detection only — not yet wired up
                engine="npcap",
                detail=(
                    f"Npcap detected at {d}. Capture engine is recognized "
                    "but live capture is not yet enabled in this build."
                ),
            )

    dumpcap = shutil.which("dumpcap")
    if dumpcap:
        return CaptureStatus(
            available=False,
            engine="wireshark",
            detail=(
                f"Wireshark dumpcap found at {dumpcap}. Live capture is "
                "not yet enabled in this build."
            ),
        )

    return CaptureStatus(
        available=False,
        engine="none",
        detail=(
            "No packet-capture driver detected. Install Npcap "
            "(https://npcap.com/) — once present the capture button "
            "can be wired up to dumpcap.exe."
        ),
    )


def start_capture_stub() -> str:
    """Conservative stand-in for the real capture path.

    Returns a single status string for the GUI / log. Intentionally does
    nothing destructive: real capture lands here in a follow-up.
    """
    log = get_logger()
    status = detect_capture_engine()
    log.warning("Packet capture requested — %s", status.detail)
    if status.engine == "none":
        return f"[capture] {status.detail}"
    return (
        f"[capture] Engine: {status.engine}. {status.detail} "
        "Add the dumpcap/pyshark invocation in voipscan/capture.py to "
        "enable live capture."
    )
