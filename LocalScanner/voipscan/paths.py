"""Resource path resolution.

Works both when running from source (``python -m voipscan``) and when
frozen by PyInstaller into a one-file executable. PyInstaller unpacks
bundled data into ``sys._MEIPASS`` at runtime; we fall back to the
project layout otherwise.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _frozen_base() -> Path | None:
    # PyInstaller one-file extraction directory.
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    return None


def app_root() -> Path:
    """Directory the user actually launches from.

    For a PyInstaller exe this is the directory containing the .exe
    (so the user's adjacent ``nmap/`` and ``logs/`` folders live there).
    For source runs it's the LocalScanner directory.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resource_path(*parts: str) -> Path:
    """Locate a bundled read-only resource (logo, etc.).

    Search order:
      1. PyInstaller _MEIPASS bundle.
      2. ``LocalScanner/`` repo layout.
    """
    rel = Path(*parts)
    base = _frozen_base()
    if base is not None:
        candidate = base / rel
        if candidate.exists():
            return candidate
    return Path(__file__).resolve().parent.parent / rel


def logo_path() -> Path:
    return resource_path("assets", "logo.png")


def nmap_executable() -> Path | None:
    """Locate the bundled nmap.exe.

    Looks next to the exe (preferred for the portable distribution) and
    inside the repo's ``LocalScanner/nmap/`` directory. Returns ``None``
    if no copy is found — the caller decides whether to fall back to the
    system PATH.
    """
    candidates: list[Path] = []
    root = app_root()
    candidates.append(root / "nmap" / "nmap.exe")
    candidates.append(root / "Nmap" / "nmap.exe")
    # Source layout fallback.
    candidates.append(Path(__file__).resolve().parent.parent / "nmap" / "nmap.exe")

    for path in candidates:
        if path.exists():
            return path
    return None


def logs_dir() -> Path:
    """Local logs directory next to the exe / source. Created on first use."""
    path = app_root() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def reports_dir() -> Path:
    path = app_root() / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def is_windows() -> bool:
    return os.name == "nt"
