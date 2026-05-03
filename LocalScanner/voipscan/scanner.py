"""Nmap-driven scan engine.

Two entry points are exposed:

* ``quick_scan(...)`` — fast sweep of common VoIP-relevant ports on the
  local subnet(s). Designed to finish in well under a minute.
* ``targeted_scan(...)`` — runs against operator-supplied gateway,
  firewall and Starbox IPs with a slightly deeper port set.

Commands are intentionally conservative. The lists below are the easy
knobs to tweak: change ports, add a flag, or add a new scan profile by
following the existing ``ScanProfile`` shape.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from . import paths
from .logger import get_logger, log_exception

# --- Tunable command knobs ------------------------------------------------
# Edit these to broaden / narrow scan coverage. Keep ``--unprivileged``
# unless you intend to ship the app with raw-socket privileges.

QUICK_TCP_PORTS = "22,80,443,1935,5038,5060,5061,5160,8080,8088,8089"
QUICK_UDP_PORTS = "5060,5061"

# Targeted scans probe RTP plus a wider control range.
TARGETED_TCP_PORTS = "22,80,443,1935,5038,5060,5061,5160,5222,8080,8088,8089"
TARGETED_UDP_PORTS = "5060,5061,10000-10100"

# Nmap timing template (0=paranoid .. 5=insane). 4 is safe on modern LANs.
NMAP_TIMING = "-T4"

# Subnets the quick scan walks. Edit to match your environment.
QUICK_SUBNETS = ["192.168.1.0/24", "192.168.41.0/24"]
# -------------------------------------------------------------------------


@dataclass
class ScanProfile:
    name: str
    args: list[str]
    targets: list[str] = field(default_factory=list)


class ScanError(RuntimeError):
    pass


def find_nmap() -> str | None:
    """Return a runnable nmap path or ``None`` if unavailable."""
    bundled = paths.nmap_executable()
    if bundled is not None:
        return str(bundled)
    on_path = shutil.which("nmap")
    if on_path:
        return on_path
    # Common Windows install locations.
    for cand in (
        Path(r"C:\\Program Files (x86)\\Nmap\\nmap.exe"),
        Path(r"C:\\Program Files\\Nmap\\nmap.exe"),
    ):
        if cand.exists():
            return str(cand)
    return None


def build_quick_profile() -> ScanProfile:
    args = [
        "-sT",
        "-Pn",
        "--unprivileged",
        NMAP_TIMING,
        "-p",
        f"T:{QUICK_TCP_PORTS},U:{QUICK_UDP_PORTS}",
        "--open",
    ]
    return ScanProfile(name="Quick Scan", args=args, targets=list(QUICK_SUBNETS))


def build_targeted_profile(targets: Iterable[str]) -> ScanProfile:
    args = [
        "-sT",
        "-sV",
        "-Pn",
        "--unprivileged",
        NMAP_TIMING,
        "-p",
        f"T:{TARGETED_TCP_PORTS},U:{TARGETED_UDP_PORTS}",
        "--open",
    ]
    cleaned = [t.strip() for t in targets if t and t.strip()]
    return ScanProfile(name="Targeted Scan", args=args, targets=cleaned)


def _nmap_command(profile: ScanProfile, nmap_path: str) -> list[str]:
    if not profile.targets:
        raise ScanError(f"No targets supplied for {profile.name}.")
    return [nmap_path, *profile.args, *profile.targets]


def run_profile(
    profile: ScanProfile,
    on_line: Callable[[str], None],
    cancel_event: threading.Event | None = None,
) -> dict:
    """Execute a scan profile, streaming each output line via ``on_line``.

    Returns a dict with ``profile``, ``command``, ``targets``, ``stdout``,
    ``stderr``, ``returncode``. Raises ``ScanError`` for setup problems
    (missing nmap, no targets) — runtime nmap failures are reported in
    the returned dict so the GUI can render them.
    """
    log = get_logger()
    nmap_path = find_nmap()
    if nmap_path is None:
        raise ScanError(
            "nmap.exe not found. Place a portable nmap build under "
            "LocalScanner/nmap/ or install Nmap to the system PATH."
        )

    command = _nmap_command(profile, nmap_path)
    log.info("Running %s: %s", profile.name, shlex.join(command))
    on_line(f"$ {shlex.join(command)}")

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    try:
        # Hide console windows on Windows when launched from a GUI exe.
        creationflags = 0
        if paths.is_windows():
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            creationflags=creationflags,
        )
    except FileNotFoundError as e:
        log_exception("Failed to launch nmap")
        raise ScanError(f"Could not launch nmap: {e}") from e

    try:
        assert proc.stdout is not None and proc.stderr is not None
        # Read stdout line-by-line so the GUI updates live.
        for line in proc.stdout:
            line = line.rstrip("\n")
            stdout_lines.append(line)
            on_line(line)
            if cancel_event is not None and cancel_event.is_set():
                proc.terminate()
                on_line("[scan cancelled]")
                break
        proc.wait(timeout=600)
        # Drain stderr after exit — nmap rarely emits much here.
        stderr_remainder = proc.stderr.read()
        if stderr_remainder:
            for line in stderr_remainder.splitlines():
                stderr_lines.append(line)
                on_line(f"[stderr] {line}")
    except subprocess.TimeoutExpired:
        proc.kill()
        log_exception("nmap timed out")
        on_line("[error] nmap timed out after 600s and was killed.")

    rc = proc.returncode
    log.info("%s finished rc=%s lines=%d", profile.name, rc, len(stdout_lines))
    return {
        "profile": profile.name,
        "command": command,
        "targets": profile.targets,
        "stdout": "\n".join(stdout_lines),
        "stderr": "\n".join(stderr_lines),
        "returncode": rc,
    }
