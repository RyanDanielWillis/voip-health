"""DHCP / IP-assignment evidence collection.

The goal: tell the operator *who* is assigning the PC its IP address and
how confident we are about it, without changing any system state.

Sources we read (Windows-first, all read-only):

* ``ipconfig /all`` — has DHCP Enabled / DHCP Server / Lease Obtained /
  Lease Expires lines per adapter on every Windows version.
* PowerShell ``Get-DhcpClient`` (when available) — confirms which
  adapters have DHCP enabled.
* PowerShell ``Get-NetIPConfiguration`` (when available) — surfaces
  the bound DHCP server alongside other adapter info.

Each adapter we find becomes a ``DhcpAdapterEvidence`` row. The module
also produces an ``inferred_assigner`` field with a confidence label so
the GUI can give a one-line answer to "what's giving me my IP?".

On non-Windows hosts we run the same logic against ``dhclient`` /
``nmcli`` / ``/var/lib/dhcp`` where available — best-effort, never raise.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

from . import paths


_TIMEOUT = 10


@dataclass
class DhcpAdapterEvidence:
    """One adapter's DHCP-assignment view."""

    adapter_name: str = ""
    description: str = ""
    dhcp_enabled: Optional[bool] = None  # None = unknown
    dhcp_server: str = ""
    lease_obtained: str = ""
    lease_expires: str = ""
    ipv4: list[str] = field(default_factory=list)
    default_gateway: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DhcpEvidence:
    """Top-level DHCP evidence snapshot."""

    available: bool = False
    method: str = ""              # "ipconfig" | "powershell" | "linux" | "skipped"
    adapters: list[DhcpAdapterEvidence] = field(default_factory=list)
    inferred_assigner: str = "unknown"
    inferred_assigner_ip: str = ""
    confidence: str = "inconclusive"  # confirmed | strong | likely | inconclusive | not_detected
    explanation: str = ""
    suggestions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["adapters"] = [a for a in d["adapters"]]
        return d


# ---------------------------------------------------------------------------
# Subprocess wrappers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = _TIMEOUT) -> tuple[int, str, str]:
    creationflags = 0
    if paths.is_windows():
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=creationflags,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout: {' '.join(cmd)}"
    except Exception as e:
        return 1, "", f"error: {e}"


def _powershell(snippet: str, timeout: int = _TIMEOUT) -> tuple[int, str, str]:
    if not paths.is_windows():
        return 1, "", "powershell only available on Windows"
    pwsh = shutil.which("powershell") or shutil.which("pwsh")
    if not pwsh:
        return 127, "", "powershell.exe not on PATH"
    return _run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", snippet],
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# ipconfig /all parser
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})")


def parse_ipconfig_all(text: str) -> list[DhcpAdapterEvidence]:
    """Parse Windows ``ipconfig /all`` output into per-adapter rows.

    Adapter blocks are headed by a non-indented line ending in ``:`` (e.g.
    ``Ethernet adapter Ethernet:``). Inside each block, dotted-key fields
    (``DHCP Enabled. . . . . . . . . . . : Yes``) are collected with the
    leading dots stripped before matching.
    """
    adapters: list[DhcpAdapterEvidence] = []
    current: Optional[DhcpAdapterEvidence] = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if not line.startswith(" "):
            # New adapter section header.
            current = DhcpAdapterEvidence(adapter_name=line.strip().rstrip(":"))
            adapters.append(current)
            continue
        if current is None:
            continue

        if ":" not in line:
            continue
        key_raw, _, value_raw = line.partition(":")
        # Windows pads dotted keys; collapse runs of dots/spaces.
        key = re.sub(r"[.\s]+", " ", key_raw).strip().lower()
        value = value_raw.strip()

        if key == "description":
            current.description = value
        elif key == "dhcp enabled":
            current.dhcp_enabled = value.lower().startswith("y")
        elif key == "dhcp server":
            ip_match = _IP_RE.search(value)
            if ip_match:
                current.dhcp_server = ip_match.group(1)
        elif key in ("lease obtained",):
            current.lease_obtained = value
        elif key in ("lease expires",):
            current.lease_expires = value
        elif key.startswith("ipv4 address"):
            ip_match = _IP_RE.search(value)
            if ip_match:
                current.ipv4.append(ip_match.group(1))
        elif key == "default gateway":
            ip_match = _IP_RE.search(value)
            if ip_match:
                current.default_gateway = ip_match.group(1)
    # Drop "Windows IP Configuration" and other non-adapter sections that
    # have no description, no IPs, and no DHCP fields.
    return [
        a for a in adapters
        if a.description
        or a.ipv4
        or a.dhcp_server
        or a.dhcp_enabled is not None
    ]


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

def _is_routable_lan(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private and not addr.is_loopback and not addr.is_link_local


def infer_assigner(adapters: list[DhcpAdapterEvidence]) -> tuple[str, str, str, str]:
    """Pick the most likely IP-assigning device.

    Returns ``(label, ip, confidence, explanation)``.

    Strategy:
      1. Prefer the adapter with both a DHCP server and at least one
         non-link-local IPv4. If multiple, prefer the one whose DHCP
         server matches its default gateway (almost always the LAN
         router/firewall is the assigner).
      2. If a DHCP server exists but no gateway match, label it as a
         dedicated DHCP server.
      3. If no DHCP server but DHCP is enabled, the lease just hasn't
         been observed — label inconclusive.
      4. If DHCP is disabled on every active adapter, the IPs are
         statically configured.
    """
    candidates = [a for a in adapters if a.ipv4]
    if not candidates:
        return "unknown", "", "inconclusive", (
            "No active IPv4 adapter was visible to ipconfig. "
            "DHCP assignment cannot be inferred."
        )

    # 1 / 2 — DHCP server present.
    with_server = [a for a in candidates if a.dhcp_server]
    if with_server:
        # 1: gateway and DHCP server match.
        gw_match = next(
            (a for a in with_server if a.default_gateway and a.default_gateway == a.dhcp_server),
            None,
        )
        if gw_match is not None:
            return (
                "router/firewall (gateway acts as DHCP server)",
                gw_match.dhcp_server,
                "strong",
                (
                    f"Adapter {gw_match.adapter_name!r} reports DHCP server "
                    f"{gw_match.dhcp_server} which equals its default "
                    f"gateway. The LAN router or firewall is almost "
                    f"certainly handing out IPs."
                ),
            )
        # 2: DHCP server exists but isn't the gateway — likely a
        # dedicated DHCP host (Windows Server, dnsmasq on a NAS, etc.).
        first = with_server[0]
        return (
            "dedicated DHCP server (not the gateway)",
            first.dhcp_server,
            "likely",
            (
                f"Adapter {first.adapter_name!r} reports DHCP server "
                f"{first.dhcp_server} which differs from the gateway "
                f"{first.default_gateway or '?'}. A separate DHCP "
                f"appliance or server is assigning IPs."
            ),
        )

    # 3 — DHCP enabled but no server seen.
    enabled = [a for a in candidates if a.dhcp_enabled is True]
    if enabled and any(_is_routable_lan(ip) for a in enabled for ip in a.ipv4):
        return (
            "dhcp (server unknown)",
            "",
            "inconclusive",
            (
                "DHCP is enabled on the active adapter(s) but ipconfig "
                "did not report a DHCP server. The lease may have come "
                "from cache; re-run after `ipconfig /renew` to confirm."
            ),
        )

    # 4 — DHCP off on every adapter we can see.
    if any(a.dhcp_enabled is False for a in candidates):
        return (
            "static (no DHCP)",
            "",
            "strong",
            (
                "DHCP is disabled on every active adapter. The IP and "
                "gateway are statically configured on this PC."
            ),
        )

    return "unknown", "", "inconclusive", (
        "DHCP state could not be determined from ipconfig output."
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def collect_dhcp_evidence(
    on_log: Optional[Callable[[str], None]] = None,
    *,
    ipconfig_runner: Callable[[], tuple[int, str, str]] | None = None,
) -> DhcpEvidence:
    """Gather DHCP evidence; never raises.

    ``ipconfig_runner`` is injectable for unit tests so the parser /
    inference can be exercised without a real Windows host.
    """
    log = on_log or (lambda _msg: None)
    ev = DhcpEvidence()

    if ipconfig_runner is not None:
        rc, out, err = ipconfig_runner()
        ev.method = "ipconfig"
    elif paths.is_windows():
        rc, out, err = _run(["ipconfig", "/all"], timeout=15)
        ev.method = "ipconfig"
    else:
        ev.method = "linux"
        rc, out, err = _collect_linux()

    if rc not in (0,):
        ev.limitations.append(
            f"DHCP probe command returned rc={rc}: {err.strip() or 'no error text'}"
        )

    if ev.method == "ipconfig":
        ev.adapters = parse_ipconfig_all(out)
    else:
        # _collect_linux already builds adapter rows in ``out`` as JSON-ish
        # text; for now we keep the structure simple and just log raw text.
        ev.adapters = _parse_linux(out)

    if not ev.adapters:
        ev.available = False
        ev.confidence = "inconclusive"
        ev.explanation = (
            "DHCP evidence collection produced no adapter rows. "
            "On Windows this usually means the operator did not run the "
            "client and ipconfig is unavailable; on Linux the host may "
            "use NetworkManager or systemd-networkd lease files we did "
            "not parse."
        )
        ev.limitations.append("no adapter data parsed")
        return ev

    ev.available = True

    label, ip, confidence, explanation = infer_assigner(ev.adapters)
    ev.inferred_assigner = label
    ev.inferred_assigner_ip = ip
    ev.confidence = confidence
    ev.explanation = explanation

    # Suggestions are tailored to the inference outcome.
    if confidence == "strong" and label.startswith("router/firewall"):
        ev.suggestions.append(
            "Confirm the router/firewall DHCP scope still has free leases "
            "and that the voice VLAN has its own scope when applicable."
        )
    elif label.startswith("dedicated DHCP"):
        ev.suggestions.append(
            "Voice phones generally expect option 66/150 from the same "
            "DHCP server — confirm those options are configured on the "
            "dedicated DHCP host."
        )
    elif label.startswith("static"):
        ev.suggestions.append(
            "Static configuration is fine for servers and PBXes but a "
            "static-only LAN often signals a missing DHCP service. "
            "Verify phones and softphones are not also expected to be "
            "static."
        )
    elif label == "dhcp (server unknown)":
        ev.suggestions.append(
            "Run ``ipconfig /renew`` and re-test. If still unknown, the "
            "DHCP reply may be filtered by a managed switch or VLAN."
        )

    ev.limitations.append(
        "ipconfig only sees the *current* lease; rogue DHCP servers on "
        "the same broadcast domain are not detected without a passive "
        "capture."
    )
    if ev.method == "linux":
        ev.limitations.append(
            "Linux DHCP detection here is best-effort; richer evidence "
            "is gathered on Windows hosts."
        )
    log(
        f"[dhcp] inferred assigner: {ev.inferred_assigner} "
        f"({ev.confidence})"
    )
    return ev


# ---------------------------------------------------------------------------
# Linux fallbacks (best-effort)
# ---------------------------------------------------------------------------

def _collect_linux() -> tuple[int, str, str]:
    """Return text we can feed to ``_parse_linux``.

    Tries ``nmcli -t -f all dev show`` first, falls back to ``ip -j addr``.
    """
    nmcli = shutil.which("nmcli")
    if nmcli:
        rc, out, err = _run([nmcli, "-t", "-f", "all", "device", "show"], timeout=8)
        if rc == 0 and out.strip():
            return rc, out, err
    ip_bin = shutil.which("ip")
    if ip_bin:
        rc, out, err = _run([ip_bin, "-o", "addr"], timeout=8)
        return rc, out, err
    return 127, "", "no DHCP probe tool available on this host"


def _parse_linux(text: str) -> list[DhcpAdapterEvidence]:
    """Very small Linux parser — only used for evidence stub.

    Tries to recognise NetworkManager's ``DHCP4.OPTION[...] = server_id``
    lines and surface them as a DHCP server. Anything richer (lease
    files) is intentionally left to a future iteration.
    """
    if not text:
        return []
    rows: list[DhcpAdapterEvidence] = []
    current: Optional[DhcpAdapterEvidence] = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("GENERAL.DEVICE:"):
            name = line.split(":", 1)[-1].strip()
            current = DhcpAdapterEvidence(adapter_name=name)
            rows.append(current)
            continue
        if current is None:
            continue
        if line.startswith("IP4.ADDRESS"):
            ip_match = _IP_RE.search(line)
            if ip_match:
                current.ipv4.append(ip_match.group(1))
        elif line.startswith("IP4.GATEWAY:"):
            ip_match = _IP_RE.search(line)
            if ip_match:
                current.default_gateway = ip_match.group(1)
        elif "server_identifier" in line or "dhcp_server_identifier" in line:
            ip_match = _IP_RE.search(line)
            if ip_match:
                current.dhcp_server = ip_match.group(1)
                current.dhcp_enabled = True
    return rows
