"""Local-network discovery helpers.

Best-effort, never-raise functions that gather host / interface /
gateway / DNS info. Each helper is independent so the scanner can call
whichever it needs and still produce a partial report when something
fails (no admin rights, missing PowerShell module, etc.).

The Windows commands used here are intentionally common: ``ipconfig``,
``route``, ``arp``, ``getmac``, ``Get-NetAdapter``, ``Get-DnsClientServerAddress``.
On non-Windows we fall back to ``ip``, ``ifconfig``, ``netstat`` etc.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
from typing import Optional

from . import paths
from .logger import get_logger
from .report import GatewayInfo, NetworkInterface


_TIMEOUT = 8


def _run(cmd: list[str], timeout: int = _TIMEOUT) -> tuple[int, str, str]:
    """Run a command and return (rc, stdout, stderr). Never raises."""
    try:
        creationflags = 0
        if paths.is_windows():
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
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
    except Exception as e:  # last-ditch
        return 1, "", f"error: {e}"


def _powershell(snippet: str, timeout: int = _TIMEOUT) -> tuple[int, str, str]:
    """Run a one-liner via powershell.exe (Windows only)."""
    if not paths.is_windows():
        return 1, "", "powershell only available on Windows"
    pwsh = shutil.which("powershell") or shutil.which("pwsh")
    if not pwsh:
        return 127, "", "powershell.exe not on PATH"
    return _run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", snippet],
        timeout=timeout,
    )


# ---- Local IPs / hostname ------------------------------------------------

def local_ipv4_addresses() -> list[str]:
    """All IPv4 addresses reachable on the host (best-effort)."""
    out: list[str] = []
    try:
        host = socket.gethostname()
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            if fam == socket.AF_INET:
                ip = sockaddr[0]
                if ip and ip not in out:
                    out.append(ip)
    except Exception:
        pass
    # Also discover via UDP-connect trick (no packets sent):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("203.0.113.1", 1))  # TEST-NET; never routed
            ip = s.getsockname()[0]
            if ip and ip not in out:
                out.append(ip)
        finally:
            s.close()
    except Exception:
        pass
    return out


# ---- Default gateway -----------------------------------------------------

_GATEWAY_RE_WIN = re.compile(
    r"Default Gateway[ .]*:\s*([0-9.]+)", re.IGNORECASE
)
_GATEWAY_RE_NIX = re.compile(r"default via ([0-9.]+)")


def detect_default_gateway() -> str:
    """Return the IPv4 default gateway as a string, or '' if unknown."""
    log = get_logger()
    if paths.is_windows():
        rc, out, _ = _run(["ipconfig"])
        if rc == 0:
            for m in _GATEWAY_RE_WIN.finditer(out):
                gw = m.group(1).strip()
                if gw and gw != "0.0.0.0":
                    return gw
        # ``route print 0.0.0.0`` fallback
        rc, out, _ = _run(["route", "print", "0.0.0.0"])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                # Active Routes lines look like:
                #   0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.50  25
                if len(parts) >= 3 and parts[0] == "0.0.0.0":
                    candidate = parts[2]
                    try:
                        ipaddress.ip_address(candidate)
                        return candidate
                    except Exception:
                        continue
    else:
        rc, out, _ = _run(["ip", "route"])
        if rc == 0:
            m = _GATEWAY_RE_NIX.search(out)
            if m:
                return m.group(1)
        rc, out, _ = _run(["netstat", "-rn"])
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("default") or line.startswith("0.0.0.0"):
                    parts = line.split()
                    for p in parts[1:]:
                        try:
                            ipaddress.ip_address(p)
                            return p
                        except Exception:
                            continue
    log.info("Could not determine default gateway.")
    return ""


# ---- Gateway MAC + vendor (via ARP) --------------------------------------

def arp_lookup(ip: str) -> tuple[str, str]:
    """Return (mac, vendor_hint). Vendor hint is best-effort."""
    if not ip:
        return "", ""
    if paths.is_windows():
        rc, out, _ = _run(["arp", "-a", ip])
    else:
        rc, out, _ = _run(["arp", "-n", ip])
    if rc != 0:
        return "", ""
    mac = ""
    for line in out.splitlines():
        if ip in line:
            for tok in line.split():
                if re.fullmatch(r"[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}", tok):
                    mac = tok.replace("-", ":").lower()
                    break
            if mac:
                break
    vendor = mac_vendor_hint(mac) if mac else ""
    return mac, vendor


# Tiny static OUI hint table — covers gateways most likely to terminate
# voice traffic. Real OUI lookup needs the IEEE registry; we deliberately
# stay offline.
_OUI_HINTS = {
    "001f9f": "Cisco",
    "00d0d3": "Cisco",
    "001d7e": "Cisco-Linksys",
    "00264a": "Apple",
    "f4f5d8": "Google",
    "002522": "Sonicwall",
    "f8d111": "Sonicwall",
    "00177c": "Fortinet",
    "905f8d": "Fortinet",
    "0017a4": "Fortinet",
    "001b21": "Intel",
    "0050c2": "IEEE/Watchguard",
    "00d05a": "WatchGuard",
    "f04ba7": "Sangoma",
    "001ba1": "Sangoma",
    "00115b": "Elitegroup",
    "001cf0": "Linksys",
    "001a2b": "Cisco-Linksys",
    "78d294": "TP-Link",
    "ac84c6": "TP-Link",
    "002608": "Apple",
    "001de1": "Netgear",
    "20e52a": "Netgear",
    "f02f74": "Pace/AT&T",
    "001eaa": "Mitel",
    "0020a6": "Proxim",
    "002710": "Polycom",
    "0004f2": "Polycom",
    "001049": "Yealink",
    "805e0c": "Yealink",
    "001565": "Yealink",
    "5cf9dd": "Dell",
}


def mac_vendor_hint(mac: str) -> str:
    if not mac:
        return ""
    mac_clean = mac.replace(":", "").replace("-", "").lower()
    if len(mac_clean) < 6:
        return ""
    return _OUI_HINTS.get(mac_clean[:6], "")


# ---- DNS servers ---------------------------------------------------------

def detect_dns_servers() -> list[str]:
    found: list[str] = []
    if paths.is_windows():
        rc, out, _ = _powershell(
            "Get-DnsClientServerAddress -AddressFamily IPv4 | "
            "Select-Object -ExpandProperty ServerAddresses"
        )
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ipaddress.ip_address(line)
                    if line not in found:
                        found.append(line)
                except Exception:
                    continue
        if not found:
            rc, out, _ = _run(["ipconfig", "/all"])
            if rc == 0:
                for m in re.finditer(
                    r"DNS Servers[ .]*:\s*([0-9.]+)", out
                ):
                    ip = m.group(1)
                    if ip and ip not in found:
                        found.append(ip)
    else:
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            found.append(parts[1])
        except Exception:
            pass
    return found


# ---- Network interfaces --------------------------------------------------

def list_interfaces() -> list[NetworkInterface]:
    """Enumerate adapters. Windows preferred; falls back to a minimal view."""
    if paths.is_windows():
        return _list_interfaces_windows()
    return _list_interfaces_unix()


def _list_interfaces_windows() -> list[NetworkInterface]:
    snippet = (
        "Get-NetAdapter | ForEach-Object { "
        "$ad=$_; "
        "$ip=Get-NetIPAddress -InterfaceIndex $ad.ifIndex -ErrorAction SilentlyContinue; "
        "$ipv4=@(); $ipv6=@(); "
        "foreach($a in $ip){ if($a.AddressFamily -eq 'IPv4'){$ipv4+=$a.IPAddress} elseif($a.AddressFamily -eq 'IPv6'){$ipv6+=$a.IPAddress} } "
        "$obj=[ordered]@{Name=$ad.Name;Description=$ad.InterfaceDescription;Mac=$ad.MacAddress;"
        "Status=$ad.Status;LinkSpeed=$ad.LinkSpeed;ifIndex=$ad.ifIndex;VlanID=$ad.VlanID;"
        "Ipv4=($ipv4 -join ',');Ipv6=($ipv6 -join ',')}; "
        "$obj | ConvertTo-Json -Compress }"
    )
    rc, out, err = _powershell(snippet, timeout=20)
    interfaces: list[NetworkInterface] = []
    if rc != 0:
        get_logger().info("Get-NetAdapter failed: %s", err.strip())
        # Fall back to ipconfig parsing
        return _interfaces_from_ipconfig()

    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            import json as _json
            data = _json.loads(line)
        except Exception:
            continue
        nic = NetworkInterface(
            name=str(data.get("Name", "")),
            description=str(data.get("Description", "")),
            mac=str(data.get("Mac", "")).replace("-", ":").lower(),
            ipv4=[s for s in str(data.get("Ipv4", "")).split(",") if s],
            ipv6=[s for s in str(data.get("Ipv6", "")).split(",") if s],
            is_up=str(data.get("Status", "")).lower() == "up",
        )
        try:
            v = data.get("VlanID")
            if v not in (None, "", 0):
                nic.vlan_id = int(v)
        except Exception:
            pass
        link = str(data.get("LinkSpeed", "") or "")
        m = re.search(r"([\d.]+)\s*(\w+)", link)
        if m:
            try:
                val = float(m.group(1))
                unit = m.group(2).lower()
                if unit.startswith("g"):
                    nic.speed_mbps = int(val * 1000)
                elif unit.startswith("m"):
                    nic.speed_mbps = int(val)
                elif unit.startswith("k"):
                    nic.speed_mbps = int(val / 1000)
            except Exception:
                pass
        interfaces.append(nic)
    return interfaces or _interfaces_from_ipconfig()


def _interfaces_from_ipconfig() -> list[NetworkInterface]:
    rc, out, _ = _run(["ipconfig", "/all"])
    if rc != 0:
        return []
    nics: list[NetworkInterface] = []
    current: Optional[NetworkInterface] = None
    for raw in out.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if not line.startswith(" "):
            # Section header like "Ethernet adapter Ethernet:"
            current = NetworkInterface(name=line.strip().rstrip(":"))
            nics.append(current)
            continue
        if current is None:
            continue
        if "Description" in line:
            current.description = line.split(":", 1)[-1].strip()
        elif "Physical Address" in line:
            mac = line.split(":", 1)[-1].strip().replace("-", ":").lower()
            current.mac = mac
        elif "IPv4 Address" in line:
            ip = re.sub(r"[^\d.]", "", line.split(":", 1)[-1])
            if ip:
                current.ipv4.append(ip)
        elif "IPv6 Address" in line and not current.ipv6:
            current.ipv6.append(line.split(":", 1)[-1].strip())
        elif "Default Gateway" in line:
            current.gateway = re.sub(r"[^\d.]", "", line.split(":", 1)[-1])
        elif "DNS Servers" in line:
            ip = re.sub(r"[^\d.]", "", line.split(":", 1)[-1])
            if ip:
                current.dns.append(ip)
    return nics


def _list_interfaces_unix() -> list[NetworkInterface]:
    nics: list[NetworkInterface] = []
    rc, out, _ = _run(["ip", "-o", "addr"])
    if rc != 0:
        return nics
    by_name: dict[str, NetworkInterface] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1]
        family = parts[2]
        addr = parts[3].split("/")[0]
        nic = by_name.setdefault(name, NetworkInterface(name=name))
        if family == "inet":
            nic.ipv4.append(addr)
        elif family == "inet6":
            nic.ipv6.append(addr)
    nics = list(by_name.values())
    return nics


# ---- Public IP -----------------------------------------------------------

def detect_public_ip() -> tuple[str, str]:
    """Best-effort public IP using a tiny HTTPS check.

    Tries one or two well-known endpoints. If nothing is reachable we
    return ("", "") rather than raising.
    """
    candidates = [
        ("https://api.ipify.org", "ipify.org"),
        ("https://ifconfig.co", "ifconfig.co"),
    ]
    try:
        from urllib.request import Request, urlopen
    except Exception:
        return "", ""
    for url, label in candidates:
        try:
            req = Request(url, headers={"User-Agent": "voipscan/2"})
            with urlopen(req, timeout=4) as r:
                body = r.read().decode("utf-8", errors="ignore").strip()
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", body)
                if ip_match:
                    return ip_match.group(1), label
        except Exception:
            continue
    return "", ""


# ---- Traceroute first hops ----------------------------------------------

def traceroute_first_hops(target: str = "8.8.8.8", hops: int = 5) -> list[str]:
    """Return the first N traceroute hop IPs (or addresses)."""
    if paths.is_windows():
        cmd = ["tracert", "-d", "-h", str(hops), "-w", "1500", target]
    else:
        cmd = ["traceroute", "-n", "-w", "2", "-q", "1", "-m", str(hops), target]
    rc, out, _ = _run(cmd, timeout=20)
    found: list[str] = []
    for line in out.splitlines():
        for tok in line.split():
            try:
                ipaddress.ip_address(tok)
                if tok not in found and tok not in ("0.0.0.0",):
                    found.append(tok)
                    break
            except Exception:
                continue
        if len(found) >= hops:
            break
    return found


def gather_gateway_info() -> GatewayInfo:
    gw_ip = detect_default_gateway()
    info = GatewayInfo(default_gateway=gw_ip)
    if gw_ip:
        mac, vendor = arp_lookup(gw_ip)
        info.gateway_mac = mac
        info.gateway_vendor = vendor
        info.first_hop_traceroute = traceroute_first_hops(hops=4)
    return info


def windows_firewall_state() -> dict:
    """Return a small dict describing Windows Defender Firewall state."""
    if not paths.is_windows():
        return {"available": False, "detail": "non-Windows host"}
    rc, out, _ = _powershell(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | "
        "ForEach-Object { '{0}={1}' -f $_.Name, $_.Enabled }",
        timeout=10,
    )
    if rc != 0:
        return {"available": False, "detail": "Get-NetFirewallProfile failed"}
    state: dict[str, str] = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            state[k.strip()] = v.strip()
    return {"available": True, "profiles": state}
