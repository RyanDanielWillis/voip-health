"""SIP ALG evidence gathering.

A client-only Windows app cannot *prove* SIP ALG is enabled or disabled
without a cooperating external SIP/echo endpoint. We instead run several
independent indirect checks, store each as an "evidence method" with its
own confidence, and let the report combine them into an overall verdict
that is honest about uncertainty.

Methods implemented here:

1. Send a SIP OPTIONS over UDP to a configured external test endpoint
   (or skip with a clear "needs_external_endpoint" flag if none).
   Compare the Via/Contact branches in any reply to what we sent — a
   different transport-layer source port or rewritten Contact strongly
   suggests ALG.
2. Send a SIP OPTIONS over TCP to the same endpoint as a sanity probe.
3. Public-vs-private IP check — if the public IP is known and differs
   from any local IP, NAT is in play (this is normal and just used as
   context, not as ALG proof on its own).
4. Local Windows firewall / SIP-helper hints (Windows only).
5. Gateway vendor hint — vendors like Sonicwall, Fortinet, Cisco-Linksys
   are infamous for shipping with SIP ALG on by default; we mark this
   as a *prior* not as proof.

Each method returns a dict shaped like:
    {
        "name": str,
        "result": "likely_on" | "likely_off" | "inconclusive" | "error",
        "confidence": "confirmed" | "strong" | "likely" | "inconclusive" | "not_detected",
        "detail": str,
        "evidence": str,   # raw text the operator can verify
    }
"""

from __future__ import annotations

import random
import re
import socket
import string
from dataclasses import dataclass
from typing import Optional

from . import paths
from .logger import get_logger
from .netinfo import _powershell, _run


SIP_ALG_VENDOR_PRIORS = {
    "sonicwall": "SonicWall firewalls historically ship with SIP ALG ON by default.",
    "fortinet": "FortiGate's session-helper for SIP rewrites packets unless 'sip-helper disabled' and 'voip alg' off.",
    "cisco": "Cisco IOS/Meraki commonly enable SIP fixup/inspection by default.",
    "cisco-linksys": "Linksys routers often have SIP ALG on with no UI to disable.",
    "netgear": "Some NETGEAR consumer routers leak SIP ALG behavior even when 'disabled'.",
    "tp-link": "Several TP-Link consumer models tamper with SIP packets.",
    "pace/at&t": "AT&T Pace gateways are known SIP-ALG offenders.",
    "watchguard": "WatchGuard SIP/H.323 proxies typically rewrite SIP unless turned off.",
}


def _rand_token(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _build_sip_options(
    *,
    src_ip: str,
    src_port: int,
    dst_host: str,
    dst_port: int,
    transport: str,
) -> bytes:
    """Construct a minimal but valid SIP OPTIONS request.

    The Via branch and Call-ID embed a unique token so we can spot
    rewriting in any reply.
    """
    branch = f"z9hG4bK-{_rand_token(8)}"
    call_id = f"{_rand_token(12)}@{src_ip or 'voipscan.local'}"
    tag = _rand_token(6)
    body = (
        f"OPTIONS sip:ping@{dst_host} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport.upper()} {src_ip or '0.0.0.0'}:{src_port};branch={branch}\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:voipscan@{src_ip or 'voipscan.local'}>;tag={tag}\r\n"
        f"To: <sip:ping@{dst_host}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Contact: <sip:voipscan@{src_ip or '0.0.0.0'}:{src_port}>\r\n"
        f"User-Agent: voipscan/2 (SIP-ALG-probe)\r\n"
        f"Accept: application/sdp\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    return body.encode("ascii", errors="ignore")


@dataclass
class _SipProbeResult:
    sent: str
    received: str
    rewritten: bool
    detail: str


def _probe_sip_udp(
    *, src_ip: str, dst_host: str, dst_port: int, timeout: float = 3.0
) -> Optional[_SipProbeResult]:
    """Send a SIP OPTIONS over UDP and try to read one reply."""
    try:
        family = socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.bind((src_ip or "0.0.0.0", 0))
            local = sock.getsockname()
            packet = _build_sip_options(
                src_ip=local[0],
                src_port=local[1],
                dst_host=dst_host,
                dst_port=dst_port,
                transport="UDP",
            )
            sock.sendto(packet, (dst_host, dst_port))
            try:
                data, _peer = sock.recvfrom(8192)
                received = data.decode("utf-8", errors="ignore")
            except socket.timeout:
                received = ""
        finally:
            sock.close()
    except Exception as e:
        return _SipProbeResult(
            sent=f"<UDP send failed: {e}>",
            received="",
            rewritten=False,
            detail=str(e),
        )

    sent = packet.decode("ascii", errors="ignore")
    rewritten = False
    detail = ""
    if received:
        # Compare Via branch and Contact — ALGs frequently rewrite both.
        via_sent = re.search(r"^Via:.*branch=([^\r\n;]+)", sent, re.MULTILINE)
        via_recv = re.search(r"^Via:.*branch=([^\r\n;]+)", received, re.MULTILINE)
        if via_sent and via_recv and via_sent.group(1) != via_recv.group(1):
            rewritten = True
            detail = "Via branch in reply differs from request — header rewriting suspected."
        contact_recv = re.search(r"^Contact:.*", received, re.MULTILINE)
        if contact_recv and src_ip and src_ip not in contact_recv.group(0):
            rewritten = True
            detail += " Contact header doesn't echo the source IP we sent."
    return _SipProbeResult(sent=sent, received=received, rewritten=rewritten, detail=detail)


def _probe_sip_tcp(
    *, dst_host: str, dst_port: int, timeout: float = 3.0
) -> Optional[_SipProbeResult]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((dst_host, dst_port))
        local = sock.getsockname()
        packet = _build_sip_options(
            src_ip=local[0],
            src_port=local[1],
            dst_host=dst_host,
            dst_port=dst_port,
            transport="TCP",
        )
        sock.sendall(packet)
        try:
            data = sock.recv(8192)
            received = data.decode("utf-8", errors="ignore")
        except socket.timeout:
            received = ""
        sock.close()
    except Exception as e:
        return _SipProbeResult(
            sent=f"<TCP connect failed: {e}>",
            received="",
            rewritten=False,
            detail=str(e),
        )
    return _SipProbeResult(
        sent=packet.decode("ascii", errors="ignore"),
        received=received,
        rewritten=False,
        detail="",
    )


def _windows_sip_helper_hints() -> dict:
    """Look at Windows-side hints. Mostly negative-evidence on Windows."""
    if not paths.is_windows():
        return {"available": False, "detail": "non-Windows host"}
    # Windows itself doesn't ship a SIP ALG; this is mostly for the report
    # so we can say "the Windows endpoint is not the ALG source".
    rc, out, _ = _powershell(
        "Get-Service -Name 'iphlpsvc','SharedAccess' "
        "| Select-Object Name,Status | ForEach-Object { '{0}={1}' -f $_.Name,$_.Status }",
        timeout=8,
    )
    detail: dict[str, str] = {}
    if rc == 0:
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                detail[k.strip()] = v.strip()
    return {"available": True, "services": detail}


def gather_sip_alg_evidence(
    *,
    sip_test_endpoint: str,
    gateway_vendor: str,
    public_ip: str,
    local_ips: list[str],
    on_log,
) -> dict:
    """Collect SIP-ALG evidence and return a dict shaped like ``SipAlgEvidence``."""
    log = get_logger()
    methods: list[dict] = []
    explanation_bits: list[str] = []
    suggestions: list[str] = []
    needs_external = not bool(sip_test_endpoint and ":" in sip_test_endpoint)

    # ---- Method 1: SIP OPTIONS over UDP ---------------------------------
    if not needs_external:
        host, _, port = sip_test_endpoint.partition(":")
        try:
            port_i = int(port or "5060")
        except ValueError:
            port_i = 5060
        on_log(f"[sipalg] UDP OPTIONS -> {host}:{port_i}")
        udp = _probe_sip_udp(src_ip=local_ips[0] if local_ips else "", dst_host=host, dst_port=port_i)
        if udp is None:
            methods.append({
                "name": "SIP OPTIONS (UDP)",
                "result": "error",
                "confidence": "inconclusive",
                "detail": "Probe failed to run.",
                "evidence": "",
            })
        elif udp.received:
            methods.append({
                "name": "SIP OPTIONS (UDP)",
                "result": "likely_on" if udp.rewritten else "likely_off",
                "confidence": "strong" if udp.rewritten else "likely",
                "detail": (
                    udp.detail or
                    "Reply received with intact branch/Contact — ALG rewriting NOT seen on this packet."
                ),
                "evidence": _trim(udp.received, 1500),
            })
        else:
            methods.append({
                "name": "SIP OPTIONS (UDP)",
                "result": "inconclusive",
                "confidence": "inconclusive",
                "detail": (
                    "No reply received within 3s. UDP loss is normal for "
                    "uninvited SIP traffic — this is not proof of blocking."
                ),
                "evidence": _trim(udp.sent, 800),
            })
    else:
        methods.append({
            "name": "SIP OPTIONS (UDP)",
            "result": "inconclusive",
            "confidence": "inconclusive",
            "detail": (
                "No external SIP test endpoint configured. Configure one "
                "in the Advanced section to enable header-rewrite detection."
            ),
            "evidence": "",
        })

    # ---- Method 2: SIP OPTIONS over TCP --------------------------------
    if not needs_external:
        host, _, port = sip_test_endpoint.partition(":")
        try:
            port_i = int(port or "5060")
        except ValueError:
            port_i = 5060
        on_log(f"[sipalg] TCP OPTIONS -> {host}:{port_i}")
        tcp = _probe_sip_tcp(dst_host=host, dst_port=port_i)
        if tcp is None:
            methods.append({
                "name": "SIP OPTIONS (TCP)",
                "result": "error",
                "confidence": "inconclusive",
                "detail": "Probe failed to run.",
                "evidence": "",
            })
        elif tcp.received:
            methods.append({
                "name": "SIP OPTIONS (TCP)",
                "result": "likely_off",
                "confidence": "likely",
                "detail": (
                    "TCP SIP traffic completed end-to-end. ALGs typically "
                    "operate on UDP; a successful TCP exchange is mildly "
                    "negative evidence for ALG."
                ),
                "evidence": _trim(tcp.received, 1500),
            })
        else:
            methods.append({
                "name": "SIP OPTIONS (TCP)",
                "result": "inconclusive",
                "confidence": "inconclusive",
                "detail": tcp.detail or "Connected but no reply observed.",
                "evidence": _trim(tcp.sent, 800),
            })

    # ---- Method 3: NAT context ------------------------------------------
    if public_ip and local_ips:
        if public_ip not in local_ips:
            methods.append({
                "name": "Public/Private IP comparison",
                "result": "inconclusive",
                "confidence": "inconclusive",
                "detail": (
                    f"Public IP ({public_ip}) differs from local IPs "
                    f"({', '.join(local_ips[:3])}). NAT is in play — "
                    "ALG behavior depends on the NAT device, not this fact alone."
                ),
                "evidence": f"public={public_ip}; local={','.join(local_ips)}",
            })
        else:
            methods.append({
                "name": "Public/Private IP comparison",
                "result": "likely_off",
                "confidence": "likely",
                "detail": "Host appears directly Internet-attached — no NAT/ALG layer above it.",
                "evidence": f"public=local={public_ip}",
            })

    # ---- Method 4: Local Windows hints ----------------------------------
    win = _windows_sip_helper_hints()
    if win.get("available"):
        methods.append({
            "name": "Windows local services",
            "result": "likely_off",
            "confidence": "likely",
            "detail": (
                "Windows does not implement SIP ALG itself. Listed services "
                "shown for context only."
            ),
            "evidence": ", ".join(
                f"{k}={v}" for k, v in (win.get("services") or {}).items()
            ),
        })

    # ---- Method 5: Gateway vendor prior --------------------------------
    if gateway_vendor:
        prior = SIP_ALG_VENDOR_PRIORS.get(gateway_vendor.lower())
        if prior:
            methods.append({
                "name": "Gateway vendor prior",
                "result": "likely_on",
                "confidence": "likely",
                "detail": prior,
                "evidence": f"gateway_vendor={gateway_vendor}",
            })
        else:
            methods.append({
                "name": "Gateway vendor prior",
                "result": "inconclusive",
                "confidence": "inconclusive",
                "detail": (
                    f"Gateway vendor '{gateway_vendor}' has no known default-ALG "
                    "behavior on file."
                ),
                "evidence": f"gateway_vendor={gateway_vendor}",
            })

    # ---- Combine ---------------------------------------------------------
    on_count = sum(1 for m in methods if m["result"] == "likely_on")
    off_count = sum(1 for m in methods if m["result"] == "likely_off")
    strong_on = any(m["result"] == "likely_on" and m["confidence"] in ("strong", "confirmed") for m in methods)

    if strong_on:
        overall = "likely_on"
        confidence = "strong"
    elif on_count and off_count == 0:
        overall = "likely_on"
        confidence = "likely"
    elif off_count and on_count == 0:
        overall = "likely_off"
        confidence = "likely"
    elif on_count and off_count:
        overall = "inconclusive"
        confidence = "inconclusive"
        explanation_bits.append("Methods disagree.")
    else:
        overall = "inconclusive"
        confidence = "inconclusive"

    if needs_external:
        explanation_bits.append(
            "No external SIP test endpoint configured — header-rewrite "
            "detection (the only client-side method that can produce "
            "strong evidence) is disabled."
        )
        suggestions.append(
            "Configure a SIP echo/test endpoint (host:port) under Advanced "
            "to enable header-rewrite detection."
        )

    suggestions.extend([
        "Disable SIP ALG / SIP helper / SIP fixup on the firewall and "
        "any router/modem in line.",
        "Capture traffic on the Windows host (Wireshark + Npcap) and "
        "compare SIP headers before/after the firewall to prove ALG.",
        "Whitelist 199.15.180.0/22 (Sangoma) so the gateway does not "
        "apply NAT helper logic to it.",
    ])

    return {
        "overall": overall,
        "confidence": confidence,
        "methods": methods,
        "explanation": " ".join(explanation_bits).strip(),
        "suggestions": suggestions,
        "needs_external_endpoint": needs_external,
        "external_endpoint_configured": sip_test_endpoint or "",
    }


def _trim(text: str, n: int) -> str:
    if len(text) <= n:
        return text
    return text[:n] + "...[truncated]"
