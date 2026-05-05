"""Port reachability tests for the Sangoma port catalog.

Two backends:

* ``socket`` — pure-Python TCP connect. Cross-platform, fast, gives a
  binary open/closed reachability picture from THIS host's perspective.
* ``nmap``   — used when available, runs the official scan with the
  ``-sT`` (TCP connect) and ``-sU`` (UDP) options. UDP results from nmap
  are inherently fuzzier (open|filtered) and we mark them as such.

Each rule from ``sangoma_ports.PortRule`` is expanded into one
``PortTestResult`` per ``sample_ports`` entry.

UDP semantics in this app:
* No reply  -> "open|filtered" with ``inconclusive`` confidence.
* ICMP unreachable / ConnectionRefused -> "closed".
* Send error / interface error -> "error".

This file deliberately keeps the per-port logic simple so operators can
edit ports, retries, and timeouts inline.
"""

from __future__ import annotations

import socket
import time
from typing import Callable, Iterable

from . import paths
from .logger import get_logger
from .netinfo import _run
from .report import PortTestResult
from .sangoma_ports import PortGroup, PortRule, DEFAULT_SANGOMA_HOST, all_rules


SOCKET_TCP_TIMEOUT = 2.0
SOCKET_UDP_TIMEOUT = 2.0


def _pick_destination(rule: PortRule, user_overrides: dict[str, str]) -> str:
    """Pick a destination host for a rule.

    Order:
      1. If the rule names a Sangoma destination network and the
         operator hasn't overridden anything, use the catalog default.
      2. ``user_overrides`` may carry a 'sangoma_host' (future) or
         'public_test_host' for non-Sangoma rules.
      3. Otherwise fall back to ``DEFAULT_SANGOMA_HOST`` for SIP-related
         rules and to a benign Internet host for HTTP/HTTPS/NTP.
    """
    # Sangoma-bound rules
    if rule.destinations:
        return user_overrides.get("sangoma_host") or DEFAULT_SANGOMA_HOST
    # Generic rules — pick a safe representative target.
    if rule.service == "NTP":
        return user_overrides.get("ntp_host") or "pool.ntp.org"
    if rule.service in ("HTTP",):
        return user_overrides.get("http_host") or "example.com"
    if rule.service in ("HTTPS",):
        return user_overrides.get("https_host") or "example.com"
    if rule.service in ("XMPP", "SIP", "RTC", "RTP/RTCP", "Application Framework Video", "StarFax Personal"):
        return user_overrides.get("sangoma_host") or DEFAULT_SANGOMA_HOST
    return DEFAULT_SANGOMA_HOST


def _socket_tcp_test(host: str, port: int) -> tuple[str, str]:
    """Return (result, evidence_text)."""
    try:
        with socket.create_connection((host, port), timeout=SOCKET_TCP_TIMEOUT) as s:
            local = s.getsockname()
            return "open", f"TCP connect succeeded from {local[0]}:{local[1]}"
    except (TimeoutError, socket.timeout):
        return "filtered", f"TCP connect to {host}:{port} timed out after {SOCKET_TCP_TIMEOUT:.0f}s"
    except ConnectionRefusedError:
        return "closed", f"TCP connect refused by {host}:{port}"
    except OSError as e:
        return "error", f"OS error: {e}"


def _socket_udp_test(host: str, port: int) -> tuple[str, str]:
    """Send a tiny payload and look for ICMP/ConnRefused or any reply."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SOCKET_UDP_TIMEOUT)
        sock.sendto(b"\x00", (host, port))
        try:
            data, _ = sock.recvfrom(2048)
            return "open", f"UDP reply received: {len(data)} bytes"
        except socket.timeout:
            return "open|filtered", "No UDP reply within timeout (UDP cannot be declared open without a response)."
        except ConnectionRefusedError:
            return "closed", "ICMP port unreachable received."
        except OSError as e:
            return "error", f"UDP recv error: {e}"
    except OSError as e:
        return "error", f"UDP send error: {e}"
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _confidence_for(method: str, result: str) -> str:
    if method == "socket":
        if result == "open":
            return "confirmed"
        if result == "closed":
            return "confirmed"
        if result == "filtered":
            return "likely"
        if result == "open|filtered":
            return "inconclusive"
    if method == "nmap":
        if result in ("open", "closed"):
            return "confirmed"
        if result == "filtered":
            return "likely"
        return "inconclusive"
    return "inconclusive"


def _likely_blocking_device(rule: PortRule, result: str, host: str) -> str:
    if result == "open":
        return "none"
    if result == "closed":
        # Closed implies the remote returned something — service is
        # likely not running on that host or upstream returned
        # connection-refused; not a firewall block in the path.
        return "remote"
    if result in ("filtered", "open|filtered"):
        # Filtered = silently dropped. Most commonly the gateway/firewall.
        return "gateway-or-firewall"
    return "unknown"


def _suggestion_for(rule: PortRule, result: str, host: str) -> str:
    if result == "open":
        return ""
    base = (
        f"Verify outbound {rule.protocol.upper()} {rule.ports} "
        f"to {host or 'Sangoma'} is allowed by the firewall."
    )
    if rule.sip_alg_relevant and rule.protocol.lower() == "udp":
        base += " Also ensure SIP ALG is OFF so RTP isn't pinned/rewritten."
    if rule.service in ("RTP", "RTC", "RTP/RTCP"):
        base += (
            " If only some sample ports fail, the firewall is enforcing a "
            "narrower range than required — open the full range."
        )
    return base


def _expand(rule: PortRule, group_name: str, user_overrides: dict[str, str]) -> Iterable[PortTestResult]:
    host = _pick_destination(rule, user_overrides)
    for port in rule.sample_ports:
        yield PortTestResult(
            group=group_name,
            service=rule.service,
            protocol=rule.protocol,
            port=port,
            destination=host,
            direction=rule.direction,
            sip_alg_relevant=rule.sip_alg_relevant,
        )


def _ports_for_rule(rule: PortRule, deep_sweep: bool) -> list[int]:
    """Return the port list to probe for this rule.

    In Advanced Scan we expand the sweep for the SIP/RTP rules so the
    operator gets evidence on more of the published range. We are still
    cautious: the RTP range is huge (10000–65000) so we only add a
    handful more sample points rather than scanning the full range.
    """
    if not deep_sweep:
        return list(rule.sample_ports)
    extras: list[int] = []
    if rule.service in ("RTP", "RTP/RTCP", "RTC", "Application Framework Video"):
        extras.extend([15000, 25000, 35000, 45000, 55000])
    if rule.service == "SIP":
        extras.extend([5061, 5160, 5161])
    if rule.service in ("HTTPS", "Web"):
        extras.extend([8088, 8089, 8443])
    merged = list(dict.fromkeys(list(rule.sample_ports) + extras))
    return merged


def run_port_tests(
    *,
    user_overrides: dict[str, str],
    on_log: Callable[[str], None],
    catalog: list[PortGroup],
    use_nmap: bool = False,
    nmap_path: str | None = None,
    deep_sweep: bool = False,
) -> list[PortTestResult]:
    """Probe every sample port and return the populated results.

    ``deep_sweep`` is set by Advanced Scan; it expands the RTP and
    SIP-relevant rules with a few extra sample ports so coverage is
    materially better than Quick Scan without exploding into a full
    UDP RTP range scan.
    """
    log = get_logger()
    results: list[PortTestResult] = []
    started = time.time()

    for group in catalog:
        on_log(f"[ports] === {group.name} ===")
        for rule in group.rules:
            host = _pick_destination(rule, user_overrides)
            for port in _ports_for_rule(rule, deep_sweep):
                pr = PortTestResult(
                    group=group.name,
                    service=rule.service,
                    protocol=rule.protocol,
                    port=port,
                    destination=host,
                    direction=rule.direction,
                    sip_alg_relevant=rule.sip_alg_relevant,
                )
                method = "socket"
                if rule.protocol.lower() == "tcp":
                    result, evidence = _socket_tcp_test(host, port)
                else:
                    result, evidence = _socket_udp_test(host, port)
                pr.method = method
                pr.result = result
                pr.confidence = _confidence_for(method, result)
                pr.likely_blocking_device = _likely_blocking_device(rule, result, host)
                pr.evidence = evidence
                pr.suggestion = _suggestion_for(rule, result, host)
                pr.raw = ""
                results.append(pr)
                on_log(
                    f"[ports] {rule.protocol.upper():3} {host}:{port:<5} "
                    f"{rule.service:<10}-> {result} ({pr.confidence})"
                )

    on_log(f"[ports] {len(results)} probes in {time.time() - started:.1f}s")
    return results


def merge_nmap_evidence(
    results: list[PortTestResult],
    nmap_stdout: str,
) -> None:
    """Best-effort: fold any matching nmap line into a result's raw field.

    We don't try to reparse nmap fully here — the structured probe already
    decided open/closed via socket. ``raw`` carries the nmap context so
    the operator can spot disagreements.
    """
    if not nmap_stdout:
        return
    for r in results:
        token = f"{r.port}/{r.protocol.lower()}"
        for line in nmap_stdout.splitlines():
            if token in line:
                r.raw = (r.raw + "\n" if r.raw else "") + line.strip()
                break
