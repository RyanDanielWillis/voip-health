"""Structured scan-result helpers.

The scanner has historically returned a single undifferentiated JSON blob per
audit. Downstream UI / analytics / dashboard work needs typed fields. This
module provides:

- ``ScanResult``: a typed container for a single scan finding.
- ``flatten_audit(payload)``: best-effort coercion of any historical or new
  upload payload into a list of ``ScanResult`` dicts.

Backwards compatibility is preserved: the original blob is always retained on
``raw`` so existing consumers can still read what they used to read.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional


SCAN_FIELDS = (
    "host", "port", "transport", "protocol", "service",
    "status", "latency_ms", "severity", "banner", "notes", "raw",
)


@dataclass
class ScanResult:
    host: Optional[str] = None
    port: Optional[int] = None
    transport: Optional[str] = None       # tcp / udp
    protocol: Optional[str] = None        # sip / rtp / ssh / https ...
    service: Optional[str] = None         # nmap product/service name
    status: Optional[str] = None          # up / down / open / closed / pass / fail
    latency_ms: Optional[float] = None
    severity: Optional[str] = None        # low / medium / high / critical
    banner: Optional[str] = None          # nmap banner / version / extra info
    notes: Optional[str] = None           # rule-driven plain English message
    raw: Optional[str] = None             # original JSON for backwards-compat

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _coerce_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _coerce_float(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _from_nmap_host(host: str, host_data: Dict[str, Any]) -> List[ScanResult]:
    """Convert a python-nmap-style host record into one ScanResult per port."""
    results: List[ScanResult] = []
    host_status = (host_data.get("status") or {}).get("state") or host_data.get("state")
    for transport in ("tcp", "udp"):
        ports = host_data.get(transport) or {}
        if not isinstance(ports, dict):
            continue
        for port, info in ports.items():
            info = info or {}
            results.append(ScanResult(
                host=host,
                port=_coerce_int(port),
                transport=transport,
                protocol=(info.get("name") or "").lower() or None,
                service=info.get("product") or info.get("name") or None,
                status=info.get("state") or host_status,
                latency_ms=None,
                severity=None,
                banner=" ".join(filter(None, [
                    info.get("product"),
                    info.get("version"),
                    info.get("extrainfo"),
                ])).strip() or None,
                notes=info.get("reason"),
            ))
    if not results and host_status:
        results.append(ScanResult(host=host, status=host_status))
    return results


def _from_analysis_list(host: str, analysis: List[Dict[str, Any]]) -> List[ScanResult]:
    """Convert the LocalScanner ``analyze_voip_health`` output."""
    out: List[ScanResult] = []
    for entry in analysis:
        if not isinstance(entry, dict):
            continue
        out.append(ScanResult(
            host=host,
            service=entry.get("check"),
            status=(entry.get("status") or "").lower() or None,
            severity="high" if (entry.get("status") == "FAIL") else "low",
            notes=entry.get("note"),
        ))
    return out


def flatten_audit(payload: Any) -> List[Dict[str, Any]]:
    """Best-effort: turn any audit payload into a list of structured rows.

    Always succeeds — unknown shapes fall back to a single row with the raw
    JSON preserved on ``raw`` so the dashboard can still show *something*.
    """
    if payload is None:
        return []

    raw_dump = json.dumps(payload, default=str)[:4000]

    # Already structured (list of dicts with our field set)
    if isinstance(payload, list):
        rows: List[Dict[str, Any]] = []
        for item in payload:
            if isinstance(item, dict):
                rows.extend(flatten_audit(item))
        return rows or [ScanResult(raw=raw_dump).to_dict()]

    if not isinstance(payload, dict):
        return [ScanResult(notes=str(payload), raw=raw_dump).to_dict()]

    # Single-result shape
    if any(k in payload for k in ("host", "ip", "target")) and not payload.get("scan"):
        host = payload.get("host") or payload.get("ip") or payload.get("target")
        sr = ScanResult(
            host=host,
            port=_coerce_int(payload.get("port")),
            transport=payload.get("transport"),
            protocol=payload.get("protocol"),
            service=payload.get("service"),
            status=payload.get("status"),
            latency_ms=_coerce_float(payload.get("latency_ms") or payload.get("latency")),
            severity=payload.get("severity"),
            banner=payload.get("banner"),
            notes=payload.get("notes") or payload.get("message"),
            raw=raw_dump,
        )
        # Some payloads also carry a sub-analysis array
        if isinstance(payload.get("analysis"), list):
            sub = _from_analysis_list(host or "", payload["analysis"])
            for r in sub:
                r.raw = raw_dump
            return [sr.to_dict()] + [r.to_dict() for r in sub]
        return [sr.to_dict()]

    # python-nmap output (PortScanner.scan(...) -> {"scan": {host: {...}}})
    if isinstance(payload.get("scan"), dict):
        rows = []
        for host, host_data in payload["scan"].items():
            for r in _from_nmap_host(host, host_data or {}):
                r.raw = raw_dump
                rows.append(r.to_dict())
        if rows:
            return rows

    # LocalScanner full_report shape: {host: {status, analysis: [...]}}
    looks_like_report = all(
        isinstance(v, dict) and ("analysis" in v or "status" in v or "tcp" in v or "udp" in v)
        for v in payload.values()
    ) and len(payload) > 0
    if looks_like_report:
        rows = []
        for host, host_data in payload.items():
            host_data = host_data or {}
            if "analysis" in host_data:
                for r in _from_analysis_list(host, host_data["analysis"]):
                    r.raw = raw_dump
                    rows.append(r.to_dict())
            if "tcp" in host_data or "udp" in host_data:
                for r in _from_nmap_host(host, host_data):
                    r.raw = raw_dump
                    rows.append(r.to_dict())
            if not rows and host_data.get("status"):
                rows.append(ScanResult(host=host, status=host_data["status"], raw=raw_dump).to_dict())
        if rows:
            return rows

    # advanced_scanner.py "compliance" shape — keep something visible
    if "Infrastructure" in payload or "Diagnostic_Output" in payload:
        infra = payload.get("Infrastructure") or {}
        rows = []
        for role, ip in infra.items():
            rows.append(ScanResult(
                host=str(ip),
                service=role,
                notes=str(payload.get("Diagnostic_Output", ""))[:240] or None,
                raw=raw_dump,
            ).to_dict())
        if rows:
            return rows

    return [ScanResult(notes=raw_dump[:240], raw=raw_dump).to_dict()]


def first_or_empty(payload: Any) -> Dict[str, Any]:
    rows = flatten_audit(payload)
    if rows:
        return rows[0]
    return ScanResult().to_dict()
