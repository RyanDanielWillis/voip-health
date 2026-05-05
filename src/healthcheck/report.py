"""Structured scan-report data model.

Everything the scanner gathers lives on a ``ScanReport`` instance.
The report is JSON-serializable so the same shape can be written to
disk, displayed in the GUI, and uploaded to the VPS dashboard later.

The layout is deliberately flat-and-readable rather than heavily nested
so that future SQL columns or document fields map onto it easily. Each
section is a list of dicts when it represents a collection (port tests,
issues, etc.) and a dict otherwise.

Confidence levels in this app:

* ``confirmed``      — directly observed (e.g. socket TCP connect succeeded).
* ``strong``         — multiple independent signals agree.
* ``likely``         — one signal but plausible.
* ``inconclusive``   — could not determine; explanation provided.
* ``not_detected``   — actively looked for; nothing found.

These strings are stable so the dashboard can index on them.
"""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


CONFIDENCE_VALUES = (
    "confirmed",
    "strong",
    "likely",
    "inconclusive",
    "not_detected",
)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class HostIdentity:
    hostname: str = ""
    os: str = ""
    os_version: str = ""
    username: str = ""
    local_ips: list[str] = field(default_factory=list)
    public_ip: str = ""
    public_ip_source: str = ""  # which check produced it (or blank if none)


@dataclass
class NetworkInterface:
    name: str = ""
    description: str = ""
    mac: str = ""
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    gateway: str = ""
    dns: list[str] = field(default_factory=list)
    vlan_id: Optional[int] = None
    is_up: bool = True
    speed_mbps: Optional[int] = None
    notes: str = ""


@dataclass
class GatewayInfo:
    default_gateway: str = ""
    gateway_mac: str = ""
    gateway_vendor: str = ""
    first_hop_traceroute: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class VlanEvidence:
    """Best-effort evidence of VLAN 41 tagging on the current connection."""

    target_vlan: int = 41
    status: str = "inconclusive"  # confirmed | not_detected | inconclusive
    confidence: str = "inconclusive"
    evidence: list[str] = field(default_factory=list)
    explanation: str = ""
    suggestions: list[str] = field(default_factory=list)


@dataclass
class SipAlgEvidence:
    """Multiple-method evidence for whether SIP ALG is on this connection."""

    overall: str = "inconclusive"  # likely_on | likely_off | inconclusive
    confidence: str = "inconclusive"
    methods: list[dict] = field(default_factory=list)
    explanation: str = ""
    suggestions: list[str] = field(default_factory=list)
    needs_external_endpoint: bool = True
    external_endpoint_configured: str = ""


@dataclass
class PortTestResult:
    """One port-test row. Mirrors the columns the dashboard wants."""

    group: str = ""
    service: str = ""
    protocol: str = ""           # "tcp" | "udp"
    port: int = 0
    destination: str = ""
    direction: str = ""
    sip_alg_relevant: bool = False
    method: str = ""             # "nmap" | "socket" | "powershell" | ...
    result: str = "unknown"      # "open" | "closed" | "filtered" | "open|filtered" | "error" | "unknown"
    confidence: str = "inconclusive"
    likely_blocking_device: str = ""  # local-firewall|gateway|isp|remote|unknown
    evidence: str = ""
    suggestion: str = ""
    raw: str = ""


@dataclass
class CaptureReadiness:
    engine: str = "none"
    available: bool = False
    detail: str = ""


@dataclass
class LatencyTargetResult:
    """One ping target's latency / jitter snapshot.

    Mirrors :class:`voipscan.latency.LatencyResult` but lives in the
    report module so the data shape is single-sourced for upload.
    """

    target_label: str = ""
    target_host: str = ""
    samples_sent: int = 0
    samples_received: int = 0
    packet_loss_pct: float = 0.0
    rtt_min_ms: Optional[float] = None
    rtt_avg_ms: Optional[float] = None
    rtt_max_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    jitter_formula: str = "mean(|rtt[i] - rtt[i-1]|) over received samples"
    confidence: str = "inconclusive"
    status: str = "unknown"
    notes: list[str] = field(default_factory=list)
    raw_rtts_ms: list[float] = field(default_factory=list)


@dataclass
class LatencyEvidence:
    """Aggregate latency / jitter / packet-loss findings."""

    targets: list[LatencyTargetResult] = field(default_factory=list)
    overall_status: str = "unknown"
    overall_summary: str = ""
    suggestions: list[str] = field(default_factory=list)


@dataclass
class DhcpAdapterRow:
    adapter_name: str = ""
    description: str = ""
    dhcp_enabled: Optional[bool] = None
    dhcp_server: str = ""
    lease_obtained: str = ""
    lease_expires: str = ""
    ipv4: list[str] = field(default_factory=list)
    default_gateway: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class DhcpEvidenceData:
    """DHCP / IP-assignment evidence."""

    available: bool = False
    method: str = ""
    adapters: list[DhcpAdapterRow] = field(default_factory=list)
    inferred_assigner: str = "unknown"
    inferred_assigner_ip: str = ""
    confidence: str = "inconclusive"
    explanation: str = ""
    suggestions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass
class DeviceAttribution:
    """Where in the path is traffic likely being blocked / rewritten."""

    likely_device: str = "unknown"  # local | gateway | firewall | isp | remote | unknown
    confidence: str = "inconclusive"
    rationale: str = ""
    user_provided_gateway_ip: str = ""
    user_provided_firewall_ip: str = ""
    user_provided_starbox_ip: str = ""
    auto_detected_gateway_ip: str = ""


@dataclass
class Issue:
    code: str = ""
    title: str = ""
    severity: str = "info"  # info | warning | critical
    confidence: str = "inconclusive"
    detail: str = ""
    suggested_fix: str = ""
    related_ports: list[int] = field(default_factory=list)


@dataclass
class FormInputs:
    """Raw values typed by the operator. All fields are optional.

    Empty string means "not specified — the scanner should auto-detect or
    skip the related check cleanly". The scanner never invents a fake
    target or flags a blank field as an error.
    """

    problem_experienced: str = ""
    other_problem: str = ""
    hosted_platform: str = ""  # blank == auto / unknown
    gateway_ip: str = ""        # blank == auto-detect from OS routes
    firewall_ip: str = ""       # blank == do NOT assume; treat path as gateway-or-firewall
    starbox_ip: str = ""        # blank == skip Starbox-specific checks cleanly
    sip_test_endpoint: str = ""  # blank == skip external SIP probes; ALG verdict limited


@dataclass
class ResolvedInputs:
    """What the scanner actually used for each input after auto-detection.

    Mirrors ``FormInputs`` but separates user-provided values from values
    we auto-detected at scan time. The future VPS upload uses this to
    know which fields were specified versus inferred so the dashboard
    can weight them differently.
    """

    manual_inputs: dict[str, str] = field(default_factory=dict)
    auto_detected: dict[str, str] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    """Top-level structured scan output."""

    schema_version: str = "1.0"
    app: str = ""
    app_version: str = ""
    # Scan profile that produced this report. ``"quick"`` is the
    # default, ``"advanced"`` corresponds to the bottom Run Advanced Scan
    # button — deeper port sweep, longer latency sampling, and a
    # service-version nmap pass when nmap is available.
    profile: str = "quick"
    session_id: str = ""
    started_at: str = field(default_factory=utcnow_iso)
    finished_at: str = ""
    duration_seconds: float = 0.0

    form: FormInputs = field(default_factory=FormInputs)
    resolved_inputs: ResolvedInputs = field(default_factory=ResolvedInputs)
    host: HostIdentity = field(default_factory=HostIdentity)
    interfaces: list[NetworkInterface] = field(default_factory=list)
    gateway: GatewayInfo = field(default_factory=GatewayInfo)
    dns_servers: list[str] = field(default_factory=list)

    vlan: VlanEvidence = field(default_factory=VlanEvidence)
    sip_alg: SipAlgEvidence = field(default_factory=SipAlgEvidence)
    port_tests: list[PortTestResult] = field(default_factory=list)
    capture: CaptureReadiness = field(default_factory=CaptureReadiness)
    attribution: DeviceAttribution = field(default_factory=DeviceAttribution)
    latency: LatencyEvidence = field(default_factory=LatencyEvidence)
    dhcp: DhcpEvidenceData = field(default_factory=DhcpEvidenceData)

    issues: list[Issue] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)

    nmap_runs: list[dict] = field(default_factory=list)
    raw_logs: list[str] = field(default_factory=list)
    sangoma_catalog: dict = field(default_factory=dict)

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def append_log(self, line: str) -> None:
        self.raw_logs.append(line)


def fill_basic_host_identity() -> HostIdentity:
    """Populate the easy host fields. Network bits filled elsewhere."""
    h = HostIdentity()
    try:
        h.hostname = platform.node() or ""
    except Exception:
        pass
    try:
        h.os = platform.system() or ""
        h.os_version = f"{platform.release()} {platform.version()}".strip()
    except Exception:
        pass
    try:
        import getpass
        h.username = getpass.getuser()
    except Exception:
        pass
    return h
