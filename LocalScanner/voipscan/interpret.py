"""Plain-English interpretation of a ``ScanReport``.

The scanner produces structured evidence; this module turns it into the
human-readable text the GUI shows after a scan completes. Output is a
list of ``Section`` objects (heading, status badge, body lines, fixes)
so the GUI can render each section with its own visual indicator.

Status icons used in this app:
*  OK     — green check
*  WARN   — yellow exclamation
*  BAD    — red cross
*  INFO   — neutral i
*  UNK    — grey question

Section icons (logical names that the GUI maps to colored shapes):
*  net | vlan | sipalg | ports | capture | attribution | summary
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .report import ScanReport, PortTestResult


@dataclass
class Section:
    key: str               # logical name used by the GUI to pick an icon
    title: str
    status: str            # OK | WARN | BAD | INFO | UNK
    summary: str
    bullets: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)


def _confidence_label(value: str) -> str:
    return {
        "confirmed": "Confirmed",
        "strong": "Strong evidence",
        "likely": "Likely",
        "inconclusive": "Inconclusive",
        "not_detected": "Not detected",
    }.get(value, value or "Inconclusive")


def _network_section(report: ScanReport) -> Section:
    bullets: list[str] = []
    bullets.append(f"Hostname: {report.host.hostname or 'unknown'}")
    if report.host.local_ips:
        bullets.append(f"Local IP(s): {', '.join(report.host.local_ips)}")
    if report.host.public_ip:
        bullets.append(
            f"Public IP: {report.host.public_ip} (via {report.host.public_ip_source})"
        )
    if report.gateway.default_gateway:
        gw_line = f"Default gateway: {report.gateway.default_gateway}"
        if report.gateway.gateway_mac:
            gw_line += f" ({report.gateway.gateway_mac}"
            if report.gateway.gateway_vendor:
                gw_line += f" — {report.gateway.gateway_vendor}"
            gw_line += ")"
        bullets.append(gw_line)
    if report.dns_servers:
        bullets.append(f"DNS: {', '.join(report.dns_servers[:4])}")
    if report.gateway.first_hop_traceroute:
        bullets.append(
            "First hops: " + " → ".join(report.gateway.first_hop_traceroute[:5])
        )
    return Section(
        key="net",
        title="Host & Network",
        status="INFO",
        summary="Snapshot of the PC's identity and the path it sees toward the Internet.",
        bullets=bullets,
    )


def _vlan_section(report: ScanReport) -> Section:
    if report.vlan.status == "confirmed":
        status, summary = "OK", f"VLAN {report.vlan.target_vlan} appears to be tagged on this connection."
    elif report.vlan.status == "not_detected":
        status, summary = "WARN", f"VLAN {report.vlan.target_vlan} was not detected on this PC."
    else:
        status, summary = "UNK", f"VLAN {report.vlan.target_vlan} state is inconclusive — read evidence below."

    bullets = [f"Confidence: {_confidence_label(report.vlan.confidence)}"]
    bullets.extend(report.vlan.evidence)
    if report.vlan.explanation:
        bullets.append(f"Note: {report.vlan.explanation}")
    return Section(
        key="vlan",
        title=f"VLAN {report.vlan.target_vlan} Tagging",
        status=status,
        summary=summary,
        bullets=bullets,
        fixes=list(report.vlan.suggestions),
    )


def _sipalg_section(report: ScanReport) -> Section:
    sip = report.sip_alg
    if sip.overall == "likely_on":
        status, summary = "BAD", "SIP ALG is likely interfering with VoIP traffic."
    elif sip.overall == "likely_off":
        status, summary = "OK", "Multiple checks suggest SIP ALG is OFF or not interfering."
    else:
        status, summary = "UNK", "SIP ALG state could not be determined from this client alone."

    bullets = [f"Overall: {_confidence_label(sip.confidence)} ({sip.overall})"]
    for m in sip.methods:
        line = f"• {m['name']}: {_confidence_label(m['confidence'])} — {m['detail']}"
        bullets.append(line)
    if sip.needs_external_endpoint:
        bullets.append(
            "Needs external SIP test endpoint for definitive proof "
            "(configure host:port under Advanced)."
        )
    if sip.explanation:
        bullets.append(sip.explanation)
    return Section(
        key="sipalg",
        title="SIP ALG Evidence",
        status=status,
        summary=summary,
        bullets=bullets,
        fixes=list(sip.suggestions),
    )


def _ports_section(report: ScanReport) -> Section:
    total = len(report.port_tests)
    bad = [p for p in report.port_tests if p.result not in ("open",)]
    voice_bad = [p for p in bad if p.sip_alg_relevant]

    if total == 0:
        return Section(
            key="ports",
            title="Sangoma Port Reachability",
            status="UNK",
            summary="Port tests did not run.",
        )
    if not bad:
        status, summary = "OK", f"All {total} sampled ports succeeded."
    elif voice_bad:
        status = "BAD"
        summary = (
            f"{len(voice_bad)} of {total} voice-related ports look blocked or filtered."
        )
    else:
        status = "WARN"
        summary = f"{len(bad)} of {total} non-voice ports were not open."

    bullets = _format_port_groups(report.port_tests)
    fixes: list[str] = []
    if voice_bad:
        fixes.append(
            "Allow outbound TCP 2160/5060/5061/5222/443 and UDP 10000-65000 "
            "to 199.15.180.0/22 on the firewall (per Sangoma's port guide)."
        )
    if any(p.protocol.lower() == "udp" for p in bad):
        fixes.append(
            "Open UDP RTP range. UDP 'open|filtered' is normal without a "
            "responding endpoint — re-test against a known live SIP echo."
        )
    return Section(
        key="ports",
        title="Sangoma Port Reachability",
        status=status,
        summary=summary,
        bullets=bullets,
        fixes=fixes,
    )


def _format_port_groups(results: list[PortTestResult]) -> list[str]:
    by_group: dict[str, list[PortTestResult]] = {}
    for r in results:
        by_group.setdefault(r.group, []).append(r)
    out: list[str] = []
    for group, rows in by_group.items():
        ok_count = sum(1 for r in rows if r.result == "open")
        out.append(f"— {group}: {ok_count}/{len(rows)} open")
        # Show the most interesting failures first.
        rows_sorted = sorted(
            rows,
            key=lambda r: (r.result == "open", r.protocol, r.port),
        )
        for r in rows_sorted[:6]:
            mark = {
                "open": "OK",
                "closed": "X",
                "filtered": "?",
                "open|filtered": "?",
                "error": "!",
            }.get(r.result, "?")
            out.append(
                f"   [{mark}] {r.protocol.upper()} {r.destination}:{r.port} "
                f"({r.service}) -> {r.result}"
            )
        if len(rows) > 6:
            out.append(f"   ...and {len(rows) - 6} more")
    return out


def _attribution_section(report: ScanReport) -> Section:
    a = report.attribution
    if a.likely_device == "none":
        status, summary = "OK", "No blocking device detected on the path."
    elif a.likely_device in ("gateway", "firewall", "gateway-or-firewall"):
        status, summary = "WARN", f"Likely culprit: {a.likely_device.replace('-', ' ')}."
    elif a.likely_device == "isp":
        status, summary = "WARN", "Likely culprit: ISP / WAN device."
    elif a.likely_device == "remote":
        status, summary = "INFO", "Issues look remote-side, not local."
    else:
        status, summary = "UNK", "Could not attribute the issue to a specific device."

    bullets = [f"Confidence: {_confidence_label(a.confidence)}"]
    if a.rationale:
        bullets.append(a.rationale)
    if a.user_provided_gateway_ip:
        bullets.append(f"User-provided gateway: {a.user_provided_gateway_ip}")
    elif a.auto_detected_gateway_ip:
        bullets.append(
            f"Auto-detected gateway: {a.auto_detected_gateway_ip} "
            "(Advanced field was left blank)"
        )
    if a.user_provided_firewall_ip:
        bullets.append(f"User-provided firewall: {a.user_provided_firewall_ip}")
    else:
        bullets.append(
            "Firewall IP: not specified — not assumed equal to gateway. "
            "In-path culprit reported as 'gateway-or-firewall' where applicable."
        )
    if a.user_provided_starbox_ip:
        bullets.append(f"User-provided Starbox: {a.user_provided_starbox_ip}")
    return Section(
        key="attribution",
        title="Likely Blocking Device",
        status=status,
        summary=summary,
        bullets=bullets,
    )


def _capture_section(report: ScanReport) -> Section:
    if report.capture.available:
        status, summary = "OK", "Packet capture engine is ready."
    elif report.capture.engine != "none":
        status, summary = "INFO", f"Capture engine detected: {report.capture.engine}."
    else:
        status, summary = "WARN", "No packet capture driver detected."
    return Section(
        key="capture",
        title="Packet Capture Readiness",
        status=status,
        summary=summary,
        bullets=[report.capture.detail] if report.capture.detail else [],
        fixes=[
            "Install Npcap (https://npcap.com/) to enable live capture for "
            "definitive SIP ALG / RTP analysis.",
        ] if not report.capture.available else [],
    )


def _summary_section(report: ScanReport) -> Section:
    issues = report.issues
    if not issues:
        return Section(
            key="summary",
            title="Summary",
            status="OK",
            summary="No issues identified.",
        )
    crit = sum(1 for i in issues if i.severity == "critical")
    warn = sum(1 for i in issues if i.severity == "warning")
    if crit:
        status = "BAD"
        summary = f"{crit} critical issue(s), {warn} warning(s)."
    elif warn:
        status = "WARN"
        summary = f"{warn} warning(s) found."
    else:
        status = "INFO"
        summary = "Informational findings only."

    bullets = []
    for i in issues:
        bullets.append(
            f"[{i.severity.upper()}] {i.title} — {_confidence_label(i.confidence)}"
        )
        if i.detail:
            bullets.append(f"   {i.detail}")
        if i.suggested_fix:
            bullets.append(f"   Fix: {i.suggested_fix}")
    return Section(
        key="summary",
        title="Summary & Recommended Fixes",
        status=status,
        summary=summary,
        bullets=bullets,
        fixes=list(report.fixes),
    )


def _inputs_section(report: ScanReport) -> Section:
    """Show what was manually provided vs auto-detected vs skipped.

    Lets the operator (and the future VPS upload) see at a glance which
    Advanced fields were typed in versus inferred at scan time.
    """
    r = report.resolved_inputs
    bullets: list[str] = []
    if r.manual_inputs:
        bullets.append("Manual inputs:")
        for k, v in r.manual_inputs.items():
            bullets.append(f"   • {k} = {v}")
    else:
        bullets.append("Manual inputs: none — Advanced was left blank.")
    if r.auto_detected:
        bullets.append("Auto-detected:")
        for k, v in r.auto_detected.items():
            bullets.append(f"   • {k} = {v}")
    if r.skipped:
        bullets.append("Skipped cleanly: " + ", ".join(r.skipped))
    for note in r.notes:
        bullets.append(f"Note: {note}")
    if not bullets:
        bullets = ["No inputs recorded."]
    return Section(
        key="net",
        title="Inputs (manual vs auto-detected)",
        status="INFO",
        summary=(
            "All Advanced fields are optional — blank values are auto-detected "
            "or skipped cleanly without producing fake evidence."
        ),
        bullets=bullets,
    )


def build_sections(report: ScanReport) -> list[Section]:
    """Top-down, ordered for the GUI."""
    return [
        _summary_section(report),
        _sipalg_section(report),
        _ports_section(report),
        _vlan_section(report),
        _attribution_section(report),
        _network_section(report),
        _inputs_section(report),
        _capture_section(report),
    ]


def render_plain_text(report: ScanReport) -> str:
    """Single-string plain text rendering of all sections."""
    out: list[str] = []
    out.append("=" * 64)
    out.append("VoIP Health Check — Plain-English Results")
    out.append("=" * 64)
    out.append(
        f"Generated: {report.finished_at}   "
        f"Duration: {report.duration_seconds:.1f}s"
    )
    out.append("")
    for s in build_sections(report):
        out.append(f"## {s.title}  [{s.status}]")
        out.append(s.summary)
        for b in s.bullets:
            out.append(f"  {b}")
        if s.fixes:
            out.append("  Suggested fixes:")
            for f in s.fixes:
                out.append(f"    • {f}")
        out.append("")
    return "\n".join(out)
