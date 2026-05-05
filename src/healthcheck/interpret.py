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
    vid = report.vlan.target_vlan
    if report.vlan.status == "confirmed":
        status = "OK"
        summary = (
            f"This PC looks like it's on the voice VLAN ({vid}). That's "
            "the right network for IP phones."
        )
    elif report.vlan.status == "not_detected":
        status = "WARN"
        summary = (
            f"We could not see VLAN {vid} on this connection. If the IP "
            "phone here is meant to use the voice VLAN, the switch port "
            "may be misconfigured."
        )
    else:
        status = "UNK"
        summary = (
            f"VLAN {vid} could not be confirmed from this PC. Windows "
            "often hides VLAN tags from user-mode tools — see the evidence "
            "below."
        )

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
        status = "BAD"
        summary = (
            "Your router/firewall appears to have SIP ALG turned ON. SIP "
            "ALG is well known for breaking VoIP — it can rewrite call "
            "headers and cause one-way audio or dropped calls."
        )
    elif sip.overall == "likely_off":
        status = "OK"
        summary = (
            "SIP ALG looks switched off — that's the right setting for "
            "Sangoma Business Voice."
        )
    else:
        status = "UNK"
        summary = (
            "We couldn't tell from this PC alone whether SIP ALG is on or "
            "off. A capture next to the firewall is the next step."
        )

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
    # Treat "filtered" / "closed" / "error" as confidently blocked.
    # "open|filtered" is the UDP-can't-tell case, which we list separately
    # so the operator can read the report without thinking it is a hard
    # block.
    blocked = [p for p in bad if p.result in ("filtered", "closed", "error")]
    udp_unclear = [p for p in bad if p.result == "open|filtered"]
    voice_blocked = [p for p in blocked if p.sip_alg_relevant]

    if total == 0:
        return Section(
            key="ports",
            title="Port reachability — what got through",
            status="UNK",
            summary="No port tests ran on this scan.",
        )
    if not bad:
        status = "OK"
        summary = (
            f"Good news — every one of the {total} ports we tested was open. "
            "Nothing on the path is blocking VoIP traffic from this PC."
        )
    elif voice_blocked:
        status = "BAD"
        names = sorted({f"{p.protocol.upper()} {p.port}" for p in voice_blocked})
        sample = ", ".join(names[:6]) + (" ..." if len(names) > 6 else "")
        summary = (
            f"{len(voice_blocked)} voice-related port(s) are blocked: {sample}. "
            "Voice traffic on those ports is being stopped before it reaches "
            "the Sangoma cloud."
        )
    elif blocked:
        status = "WARN"
        names = sorted({f"{p.protocol.upper()} {p.port}" for p in blocked})
        sample = ", ".join(names[:6]) + (" ..." if len(names) > 6 else "")
        summary = (
            f"{len(blocked)} non-voice port(s) are blocked: {sample}. "
            "Voice should still work, but other Sangoma services on those "
            "ports won't."
        )
    else:
        status = "INFO"
        summary = (
            "All confirmed checks passed. A few UDP ports could not be "
            "confirmed open without a live responder — that's normal."
        )

    bullets: list[str] = []
    if blocked:
        # Plain-English, explicit list of what is blocked. This is the
        # exact information the operator asked for: which ports are
        # blocked, and what the protocol is.
        bullets.append("Blocked ports (in plain English):")
        for p in blocked[:20]:
            destination = p.destination or "the test target"
            bullets.append(
                f"  • {p.protocol.upper()} port {p.port} to {destination} "
                f"({p.service}) — {p.result}. {p.evidence}"
            )
        if len(blocked) > 20:
            bullets.append(f"  ...and {len(blocked) - 20} more blocked ports.")
    else:
        bullets.append("No blocked ports were detected.")

    if udp_unclear:
        bullets.append("")
        bullets.append(
            f"{len(udp_unclear)} UDP port(s) were 'silent' — no reply was "
            "received in the timeout window. UDP can't be declared open "
            "from this PC alone without a live responder, so this is "
            "informational, not a confirmed block."
        )

    bullets.append("")
    bullets.append("Full per-group breakdown:")
    bullets.extend(_format_port_groups(report.port_tests))

    fixes: list[str] = []
    if voice_blocked:
        fixes.append(
            "Ask the firewall admin to allow outbound TCP 2160/5060/5061/5222/443 "
            "and UDP 10000-65000 to 199.15.180.0/22 (Sangoma's published range)."
        )
    if any(p.protocol.lower() == "udp" for p in blocked):
        fixes.append(
            "Open the UDP RTP range outbound. RTP audio packets ride that "
            "range — if the firewall blocks it, calls connect but go silent."
        )
    return Section(
        key="ports",
        title="Port reachability — what got through",
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


def _latency_section(report: ScanReport) -> Section:
    lat = report.latency
    if not lat.targets:
        return Section(
            key="latency",
            title="Latency, Jitter & Packet Loss",
            status="UNK",
            summary=lat.overall_summary
                or "Latency probe did not run (no usable targets).",
        )

    status_map = {"ok": "OK", "warn": "WARN", "bad": "BAD", "unknown": "UNK"}
    status = status_map.get(lat.overall_status, "UNK")
    plain_summary_map = {
        "ok": (
            "Latency, jitter and packet loss are all within the comfort "
            "range for clear VoIP calls."
        ),
        "warn": (
            "Latency or jitter is borderline. Calls will probably work, "
            "but expect occasional choppy audio if the network gets busier."
        ),
        "bad": (
            "Latency, jitter or packet loss is outside the comfort range "
            "for VoIP. Expect choppy or one-way audio until this is fixed."
        ),
        "unknown": (
            "Latency could not be measured — no targets responded to ping."
        ),
    }
    plain_summary = plain_summary_map.get(lat.overall_status, lat.overall_summary)
    bullets: list[str] = []
    if lat.overall_summary and lat.overall_summary != plain_summary:
        bullets.append(lat.overall_summary)
    for t in lat.targets:
        if t.samples_received:
            bullets.append(
                f"• {t.target_label} {t.target_host}: "
                f"avg {t.rtt_avg_ms} ms, min {t.rtt_min_ms} ms, "
                f"max {t.rtt_max_ms} ms, jitter {t.jitter_ms} ms, "
                f"loss {t.packet_loss_pct}% "
                f"({t.samples_received}/{t.samples_sent} replies) "
                f"[{t.status}]"
            )
        elif t.status == "skipped":
            bullets.append(f"• {t.target_label}: skipped — no host configured")
        else:
            bullets.append(
                f"• {t.target_label} {t.target_host}: no replies "
                f"({t.samples_sent} pings) [{t.status}]"
            )
        for note in t.notes:
            bullets.append(f"    note: {note}")
    if lat.targets:
        bullets.append(
            "Jitter formula: "
            + (lat.targets[0].jitter_formula or "mean(|rtt[i] - rtt[i-1]|)")
        )
    return Section(
        key="latency",
        title="Latency, jitter & packet loss",
        status=status,
        summary=plain_summary or "Latency snapshot collected.",
        bullets=bullets,
        fixes=list(lat.suggestions),
    )


def _dhcp_section(report: ScanReport) -> Section:
    d = report.dhcp
    if not d.available:
        return Section(
            key="dhcp",
            title="DHCP / IP Assignment",
            status="UNK",
            summary="DHCP evidence not available on this host.",
            bullets=[d.explanation] if d.explanation else [],
            fixes=list(d.suggestions),
        )

    if d.confidence in ("strong", "confirmed"):
        status = "OK" if d.inferred_assigner != "unknown" else "INFO"
    elif d.confidence == "likely":
        status = "INFO"
    else:
        status = "UNK"

    bullets: list[str] = [
        f"Inferred assigner: {d.inferred_assigner}"
        + (f" ({d.inferred_assigner_ip})" if d.inferred_assigner_ip else ""),
        f"Confidence: {_confidence_label(d.confidence)}",
        f"Method: {d.method or 'unknown'}",
    ]
    if d.explanation:
        bullets.append(d.explanation)
    for a in d.adapters[:6]:
        bits = [f"adapter: {a.adapter_name or '?'}"]
        if a.description:
            bits.append(f"desc={a.description}")
        if a.dhcp_enabled is not None:
            bits.append(f"dhcp={'on' if a.dhcp_enabled else 'off'}")
        if a.dhcp_server:
            bits.append(f"server={a.dhcp_server}")
        if a.ipv4:
            bits.append(f"ipv4={','.join(a.ipv4)}")
        if a.default_gateway:
            bits.append(f"gw={a.default_gateway}")
        if a.lease_obtained:
            bits.append(f"lease_obtained={a.lease_obtained}")
        if a.lease_expires:
            bits.append(f"lease_expires={a.lease_expires}")
        bullets.append("• " + ", ".join(bits))
    if len(d.adapters) > 6:
        bullets.append(f"...and {len(d.adapters) - 6} more adapter(s)")
    for limit in d.limitations:
        bullets.append(f"Limitation: {limit}")
    plain_summary = (
        f"This PC is getting its IP address from {d.inferred_assigner}."
        if d.inferred_assigner != "unknown"
        else "We could not tell which device is handing out IP addresses."
    )
    return Section(
        key="dhcp",
        title="DHCP / IP address assignment",
        status=status,
        summary=plain_summary,
        bullets=bullets,
        fixes=list(d.suggestions),
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
    profile_note = (
        "Advanced Scan profile" if getattr(report, "profile", "quick") == "advanced"
        else "Quick Scan profile"
    )
    if not issues:
        return Section(
            key="summary",
            title="Overall summary",
            status="OK",
            summary=f"{profile_note}. No issues identified — the network "
                    "looks healthy for VoIP from this PC.",
        )
    crit = sum(1 for i in issues if i.severity == "critical")
    warn = sum(1 for i in issues if i.severity == "warning")
    if crit:
        status = "BAD"
        summary = (
            f"{profile_note}. {crit} critical issue(s) need attention, "
            f"plus {warn} warning(s)."
        )
    elif warn:
        status = "WARN"
        summary = f"{profile_note}. {warn} warning(s) — review below."
    else:
        status = "INFO"
        summary = f"{profile_note}. Informational findings only."

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
        title="Overall summary & recommended fixes",
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
        _latency_section(report),
        _dhcp_section(report),
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
