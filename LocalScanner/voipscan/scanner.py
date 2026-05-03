"""Scan orchestration.

Two entry points:

* ``run_evidence_scan(...)`` — the primary, evidence-focused scan added
  in v2.1. Gathers host/network info, runs the Sangoma port catalog,
  collects SIP-ALG evidence, assesses VLAN 41, infers device
  attribution, and returns a fully populated ``ScanReport``.
* ``run_nmap_profile(...)`` — kept around for the optional nmap pass
  the GUI still surfaces. Streams output line-by-line.

The port catalog and SIP probe targets are easy to edit in
``sangoma_ports.py`` and the ``Optional`` advanced fields in the GUI.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from . import capture as capture_mod
from . import netinfo, paths, porttests, sangoma_ports, sipalg, vlan
from .logger import get_logger, log_exception
from .report import (
    CaptureReadiness,
    DeviceAttribution,
    FormInputs,
    Issue,
    ScanReport,
    SipAlgEvidence,
    VlanEvidence,
    fill_basic_host_identity,
    utcnow_iso,
)


# --- Tunable nmap knobs (legacy nmap pass) -------------------------------
QUICK_TCP_PORTS = "22,80,443,1935,5038,5060,5061,5160,8080,8088,8089"
QUICK_UDP_PORTS = "5060,5061"
TARGETED_TCP_PORTS = "22,80,443,1935,5038,5060,5061,5160,5222,8080,8088,8089"
TARGETED_UDP_PORTS = "5060,5061,10000-10100"
NMAP_TIMING = "-T4"
QUICK_SUBNETS = ["192.168.1.0/24", "192.168.41.0/24"]


@dataclass
class ScanProfile:
    name: str
    args: list[str]
    targets: list[str] = field(default_factory=list)


class ScanError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Nmap helpers (legacy / optional)
# ---------------------------------------------------------------------------

def find_nmap() -> str | None:
    bundled = paths.nmap_executable()
    if bundled is not None:
        return str(bundled)
    on_path = shutil.which("nmap")
    if on_path:
        return on_path
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


def run_nmap_profile(
    profile: ScanProfile,
    on_line: Callable[[str], None],
    cancel_event: threading.Event | None = None,
) -> dict:
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
        for line in proc.stdout:
            line = line.rstrip("\n")
            stdout_lines.append(line)
            on_line(line)
            if cancel_event is not None and cancel_event.is_set():
                proc.terminate()
                on_line("[scan cancelled]")
                break
        proc.wait(timeout=600)
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


# Backwards-compat alias for callers expecting the older name.
run_profile = run_nmap_profile


# ---------------------------------------------------------------------------
# Evidence-focused scan
# ---------------------------------------------------------------------------

def _attribute_blocking_device(report: ScanReport) -> DeviceAttribution:
    """Best-effort guess about WHERE traffic is being dropped/rewritten."""
    closed_or_filtered = [
        p for p in report.port_tests
        if p.result in ("closed", "filtered", "open|filtered")
    ]
    if not closed_or_filtered:
        return DeviceAttribution(
            likely_device="none",
            confidence="strong",
            rationale="All probed ports succeeded — no blocking detected.",
            user_provided_gateway_ip=report.form.gateway_ip,
            user_provided_firewall_ip=report.form.firewall_ip,
            user_provided_starbox_ip=report.form.starbox_ip,
        )

    # If only UDP RTP/SIP ranges are filtered, blame gateway/firewall.
    udp_only = all(p.protocol.lower() == "udp" for p in closed_or_filtered)
    sip_only = all(p.sip_alg_relevant for p in closed_or_filtered)

    rationale_parts: list[str] = []
    if udp_only:
        rationale_parts.append(
            "Only UDP probes were silently dropped — consistent with a "
            "stateful firewall or NAT device that doesn't have UDP pinholes."
        )
    if sip_only:
        rationale_parts.append(
            "All affected ports are in the SIP/RTP path — pointing at a "
            "device with SIP awareness (firewall/router with SIP ALG)."
        )

    likely = "gateway-or-firewall"
    confidence = "likely"

    fw = report.form.firewall_ip
    gw = report.form.gateway_ip
    if fw and gw and fw != gw:
        rationale_parts.append(
            f"Operator distinguished firewall ({fw}) from gateway ({gw}); "
            "the firewall is the most likely culprit since it is in line."
        )
        likely = "firewall"
        confidence = "likely"
    elif gw:
        rationale_parts.append(
            f"Operator-supplied gateway is {gw}; absent a separate firewall, "
            "the gateway/router is the most likely culprit."
        )
        likely = "gateway"

    if report.gateway.gateway_vendor:
        rationale_parts.append(
            f"Default gateway vendor (by MAC OUI): {report.gateway.gateway_vendor}."
        )

    if any(p.result == "closed" for p in closed_or_filtered):
        rationale_parts.append(
            "Some probes returned a definitive 'closed' (RST or ICMP refused) "
            "— that points at the destination service rather than an in-path firewall."
        )
        confidence = "inconclusive"

    return DeviceAttribution(
        likely_device=likely,
        confidence=confidence,
        rationale=" ".join(rationale_parts).strip(),
        user_provided_gateway_ip=report.form.gateway_ip,
        user_provided_firewall_ip=report.form.firewall_ip,
        user_provided_starbox_ip=report.form.starbox_ip,
    )


def _summarize_issues(report: ScanReport) -> tuple[list[Issue], list[str]]:
    issues: list[Issue] = []
    fixes: list[str] = []

    # SIP ALG
    if report.sip_alg.overall == "likely_on":
        issues.append(Issue(
            code="sip_alg_on",
            title="SIP ALG appears to be enabled",
            severity="critical",
            confidence=report.sip_alg.confidence,
            detail=(
                "Multiple checks suggest a SIP-aware device is rewriting "
                "or pinning SIP traffic. This commonly causes one-way "
                "audio, registration loops, and dropped calls."
            ),
            suggested_fix=(
                "Disable SIP ALG / SIP fixup / SIP helper on every "
                "router and firewall in line. Whitelist 199.15.180.0/22."
            ),
        ))
        fixes.append("Disable SIP ALG / SIP helper on the router/firewall.")
    elif report.sip_alg.overall == "inconclusive":
        issues.append(Issue(
            code="sip_alg_unknown",
            title="SIP ALG state is inconclusive",
            severity="info",
            confidence="inconclusive",
            detail=(
                "Client-only checks cannot prove SIP ALG without a "
                "cooperating SIP echo endpoint. Configure one to enable "
                "header-rewrite detection."
            ),
            suggested_fix=(
                "Provide a SIP test endpoint host:port under Advanced, "
                "or capture SIP traffic with Wireshark before/after the "
                "firewall and compare Via/Contact headers."
            ),
        ))

    # Port problems
    bad_ports = [p for p in report.port_tests if p.result not in ("open",)]
    sip_blocked = [p for p in bad_ports if p.sip_alg_relevant]
    if sip_blocked:
        ports_short = sorted({p.port for p in sip_blocked})[:8]
        issues.append(Issue(
            code="voice_ports_blocked",
            title="Voice-related ports look blocked or filtered",
            severity="critical",
            confidence="strong" if any(p.confidence == "confirmed" for p in sip_blocked) else "likely",
            detail=(
                f"{len(sip_blocked)} probes returned non-open results on "
                f"voice-relevant ports (sample: {', '.join(map(str, ports_short))})."
            ),
            suggested_fix=(
                "Allow outbound TCP 2160/5060/5061/5222/443 and UDP "
                "10000-65000 to 199.15.180.0/22 on the firewall."
            ),
            related_ports=ports_short,
        ))
        fixes.append("Open Sangoma's voice ports outbound (see report for list).")

    # VLAN
    if report.vlan.status == "confirmed":
        # nothing to flag — just include success in fixes summary
        pass
    elif report.vlan.status == "not_detected":
        issues.append(Issue(
            code="vlan_not_detected",
            title="VLAN 41 was not detected on this PC",
            severity="warning",
            confidence=report.vlan.confidence,
            detail=report.vlan.explanation,
            suggested_fix=(
                "If the phone or PC is meant to be on the voice VLAN, "
                "verify the switch port and NIC VLAN configuration."
            ),
        ))
        fixes.append("Verify VLAN 41 tagging on the switch port and NIC.")

    # Local Windows firewall hint
    fw = next((p for p in report.port_tests if p.result == "filtered" and p.protocol.lower() == "tcp"), None)
    if fw and not report.form.firewall_ip:
        issues.append(Issue(
            code="local_firewall_check",
            title="Some TCP probes were silently dropped",
            severity="warning",
            confidence="likely",
            detail=(
                "Filtered TCP results can come from the local Windows "
                "firewall as well as upstream devices. Check Windows "
                "Defender Firewall outbound rules."
            ),
            suggested_fix=(
                "Open Windows Defender Firewall and confirm no outbound "
                "rule blocks the StarPhone / SIP client."
            ),
        ))

    if not issues:
        issues.append(Issue(
            code="all_clear",
            title="No major issues detected",
            severity="info",
            confidence="strong",
            detail="All sampled ports succeeded and SIP ALG was not flagged.",
            suggested_fix="",
        ))

    return issues, fixes


def run_evidence_scan(
    *,
    form: FormInputs,
    on_log: Callable[[str], None],
    use_nmap: bool = True,
    cancel_event: threading.Event | None = None,
) -> ScanReport:
    """Top-level scan. Streams progress via ``on_log`` and returns a report."""
    log = get_logger()
    started = time.time()
    report = ScanReport()
    report.form = form
    report.app = "VoIP Health Check"
    report.session_id = paths.app_root().name + "-" + utcnow_iso().replace(":", "")
    report.started_at = utcnow_iso()
    report.sangoma_catalog = sangoma_ports.catalog_as_dict()

    on_log("[scan] === Evidence scan starting ===")

    # 1. Host identity
    on_log("[scan] Gathering host identity...")
    report.host = fill_basic_host_identity()
    report.host.local_ips = netinfo.local_ipv4_addresses()
    pub_ip, source = netinfo.detect_public_ip()
    if pub_ip:
        report.host.public_ip = pub_ip
        report.host.public_ip_source = source
        on_log(f"[scan] Public IP {pub_ip} (via {source})")
    else:
        on_log("[scan] Public IP could not be determined.")

    # 2. Interfaces
    on_log("[scan] Enumerating network interfaces...")
    try:
        report.interfaces = netinfo.list_interfaces()
        on_log(f"[scan] {len(report.interfaces)} interface(s) found.")
    except Exception:
        log_exception("interface enumeration failed")

    # 3. Gateway + DNS
    on_log("[scan] Resolving default gateway and DNS...")
    try:
        report.gateway = netinfo.gather_gateway_info()
        if report.gateway.default_gateway:
            on_log(
                f"[scan] Gateway {report.gateway.default_gateway} "
                f"MAC={report.gateway.gateway_mac or '?'} "
                f"vendor={report.gateway.gateway_vendor or '?'}"
            )
    except Exception:
        log_exception("gateway gathering failed")
    try:
        report.dns_servers = netinfo.detect_dns_servers()
    except Exception:
        log_exception("DNS server lookup failed")

    # 4. VLAN evidence
    on_log("[scan] Looking for VLAN 41 evidence...")
    try:
        report.vlan = vlan.assess_vlan(
            report.interfaces,
            user_gateway=form.gateway_ip,
        )
        on_log(
            f"[scan] VLAN {report.vlan.target_vlan}: "
            f"{report.vlan.status} ({report.vlan.confidence})"
        )
    except Exception:
        log_exception("VLAN assessment failed")

    if cancel_event and cancel_event.is_set():
        on_log("[scan] Cancelled.")
        report.finished_at = utcnow_iso()
        report.duration_seconds = time.time() - started
        return report

    # 5. Port tests
    on_log("[scan] Running port tests against Sangoma catalog...")
    try:
        overrides: dict[str, str] = {}
        if form.starbox_ip:
            overrides["sangoma_host"] = form.starbox_ip
        report.port_tests = porttests.run_port_tests(
            user_overrides=overrides,
            on_log=on_log,
            catalog=sangoma_ports.PORT_CATALOG,
        )
    except Exception:
        log_exception("port tests failed")

    # 5b. Optional nmap pass
    if use_nmap and find_nmap():
        try:
            targets: list[str] = []
            for v in (form.gateway_ip, form.firewall_ip, form.starbox_ip):
                if v and v.strip():
                    targets.append(v.strip())
            if not targets:
                targets = [sangoma_ports.DEFAULT_SANGOMA_HOST]
            profile = build_targeted_profile(targets)
            on_log(f"[scan] Optional nmap pass against {targets}")
            nmap_result = run_nmap_profile(
                profile, on_line=on_log, cancel_event=cancel_event
            )
            report.nmap_runs.append(nmap_result)
            porttests.merge_nmap_evidence(report.port_tests, nmap_result.get("stdout", ""))
        except ScanError as e:
            on_log(f"[scan] nmap skipped: {e}")
        except Exception:
            log_exception("optional nmap pass failed")
    else:
        on_log("[scan] nmap not available — skipping nmap pass.")

    # 6. SIP ALG evidence
    on_log("[scan] Gathering SIP ALG evidence...")
    try:
        sip_data = sipalg.gather_sip_alg_evidence(
            sip_test_endpoint=form.sip_test_endpoint,
            gateway_vendor=report.gateway.gateway_vendor,
            public_ip=report.host.public_ip,
            local_ips=report.host.local_ips,
            on_log=on_log,
        )
        report.sip_alg = SipAlgEvidence(**sip_data)
        on_log(
            f"[scan] SIP ALG verdict: {report.sip_alg.overall} "
            f"({report.sip_alg.confidence})"
        )
    except Exception:
        log_exception("SIP ALG check failed")

    # 7. Capture readiness
    try:
        cap = capture_mod.detect_capture_engine()
        report.capture = CaptureReadiness(
            engine=cap.engine, available=cap.available, detail=cap.detail
        )
    except Exception:
        log_exception("capture detection failed")

    # 8. Device attribution
    try:
        report.attribution = _attribute_blocking_device(report)
    except Exception:
        log_exception("attribution failed")

    # 9. Issues + fixes
    try:
        issues, fixes = _summarize_issues(report)
        report.issues = issues
        report.fixes = fixes
    except Exception:
        log_exception("issue summary failed")

    report.finished_at = utcnow_iso()
    report.duration_seconds = round(time.time() - started, 2)
    on_log(
        f"[scan] === Evidence scan finished in "
        f"{report.duration_seconds:.1f}s ==="
    )
    return report
