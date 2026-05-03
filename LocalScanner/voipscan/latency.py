"""Latency / jitter / packet-loss diagnostics via safe ICMP ping.

Ping is deliberately the only mechanism here:

* It's available out of the box on every Windows / Linux / macOS host.
* It does not require admin rights for the system ``ping`` binary.
* It produces enough RTT samples to compute simple but well-defined
  VoIP-relevant statistics.

For each configured target the module fires a small, bounded burst of
pings (``DEFAULT_COUNT``), parses the per-reply RTT values out of the
OS-native ``ping`` output, and computes:

* ``samples_sent`` — number of pings issued.
* ``samples_received`` — number of replies parsed.
* ``packet_loss_pct`` — ``(sent - received) / sent * 100``.
* ``rtt_min_ms`` / ``rtt_avg_ms`` / ``rtt_max_ms`` — straight summary stats
  over received samples.
* ``jitter_ms`` — *mean absolute difference between consecutive RTTs*::

      jitter = mean( |rtt[i] - rtt[i-1]| )   for i in 1..len(rtt)-1

  This is the classic VoIP / RFC 3550-style "interarrival jitter" applied
  to the RTT timeline rather than to received packets, which is the best
  approximation a client-side ping can give without RTP.

Targets:

* ``gateway`` — caller-supplied or auto-detected default gateway. Skipped
  cleanly when no gateway is known.
* ``public`` — a small, stable list of public anchors (``8.8.8.8``,
  ``1.1.1.1``) so the scan still produces evidence when the gateway is
  unreachable.
* ``sangoma`` — Sangoma representative host
  (``sangoma_ports.DEFAULT_SANGOMA_HOST``) or whatever the operator
  supplied as ``starbox_ip`` if present.

The output is a list of ``LatencyResult`` rows ready to drop into
``ScanReport.latency``.
"""

from __future__ import annotations

import re
import statistics
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable, Optional

from . import paths


DEFAULT_COUNT = 8
DEFAULT_TIMEOUT_MS = 1500
PING_OVERALL_TIMEOUT_S = 30

# Public anchors used when probing "the internet" generally. Both are
# globally routed, well-known, and respond to ICMP.
PUBLIC_ANCHORS: list[str] = ["8.8.8.8", "1.1.1.1"]

# VoIP rule-of-thumb thresholds. The interpretation layer reads these
# constants so they stay in one place.
RTT_GOOD_MS = 80.0
RTT_WARN_MS = 150.0
JITTER_GOOD_MS = 20.0
JITTER_WARN_MS = 30.0
LOSS_GOOD_PCT = 1.0
LOSS_WARN_PCT = 3.0


# Compiled once at import time. Matches numeric ``time=12.3 ms`` (Linux,
# ``ms`` may be uppercase on some Windows builds), ``time=12ms`` (Windows
# default — no space), and ``time<1ms`` (Windows, sub-millisecond).
_TIME_RE = re.compile(
    r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms",
    re.IGNORECASE,
)


@dataclass
class LatencyResult:
    """One target's parsed latency / jitter snapshot."""

    target_label: str = ""        # human-friendly label (e.g. "gateway")
    target_host: str = ""         # actual IP / hostname pinged
    samples_sent: int = 0
    samples_received: int = 0
    packet_loss_pct: float = 0.0
    rtt_min_ms: Optional[float] = None
    rtt_avg_ms: Optional[float] = None
    rtt_max_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    jitter_formula: str = "mean(|rtt[i] - rtt[i-1]|) over received samples"
    confidence: str = "inconclusive"  # confirmed | likely | inconclusive | not_detected
    status: str = "unknown"           # ok | warn | bad | unreachable | skipped
    notes: list[str] = field(default_factory=list)
    raw_rtts_ms: list[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LatencySummary:
    """Aggregate of all per-target results plus a plain-English summary."""

    targets: list[LatencyResult] = field(default_factory=list)
    overall_status: str = "unknown"   # ok | warn | bad | unknown
    overall_summary: str = ""
    suggestions: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_ping_output(text: str) -> list[float]:
    """Extract per-reply RTT values from a ``ping`` stdout/stderr blob.

    Returns RTTs in milliseconds, in the order they appear. Missing
    replies (timeouts, "Destination host unreachable", etc.) are simply
    not represented — packet loss is derived from ``samples_sent`` minus
    the length of the returned list.
    """
    if not text:
        return []
    rtts: list[float] = []
    for match in _TIME_RE.finditer(text):
        try:
            rtts.append(float(match.group(1)))
        except ValueError:
            continue
    return rtts


def compute_jitter(rtts: Iterable[float]) -> Optional[float]:
    """Mean absolute difference between consecutive RTTs (ms).

    Returns ``None`` when fewer than two samples are available.
    """
    seq = list(rtts)
    if len(seq) < 2:
        return None
    diffs = [abs(seq[i] - seq[i - 1]) for i in range(1, len(seq))]
    if not diffs:
        return None
    return round(statistics.fmean(diffs), 3)


def summarize_rtts(rtts: list[float], samples_sent: int) -> dict:
    """Build the summary stat block for one target."""
    received = len(rtts)
    loss_pct = 0.0
    if samples_sent > 0:
        loss_pct = round(((samples_sent - received) / samples_sent) * 100, 2)
    if received == 0:
        return {
            "samples_received": 0,
            "packet_loss_pct": loss_pct,
            "rtt_min_ms": None,
            "rtt_avg_ms": None,
            "rtt_max_ms": None,
            "jitter_ms": None,
        }
    return {
        "samples_received": received,
        "packet_loss_pct": loss_pct,
        "rtt_min_ms": round(min(rtts), 3),
        "rtt_avg_ms": round(statistics.fmean(rtts), 3),
        "rtt_max_ms": round(max(rtts), 3),
        "jitter_ms": compute_jitter(rtts),
    }


def classify(result: LatencyResult) -> tuple[str, str]:
    """Return (status, confidence) using the module thresholds.

    ``status`` is one of ``ok|warn|bad|unreachable|skipped``.
    """
    if result.samples_sent == 0:
        return "skipped", "inconclusive"
    if result.samples_received == 0:
        return "unreachable", "likely"

    bad = False
    warn = False
    avg = result.rtt_avg_ms or 0.0
    jit = result.jitter_ms if result.jitter_ms is not None else 0.0
    loss = result.packet_loss_pct

    if avg > RTT_WARN_MS or jit > JITTER_WARN_MS or loss > LOSS_WARN_PCT:
        bad = True
    elif avg > RTT_GOOD_MS or jit > JITTER_GOOD_MS or loss > LOSS_GOOD_PCT:
        warn = True

    if bad:
        return "bad", "strong"
    if warn:
        return "warn", "likely"
    return "ok", "strong"


# ---------------------------------------------------------------------------
# Subprocess wrapper
# ---------------------------------------------------------------------------

def _ping_command(host: str, count: int, timeout_ms: int) -> list[str]:
    if paths.is_windows():
        # ``-n`` count, ``-w`` per-reply timeout in milliseconds.
        return ["ping", "-n", str(count), "-w", str(timeout_ms), host]
    # Unix ``ping``: ``-c`` count, ``-W`` per-reply timeout in seconds.
    return ["ping", "-c", str(count), "-W", str(max(1, timeout_ms // 1000)), host]


def _run_ping(host: str, count: int, timeout_ms: int) -> tuple[int, str]:
    """Run the OS ping. Combines stdout+stderr for parsing convenience."""
    cmd = _ping_command(host, count, timeout_ms)
    creationflags = 0
    if paths.is_windows():
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PING_OVERALL_TIMEOUT_S,
            creationflags=creationflags,
        )
        merged = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return proc.returncode, merged
    except FileNotFoundError:
        return 127, "ping binary not found"
    except subprocess.TimeoutExpired:
        return 124, "ping wall-clock timeout"
    except Exception as e:  # pragma: no cover — never raise out of a scan
        return 1, f"ping error: {e}"


def ping_target(
    label: str,
    host: str,
    *,
    count: int = DEFAULT_COUNT,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    runner: Callable[[str, int, int], tuple[int, str]] = _run_ping,
) -> LatencyResult:
    """Ping one host and return a populated ``LatencyResult``.

    ``runner`` is injectable so unit tests can supply a fake subprocess.
    """
    result = LatencyResult(target_label=label, target_host=host)
    if not host:
        result.status = "skipped"
        result.notes.append("no host configured for this target")
        return result

    result.samples_sent = count
    rc, output = runner(host, count, timeout_ms)
    rtts = parse_ping_output(output)
    result.raw_rtts_ms = rtts
    summary = summarize_rtts(rtts, count)
    result.samples_received = summary["samples_received"]
    result.packet_loss_pct = summary["packet_loss_pct"]
    result.rtt_min_ms = summary["rtt_min_ms"]
    result.rtt_avg_ms = summary["rtt_avg_ms"]
    result.rtt_max_ms = summary["rtt_max_ms"]
    result.jitter_ms = summary["jitter_ms"]

    status, confidence = classify(result)
    result.status = status
    result.confidence = confidence

    if rc not in (0, None) and result.samples_received == 0:
        result.notes.append(f"ping exited rc={rc}")
    if result.samples_received and result.samples_received < count:
        result.notes.append(
            f"received {result.samples_received}/{count} replies "
            f"({result.packet_loss_pct}% loss)"
        )
    return result


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def build_targets(
    *,
    gateway: str,
    sangoma_host: str,
    public_anchors: Optional[list[str]] = None,
) -> list[tuple[str, str]]:
    """Decide which (label, host) pairs to ping for this scan.

    Empty values are dropped. Public anchors default to PUBLIC_ANCHORS but
    callers can shrink the list (e.g. lab environments).
    """
    anchors = public_anchors if public_anchors is not None else list(PUBLIC_ANCHORS)
    targets: list[tuple[str, str]] = []
    if gateway:
        targets.append(("gateway", gateway))
    for ip in anchors:
        if ip:
            targets.append(("public", ip))
    if sangoma_host:
        targets.append(("sangoma", sangoma_host))
    return targets


def run_latency_tests(
    *,
    gateway: str,
    sangoma_host: str,
    on_log: Optional[Callable[[str], None]] = None,
    count: int = DEFAULT_COUNT,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    runner: Callable[[str, int, int], tuple[int, str]] = _run_ping,
    public_anchors: Optional[list[str]] = None,
) -> LatencySummary:
    """Run pings against gateway / public anchors / Sangoma and roll up."""
    log = on_log or (lambda _msg: None)
    summary = LatencySummary()
    targets = build_targets(
        gateway=gateway,
        sangoma_host=sangoma_host,
        public_anchors=public_anchors,
    )
    if not targets:
        summary.overall_status = "unknown"
        summary.overall_summary = (
            "No latency targets resolved (no gateway, anchors disabled, "
            "no Sangoma host) — latency / jitter check skipped cleanly."
        )
        return summary

    for label, host in targets:
        log(f"[latency] Pinging {label} {host} ({count} samples)...")
        try:
            res = ping_target(
                label, host, count=count, timeout_ms=timeout_ms, runner=runner
            )
        except Exception as e:  # pragma: no cover
            res = LatencyResult(target_label=label, target_host=host)
            res.samples_sent = count
            res.status = "unreachable"
            res.confidence = "inconclusive"
            res.notes.append(f"unexpected error: {e}")
        if res.samples_received:
            log(
                f"[latency] {label} {host}: avg={res.rtt_avg_ms}ms "
                f"jitter={res.jitter_ms}ms loss={res.packet_loss_pct}%"
            )
        else:
            log(f"[latency] {label} {host}: no replies received")
        summary.targets.append(res)

    summary.overall_status, summary.overall_summary, summary.suggestions = (
        _roll_up(summary.targets)
    )
    return summary


def _roll_up(targets: list[LatencyResult]) -> tuple[str, str, list[str]]:
    if not targets:
        return "unknown", "No targets pinged.", []

    statuses = [t.status for t in targets]
    suggestions: list[str] = []
    bad = [t for t in targets if t.status in ("bad", "unreachable")]
    warn = [t for t in targets if t.status == "warn"]

    if any(t.status == "unreachable" for t in targets):
        suggestions.append(
            "One or more targets did not respond to ICMP. Some firewalls "
            "drop ping but still pass voice traffic — re-test against the "
            "Sangoma SBC with SIP OPTIONS to confirm reachability."
        )
    if any(
        t.jitter_ms is not None and t.jitter_ms > JITTER_WARN_MS
        for t in targets
    ):
        suggestions.append(
            "Jitter exceeds the VoIP comfort threshold (>30 ms). Enable "
            "QoS / DSCP EF marking for SIP and RTP and confirm no Wi-Fi "
            "or mesh hop between the phone and the firewall."
        )
    if any(
        t.packet_loss_pct > LOSS_WARN_PCT
        for t in targets
    ):
        suggestions.append(
            "Packet loss above 3% will cause audible drop-outs. Check "
            "the WAN link, ISP throughput, and any in-path firewall "
            "rate-limits or buffer-bloat."
        )
    if any(
        (t.rtt_avg_ms or 0.0) > RTT_WARN_MS
        for t in targets
    ):
        suggestions.append(
            "Average RTT above 150 ms erodes call quality even without "
            "loss. Check the LAN path, switch CPU load, and whether the "
            "gateway is doing deep packet inspection on voice traffic."
        )

    if bad:
        return (
            "bad",
            f"{len(bad)} target(s) showing unreachable / poor latency.",
            suggestions,
        )
    if warn:
        return (
            "warn",
            f"{len(warn)} target(s) borderline for VoIP — investigate.",
            suggestions,
        )
    if all(s == "ok" for s in statuses):
        return (
            "ok",
            f"All {len(targets)} latency targets within VoIP comfort range.",
            suggestions,
        )
    return "unknown", "Mixed / inconclusive latency results.", suggestions
