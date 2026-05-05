"""Flask app for VoIP Health Check dashboard.

Endpoints (v2):

* ``GET  /``                                         — homepage
* ``GET  /dashboard``                                — analytics dashboard
* ``GET  /scan/<sid>``                               — per-scan detail page
* ``POST /api/v2/scan/upload``                       — JSON scan upload
* ``POST /api/v2/scan/<sid>/artifact``               — multipart artifact for a scan
* ``POST /api/v2/capture/upload``                    — standalone capture upload
* ``GET  /api/v2/scan/<sid>``                        — JSON dump of a session
* ``GET  /api/v2/scans``                             — list recent sessions
* ``GET  /api/v2/artifact/<aid>/download``           — raw artifact download
* ``GET  /api/v2/scan/<sid>/report.json``            — full ScanReport JSON download

Backwards-compat:

* ``POST /api/upload-audit``  — legacy ingest, accepts the old freeform JSON
  and stores it via the new ``scan_sessions`` table so the dashboard still
  surfaces it. Returns ``{status, id}`` like the old endpoint.

Uploads accept an optional ``Authorization: Bearer <token>`` header. When
the ``VOIPSCAN_UPLOAD_TOKEN`` env var is set on the server, requests
without the matching token are rejected. Comparisons use ``hmac.compare_digest``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename


# Make the ``scanner`` package importable when run directly.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from results import flatten_audit, first_or_empty  # noqa: E402

from . import db as analytics_db  # noqa: E402


# --- Config ----------------------------------------------------------------
ARTIFACT_ROOT = Path(os.environ.get(
    "VOIPSCAN_ARTIFACT_DIR",
    str(Path.home() / "voipscan_api" / "artifacts"),
))
MAX_UPLOAD_BYTES = int(os.environ.get("VOIPSCAN_MAX_UPLOAD", str(25 * 1024 * 1024)))
ALLOWED_ARTIFACT_KINDS = {"log", "capture", "report_json", "other"}
# Conservative extension allow-list. ``.txt`` covers pktmon text dumps,
# ``.etl`` covers the legacy pktmon binary format.
ALLOWED_EXTENSIONS = {
    ".pcap", ".pcapng", ".cap", ".etl", ".txt", ".log", ".json",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


# --- Auth helpers ----------------------------------------------------------

def _required_token() -> str:
    return (os.environ.get("VOIPSCAN_UPLOAD_TOKEN") or "").strip()


def _auth_ok(req) -> bool:
    """Constant-time auth check. No token configured == open."""
    expected = _required_token()
    if not expected:
        return True
    header = req.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return False
    provided = header[7:].strip()
    return hmac.compare_digest(expected, provided)


# --- Storage helpers -------------------------------------------------------

def _ensure_artifact_root() -> Path:
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_ROOT


_FN_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename(name: str, fallback: str = "file") -> str:
    cleaned = secure_filename(name) or _FN_SAFE.sub("_", name)
    if not cleaned:
        cleaned = fallback
    return cleaned[:128]


def _save_artifact_file(file_storage, kind: str, session_id: Optional[int]) -> dict:
    raw_name = _safe_filename(file_storage.filename or "artifact", fallback=kind)
    suffix = Path(raw_name).suffix.lower()
    if suffix and suffix not in ALLOWED_EXTENSIONS:
        abort(400, description=f"file extension not allowed: {suffix}")

    root = _ensure_artifact_root()
    sid_dir = root / (f"session-{session_id}" if session_id else "standalone")
    sid_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    stored = sid_dir / f"{ts}_{kind}_{raw_name}"

    sha = hashlib.sha256()
    size = 0
    with stored.open("wb") as out:
        while True:
            chunk = file_storage.stream.read(64 * 1024)
            if not chunk:
                break
            sha.update(chunk)
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                # Clean up the partial file before refusing.
                out.close()
                stored.unlink(missing_ok=True)
                abort(413, description="upload exceeds size cap")
            out.write(chunk)
    return {
        "filename": raw_name,
        "stored_path": str(stored),
        "bytes": size,
        "sha256": sha.hexdigest(),
    }


# --- Init on import --------------------------------------------------------

def _bootstrap() -> dict:
    info = analytics_db.init_db()
    if info.get("reset"):
        app.logger.warning(
            "analytics DB reset performed (legacy data backed up to %s)",
            info.get("backup"),
        )
    _ensure_artifact_root()
    return info


_BOOTSTRAP_INFO = _bootstrap()


# --- Pages -----------------------------------------------------------------

@app.route("/")
def index():
    with analytics_db.connect() as conn:
        rows = analytics_db.get_recent_sessions(conn, limit=6)
        recent = [dict(r) for r in rows]
    return render_template("index.html", recent_sessions=recent)


@app.route("/dashboard")
def dashboard():
    with analytics_db.connect() as conn:
        kpis = analytics_db.aggregate_kpis(conn)
        rows = analytics_db.get_recent_sessions(conn, limit=50)
        sessions = [dict(r) for r in rows]
        # Per-session artifact counts, plus issue mix for the chart strip.
        if sessions:
            ids = [s["id"] for s in sessions]
            placeholders = ",".join("?" * len(ids))
            art_counts: dict[int, int] = {}
            for r in conn.execute(
                f"SELECT session_id, count(*) AS n FROM artifacts "
                f"WHERE session_id IN ({placeholders}) GROUP BY session_id",
                ids,
            ):
                art_counts[int(r["session_id"])] = int(r["n"])
            # Pull blocked port labels per session for a compact troubleshooting
            # column. Done in one indexed query rather than per-row.
            blocked_by_sid: dict[int, list[str]] = {}
            for r in conn.execute(
                f"SELECT session_id, protocol, port FROM port_results "
                f"WHERE session_id IN ({placeholders}) "
                f"AND result IN ('closed','filtered','open|filtered','error') "
                f"ORDER BY session_id, port",
                ids,
            ):
                sid = int(r["session_id"])
                proto = (r["protocol"] or "?").upper()
                blocked_by_sid.setdefault(sid, []).append(f"{proto}/{r['port']}")
            for s in sessions:
                s["artifact_count"] = art_counts.get(s["id"], 0)
                blocked = blocked_by_sid.get(s["id"], [])
                s["blocked_port_labels"] = blocked[:5]
                s["blocked_port_more"] = max(0, len(blocked) - 5)
                s["starbox_ip"], s["firewall_ip"] = _row_ips(s.get("report_json"))
        else:
            for s in sessions:
                s["artifact_count"] = 0
                s["blocked_port_labels"] = []
                s["blocked_port_more"] = 0
                s["starbox_ip"] = ""
                s["firewall_ip"] = ""
        # report_json is large — drop after use to keep the template fast.
        for s in sessions:
            s.pop("report_json", None)

        # Latency trend (avg latency / loss across the most recent 20 scans)
        trend_rows = list(conn.execute(
            "SELECT s.id AS sid, s.uploaded_at AS at, "
            "       avg(t.rtt_avg_ms) AS avg_rtt, "
            "       avg(t.jitter_ms) AS avg_jitter, "
            "       avg(t.packet_loss_pct) AS avg_loss "
            "FROM scan_sessions s LEFT JOIN latency_targets t ON t.session_id = s.id "
            "GROUP BY s.id ORDER BY s.id DESC LIMIT 20"
        ).fetchall())
    trend = list(reversed([
        {
            "sid": r["sid"],
            "at": r["at"],
            "avg_rtt": round(r["avg_rtt"], 1) if r["avg_rtt"] is not None else None,
            "avg_jitter": round(r["avg_jitter"], 1) if r["avg_jitter"] is not None else None,
            "avg_loss": round(r["avg_loss"], 2) if r["avg_loss"] is not None else None,
        }
        for r in trend_rows
    ]))
    return render_template(
        "dashboard.html", kpis=kpis, sessions=sessions, trend=trend
    )


@app.route("/docs")
def docs():
    """Project documentation page (in-app, kept in sync with the README)."""
    return render_template("docs.html")


@app.route("/old")
@app.route("/docs/old")
def docs_old():
    """Archived, full-length documentation kept for reference."""
    return render_template("docs_old.html")


def _safe_dict(v) -> dict:
    return v if isinstance(v, dict) else {}


def _safe_list(v) -> list:
    return v if isinstance(v, list) else []


def _row_ips(report_json: str | None) -> tuple[str, str]:
    """Return (starbox_ip, firewall_ip) parsed from the stored ScanReport.

    Used by the dashboard list to show operator-supplied IPs without an
    extra SQL column. Empty strings when missing or unparseable.
    """
    try:
        report = json.loads(report_json) if report_json else {}
    except Exception:
        return "", ""
    if not isinstance(report, dict):
        return "", ""
    form = _safe_dict(report.get("form"))
    auto = _safe_dict(_safe_dict(report.get("resolved_inputs")).get("auto_detected"))
    starbox = (form.get("starbox_ip") or auto.get("starbox_ip") or "").strip()
    firewall = (form.get("firewall_ip") or auto.get("firewall_ip") or "").strip()
    return starbox, firewall


# Rating thresholds for latency / jitter / loss. Kept aligned with
# ``LocalScanner/voipscan/latency.py`` (RTT_WARN_MS=150, JITTER_WARN_MS=30,
# LOSS_WARN_PCT=3); "bad" is roughly 2x warn, the same shape the local
# scanner uses to escalate per-target status.
_RTT_WARN_MS = 150.0
_RTT_BAD_MS = 300.0
_JITTER_WARN_MS = 30.0
_JITTER_BAD_MS = 60.0
_LOSS_WARN_PCT = 3.0
_LOSS_BAD_PCT = 8.0


def _rate(value: float | None, warn: float, bad: float) -> str:
    """Bucket a numeric measurement into ok / warn / bad / unknown."""
    if value is None:
        return "unknown"
    if value >= bad:
        return "bad"
    if value >= warn:
        return "warn"
    return "ok"


def _worst_rating(*ratings: str) -> str:
    order = {"unknown": 0, "ok": 1, "warn": 2, "bad": 3}
    worst = max(ratings, key=lambda r: order.get(r, 0), default="unknown")
    return worst


def _derive_issues_and_fixes(quick: dict) -> tuple[list[str], list[str]]:
    """Build short non-technical 'top issues' and 'potential fixes' lines
    from already-parsed quick-view data. Capped to keep the card scannable.
    """
    issues: list[str] = []
    fixes: list[str] = []

    if quick.get("sip_alg_overall") == "likely_on":
        issues.append("SIP ALG looks enabled on the firewall/router")
        fixes.append("Disable SIP ALG on the firewall and router, then reboot the phone")

    blocked = quick.get("blocked_ports") or []
    if blocked:
        labels = ", ".join(b["label"] for b in blocked[:4])
        more = "" if len(blocked) <= 4 else f" (+{len(blocked) - 4} more)"
        issues.append(f"{len(blocked)} VoIP port(s) blocked: {labels}{more}")
        fixes.append(
            "Open the listed ports outbound to the SBC on the firewall and any upstream device"
        )

    lat_rating = quick.get("latency_rating") or quick.get("latency_status")
    jit_rating = quick.get("jitter_rating")
    if lat_rating in ("warn", "bad"):
        issues.append(f"Latency rating: {lat_rating}")
        fixes.append("Check ISP/WAN health and any in-path firewall doing deep inspection on voice")
    if jit_rating in ("warn", "bad"):
        issues.append(f"Jitter rating: {jit_rating}")
        fixes.append("Enable QoS for SIP/RTP and avoid Wi-Fi or mesh hops between phone and firewall")
    if quick.get("loss_rating") in ("warn", "bad"):
        issues.append("Packet loss above VoIP comfort threshold")
        fixes.append("Investigate the WAN link and ISP throughput for the affected target(s)")

    vlan_status = (quick.get("vlan_status") or "").lower()
    vlan_id = quick.get("vlan_id")
    if vlan_status in ("not_detected", "missing", "absent") or (
        vlan_status and vlan_status not in ("detected", "ok") and not vlan_id
    ):
        issues.append("Voice VLAN not detected on this port")
        fixes.append("Confirm VLAN 41 (or your voice VLAN) is tagged on the switch port")

    if not quick.get("gateway_ip"):
        issues.append("No default gateway detected")
        fixes.append("Verify the PC has a working DHCP lease and a reachable default gateway")
    if not quick.get("firewall_ip"):
        issues.append("Firewall IP not provided")
        fixes.append("Add the firewall IP in the scan form so blame can be attributed correctly")
    if not quick.get("starbox_ip"):
        issues.append("Starbox IP not provided")
        fixes.append("Add the Sangoma Starbox IP in the scan form for end-to-end checks")

    dhcp_assigner = (quick.get("dhcp_assigner") or "").lower()
    if dhcp_assigner and dhcp_assigner not in ("router", "firewall", "starbox", "dhcp_server"):
        issues.append(f"DHCP assigner unclear ({quick.get('dhcp_assigner')})")
        fixes.append("Confirm which device is handing out DHCP — a rogue server can break voice")

    if quick.get("pcap_unavailable"):
        issues.append("Packet capture unavailable on this run")
        fixes.append("Re-run the scanner as Administrator so it can capture packets for analysis")

    # Keep the surface area small — the user asked for 3-5 simple items.
    return issues[:5], fixes[:5]


def _quick_view(report_json: str | None, ports: list[dict], latency: list[dict] | None = None) -> dict:
    """Compact troubleshooting fields parsed from the stored ScanReport JSON.

    Falls back to empty values when the report is missing or malformed; the
    template renders an em-dash for any blank field.
    """
    try:
        report = json.loads(report_json) if report_json else {}
    except Exception:
        report = {}
    if not isinstance(report, dict):
        report = {}

    form = _safe_dict(report.get("form"))
    resolved = _safe_dict(report.get("resolved_inputs"))
    auto = _safe_dict(resolved.get("auto_detected"))
    gateway = _safe_dict(report.get("gateway"))

    starbox_ip = (form.get("starbox_ip") or auto.get("starbox_ip") or "").strip()
    firewall_ip = (form.get("firewall_ip") or auto.get("firewall_ip") or "").strip()
    gateway_ip = (
        gateway.get("default_gateway")
        or form.get("gateway_ip")
        or auto.get("gateway_ip")
        or ""
    ).strip()

    blocked_states = {"closed", "filtered", "open|filtered", "error"}
    blocked_ports = []
    open_ports = []
    for p in ports:
        port_num = p.get("port")
        proto = (p.get("protocol") or "").lower()
        result = (p.get("result") or "").lower()
        if not port_num:
            continue
        label = f"{proto.upper() or '?'}/{port_num}"
        if result in blocked_states:
            blocked_ports.append({
                "label": label,
                "service": p.get("service") or "",
                "destination": p.get("destination") or "",
                "result": result,
            })
        elif result == "open":
            open_ports.append(label)

    sip_alg = _safe_dict(report.get("sip_alg"))
    latency_block = _safe_dict(report.get("latency"))
    dhcp = _safe_dict(report.get("dhcp"))
    vlan = _safe_dict(report.get("vlan"))
    capture = _safe_dict(report.get("capture") or report.get("pcap"))

    # Worst-case latency / jitter / loss across measured targets, used to
    # produce simple ratings even when the local scanner did not write an
    # explicit overall_status.
    worst_rtt = None
    worst_jitter = None
    worst_loss = None
    for t in latency or []:
        rtt = t.get("rtt_avg_ms")
        jit = t.get("jitter_ms")
        loss = t.get("packet_loss_pct")
        if rtt is not None:
            worst_rtt = rtt if worst_rtt is None else max(worst_rtt, rtt)
        if jit is not None:
            worst_jitter = jit if worst_jitter is None else max(worst_jitter, jit)
        if loss is not None:
            worst_loss = loss if worst_loss is None else max(worst_loss, loss)

    rtt_rating = _rate(worst_rtt, _RTT_WARN_MS, _RTT_BAD_MS)
    jitter_rating = _rate(worst_jitter, _JITTER_WARN_MS, _JITTER_BAD_MS)
    loss_rating = _rate(worst_loss, _LOSS_WARN_PCT, _LOSS_BAD_PCT)

    # Prefer the scanner's overall status when present; otherwise fall back
    # to the rating derived from the worst-target RTT.
    latency_status = latency_block.get("overall_status") or ""
    latency_rating = (
        latency_status if latency_status in ("ok", "warn", "bad")
        else _worst_rating(rtt_rating, loss_rating)
    )

    pcap_unavailable = bool(
        capture.get("unavailable")
        or capture.get("error")
        or (isinstance(capture.get("status"), str)
            and capture["status"].lower() in ("unavailable", "missing", "error"))
    )

    quick = {
        "starbox_ip": starbox_ip,
        "firewall_ip": firewall_ip,
        "gateway_ip": gateway_ip,
        "gateway_vendor": gateway.get("gateway_vendor") or "",
        "sip_alg_overall": sip_alg.get("overall") or "",
        "sip_alg_confidence": sip_alg.get("confidence") or "",
        "sip_alg_summary": sip_alg.get("summary") or sip_alg.get("explanation") or "",
        "vlan_status": vlan.get("status") or "",
        "vlan_id": vlan.get("vlan_id") or "",
        "latency_status": latency_status,
        "latency_rating": latency_rating,
        "latency_summary": latency_block.get("overall_summary") or "",
        "jitter_rating": jitter_rating,
        "loss_rating": loss_rating,
        "worst_rtt_ms": round(worst_rtt, 1) if worst_rtt is not None else None,
        "worst_jitter_ms": round(worst_jitter, 1) if worst_jitter is not None else None,
        "worst_loss_pct": round(worst_loss, 2) if worst_loss is not None else None,
        "dhcp_assigner": dhcp.get("inferred_assigner") or "",
        "dhcp_confidence": dhcp.get("confidence") or "",
        "blocked_ports": blocked_ports,
        "blocked_count": len(blocked_ports),
        "open_ports_preview": open_ports[:6],
        "open_count": len(open_ports),
        "total_ports": len(ports),
        "pcap_unavailable": pcap_unavailable,
    }
    quick["top_issues"], quick["potential_fixes"] = _derive_issues_and_fixes(quick)
    return quick


@app.route("/scan/<int:sid>")
def scan_detail(sid: int):
    with analytics_db.connect() as conn:
        session = analytics_db.get_session(conn, sid)
        if session is None:
            abort(404)
        artifacts = [dict(r) for r in analytics_db.get_artifacts(conn, sid)]
        issues = [dict(r) for r in analytics_db.get_session_issues(conn, sid)]
        latency = [dict(r) for r in analytics_db.get_session_latency(conn, sid)]
        ports = [dict(r) for r in analytics_db.get_session_ports(conn, sid)]
    session_d = dict(session)
    quick = _quick_view(session_d.get("report_json"), ports, latency)
    return render_template(
        "scan_detail.html",
        session=session_d,
        artifacts=artifacts,
        issues=issues,
        latency=latency,
        ports=ports,
        quick=quick,
    )


# --- v2 ingest API ---------------------------------------------------------

@app.route("/api/v2/scan/upload", methods=["POST"])
def api_v2_scan_upload():
    if not _auth_ok(request):
        return jsonify({"status": "error", "message": "unauthorized"}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "invalid JSON body"}), 400

    report = payload.get("report")
    if not isinstance(report, dict):
        return jsonify({"status": "error", "message": "missing 'report' object"}), 400

    client_session_id = str(payload.get("client_session_id") or report.get("session_id") or "")
    with analytics_db.connect() as conn:
        sid = analytics_db.insert_scan_session(
            conn, report, client_session_id=client_session_id,
        )

        # Persist the report JSON as a downloadable artifact too so the
        # dashboard's raw-data link always has something to serve.
        root = _ensure_artifact_root() / f"session-{sid}"
        root.mkdir(parents=True, exist_ok=True)
        report_path = root / f"report_{sid}.json"
        with report_path.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        size = report_path.stat().st_size
        sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
        analytics_db.insert_artifact(
            conn,
            session_id=sid,
            kind="report_json",
            filename=report_path.name,
            stored_path=str(report_path),
            bytes_size=size,
            sha256=sha,
        )
        conn.commit()

    return jsonify({
        "status": "success",
        "session_id": sid,
        "report_url": url_for("api_v2_scan_report_json", sid=sid, _external=False),
        "detail_url": url_for("scan_detail", sid=sid, _external=False),
    }), 200


@app.route("/api/v2/scan/<int:sid>/artifact", methods=["POST"])
def api_v2_scan_artifact(sid: int):
    if not _auth_ok(request):
        return jsonify({"status": "error", "message": "unauthorized"}), 401

    file_storage = request.files.get("file")
    if file_storage is None:
        return jsonify({"status": "error", "message": "missing file field"}), 400

    kind = (request.form.get("kind") or "other").strip().lower()
    if kind not in ALLOWED_ARTIFACT_KINDS:
        kind = "other"
    engine = request.form.get("engine", "")[:64]
    notes = request.form.get("notes", "")[:1000]

    with analytics_db.connect() as conn:
        session_row = analytics_db.get_session(conn, sid)
        if session_row is None:
            return jsonify({"status": "error", "message": "scan not found"}), 404
        meta = _save_artifact_file(file_storage, kind, sid)
        aid = analytics_db.insert_artifact(
            conn,
            session_id=sid,
            kind=kind,
            filename=meta["filename"],
            stored_path=meta["stored_path"],
            bytes_size=meta["bytes"],
            sha256=meta["sha256"],
            engine=engine,
            notes=notes,
        )
        conn.commit()

    return jsonify({
        "status": "success",
        "artifact_id": aid,
        "session_id": sid,
        "download_url": url_for("api_v2_artifact_download", aid=aid, _external=False),
        "bytes": meta["bytes"],
        "sha256": meta["sha256"],
    }), 200


@app.route("/api/v2/capture/upload", methods=["POST"])
def api_v2_capture_upload():
    if not _auth_ok(request):
        return jsonify({"status": "error", "message": "unauthorized"}), 401

    file_storage = request.files.get("file")
    if file_storage is None:
        return jsonify({"status": "error", "message": "missing file field"}), 400
    engine = request.form.get("engine", "")[:64]
    notes = request.form.get("notes", "")[:1000]
    meta = _save_artifact_file(file_storage, "capture", session_id=None)
    with analytics_db.connect() as conn:
        aid = analytics_db.insert_artifact(
            conn,
            session_id=None,
            kind="capture",
            filename=meta["filename"],
            stored_path=meta["stored_path"],
            bytes_size=meta["bytes"],
            sha256=meta["sha256"],
            engine=engine,
            notes=notes,
        )
        conn.commit()
    return jsonify({
        "status": "success",
        "artifact_id": aid,
        "download_url": url_for("api_v2_artifact_download", aid=aid, _external=False),
        "bytes": meta["bytes"],
        "sha256": meta["sha256"],
    }), 200


# --- Read APIs / downloads -------------------------------------------------

@app.route("/api/v2/scan/<int:sid>")
def api_v2_scan_get(sid: int):
    with analytics_db.connect() as conn:
        row = analytics_db.get_session(conn, sid)
        if row is None:
            return jsonify({"status": "error", "message": "not found"}), 404
        artifacts = [dict(r) for r in analytics_db.get_artifacts(conn, sid)]
    out = dict(row)
    try:
        out["report"] = json.loads(out.pop("report_json", "null"))
    except Exception:
        out["report"] = None
    out["artifacts"] = [
        {
            "id": a["id"],
            "kind": a["kind"],
            "filename": a["filename"],
            "bytes": a["bytes"],
            "sha256": a["sha256"],
            "engine": a["engine"],
            "uploaded_at": a["uploaded_at"],
            "download_url": url_for("api_v2_artifact_download", aid=a["id"]),
        }
        for a in artifacts
    ]
    return jsonify(out), 200


@app.route("/api/v2/scans")
def api_v2_scans():
    with analytics_db.connect() as conn:
        rows = analytics_db.get_recent_sessions(conn, limit=100)
    out = []
    for r in rows:
        d = dict(r)
        d.pop("report_json", None)
        out.append(d)
    return jsonify({"count": len(out), "sessions": out}), 200


@app.route("/api/v2/artifact/<int:aid>/download")
def api_v2_artifact_download(aid: int):
    with analytics_db.connect() as conn:
        a = analytics_db.get_artifact(conn, aid)
    if a is None:
        abort(404)
    path = Path(a["stored_path"])
    if not path.exists():
        abort(410, description="artifact file is missing on disk")
    return send_file(
        path,
        as_attachment=True,
        download_name=a["filename"],
    )


@app.route("/api/v2/scan/<int:sid>/report.json")
def api_v2_scan_report_json(sid: int):
    with analytics_db.connect() as conn:
        row = analytics_db.get_session(conn, sid)
    if row is None:
        abort(404)
    response = app.response_class(
        response=row["report_json"] or "{}",
        status=200,
        mimetype="application/json",
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="scan_{sid}_report.json"'
    )
    return response


# --- Legacy / compatibility -----------------------------------------------

@app.route("/api/upload-audit", methods=["POST"])
def upload_audit_legacy():
    """Old endpoint kept for older clients still pointed at it."""
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"status": "error", "message": "No JSON provided"}), 400

    # Wrap whatever we got into the v2 shape so we still benefit from the
    # normalized columns. ``results.flatten_audit`` keeps the legacy
    # dashboard rendering path useful for anything not in the new schema.
    if isinstance(data, dict) and "report" in data:
        report = data.get("report") if isinstance(data.get("report"), dict) else {}
    elif isinstance(data, dict):
        report = data
    else:
        report = {"legacy_payload": data}

    with analytics_db.connect() as conn:
        sid = analytics_db.insert_scan_session(conn, report, client_session_id="")
        conn.commit()

    structured = flatten_audit(data)
    return jsonify({
        "status": "success",
        "id": sid,
        "results": structured,
        "count": len(structured),
    }), 200


@app.route("/api/audits")
def list_audits_legacy():
    """JSON feed of recent sessions in the old shape."""
    with analytics_db.connect() as conn:
        rows = analytics_db.get_recent_sessions(conn, limit=200)
    out = []
    for r in rows:
        try:
            payload = json.loads(r["report_json"])
        except Exception:
            payload = {}
        structured = flatten_audit(payload)
        out.append({
            "id": r["id"],
            "fields": first_or_empty(payload),
            "results": structured,
        })
    return jsonify({"count": len(out), "audits": out})


# --- Health / status -------------------------------------------------------

@app.route("/api/v2/status")
def api_v2_status():
    with analytics_db.connect() as conn:
        kpis = analytics_db.aggregate_kpis(conn)
    return jsonify({
        "ok": True,
        "schema_version": analytics_db.CURRENT_SCHEMA_VERSION,
        "bootstrap": _BOOTSTRAP_INFO,
        "kpis": kpis,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
