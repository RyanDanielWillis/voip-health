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

from scanner.results import flatten_audit, first_or_empty  # noqa: E402

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
            for s in sessions:
                s["artifact_count"] = art_counts.get(s["id"], 0)
        else:
            for s in sessions:
                s["artifact_count"] = 0

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
    return render_template(
        "scan_detail.html",
        session=session_d,
        artifacts=artifacts,
        issues=issues,
        latency=latency,
        ports=ports,
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
    # normalized columns. ``scanner.results.flatten_audit`` keeps the legacy
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
