"""SQLite analytics schema for VoIP Health Check.

Two responsibilities live here:

1. Schema versioning + one-time reset. The previous app stored audits as
   a single JSON blob; we erase that legacy database **once** when the
   ``schema_version`` table either does not exist or records a version
   below ``CURRENT_SCHEMA_VERSION``. The pre-reset DB file is renamed
   to ``audit_data.db.legacy_<ts>.bak`` so the operator can recover it
   if needed. After the reset the version row is written and ``init_db``
   is idempotent on every subsequent deploy / process restart.

2. Insert helpers that take a single ``ScanReport``-shaped dict from the
   desktop client and fan out into normalized analytics tables. The
   tables stay narrow and indexed on the columns the dashboard filters
   by; everything else lives in JSON columns so the schema doesn't have
   to chase every minor change to the client.

Tables (created if missing):

* ``schema_version``       — single-row marker for migrations / reset.
* ``scan_sessions``        — one row per uploaded scan from the client.
* ``scan_inputs``          — operator-supplied + auto-detected inputs.
* ``network_interfaces``   — per-NIC row, includes VLAN id when known.
* ``dhcp_adapters``        — DHCP / IP-assignment evidence per adapter.
* ``latency_targets``      — one row per ping target in the scan.
* ``port_results``         — one row per probed port.
* ``issues``               — diagnosed issue rows (severity, confidence).
* ``recommendations``      — flat list of suggested fixes for the scan.
* ``artifacts``            — uploaded raw files (log, capture, json).
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional


CURRENT_SCHEMA_VERSION = 2
RESET_MARKER_REASON = "phase2-analytics-redesign"

# Default DB filename — kept in sync with the older app.py default so a
# fresh deploy still finds the same path. Override via env ``AVS_DB``.
DEFAULT_DB_NAME = "audit_data.db"


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def get_db_path() -> Path:
    return Path(os.environ.get("AVS_DB", DEFAULT_DB_NAME))


@contextmanager
def connect(db_path: Optional[Path] = None) -> Iterator[sqlite3.Connection]:
    path = Path(db_path) if db_path else get_db_path()
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema management + one-time reset
# ---------------------------------------------------------------------------

_SCHEMA_SQL = [
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        id            INTEGER PRIMARY KEY CHECK (id = 1),
        version       INTEGER NOT NULL,
        applied_at    TEXT    NOT NULL,
        reset_reason  TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_sessions (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        client_session_id TEXT,
        schema_version    TEXT,
        app               TEXT,
        app_version       TEXT,
        hostname          TEXT,
        public_ip         TEXT,
        gateway_ip        TEXT,
        gateway_vendor    TEXT,
        problem           TEXT,
        hosted_platform   TEXT,
        started_at        TEXT,
        finished_at       TEXT,
        duration_seconds  REAL,
        likely_blocking   TEXT,
        attribution_conf  TEXT,
        sip_alg_overall   TEXT,
        sip_alg_conf      TEXT,
        vlan_status       TEXT,
        vlan_conf         TEXT,
        latency_status    TEXT,
        latency_summary   TEXT,
        dhcp_assigner     TEXT,
        dhcp_conf         TEXT,
        port_total        INTEGER DEFAULT 0,
        port_open         INTEGER DEFAULT 0,
        port_blocked      INTEGER DEFAULT 0,
        issue_critical    INTEGER DEFAULT 0,
        issue_warning     INTEGER DEFAULT 0,
        issue_info        INTEGER DEFAULT 0,
        report_json       TEXT NOT NULL,
        uploaded_at       TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_sessions_uploaded ON scan_sessions (uploaded_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_host ON scan_sessions (hostname)",
    """
    CREATE TABLE IF NOT EXISTS scan_inputs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  INTEGER NOT NULL,
        kind        TEXT NOT NULL,            -- manual | auto | skipped | note
        name        TEXT NOT NULL,
        value       TEXT,
        FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_inputs_session ON scan_inputs (session_id)",
    """
    CREATE TABLE IF NOT EXISTS network_interfaces (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id   INTEGER NOT NULL,
        name         TEXT,
        description  TEXT,
        mac          TEXT,
        ipv4         TEXT,
        ipv6         TEXT,
        gateway      TEXT,
        dns          TEXT,
        vlan_id      INTEGER,
        is_up        INTEGER,
        speed_mbps   INTEGER,
        notes        TEXT,
        FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_iface_session ON network_interfaces (session_id)",
    """
    CREATE TABLE IF NOT EXISTS dhcp_adapters (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      INTEGER NOT NULL,
        adapter_name    TEXT,
        description     TEXT,
        dhcp_enabled    INTEGER,
        dhcp_server     TEXT,
        lease_obtained  TEXT,
        lease_expires   TEXT,
        ipv4            TEXT,
        default_gateway TEXT,
        notes           TEXT,
        FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_dhcp_session ON dhcp_adapters (session_id)",
    """
    CREATE TABLE IF NOT EXISTS latency_targets (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id        INTEGER NOT NULL,
        target_label      TEXT,
        target_host       TEXT,
        samples_sent      INTEGER,
        samples_received  INTEGER,
        packet_loss_pct   REAL,
        rtt_min_ms        REAL,
        rtt_avg_ms        REAL,
        rtt_max_ms        REAL,
        jitter_ms         REAL,
        confidence        TEXT,
        status            TEXT,
        notes             TEXT,
        FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_latency_session ON latency_targets (session_id)",
    """
    CREATE TABLE IF NOT EXISTS port_results (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id          INTEGER NOT NULL,
        grp                 TEXT,
        service             TEXT,
        protocol            TEXT,
        port                INTEGER,
        destination         TEXT,
        direction           TEXT,
        sip_alg_relevant    INTEGER,
        method              TEXT,
        result              TEXT,
        confidence          TEXT,
        likely_blocking_dev TEXT,
        evidence            TEXT,
        suggestion          TEXT,
        FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ports_session ON port_results (session_id)",
    "CREATE INDEX IF NOT EXISTS idx_ports_result ON port_results (result)",
    """
    CREATE TABLE IF NOT EXISTS issues (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id    INTEGER NOT NULL,
        code          TEXT,
        title         TEXT,
        severity      TEXT,
        confidence    TEXT,
        detail        TEXT,
        suggested_fix TEXT,
        related_ports TEXT,
        FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_issues_session ON issues (session_id)",
    "CREATE INDEX IF NOT EXISTS idx_issues_severity ON issues (severity)",
    """
    CREATE TABLE IF NOT EXISTS recommendations (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  INTEGER NOT NULL,
        ord         INTEGER,
        text        TEXT,
        FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_recs_session ON recommendations (session_id)",
    """
    CREATE TABLE IF NOT EXISTS artifacts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id   INTEGER,                  -- NULL = standalone capture
        kind         TEXT NOT NULL,            -- log | capture | report_json | other
        filename     TEXT NOT NULL,
        stored_path  TEXT NOT NULL,
        bytes        INTEGER,
        sha256       TEXT,
        engine       TEXT,
        notes        TEXT,
        uploaded_at  TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE SET NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts (session_id)",
    "CREATE INDEX IF NOT EXISTS idx_artifacts_kind ON artifacts (kind)",
]


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    )
    return cur.fetchone() is not None


def _read_version(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "schema_version"):
        return 0
    cur = conn.execute("SELECT version FROM schema_version WHERE id = 1")
    row = cur.fetchone()
    return int(row["version"]) if row else 0


def _legacy_data_present(conn: sqlite3.Connection) -> bool:
    """Detect a v1 ``audits`` table from the previous app."""
    if not _table_exists(conn, "audits"):
        return False
    cur = conn.execute("SELECT count(*) FROM audits")
    row = cur.fetchone()
    if not row:
        return False
    return int(row[0]) > 0


def _backup_database(path: Path) -> Optional[Path]:
    if not path.exists():
        return None
    ts = time.strftime("%Y%m%d_%H%M%S")
    bak = path.with_suffix(path.suffix + f".legacy_{ts}.bak")
    try:
        shutil.copy2(path, bak)
        return bak
    except Exception:
        return None


def _drop_all_tables(conn: sqlite3.Connection) -> None:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )
    for row in cur.fetchall():
        conn.execute(f'DROP TABLE IF EXISTS "{row[0]}"')


def _create_schema(conn: sqlite3.Connection) -> None:
    for stmt in _SCHEMA_SQL:
        conn.execute(stmt)


def _stamp_version(conn: sqlite3.Connection, reason: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO schema_version (id, version, applied_at, reset_reason) "
        "VALUES (1, ?, ?, ?)",
        (CURRENT_SCHEMA_VERSION, time.strftime("%Y-%m-%dT%H:%M:%SZ"), reason),
    )


def init_db(db_path: Optional[Path] = None) -> dict:
    """Idempotent. Performs a one-time reset when version < CURRENT.

    The reset is **only** triggered the first time a process boots
    against an older schema. Subsequent calls (every gunicorn reload,
    every ``update.py`` deploy) just create-if-missing the tables and
    return ``{'reset': False}``.
    """
    path = Path(db_path) if db_path else get_db_path()
    info: dict[str, Any] = {
        "db_path": str(path), "reset": False, "fresh": False, "backup": None,
    }

    db_existed = path.exists()
    with connect(path) as conn:
        version = _read_version(conn)
        legacy = _legacy_data_present(conn)
        info["previous_version"] = version

        if version >= CURRENT_SCHEMA_VERSION:
            # Already at current version — ensure every table exists.
            _create_schema(conn)
            conn.commit()
            return info

        if not db_existed or (version == 0 and not legacy and
                              not _table_exists(conn, "audits") and
                              not _table_exists(conn, "scan_sessions")):
            # Fresh deploy — no data anywhere yet. Skip the backup+drop
            # dance and just stamp the schema.
            _create_schema(conn)
            _stamp_version(conn, "fresh-install")
            conn.commit()
            info["fresh"] = True
            return info

        # Legacy data (or partial older schema) present — one-time reset.
        backup = _backup_database(path)
        info["backup"] = str(backup) if backup else None
        info["reset"] = True
        info["legacy_audits_present"] = legacy
        _drop_all_tables(conn)
        _create_schema(conn)
        _stamp_version(conn, RESET_MARKER_REASON)
        conn.commit()

    return info


# ---------------------------------------------------------------------------
# Insert helpers
# ---------------------------------------------------------------------------

def _safe_get(d: Any, *path: str, default: Any = None) -> Any:
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
        if cur is None:
            return default
    return cur


def _csv(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, (list, tuple)):
        return ",".join(str(x) for x in v if x is not None)
    return str(v)


def insert_scan_session(
    conn: sqlite3.Connection,
    report: dict,
    *,
    client_session_id: str = "",
    uploaded_at: Optional[str] = None,
) -> int:
    uploaded_at = uploaded_at or time.strftime("%Y-%m-%dT%H:%M:%SZ")

    issues = report.get("issues") or []
    crit = sum(1 for i in issues if (i or {}).get("severity") == "critical")
    warn = sum(1 for i in issues if (i or {}).get("severity") == "warning")
    info = sum(1 for i in issues if (i or {}).get("severity") == "info")

    ports = report.get("port_tests") or []
    port_total = len(ports)
    port_open = sum(1 for p in ports if (p or {}).get("result") == "open")
    port_blocked = sum(
        1 for p in ports
        if (p or {}).get("result") in ("closed", "filtered", "open|filtered", "error")
    )

    session_row = {
        "client_session_id": client_session_id or report.get("session_id", ""),
        "schema_version": str(report.get("schema_version", "1.0")),
        "app": report.get("app", ""),
        "app_version": report.get("app_version", ""),
        "hostname": _safe_get(report, "host", "hostname", default=""),
        "public_ip": _safe_get(report, "host", "public_ip", default=""),
        "gateway_ip": _safe_get(report, "gateway", "default_gateway", default=""),
        "gateway_vendor": _safe_get(report, "gateway", "gateway_vendor", default=""),
        "problem": _safe_get(report, "form", "problem_experienced", default="")
                    or _safe_get(report, "form", "other_problem", default=""),
        "hosted_platform": _safe_get(report, "form", "hosted_platform", default=""),
        "started_at": report.get("started_at", ""),
        "finished_at": report.get("finished_at", ""),
        "duration_seconds": float(report.get("duration_seconds") or 0.0),
        "likely_blocking": _safe_get(report, "attribution", "likely_device", default=""),
        "attribution_conf": _safe_get(report, "attribution", "confidence", default=""),
        "sip_alg_overall": _safe_get(report, "sip_alg", "overall", default=""),
        "sip_alg_conf": _safe_get(report, "sip_alg", "confidence", default=""),
        "vlan_status": _safe_get(report, "vlan", "status", default=""),
        "vlan_conf": _safe_get(report, "vlan", "confidence", default=""),
        "latency_status": _safe_get(report, "latency", "overall_status", default=""),
        "latency_summary": _safe_get(report, "latency", "overall_summary", default=""),
        "dhcp_assigner": _safe_get(report, "dhcp", "inferred_assigner", default=""),
        "dhcp_conf": _safe_get(report, "dhcp", "confidence", default=""),
        "port_total": port_total,
        "port_open": port_open,
        "port_blocked": port_blocked,
        "issue_critical": crit,
        "issue_warning": warn,
        "issue_info": info,
        "report_json": json.dumps(report, default=str),
        "uploaded_at": uploaded_at,
    }

    cols = ",".join(session_row.keys())
    placeholders = ",".join("?" for _ in session_row)
    cur = conn.execute(
        f"INSERT INTO scan_sessions ({cols}) VALUES ({placeholders})",
        tuple(session_row.values()),
    )
    sid = cur.lastrowid
    if sid is None:
        raise RuntimeError("scan_sessions insert returned no rowid")

    # Inputs (manual / auto / skipped / note)
    resolved = report.get("resolved_inputs") or {}
    for k, v in (resolved.get("manual_inputs") or {}).items():
        conn.execute(
            "INSERT INTO scan_inputs (session_id, kind, name, value) VALUES (?,?,?,?)",
            (sid, "manual", k, str(v)),
        )
    for k, v in (resolved.get("auto_detected") or {}).items():
        conn.execute(
            "INSERT INTO scan_inputs (session_id, kind, name, value) VALUES (?,?,?,?)",
            (sid, "auto", k, str(v)),
        )
    for k in (resolved.get("skipped") or []):
        conn.execute(
            "INSERT INTO scan_inputs (session_id, kind, name, value) VALUES (?,?,?,?)",
            (sid, "skipped", str(k), None),
        )
    for n in (resolved.get("notes") or []):
        conn.execute(
            "INSERT INTO scan_inputs (session_id, kind, name, value) VALUES (?,?,?,?)",
            (sid, "note", "", str(n)),
        )

    # Interfaces
    for iface in report.get("interfaces") or []:
        conn.execute(
            "INSERT INTO network_interfaces (session_id, name, description, mac, "
            "ipv4, ipv6, gateway, dns, vlan_id, is_up, speed_mbps, notes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                sid,
                iface.get("name"),
                iface.get("description"),
                iface.get("mac"),
                _csv(iface.get("ipv4")),
                _csv(iface.get("ipv6")),
                iface.get("gateway"),
                _csv(iface.get("dns")),
                iface.get("vlan_id"),
                int(bool(iface.get("is_up"))),
                iface.get("speed_mbps"),
                iface.get("notes"),
            ),
        )

    # DHCP adapters
    for ad in _safe_get(report, "dhcp", "adapters", default=[]) or []:
        conn.execute(
            "INSERT INTO dhcp_adapters (session_id, adapter_name, description, "
            "dhcp_enabled, dhcp_server, lease_obtained, lease_expires, ipv4, "
            "default_gateway, notes) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                sid,
                ad.get("adapter_name"),
                ad.get("description"),
                None if ad.get("dhcp_enabled") is None else int(bool(ad.get("dhcp_enabled"))),
                ad.get("dhcp_server"),
                ad.get("lease_obtained"),
                ad.get("lease_expires"),
                _csv(ad.get("ipv4")),
                ad.get("default_gateway"),
                _csv(ad.get("notes")),
            ),
        )

    # Latency targets
    for t in _safe_get(report, "latency", "targets", default=[]) or []:
        conn.execute(
            "INSERT INTO latency_targets (session_id, target_label, target_host, "
            "samples_sent, samples_received, packet_loss_pct, rtt_min_ms, rtt_avg_ms, "
            "rtt_max_ms, jitter_ms, confidence, status, notes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                sid,
                t.get("target_label"),
                t.get("target_host"),
                t.get("samples_sent"),
                t.get("samples_received"),
                t.get("packet_loss_pct"),
                t.get("rtt_min_ms"),
                t.get("rtt_avg_ms"),
                t.get("rtt_max_ms"),
                t.get("jitter_ms"),
                t.get("confidence"),
                t.get("status"),
                _csv(t.get("notes")),
            ),
        )

    # Port results
    for p in report.get("port_tests") or []:
        conn.execute(
            "INSERT INTO port_results (session_id, grp, service, protocol, port, "
            "destination, direction, sip_alg_relevant, method, result, confidence, "
            "likely_blocking_dev, evidence, suggestion) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                sid,
                p.get("group"),
                p.get("service"),
                p.get("protocol"),
                p.get("port"),
                p.get("destination"),
                p.get("direction"),
                int(bool(p.get("sip_alg_relevant"))),
                p.get("method"),
                p.get("result"),
                p.get("confidence"),
                p.get("likely_blocking_device"),
                p.get("evidence"),
                p.get("suggestion"),
            ),
        )

    # Issues
    for i in report.get("issues") or []:
        conn.execute(
            "INSERT INTO issues (session_id, code, title, severity, confidence, "
            "detail, suggested_fix, related_ports) VALUES (?,?,?,?,?,?,?,?)",
            (
                sid,
                i.get("code"),
                i.get("title"),
                i.get("severity"),
                i.get("confidence"),
                i.get("detail"),
                i.get("suggested_fix"),
                _csv(i.get("related_ports")),
            ),
        )

    # Recommendations / fixes
    for ord_, fix in enumerate(report.get("fixes") or []):
        conn.execute(
            "INSERT INTO recommendations (session_id, ord, text) VALUES (?,?,?)",
            (sid, ord_, str(fix)),
        )

    return sid


def insert_artifact(
    conn: sqlite3.Connection,
    *,
    session_id: Optional[int],
    kind: str,
    filename: str,
    stored_path: str,
    bytes_size: int,
    sha256: str,
    engine: str = "",
    notes: str = "",
    uploaded_at: Optional[str] = None,
) -> int:
    uploaded_at = uploaded_at or time.strftime("%Y-%m-%dT%H:%M:%SZ")
    cur = conn.execute(
        "INSERT INTO artifacts (session_id, kind, filename, stored_path, bytes, "
        "sha256, engine, notes, uploaded_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (session_id, kind, filename, stored_path, bytes_size, sha256, engine, notes, uploaded_at),
    )
    aid = cur.lastrowid
    if aid is None:
        raise RuntimeError("artifacts insert returned no rowid")
    return aid


# ---------------------------------------------------------------------------
# Query helpers (kept thin — used by the dashboard view)
# ---------------------------------------------------------------------------

def get_recent_sessions(conn: sqlite3.Connection, limit: int = 25) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM scan_sessions ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall())


def get_session(conn: sqlite3.Connection, sid: int) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM scan_sessions WHERE id = ?", (sid,)
    ).fetchone()


def get_artifacts(conn: sqlite3.Connection, sid: int) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM artifacts WHERE session_id = ? ORDER BY id ASC", (sid,)
    ).fetchall())


def get_artifact(conn: sqlite3.Connection, aid: int) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM artifacts WHERE id = ?", (aid,)
    ).fetchone()


def get_session_issues(conn: sqlite3.Connection, sid: int) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM issues WHERE session_id = ? ORDER BY "
        "CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, id",
        (sid,),
    ).fetchall())


def get_session_latency(conn: sqlite3.Connection, sid: int) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM latency_targets WHERE session_id = ? ORDER BY id", (sid,)
    ).fetchall())


def get_session_ports(conn: sqlite3.Connection, sid: int) -> list[sqlite3.Row]:
    return list(conn.execute(
        "SELECT * FROM port_results WHERE session_id = ? ORDER BY id", (sid,)
    ).fetchall())


def aggregate_kpis(conn: sqlite3.Connection) -> dict:
    """High-level numbers for the dashboard hero strip."""
    row = conn.execute(
        "SELECT count(*) AS scans, "
        "       sum(issue_critical) AS critical, "
        "       sum(issue_warning) AS warnings, "
        "       sum(port_blocked) AS ports_blocked, "
        "       avg(duration_seconds) AS avg_duration "
        "FROM scan_sessions"
    ).fetchone()
    return {
        "scans": int((row["scans"] or 0)),
        "critical": int((row["critical"] or 0)),
        "warnings": int((row["warnings"] or 0)),
        "ports_blocked": int((row["ports_blocked"] or 0)),
        "avg_duration": float(row["avg_duration"] or 0.0),
    }
