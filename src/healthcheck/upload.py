"""Auto-upload of scan reports / logs / captures to the VPS dashboard.

The desktop client calls these functions from ``ui.py`` once a scan
finishes (``upload_scan_session``) and once a packet capture stops
(``upload_capture_artifact``). Network failures never raise — the
helpers always return a status dict and the local files are kept on
disk regardless of what happens upstream.

Endpoint configuration (in priority order):

1. Environment variable ``VOIPSCAN_VPS_URL`` (full base URL, e.g.
   ``https://voipscan.danielscience.com``).
2. ``vps_url`` value in ``%LOCALAPPDATA%/VoipScan/upload.json`` /
   ``~/.config/voipscan/upload.json``.
3. The hard-coded ``DEFAULT_VPS_URL`` below.

Optional bearer token (sent as ``Authorization: Bearer <token>``):

1. Environment variable ``VOIPSCAN_UPLOAD_TOKEN``.
2. ``token`` value in the JSON config file above.

Tokens are *optional*. The VPS endpoint accepts unauthenticated uploads
when no ``VOIPSCAN_UPLOAD_TOKEN`` is set on the server side. When a
token *is* set on the server, the desktop client must send the matching
value or the upload is rejected with HTTP 401.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any, Optional

try:  # ``requests`` is preferred when available — bundled in many envs.
    import requests  # type: ignore
except Exception:  # pragma: no cover - graceful fallback for stdlib-only builds
    requests = None  # type: ignore

import urllib.error
import urllib.request

from .logger import get_logger
from .report import ScanReport

# Sensible default — the production VPS. Can always be overridden via
# environment or config without editing the file.
DEFAULT_VPS_URL = "https://voipscan.danielscience.com"

# 25 MB cap on a single uploaded artifact (capture/log). Keeps the VPS
# from blowing up on accidental gigabyte captures while still big enough
# for normal SIP/RTP traces.
MAX_ARTIFACT_BYTES = 25 * 1024 * 1024

UPLOAD_TIMEOUT_SECONDS = 30


def _config_dir() -> Path:
    """Per-user dir for the optional ``upload.json`` overrides file."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return Path(base) / "VoipScan"
    return Path(os.path.expanduser("~/.config/voipscan"))


def _load_config_file() -> dict:
    path = _config_dir() / "upload.json"
    try:
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        get_logger().info("upload.json could not be read; using defaults.")
    return {}


def get_vps_url() -> str:
    env = (os.environ.get("VOIPSCAN_VPS_URL") or "").strip()
    if env:
        return env.rstrip("/")
    cfg = _load_config_file()
    cfg_url = (cfg.get("vps_url") or "").strip()
    if cfg_url:
        return cfg_url.rstrip("/")
    return DEFAULT_VPS_URL.rstrip("/")


def get_upload_token() -> str:
    env = (os.environ.get("VOIPSCAN_UPLOAD_TOKEN") or "").strip()
    if env:
        return env
    cfg = _load_config_file()
    return (cfg.get("token") or "").strip()


def _auth_headers() -> dict[str, str]:
    token = get_upload_token()
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


# --- Low-level HTTP helpers ------------------------------------------------

def _user_agent() -> str:
    """Identify the LocalScanner build to the VPS / any proxy in front of it.

    Some default nginx / WAF rules block requests that arrive with a
    bare Python user-agent, which is one of the common causes of an
    otherwise-mysterious HTTP 403 on POST. Sending a stable, identifying
    UA is both more polite and easier to whitelist.
    """
    try:
        from . import __version__
    except Exception:
        __version__ = "unknown"
    return f"VoIPScan-LocalScanner/{__version__}"


def _read_response_with_status(r) -> tuple[int, dict]:
    text = r.read().decode("utf-8", errors="replace")
    try:
        return r.status, json.loads(text)
    except Exception:
        return r.status, {"_text": text[:2000]}


def _http_error_to_tuple(e: urllib.error.HTTPError) -> tuple[int, dict]:
    """Convert an HTTPError into the same (status, body) shape as success.

    Without this, urllib raises HTTPError on any 4xx/5xx — the previous
    upload code converted the exception into a generic "network error"
    log line which is exactly what the user saw with the 403. Capturing
    the status code lets the GUI tell the operator "rejected by server"
    vs "no network".
    """
    try:
        body_bytes = e.read() or b""
    except Exception:
        body_bytes = b""
    text = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    try:
        body = json.loads(text) if text else {}
    except Exception:
        body = {"_text": text[:2000]}
    return int(e.code), body


def _post_json(url: str, payload: dict) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": _user_agent()}
    headers.update(_auth_headers())

    if requests is not None:
        resp = requests.post(
            url,
            data=body,
            headers=headers,
            timeout=UPLOAD_TIMEOUT_SECONDS,
        )
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, {"_text": resp.text[:2000]}

    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=UPLOAD_TIMEOUT_SECONDS) as r:
            return _read_response_with_status(r)
    except urllib.error.HTTPError as e:
        return _http_error_to_tuple(e)


def _post_multipart(
    url: str, file_path: Path, fields: dict[str, str], file_field: str = "file"
) -> tuple[int, dict]:
    if not file_path.exists():
        raise FileNotFoundError(file_path)
    size = file_path.stat().st_size
    if size > MAX_ARTIFACT_BYTES:
        raise ValueError(f"artifact {file_path.name} ({size}B) exceeds {MAX_ARTIFACT_BYTES}B cap")

    headers = _auth_headers()
    headers["User-Agent"] = _user_agent()
    if requests is not None:
        with file_path.open("rb") as f:
            files = {file_field: (file_path.name, f, "application/octet-stream")}
            resp = requests.post(
                url,
                data=fields,
                files=files,
                headers=headers,
                timeout=UPLOAD_TIMEOUT_SECONDS,
            )
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, {"_text": resp.text[:2000]}

    # Stdlib fallback — build a multipart body by hand. Avoids adding a
    # hard dep on ``requests`` for the portable Windows exe build.
    boundary = "----voipscanboundary" + os.urandom(8).hex()
    parts: list[bytes] = []
    for k, v in fields.items():
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
        parts.append(f"{v}\r\n".encode())
    with file_path.open("rb") as fh:
        file_bytes = fh.read()
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{file_path.name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode()
    )
    parts.append(file_bytes)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    body = b"".join(parts)
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    headers["Content-Length"] = str(len(body))
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=UPLOAD_TIMEOUT_SECONDS) as r:
            return _read_response_with_status(r)
    except urllib.error.HTTPError as e:
        return _http_error_to_tuple(e)


# --- Public API ------------------------------------------------------------

def example_payload() -> dict[str, Any]:
    """Returns the empty ScanReport dict — useful for VPS schema work."""
    return ScanReport().to_dict()


def upload_scan_session(
    report: ScanReport,
    log_path: Optional[Path] = None,
) -> dict:
    """Upload a structured ScanReport plus its raw log to the VPS.

    Never raises. Returns a status dict with at least:
      ``ok``, ``url``, ``session_id`` (server-assigned), ``artifact_ids``.
    """
    log = get_logger()
    base = get_vps_url()
    if not base:
        return {"ok": False, "implemented": False,
                "message": "no VPS URL configured"}

    payload = {
        "schema_version": report.schema_version,
        "client_session_id": report.session_id,
        "report": report.to_dict(),
    }
    out: dict[str, Any] = {"ok": False, "url": base, "artifact_ids": []}

    try:
        status, body = _post_json(f"{base}/api/v2/scan/upload", payload)
        out["status_code"] = status
        out["server"] = body
        if status >= 400:
            log.warning("scan upload returned HTTP %s", status)
            if isinstance(body, dict):
                out["message"] = (
                    body.get("message")
                    or body.get("_text")
                    or f"HTTP {status}"
                )
            else:
                out["message"] = f"HTTP {status}: {body}"
            return out
        server_id = (body or {}).get("session_id")
        out["session_id"] = server_id
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        log.warning("scan upload network failure: %s", e)
        out["message"] = f"network error: {e}"
        return out
    except Exception as e:
        log.warning("scan upload unexpected error: %s", e)
        out["message"] = f"error: {e}"
        return out

    # Best-effort raw-log upload alongside the JSON. A missing log file
    # isn't fatal — the JSON has already been recorded server-side.
    if log_path and log_path.exists() and out.get("session_id"):
        try:
            status, body = _post_multipart(
                f"{base}/api/v2/scan/{out['session_id']}/artifact",
                log_path,
                fields={"kind": "log"},
            )
            if status < 400 and isinstance(body, dict) and body.get("artifact_id"):
                out["artifact_ids"].append(body["artifact_id"])
            elif status >= 400:
                log.warning("scan log artifact returned HTTP %s", status)
        except Exception as e:
            log.warning("scan log artifact upload failed: %s", e)

    out["ok"] = True
    return out


def upload_log_artifact(
    log_path: Path,
    *,
    session_id: Optional[str] = None,
    notes: str = "",
) -> dict:
    """Upload a log file as a standalone (or session-attached) artifact.

    Used by the GUI to guarantee a log is shipped on every completion
    path — scan success, scan failure, capture stop, even when no PCAP
    or scan JSON exists. Never raises.
    """
    log = get_logger()
    base = get_vps_url()
    if not base:
        return {"ok": False, "message": "no VPS URL configured"}
    if not log_path.exists():
        return {"ok": False, "message": f"missing log file: {log_path}"}

    fields = {"kind": "log", "notes": (notes or "")[:1000]}
    if session_id:
        url = f"{base}/api/v2/scan/{session_id}/artifact"
    else:
        # No scan session yet — use the standalone capture endpoint,
        # which accepts ``.txt``/``.log`` extensions and records the
        # artifact under session_id=NULL so the dashboard still surfaces it.
        fields["kind"] = "capture"
        fields["engine"] = "log-only"
        url = f"{base}/api/v2/capture/upload"

    try:
        status, body = _post_multipart(url, log_path, fields)
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        log.warning("log artifact network failure: %s", e)
        return {"ok": False, "message": f"network error: {e}"}
    except Exception as e:
        log.warning("log artifact unexpected error: %s", e)
        return {"ok": False, "message": f"error: {e}"}

    out = {
        "ok": status < 400,
        "status_code": status,
        "server": body,
        "url": url,
    }
    if not out["ok"] and isinstance(body, dict):
        out["message"] = body.get("message") or body.get("_text") or f"HTTP {status}"
    return out


def upload_capture_artifact(
    capture_path: Path,
    *,
    session_id: Optional[str] = None,
    engine: str = "",
    notes: str = "",
) -> dict:
    """Upload a capture file (.pcapng / .etl / .txt). Never raises.

    If ``session_id`` is provided the capture is associated to that
    server-assigned scan session. Otherwise it is uploaded as a
    standalone capture so the dashboard can still surface it.
    """
    log = get_logger()
    base = get_vps_url()
    if not base:
        return {"ok": False, "message": "no VPS URL configured"}
    if not capture_path.exists():
        return {"ok": False, "message": f"missing file: {capture_path}"}

    fields = {
        "kind": "capture",
        "engine": engine or "",
        "notes": notes or "",
    }
    if session_id:
        url = f"{base}/api/v2/scan/{session_id}/artifact"
    else:
        url = f"{base}/api/v2/capture/upload"

    try:
        status, body = _post_multipart(url, capture_path, fields)
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        log.warning("capture upload network failure: %s", e)
        return {"ok": False, "message": f"network error: {e}"}
    except Exception as e:
        log.warning("capture upload error: %s", e)
        return {"ok": False, "message": f"error: {e}"}

    out: dict = {
        "ok": status < 400,
        "status_code": status,
        "server": body,
        "url": url,
    }
    if not out["ok"] and isinstance(body, dict):
        out["message"] = body.get("message") or body.get("_text") or f"HTTP {status}"
    return out


def upload_report(payload: dict) -> dict:
    """Backwards-compatible shim for the old single-call upload.

    Accepts a ``ScanReport.to_dict()`` payload (what older callers pass)
    and forwards it to the v2 endpoint without an accompanying log.
    """
    base = get_vps_url()
    if not base:
        return {"ok": False, "implemented": False,
                "message": "no VPS URL configured"}
    body = {
        "schema_version": payload.get("schema_version", "1.0"),
        "client_session_id": payload.get("session_id", ""),
        "report": payload,
    }
    try:
        status, server = _post_json(f"{base}/api/v2/scan/upload", body)
        return {"ok": status < 400, "status_code": status, "server": server}
    except Exception as e:
        return {"ok": False, "message": f"error: {e}"}
