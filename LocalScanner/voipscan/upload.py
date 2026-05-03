"""Future VPS upload hook.

Intentionally inert. The dashboard will eventually ingest the
JSON-serialized ``ScanReport`` produced by ``voipscan.scanner``; the
shape is documented in :func:`example_payload` below so the VPS-side
schema can be designed against the same fields.

Suggested implementation when ready:

    import requests
    resp = requests.post(VPS_URL, json=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()

The ``payload`` should be exactly ``ScanReport.to_dict()`` so the schema
stays single-sourced in ``report.py``.
"""

from __future__ import annotations

from typing import Any

from .logger import get_logger
from .report import ScanReport

# Set to your dashboard endpoint when implementing.
VPS_URL = ""


def example_payload() -> dict[str, Any]:
    """Returns the empty ScanReport dict so VPS schema authors can see
    every field without running a scan."""
    return ScanReport().to_dict()


def upload_report(payload: dict) -> dict:
    """Stub. Returns a status dict; never raises.

    Accepts the dict produced by ``ScanReport.to_dict()``.
    """
    log = get_logger()
    log.info(
        "upload_report() called but upload is not implemented. "
        "Top-level keys: %s",
        sorted(payload.keys()),
    )
    return {
        "ok": False,
        "implemented": False,
        "schema_version": payload.get("schema_version"),
        "message": (
            "VPS upload is not enabled yet. Configure VPS_URL in "
            "voipscan/upload.py and POST the ScanReport.to_dict() payload "
            "once the dashboard endpoint is live."
        ),
    }
