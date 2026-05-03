"""Future VPS upload hook.

Intentionally inert. Once the dashboard payload format is finalized the
``upload_report`` function below should POST to the API and surface the
result. Keep all upload concerns isolated to this module so the rest of
the app stays unaware of the network boundary.

Suggested implementation when ready:

    import requests
    resp = requests.post(VPS_URL, json=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()
"""

from __future__ import annotations

from .logger import get_logger

# Set to your dashboard endpoint when implementing.
VPS_URL = ""


def upload_report(payload: dict) -> dict:
    """Stub. Returns a status dict; never raises."""
    log = get_logger()
    log.info(
        "upload_report() called but upload is not implemented. "
        "Payload keys: %s",
        sorted(payload.keys()),
    )
    return {
        "ok": False,
        "implemented": False,
        "message": (
            "VPS upload is not enabled yet. Configure VPS_URL in "
            "voipscan/upload.py and replace this stub once the payload "
            "format is finalized."
        ),
    }
