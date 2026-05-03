"""VoIP Health Check — desktop client package.

Modules:
    paths         — locates bundled resources (nmap, logo, logs) at runtime.
    logger        — file + in-memory logging helpers.
    sangoma_ports — readable, editable Sangoma Business Voice port catalog.
    report        — structured ScanReport dataclasses (JSON-serializable).
    netinfo       — host/interface/gateway/DNS discovery helpers.
    porttests     — Python socket port reachability tests.
    sipalg        — multi-method SIP ALG evidence gathering.
    vlan          — VLAN 41 evidence assessment.
    interpret     — turns a ScanReport into plain-English Section objects.
    scanner       — orchestrator + legacy nmap profile runner.
    capture       — packet-capture stub (Windows driver dependent).
    upload        — placeholder for future VPS dashboard upload.
    ui            — Tkinter GUI with streaming log + post-scan summary view.
"""

__version__ = "2.1.0"
__app_name__ = "VoIP Health Check"
