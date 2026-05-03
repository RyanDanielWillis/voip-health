"""VoIP Health Check — desktop client package.

Modules:
    paths    — locates bundled resources (nmap, logo, logs) at runtime.
    logger   — file + in-memory logging helpers.
    scanner  — nmap-driven scan logic. Easy to extend with new commands.
    capture  — packet-capture stub (Windows driver dependent).
    upload   — placeholder for future VPS dashboard upload.
    ui       — Tkinter GUI.
"""

__version__ = "2.0.0"
__app_name__ = "VoIP Health Check"
