# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for the VoIP Health Check desktop client.
# Produces a single-file Windows .exe with the logo bundled in.
#
# Build:
#     cd LocalScanner
#     pyinstaller build_tools/voipscan.spec --noconfirm
#
# The bundled nmap/ directory is intentionally NOT embedded inside the
# .exe — it's distributed alongside the binary so users can update nmap
# without rebuilding the client. ``voipscan/paths.py`` looks for it next
# to the running .exe at ``./nmap/nmap.exe``.

import os
from pathlib import Path

# ``SPECPATH`` is provided by PyInstaller and points at this spec file's
# directory.
HERE = Path(SPECPATH).resolve()
PROJECT = HERE.parent  # LocalScanner/

datas = [
    (str(PROJECT / "assets" / "logo.png"), "assets"),
]

a = Analysis(
    [str(PROJECT / "voipscan_app.py")],
    pathex=[str(PROJECT)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="VoIPHealthCheck",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI app — no console window.
    disable_windowed_traceback=False,
    icon=None,
)
