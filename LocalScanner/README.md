# VoIP Health Check — Desktop Client (LocalScanner)

A small portable Windows GUI that runs local network diagnostics for
VoIP troubleshooting. Built around a bundled `nmap.exe` so it can run
straight from a USB stick on locked-down customer machines without
installation.

```
LocalScanner/
├── voipscan/           # GUI + scan engine (modular, easy to edit)
│   ├── ui.py           # Tkinter layout, theming, button handlers
│   ├── scanner.py      # nmap command builders + runner
│   ├── capture.py      # packet-capture detection / stub
│   ├── upload.py       # placeholder for future VPS upload
│   ├── logger.py       # rotating file log + GUI sink
│   └── paths.py        # finds bundled nmap, logo, log dir
├── voipscan_app.py     # entry point used by run.bat / PyInstaller
├── assets/logo.png     # branding (mirrors web/static/logo.png)
├── build_tools/
│   ├── voipscan.spec   # PyInstaller spec — produces one-file .exe
│   └── build_windows.bat
├── nmap/               # PRESERVED — drop a portable Nmap build here
├── run.bat             # dev launcher
├── requirements.txt
└── legacy_backup/      # previous client kept for reference only
```

> **Heads up:** the `nmap/` directory is intentionally untouched by
> this client. Keep your portable Nmap build there exactly as before;
> the new GUI looks for `nmap/nmap.exe` next to the running executable
> first, then for `Nmap/nmap.exe`, then for a system install.

## Features

- **Quick Scan** — fast TCP/UDP sweep of the common VoIP ports across
  the configured local subnets.
- **Scan Now** (under *Optional*) — targeted scan of operator-supplied
  Gateway / Firewall / Starbox IPs, with a deeper port set.
- **Optional metadata** — drop-down for the user-reported problem,
  free-text "different problem" field, and an Advanced section with
  hosted-platform radio buttons and IP fields.
- **Live results / log** — every nmap line is streamed into the bottom
  panel as it arrives.
- **Download Results** — saves a JSON (default) or plain-text report,
  including the form metadata, command line, and full output.
- **Detailed logging** — rotating file log under `logs/voipscan.log`
  with full stack traces for any exception. Friendly error dialogs
  surface in the GUI.
- **Packet capture (foundation only)** — UI present, but live capture
  is *not* enabled until the Windows packet driver is confirmed. The
  button reports detected engines (Npcap / dumpcap) without pretending
  to capture.

## Run from source (dev)

Requires Python 3.10+ on Windows (Tkinter ships with the official
python.org installer). On other platforms the GUI may run but nmap
discovery / packet capture are Windows-specific.

```cmd
cd LocalScanner
run.bat
```

…or directly:

```cmd
cd LocalScanner
python voipscan_app.py
```

## Build a portable Windows `.exe`

```cmd
cd LocalScanner
build_tools\build_windows.bat
```

Output: `LocalScanner\dist\VoIPHealthCheck.exe` (one-file, no
installer needed).

When distributing, ship the `.exe` *with* a sibling `nmap/` folder:

```
VoIPHealthCheck/
├── VoIPHealthCheck.exe
├── nmap/
│   └── nmap.exe (+ data files)
└── (logs/, reports/ are created on first run)
```

## Where things go

| Path | What |
|------|------|
| `logs/voipscan.log` | Rotating log file (1 MB × 3) |
| `reports/` | Default save location for "Download Results" |

## Customizing

- **Edit dropdown options / labels** — top of `voipscan/ui.py`
  (`PROBLEM_OPTIONS`, `HOSTED_PLATFORMS`).
- **Edit nmap commands / port lists** — top of `voipscan/scanner.py`
  (`QUICK_TCP_PORTS`, `TARGETED_TCP_PORTS`, `QUICK_SUBNETS`, …).
- **Add a new scan profile** — copy `build_quick_profile()` in
  `voipscan/scanner.py`, expose a new button in `voipscan/ui.py`.
- **Wire up VPS upload** — fill in `voipscan/upload.py`'s
  `upload_report()`. The rest of the app already collects a structured
  payload via `_collect_form()` + scan results.
- **Enable real packet capture** — replace `start_capture_stub()` in
  `voipscan/capture.py` with a `dumpcap.exe` shellout or `pyshark`
  call once the driver story is settled.

## Legacy

The previous `local_scanner.py` / `advanced_scanner.py` / `run_scanner.bat`
have been moved to `legacy_backup/` for reference. They are not used by
the new client.
