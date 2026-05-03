# VoIP Health Check — Desktop Client (LocalScanner)

A small portable Windows GUI that runs **evidence-focused** local
network diagnostics for VoIP troubleshooting. Built around Python's
standard library + a bundled `nmap.exe` so it can run straight from a
USB stick on locked-down customer machines without installation.

```
LocalScanner/
├── voipscan/                 # GUI + scan engine (modular, easy to edit)
│   ├── ui.py                 # Tkinter layout, streaming log + summary view
│   ├── scanner.py            # Orchestrator: runs every evidence module
│   ├── sangoma_ports.py      # Editable Sangoma Business Voice port catalog
│   ├── report.py             # Structured ScanReport dataclasses (JSON-ready)
│   ├── netinfo.py            # Host / interface / gateway / DNS discovery
│   ├── porttests.py          # Python-socket TCP/UDP probes
│   ├── sipalg.py             # Multi-method SIP ALG evidence
│   ├── vlan.py               # VLAN 41 evidence assessment
│   ├── interpret.py          # Plain-English section builder
│   ├── capture.py            # Packet-capture detection / stub
│   ├── upload.py             # Future VPS upload hook (inert)
│   ├── logger.py             # Rotating file log + GUI sink
│   └── paths.py              # Finds bundled nmap, logo, log dir
├── voipscan_app.py           # Entry point used by run.bat / PyInstaller
├── assets/logo.png           # Branding (mirrors web/static/logo.png)
├── build_tools/
│   ├── voipscan.spec         # PyInstaller spec — produces one-file .exe
│   └── build_windows.bat
├── nmap/                     # PRESERVED — drop a portable Nmap build here
├── run.bat                   # Dev launcher
├── requirements.txt
└── legacy_backup/            # Previous client kept for reference only
```

> **Heads up:** the `nmap/` directory is intentionally untouched by
> this client. Keep your portable Nmap build there exactly as before;
> the GUI looks for `nmap/nmap.exe` next to the running executable
> first, then for `Nmap/nmap.exe`, then for a system install. The
> evidence scan **does not require nmap** — when it's missing, the
> Python-socket port tests and SIP probes still run.

## What the evidence scan checks

| Group | What we gather | Confidence we can claim |
|-------|----------------|-------------------------|
| Host & Network | Hostname, local + public IP, default gateway (with MAC + vendor hint), DNS, first traceroute hops | Confirmed |
| VLAN 41 | `Get-NetAdapter` VLAN ID, NIC advanced VLAN registry hint, IPv4 subnet hint (`10.41.x.x` / `192.168.41.x`), operator gateway hint | Confirmed / Likely / Inconclusive |
| SIP ALG | SIP OPTIONS over UDP and TCP to a configured test endpoint (Via/Contact rewrite check), public-vs-private IP context, Windows local services (negative evidence), gateway-vendor prior (SonicWall / FortiGate / Cisco / etc.) | Strong / Likely / Inconclusive |
| Sangoma port reachability | Every rule in the published port guide. Big ranges (RTP 10000-65000, Mobile 10000-40000, etc.) are **sampled** — see `sangoma_ports.py`. | Confirmed (TCP), Inconclusive (UDP without reply) |
| Device attribution | Combines port test results, gateway vendor and operator-supplied IPs to point at *local-firewall / gateway / firewall / ISP / remote* | Likely / Inconclusive |
| Packet capture | Detects Npcap / Wireshark dumpcap so the operator can confirm the only definitive proof method (capture → diff) is feasible | n/a |

### Honest limits

A client-only Windows app **cannot absolutely prove** SIP ALG or a UDP
firewall block without a cooperating external test endpoint. The report
is explicit about this — verdicts are tagged `confirmed`, `strong`,
`likely`, `inconclusive`, or `not_detected`, and every ALG suggestion
includes the next-step that *would* yield definitive proof (capture +
header diff, or a known SBC echo).

### Configurable SIP test endpoint

Under *Optional → Advanced → SIP test endpoint*, paste a SIP OPTIONS
target as `host:port` (default port 5060). When set, the SIP ALG module
sends UDP and TCP OPTIONS messages and compares the reply's `Via` /
`Contact` headers against what was sent — a mismatch is **strong**
evidence of header rewriting, i.e. SIP ALG.

### Advanced is fully optional (auto-detected where possible)

Every field under *Advanced* is optional. If you leave a field blank
the scanner does **not** treat it as missing or as an error — it
either auto-detects the value or skips that specific check cleanly:

| Field | Blank behavior |
|-------|----------------|
| Hosted Platform | Defaults to *Auto / unknown*. The scanner infers context from scan data instead of forcing a platform. |
| Gateway IP | Auto-detected from `ipconfig` / `route` (Windows) or `ip route` (Linux). The auto value is recorded as `auto_detected` in the report. |
| Firewall IP | Not assumed to equal the gateway. In-path attribution reports `gateway-or-firewall` and explains that confidence is limited by the missing input. |
| Starbox IP | Starbox-specific overrides are skipped cleanly — no fake target is invented. |
| SIP test endpoint | External SIP OPTIONS probes are skipped. The ALG verdict is reported as *limited / inconclusive*; non-endpoint ALG signals (vendor prior, NAT context, Windows services, port reachability) still run. |
| Problem dropdown / custom problem | Both blank → scan still runs. The summary records "no problem specified" instead of forcing a problem-specific analysis. |

The structured `ScanReport` carries a `resolved_inputs` block that
splits values into `manual_inputs` (what the operator typed),
`auto_detected` (what the scanner inferred), and `skipped` (which
checks were intentionally left out) so the future VPS upload can tell
provided values apart from inferred ones.

## Output

* The streaming log box mirrors every module's progress live during the
  scan. When the scan finishes:
  * The full streaming log + JSON `ScanReport` is saved to
    `logs/voipscan_evidence_YYYYMMDD_HHMMSS.log`.
  * The Results panel switches to a **plain-English summary** with
    one section per evidence group, each marked with a colored status
    badge (green / yellow / red / blue / grey) drawn directly on a Tk
    Canvas (no external image assets).
* **Download Results** saves either the structured JSON (default — same
  shape `voipscan/upload.py` will eventually POST to the VPS) or a
  plain-text rendering that includes the summary + raw log.
* Use **Show Raw Log** / **Show Summary** to switch between views at
  any time.

## Run from source (dev)

Requires Python 3.10+ on Windows (Tkinter ships with the official
python.org installer). On Linux/macOS the GUI runs but Windows-specific
modules (`Get-NetAdapter`, `ipconfig`, `arp`) are short-circuited.

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

Output: `LocalScanner\dist\VoIPHealthCheck.exe` (one-file, no installer).

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
| `logs/voipscan.log` | Rotating runtime log (1 MB × 3) |
| `logs/voipscan_evidence_*.log` | Per-scan saved log + JSON report |
| `reports/` | Default save location for "Download Results" |

## Customizing

- **Edit dropdown options / labels** — top of `voipscan/ui.py`
  (`PROBLEM_OPTIONS`, `HOSTED_PLATFORMS`).
- **Edit Sangoma port catalog** — `voipscan/sangoma_ports.py`. Each
  rule has a `sample_ports` list controlling exactly which ports are
  actually probed; trim or extend it freely.
- **Edit nmap commands / port lists (legacy pass)** — top of
  `voipscan/scanner.py` (`QUICK_TCP_PORTS`, `TARGETED_TCP_PORTS`, …).
- **Add a new evidence module** — drop a new file under `voipscan/`,
  call it from `run_evidence_scan()` in `voipscan/scanner.py`, attach
  its results to the `ScanReport` and add a section in
  `voipscan/interpret.py` so it shows in the GUI.
- **Wire up VPS upload** — fill in `voipscan/upload.py`'s
  `upload_report()`. The payload is exactly `ScanReport.to_dict()` so
  the schema is single-sourced in `report.py`.
- **Enable real packet capture** — replace `start_capture_stub()` in
  `voipscan/capture.py` with a `dumpcap.exe` shellout or `pyshark`
  call once the driver story is settled.

## Legacy

The previous `local_scanner.py` / `advanced_scanner.py` / `run_scanner.bat`
have been moved to `legacy_backup/` for reference. They are not used by
the new client.
