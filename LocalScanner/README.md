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
| Packet capture | Live capture from the GUI using Wireshark `dumpcap` (preferred) or built-in Windows `pktmon` (fallback). Output saved to `captures/` as `.pcapng` (or `.etl`/`.txt` for older pktmon). | n/a |

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

## Packet capture

The **Start Packet Capture** button records VoIP-relevant traffic to a
file you can open in Wireshark. Click it once to start; click again
(the button reads **Stop Packet Capture**) to stop and finalize the
file. Captures are written to a `captures/` folder next to the
executable with timestamped filenames.

The app picks an engine in this order:

1. **Wireshark `dumpcap`** — preferred. Looked up on `PATH` and at
   `C:\Program Files\Wireshark\dumpcap.exe`. Writes a real `.pcapng`
   with a BPF filter focused on SIP (5060/5061), Sangoma signalling
   (5160/5161, 8088/8089, 2160) and a slice of RTP (`UDP 10000-20000`).
   Requires **Npcap** (https://npcap.com/) for live capture; if Npcap
   isn't found a warning is logged but capture is still attempted.
2. **Windows `pktmon`** — built-in fallback (Windows 10 1809+). Filters
   the same SIP/Sangoma ports, captures to `.etl`, and on stop tries to
   convert to `.pcapng` via `pktmon etl2pcap`. On older builds without
   `etl2pcap` the app additionally writes a text dump from
   `pktmon format` so the data is still inspectable. **`pktmon`
   requires running the app as Administrator.**

If neither tool is available a friendly message points at the
Wireshark installer or the built-in `pktmon` so the operator knows
exactly what to install.

If a capture starts but produces an empty file, the most common cause
is missing Npcap (for `dumpcap`) or insufficient privileges (for
`pktmon`). Re-run the app **as Administrator** and confirm Npcap is
installed.

The BPF filter, port list, soft stop time, and output location are
declared as constants at the top of `voipscan/capture.py` so they're
easy to tweak.

## Quick Scan / nmap pass behavior

The legacy nmap "Quick Scan" used to broadcast across two full `/24`
subnets with both TCP and UDP ports listed under a `-sT` connect scan,
which both wasted UDP probes (nmap silently ignores UDP entries with
`-sT`) and frequently took 10+ minutes — long enough that the operator
saw the GUI as hung.

The current nmap pass:

* Defaults to **no broad subnet target** — only operator-supplied IPs
  (Gateway / Firewall / Starbox under *Advanced*) or the auto-detected
  default gateway.
* Splits TCP and UDP correctly: Quick Scan is TCP-only, the Targeted
  Scan adds `-sU` for UDP because the host list is small.
* Adds `--host-timeout 60s` and `--max-retries 1` so a single
  unresponsive host can't stall the whole scan.
* Caps overall nmap wall-clock at 5 minutes; on timeout the run is
  killed and the rest of the evidence scan still finishes.
* Streams `[scan] starting`, the literal command, every nmap output
  line, and a final `completed` / `timed out` / `rc=…` line so the
  operator can always see why the scan ended.

The constants live at the top of `voipscan/scanner.py`
(`QUICK_TCP_PORTS`, `NMAP_HOST_TIMEOUT`, `NMAP_OVERALL_TIMEOUT_SECONDS`)
and can be edited freely.

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
| `captures/` | Packet captures (`.pcapng` from dumpcap, or `.etl`/`.pcapng`/`.txt` from pktmon) |

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
- **Tweak packet capture filters / output** — top of
  `voipscan/capture.py` (`DUMPCAP_BPF_FILTER`,
  `DUMPCAP_AUTOSTOP_SECONDS`, `DUMPCAP_AUTOSTOP_MEGABYTES`, the pktmon
  port set, `PKTMON_AUTOSTOP_SECONDS`).

## Legacy

The previous `local_scanner.py` / `advanced_scanner.py` / `run_scanner.bat`
have been moved to `legacy_backup/` for reference. They are not used by
the new client.
