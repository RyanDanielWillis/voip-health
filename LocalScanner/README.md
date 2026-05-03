# VoIP Health Check — Desktop Client (LocalScanner)

A small portable Windows GUI that runs **evidence-focused** local
network diagnostics for VoIP troubleshooting. Built around Python's
standard library + a bundled `nmap.exe` so it can run straight from a
USB stick on locked-down customer machines without installation.

> **Screenshot of the desktop client** is checked in at the repo root
> as `client_gui.png` (also served by the Flask homepage at
> `/static/client_gui.png`). The repo-root README and the homepage
> describe what each control on the window does.

## Download (Windows)

The portable `VoIPHealthCheck.exe` is produced by GitHub Actions from
[`build-localscanner.yml`](../.github/workflows/build-localscanner.yml).
The latest exe is available as a workflow-run artifact:

1. Open the **Build LocalScanner Windows EXE** workflow in GitHub
   Actions.
2. Pick the most recent successful run on `main`.
3. Download `VoIPHealthCheck-windows-exe` (just the exe) or
   `VoIPHealthCheck-windows-package` (exe + bundled `nmap/`).

A direct `.exe` is **not** committed to the repo on purpose — the build
workflow is the source of truth so the binary always tracks the source.

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
| **Latency / jitter / packet loss** | ICMP ping (8 samples, 1.5 s timeout) to gateway, two public anchors (`8.8.8.8`, `1.1.1.1`) and a Sangoma representative host. Computes min / avg / max RTT, packet loss, and **jitter = mean(\|rtt[i] − rtt[i−1]\|)** over received samples. | Strong (when replies arrive), Likely / Inconclusive otherwise |
| **DHCP / IP-assignment evidence** | Parses `ipconfig /all` (Windows) or `nmcli`/`ip` (Linux) for per-adapter DHCP-enabled flag, DHCP server IP, lease times, IPv4 and gateway. Infers whether the gateway, a dedicated DHCP server, or a static config is assigning the IP. | Strong / Likely / Inconclusive |
| Device attribution | Combines port test results, gateway vendor and operator-supplied IPs to point at *local-firewall / gateway / firewall / ISP / remote* | Likely / Inconclusive |
| Packet capture | Live capture from the GUI using Wireshark `dumpcap` (preferred) or built-in Windows `pktmon` (fallback). Output saved to `captures/` as `.pcapng` (or `.etl`/`.txt` for older pktmon). | n/a |

### Latency / jitter / packet loss (`voipscan/latency.py`)

The latency module is intentionally limited to the system `ping` binary
so it works without admin rights and on locked-down customer machines:

* **Targets** — the operator-supplied or auto-detected default gateway,
  two stable public anchors (`8.8.8.8`, `1.1.1.1`), and a Sangoma
  representative host (`sangoma_ports.DEFAULT_SANGOMA_HOST`, or the
  Starbox IP if the operator provided one).
* **Stats** — per-target `samples_sent`, `samples_received`,
  `packet_loss_pct`, `rtt_min_ms`, `rtt_avg_ms`, `rtt_max_ms`, and
  `jitter_ms`.
* **Jitter formula** — mean of the absolute differences between
  consecutive RTT samples (`mean(|rtt[i] - rtt[i-1]|)`). This is the
  classic VoIP / RFC 3550-style "interarrival jitter" approximation
  available from RTT timelines.
* **VoIP thresholds** — declared as constants at the top of
  `latency.py` (`RTT_GOOD_MS`, `JITTER_WARN_MS`, `LOSS_WARN_PCT`, …)
  so they're easy to tune.

Each target row is stored on `ScanReport.latency.targets` so the
structured JSON is upload-ready. Ping output parsing is exposed via
`parse_ping_output()` and `compute_jitter()` for unit testing without a
live network.

### DHCP / IP-assignment evidence (`voipscan/dhcp.py`)

* On Windows the module reads `ipconfig /all` and parses each adapter
  block for `DHCP Enabled`, `DHCP Server`, `Lease Obtained`, `Lease
  Expires`, `IPv4 Address`, and `Default Gateway`.
* On Linux it falls back to `nmcli device show` / `ip addr` and surfaces
  whatever it can find (best-effort).
* `infer_assigner()` then picks one of:
  * `router/firewall (gateway acts as DHCP server)` — strong confidence
    when the DHCP server IP equals the default gateway.
  * `dedicated DHCP server (not the gateway)` — likely confidence
    otherwise.
  * `static (no DHCP)` — strong confidence when DHCP is disabled.
  * `dhcp (server unknown)` — inconclusive when DHCP is enabled but no
    server has been seen.
* The report records an `inferred_assigner`, `inferred_assigner_ip`,
  `confidence`, `explanation` and a list of `limitations` (notably:
  *ipconfig only sees the current lease — rogue DHCP servers on the
  same broadcast domain are not detected without a passive capture*).

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

There are now **two dedicated buttons** — **Start Packet Capture** and
**Stop Packet Capture** — sitting side-by-side on the primary action
row with equal sizing and spacing. Start enables only when no capture
is running; Stop enables only while a capture is in progress, so the
operator can never get confused about whether a session is live.
Captures are written to a `captures/` folder next to the executable
with timestamped filenames.

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

### Troubleshooting: "scan never completes" / Quick Scan hangs

Starting in **2.2.0** (`__build_tag__ = "Safe Quick Scan profile"`) the
client emits these lines at startup, both to the GUI log box and to
`logs/voipscan.log`:

```
VoIP Health Check LocalScanner version 2.2.0 starting (build: Safe Quick Scan profile)
Executable: <full path to running exe> (frozen=True)
Working directory: <full path>
App root: <full path>
Build info: <path>\BUILD_INFO.txt
[safe] Safe Quick Scan profile active — build 2.2.0 (Safe Quick Scan profile). Legacy broad sweep across 192.168.1.0/24 + 192.168.41.0/24 is disabled in this build.
```

The version is also rendered as a chip in the upper-right of the GUI
header. If both the startup banner and the chip read `2.2.0` (or
later) you are on the safe build.

The CI-built distribution package now also contains:

* `VoIPHealthCheck.exe` — canonical name (existing shortcuts keep working).
* `VoIPHealthCheck-2.2.0.exe` — versioned copy. **Prefer launching this
  one** so the file name itself tells you which build is running.
* `BUILD_INFO.txt` — version, build tag, git SHA, GitHub Actions
  workflow run id, and a UTC build timestamp.
* `VERSION.txt` — single-line version string for tooling / quick checks.

If your log shows version `2.0.0`, an old `Quick Scan: ...
192.168.1.0/24 192.168.41.0/24` line, or no `Executable:` /
`Working directory:` lines at all, you are running an **old
executable** (likely a stale shortcut to `VoipScanner_Desktop\` from a
previous install). To recover:

1. Delete the old `VoipScanner_Desktop` folder (and any desktop or
   Start Menu shortcuts that point at it). Confirm there is no
   `VoIPHealthCheck.exe` left under your old install path.
2. Download the latest `VoIPHealthCheck-windows-package` artifact from
   the **Build LocalScanner Windows EXE** workflow on GitHub Actions.
3. **Extract the zip to a fresh folder** (for example
   `C:\Tools\VoIPHealthCheck-2.2.0\`). Do not extract on top of an
   older folder — the OS may keep the old exe if file names collide.
4. Launch `VoIPHealthCheck-2.2.0.exe` from inside the freshly
   extracted folder. Confirm:
   * The startup banner reads `version 2.2.0 starting (build: Safe
     Quick Scan profile)`.
   * The `Executable:` line points at the freshly extracted folder.
   * `BUILD_INFO.txt` exists next to the exe and lists the expected
     git SHA / workflow run.
5. If you are running from source, `git pull` and re-run
   `python voipscan_app.py` — the safe profile is enforced in
   `voipscan/scanner.py:build_quick_profile`, which now refuses any
   call that targets `192.168.1.0/24` / `192.168.41.0/24` or that
   pairs `-sT` with UDP ports. The legacy `legacy_backup/` scripts
   will also refuse to import.

## Output

* The streaming log box mirrors every module's progress live during the
  scan. When the scan finishes:
  * The full streaming log + JSON `ScanReport` is saved to
    `logs/voipscan_evidence_YYYYMMDD_HHMMSS.log`.
  * The Results panel switches to a **plain-English summary** with
    one section per evidence group, each marked with a colored status
    badge (green / yellow / red / blue / grey) drawn directly on a Tk
    Canvas (no external image assets).
* **Download Results** saves either the structured JSON (default — the
  same shape `voipscan/upload.py` POSTs to the VPS) or a plain-text
  rendering that includes the summary + raw log.
* Use **Show Raw Log** / **Show Summary** to switch between views at
  any time.

## Automatic VPS upload

When a scan finishes the client automatically POSTs the structured
`ScanReport` JSON and the raw log to the VPS dashboard at
`https://voipscan.danielscience.com/api/v2/scan/upload`. When a packet
capture stops, the resulting `.pcapng` / `.etl` / `.txt` file is
automatically uploaded too — associated with the previous scan when one
was uploaded earlier in the same session, otherwise as a standalone
capture.

Network failures never break the local scan or capture flow; the local
files always remain on disk regardless of upload status. Errors are
logged to the streaming output as `[upload] ...` lines.

### Configuration

| Setting | Env var | JSON field |
|---------|---------|------------|
| Endpoint base URL | `VOIPSCAN_VPS_URL` | `vps_url` |
| Optional bearer token | `VOIPSCAN_UPLOAD_TOKEN` | `token` |

The JSON config file lives at:

* Windows: `%LOCALAPPDATA%\VoipScan\upload.json`
* Linux / macOS: `~/.config/voipscan/upload.json`

Example `upload.json`:

```json
{
  "vps_url": "https://voipscan.danielscience.com",
  "token": "OPTIONAL_BEARER_TOKEN"
}
```

When the server has no `VOIPSCAN_UPLOAD_TOKEN` set, the desktop client
can leave its `token` blank too — uploads are accepted without auth.

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

When distributing, ship the `.exe` *with* a sibling `nmap/` folder.
The CI workflow (and `build_windows.bat` locally) stage a
self-identifying package so an operator can confirm what they are
running without launching the GUI:

```
VoIPHealthCheck/
├── VoIPHealthCheck.exe              # canonical name (keeps shortcuts working)
├── VoIPHealthCheck-2.2.0.exe        # versioned copy — prefer launching this
├── BUILD_INFO.txt                   # version, build tag, git SHA, workflow run id, UTC timestamp
├── VERSION.txt                      # single-line version string
├── nmap/
│   └── nmap.exe (+ data files)
└── (logs/, reports/ are created on first run)
```

The two exe files are byte-identical — both are produced from the same
PyInstaller build. Keep both: shortcuts pointing at the canonical name
keep working, and the versioned name makes it obvious at a glance
which build is in the folder.

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
