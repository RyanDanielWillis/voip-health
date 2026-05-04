<table>
  <tr><td width="200" align="center">
    <img src="web/static/logo.png" alt="VoIP Health Check logo" width="160">
  </td>
  <td>
   <h1>VoIP Health Check</h1>

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)[![Beta]]

**Diagnose VoIP problems and security risks with plain-english fixes.** <br>
Scans your PBX/phone system for one-way audio, choppy calls, exposed extensions, and more — then tells you exactly what's wrong and how to fix it.
  </td></tr>
</table>

## What it finds & fixes

| Problem | Likely Cause | Simple Fix |
|---------|--------------|------------|
| **One-way audio** | NAT/firewall blocking RTP | Disable SIP ALG + disable NAT on the internet modem |
| **Choppy audio** | Packet loss or jitter | Prioritize VoIP traffic with QoS (EF marking) |
| **No audio at all** | Codec mismatch | Enable G.711 on FreePBX |
| **Registration fails** | Wrong auth or NAT | Check phone configuration or firmware version |

## Usage
Download the portable Windows client from the
[**GitHub Releases page**](https://github.com/RyanDanielWillis/voip-health/releases/latest)
(permanent location, latest release) — also linked from the
[hosted homepage](https://voipscan.danielscience.com). See results at
https://voipscan.danielscience.com/dashboard.

## Desktop client (Windows)

<p align="center">
  <img src="client_gui.png"
       alt="VoIP Health Check Windows client GUI showing Quick Scan, packet capture, and the scan results / log pane."
       width="400">
</p>

A portable Windows GUI for on-site VoIP diagnostics. One click runs the
full pipeline (SIP ALG, port reachability, latency / jitter, DHCP, VLAN)
and uploads a structured report to the hosted dashboard.

**Main controls:**

- **Quick Scan** — one-click diagnostics; gateway is auto-detected.
- **Start / Stop Packet Capture** — dedicated buttons; uses `dumpcap`
  (Wireshark/Npcap) when present and falls back to a non-admin
  `pktmon` evidence file so something always lands on disk.
- **Stop Scan** — cancel a running scan cleanly without closing the
  app.
- **Advanced options → Run Advanced Scan** — same Quick Scan checks
  plus a deeper SIP/RTP port sweep and longer latency sampling. Tucked
  under Advanced so the main view stays simple.
- **Optional card** — *Problem Experienced* dropdown, free-text field,
  and (under Advanced) hosted platform / gateway IP / firewall IP /
  starbox IP / SIP test endpoint. Every field is optional.

After each scan the report, raw log, and any captures are uploaded to
the VPS automatically and surface on the
[dashboard](https://voipscan.danielscience.com/dashboard) with latency
and jitter ratings, top issues, suggested fixes, relevant IPs, and any
blocked ports. Local copies are always kept on the operator's machine.

### Download

Get the latest portable build from the
[**GitHub Releases page**](https://github.com/RyanDanielWillis/voip-health/releases/latest)
— grab `VoIPHealthCheck-windows-package-<version>.zip`, unzip into a
fresh folder, and run the versioned `VoIPHealthCheck-<version>.exe`.
No installer required. Releases are the permanent download location;
per-commit dev builds are published as
[Actions workflow artifacts](https://github.com/RyanDanielWillis/voip-health/actions/workflows/build-localscanner.yml)
for testing only.

The hosted site at https://voipscan.danielscience.com surfaces the same
download link plus a quick-start guide at
[`/docs`](https://voipscan.danielscience.com/docs). The previous
deeper reference (REST API, schema, security model) is preserved at
[`/old`](https://voipscan.danielscience.com/old).

### Troubleshooting: scan appears to hang / shows wrong version

The 2.2.0 build replaced the legacy broad nmap sweep with the **Safe
Quick Scan profile**. On startup the client now logs:

```
VoIP Health Check LocalScanner version 2.2.0 starting (build: Safe Quick Scan profile)
Executable: <full path to running exe> (frozen=True)
Working directory: <full path>
App root: <full path>
Build info: <path>\BUILD_INFO.txt
[safe] Safe Quick Scan profile active ...
```

The CI distribution package is now self-identifying — alongside
`VoIPHealthCheck.exe` you will find a versioned `VoIPHealthCheck-2.2.0.exe`,
a `BUILD_INFO.txt` (version, build tag, git SHA, workflow run id, UTC
build timestamp) and a `VERSION.txt`. **Prefer launching the versioned
exe** so the file name itself confirms the build.

If your log shows version `2.0.0`, an old `Running Quick Scan: ...
192.168.1.0/24 192.168.41.0/24 ...` line, or no `Executable:` /
`Working directory:` lines at all, you are running an **old
executable** — most often a stale shortcut to a `VoipScanner_Desktop`
folder from a previous install. To recover:

1. Delete the old `VoipScanner_Desktop` folder and any desktop / Start
   Menu shortcuts that point at it.
2. Download the latest `VoIPHealthCheck-windows-package-<version>.zip`
   from the
   [Releases page](https://github.com/RyanDanielWillis/voip-health/releases/latest)
   (the *Release LocalScanner Windows EXE* workflow publishes it).
3. **Extract the zip to a fresh folder** (e.g.
   `C:\Tools\VoIPHealthCheck-2.2.0\`). Do not extract on top of an
   older folder.
4. Launch `VoIPHealthCheck-2.2.0.exe` and confirm the startup banner
   reads `version 2.2.0` and the `Executable:` line points at the new
   folder.

See [LocalScanner/README.md](LocalScanner/README.md#troubleshooting-scan-never-completes--quick-scan-hangs)
for the full procedure.

## Output:
🔍 SCANNING 192.168.1.100...
❌ ONE-WAY AUDIO DETECTED
Cause: RTP ports 10000-20000 blocked by firewall
Fix: Open UDP 10000-20000 + enable SIP ALG

✅ SIP SECURE: ACLs configured correctly

## Features
- **Network diagnostics**: Ping, traceroute, jitter tests
- **SIP enumeration**: svmap + custom probes
- **Security scan**: Open ports, weak auth, container vulns
- **Root cause analysis**: 20+ job-tested rules
- **Pipeline ready**: SARIF output for GitHub Actions
- **Non-technical reports**: HTML + plain English

## Demo
https://voipscan.danielscience.com

## Server / dashboard

The Flask app under `web/` ingests scans uploaded by the desktop client
and surfaces them on a real-time dashboard. Key endpoints:

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v2/scan/upload` | JSON `ScanReport` upload (auto-called by client) |
| `POST /api/v2/scan/<id>/artifact` | Multipart upload (raw log, capture file) for a scan |
| `POST /api/v2/capture/upload` | Standalone capture upload (no scan id) |
| `GET  /api/v2/scan/<id>/report.json` | Download canonical scan JSON |
| `GET  /api/v2/artifact/<id>/download` | Download raw artifact file |
| `GET  /scan/<id>` | Per-scan detail page with KPIs, issues, ports, downloads |
| `GET  /dashboard` | Aggregate KPIs + latency / jitter trend chart |

### Optional upload token

Set `VOIPSCAN_UPLOAD_TOKEN` on the server to require an
`Authorization: Bearer <token>` header on every upload. Comparison uses
`hmac.compare_digest` so it's safe against timing attacks. The desktop
client picks up the matching token from the `VOIPSCAN_UPLOAD_TOKEN` env
var or from `~/.config/voipscan/upload.json` (`%LOCALAPPDATA%\VoipScan\upload.json`
on Windows).

### One-time DB reset (Phase 2)

The new analytics schema lives in `web/db.py`. On the first deploy under
schema version 2 the previous `audit_data.db` (single `audits` JSON blob)
is **automatically backed up** to `audit_data.db.legacy_<timestamp>.bak`
next to the original file, dropped, and recreated with the new tables.
Subsequent restarts of `gunicorn` (and `update.py` re-runs) are no-ops:
the version row records that the reset has already happened, so nothing
gets wiped on every deploy.

The artifact directory defaults to `~/voipscan_api/artifacts/` and can
be overridden with `VOIPSCAN_ARTIFACT_DIR`.

## Documentation

The hosted Flask app exposes a full reference at
[`/docs`](https://voipscan.danielscience.com/docs). The same page is rendered
from `web/templates/docs.html` and is the canonical, in-product
documentation for end users, technicians, and reviewers.

### Keeping documentation in sync

Whenever a change touches the desktop client, REST API, schema,
diagnostics modules, deployment story, or security model, update the
documentation in the **same pull request**. The page and this README are
designed to drift together.

Quick checklist:

- [ ] **New REST endpoint** — add a row in the docs page *Backend &
  database* section and (if user-visible) in the README API table.
- [ ] **New diagnostics module** — add a bullet in the docs page
  *Evidence collection* and *Diagnostics* sections.
- [ ] **Schema / database change** — refresh the schema list in the docs
  page and the legacy-reset notes here.
- [ ] **Auth / security change** — update the docs *Security model*
  section.
- [ ] **New environment variable / deployment step** — update the docs
  *Deployment & operations* section.
- [ ] **GUI change** — refresh the docs *Desktop client* section and the
  `client_gui.png` screenshot in this README.
- [ ] **Version bump** — update the troubleshooting banner text in both
  this README and the docs *Troubleshooting* section.

## Why it exists
Built from real VoIP troubleshooting pain. Tired of "reboot router" answers? This tells you *exactly* what's broken and how to fix it.

⭐ **Star if it saves you a call to support!**
