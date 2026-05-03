<table>
  <tr><td width="200" align="center">
    <img src=/web/static/logo.png />
  </td>
  <td>
   <h1>VoIP Health Check</h1>

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)

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
Download the portable desktop client from https://voipscan.danielscience.com
and see results at https://voipscan.danielscience.com/dashboard

## Desktop client (Windows)

<td width="400" align="center"><img src=/web/static/client_gui.png) /></td>

The desktop client is a portable Windows GUI titled **VoIP Health Check —
Local network diagnostics for VoIP health**. The screenshot above shows the
main window:

- A red **Quick Scan** button and a neighbouring **Start Packet Capture**
  button along the top action row, both sized and spaced to match — the
  packet-capture flow now has a dedicated **Stop Packet Capture** button
  beside Start so the operator can finalize a capture without relying on
  a single toggle.
- An **Optional** card with a *Problem Experienced* dropdown, a *Do you
  have a different problem?* free-text field, an *Advanced* (collapsible)
  panel where every field is optional and auto-detected when blank, and
  a red **Scan Now** button.
- A dark **Scan Results / Log** pane that streams diagnostic lines
  during a scan and switches to a plain-English summary (with status
  badges) when the scan finishes. The screenshot shows the idle state
  with the app version banner, the local logs path, and the resolved
  `nmap.exe` path.

### Download the Windows client

The portable Windows `.exe` is built and published by the GitHub Actions
workflow on every push to `main` (and on demand via *Run workflow*). To
get the latest build:

1. Open the [**Build LocalScanner Windows EXE**](https://github.com/RyanDanielWillis/voip-health/actions/workflows/build-localscanner.yml)
   workflow page.
2. Click the most recent successful run.
3. Under **Artifacts**, download
   [`VoIPHealthCheck-windows-exe`](https://github.com/RyanDanielWillis/voip-health/actions/workflows/build-localscanner.yml)
   (single `.exe`) or `VoIPHealthCheck-windows-package` (the `.exe`
   alongside the bundled `nmap/` folder, recommended for full scanning).
4. Unzip and run `VoIPHealthCheck.exe` — no installer required.

The hosted homepage at https://voipscan.danielscience.com also surfaces
the same screenshot, copy and download instructions for end users.

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

## Why it exists
Built from real VoIP troubleshooting pain. Tired of "reboot router" answers? This tells you *exactly* what's broken and how to fix it.

⭐ **Star if it saves you a call to support!**
