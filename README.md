<table>
  <tr><td width="200" align="center">
    <img src="web/static/logo.png" alt="VoIP Health Check logo" width="160">
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

Note: NMap must be installed for the portable scanner to work.

## Features
- **Network diagnostics**: Ping, traceroute, jitter tests
- **SIP enumeration**: svmap + custom probes
- **Security scan**: Open ports, weak auth, container vulns
- **Root cause analysis**: 20+ job-tested rules
- **Pipeline ready**: SARIF output for GitHub Actions
- **Non-technical reports**: HTML + plain English

## Demo
[`voipscan.danielscience.com`](https://voipscan.danielscience.com/)

## Documentation
[`voipscan.danielscience.com/docs`](https://voipscan.danielscience.com/docs)


## Why it exists
Built from real VoIP troubleshooting pain. Tired of "reboot router" answers? This tells you *exactly* what's broken and how to fix it.

⭐ **Star if it saves you a call to support!**
