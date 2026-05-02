<table>
  <tr><td width="200" align="center">
    <img src=/logo.png />
  </td>
  <td>
   <h1>Angry VoIP Scanner</h1>

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
