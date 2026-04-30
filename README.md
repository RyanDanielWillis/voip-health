# Angry VoIP Scanner

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![GitHub Action](https://github.com/RyanDanielWillis/Angry-Voip-Scanner/actions/workflows/scan.yml/badge.svg)](https://github.com/RyanDanielWillis/Angry-Voip-Scanner/actions)

**Diagnoses VoIP problems and security risks with plain-English fixes.** Scans your PBX/phone system for one-way audio, choppy calls, exposed extensions, and more — then tells you exactly what's wrong and how to fix it.

## What it finds & fixes

| Problem | Likely Cause | Simple Fix |
|---------|--------------|------------|
| **One-way audio** | NAT/firewall blocking RTP | Disable SIP ALG + disable NAT on the internet modem |
| **Choppy audio** | Packet loss or jitter | Prioritize VoIP traffic with QoS (EF marking) |
| **No audio at all** | Codec mismatch | Enable G.711 on FreePBX |
| **Registration fails** | Wrong auth or NAT | Check phone confirguration or firmware version |

## Quick start
```bash
pip install -r requirements.txt
python angry_voip_scanner.py scan 192.168.1.100
```

**Output:**
