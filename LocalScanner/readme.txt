VoipScan Local Auditor (v1.2)
This tool performs a professional-grade network audit to verify compliance with Star2Star/Starbox connectivity, firewall, and port requirements. It provides automated, actionable analysis for VoIP health.

How to Run
Preparation: Place the Nmap/ folder and local_scanner.exe inside the VoipScan directory.

Execution: Double-click run_scanner.bat.

Audit Configuration:

OS Discovery: Type y to enable device fingerprinting (useful for identifying unauthorized hardware).

Results: The tool outputs a detailed JSON report. The final section, analysis, provides a compliance checklist:

Status: "PASS" or "FAIL" for every mission-critical port.

Proof: Undeniable evidence of detected traffic vs. missing services.

Suggested Fixes: Simple, actionable instructions for your ISP or Network team to resolve identified bottlenecks.

Integration with Dashboard
After the scan completes, copy the full JSON report from your terminal and paste it into the "Local Network Results" tab at:
https://danielscience.com/voipscan/

Compliance Checklist Checked
The scanner automatically validates these Star2Star requirements:

SIP Gateway (UDP 5060): Verified for call signaling.

RTP Audio Path (10k-20k): Verified for clear voice traffic.

SSH Remote Management (TCP 22): Verified for remote Starbox support.

App Framework (HTTP 80/HTTPS 443): Verified for API and portal communication.

AMI Interface (TCP 5038): Verified for server management.

Video Conferencing (TCP 1935): Verified for video streaming frames.

Troubleshooting
Scan Incomplete: Check scan.log in this directory for the last recorded step; this log contains the full audit history.

Compliance Failure: If a check returns "FAIL," follow the suggested "fix" in the JSON output, which is specifically tailored to your Starbox firewall settings.
