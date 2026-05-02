VoipScan Local Auditor (v1.0)

This tool is designed to perform a secure, local network audit to verify compliance with Starbox connectivity and firewall requirements.

How to Run
Preparation: Ensure you have the VoipScan folder unzipped on the machine connected to your local network.

Execution: Double-click run_scanner.bat.

Audit Mode:

Standard Scan: Type n when prompted. This is a non-privileged, safe network audit.

Deep PCAP Capture: Type y when prompted (requires Administrator privileges). This captures live traffic for troubleshooting.

Results: Once the scan is complete, the output will be displayed in the terminal and automatically saved to scan.log within this folder.

Integration with Dashboard
After the scan completes, copy the JSON output from your terminal and paste it into the "Local Network Results" tab at:
https://danielscience.com/voipscan/

Troubleshooting
"Nmap not found": Ensure the nmap/ folder exists inside the VoipScan directory.

Permission Denied: If choosing the PCAP (y) option, ensure you are running the run_scanner.bat file as an Administrator (Right-click > Run as Administrator).

Logs: If the tool closes unexpectedly, check the scan.log file in this directory for the last recorded error.
