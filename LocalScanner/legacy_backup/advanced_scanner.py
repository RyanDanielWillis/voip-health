"""LEGACY — DO NOT RUN. Kept for reference only.

This is the pre-2.2.0 ``advanced_scanner.py``. The active client is
``LocalScanner/voipscan/`` (launched via ``voipscan_app.py``). This
file is preserved so historical compliance reports can be matched
against the exact code that produced them; running it would call the
old broad-sweep nmap path and re-introduce the hang the 2.2.0 release
fixed.
"""
import sys

raise RuntimeError(
    "LEGACY advanced_scanner.py is disabled. Run LocalScanner/voipscan_app.py "
    "(or `python -m voipscan`) instead — that path uses the safe Quick Scan "
    "profile that replaced the broad two-/24 sweep."
)


import json  # noqa: E402  -- unreachable, kept for historical reference
import requests  # noqa: E402
import platform  # noqa: E402
import subprocess  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
from tqdm import tqdm  # noqa: E402
import re  # noqa: E402

# IMPORTANT: Update this with your actual VPS domain or IP
VPS_URL = "http://74.208.207.186/api/upload-audit"

LOG_FILE = "audit_log.log"
REPORT_FILE = "compliance_report.json"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename=LOG_FILE)

def sanitize_ip(ip):
    """Validates that the input is a valid IP address."""
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        return ip
    raise ValueError("Invalid IP format.")

def run_nmap_advanced(target, os_detect, pcap):
    """Executes Nmap diagnostics safely."""
    args = ["nmap"]
    if os_detect: args.append("-O")
    if pcap: args.append("--packet-trace")
    args.append(target)
    try:
        result = subprocess.check_output(args, stderr=subprocess.STDOUT).decode('utf-8')
        logging.info(f"Nmap scan successful on {target}")
        return result
    except Exception as e:
        logging.error(f"Scan failed on {target}: {str(e)}")
        return f"Scan failed: {str(e)}"

def run_full_audit():
    print("--- VoIP Network Compliance & Diagnostic Suite ---")
    
    try:
        gw = input("Enter Gateway IP: ") or "192.168.1.1"
        firewall = input("Enter Firewall IP: ") or gw
        pbx = input("Enter PBX/Server IP: ") or "192.168.1.10"
        sanitize_ip(gw); sanitize_ip(firewall); sanitize_ip(pbx)
    except ValueError as e:
        print(f"Error: {e}")
        return

    os_d = input("Enable OS discovery? (y/N): ").lower() == 'y'
    pc_c = input("Run packet-trace capture? (y/N): ").lower() == 'y'

    print("\nRunning advanced diagnostics...")
    with tqdm(total=1, desc="Performing Audit") as pbar:
        diag_results = run_nmap_advanced(gw, os_d, pc_c)
        pbar.update(1)

    report = {
        "Infrastructure": {"Gateway": gw, "Firewall": firewall, "PBX": pbx},
        "Diagnostic_Output": diag_results,
        "Compliance_Checklist": {
            "NAT_Disabled": "Verify Bridge/Manual Mode.",
            "SIP_ALG_Disabled": "Disable SIP ALG/Passthrough.",
            "VLAN_Configuration": "Confirm VLAN 41 (Voice) & VLAN 1 (Data).",
            "QoS_Settings": "Confirm Trust DSCP 46 (High Priority)."
        }
    }

    # Push to VPS
    try:
        response = requests.post(VPS_URL, json=report, timeout=10)
        print(f"\nReport pushed to VPS. Status: {response.status_code}")
    except Exception as e:
        print(f"\nWarning: Failed to push to VPS: {e}")

    with open(REPORT_FILE, 'w') as f:
        json.dump(report, f, indent=4)
        
    print(f"\n[!] Audit complete. Report saved locally as {REPORT_FILE} and pushed to dashboard.")

if __name__ == "__main__":
    run_full_audit()
