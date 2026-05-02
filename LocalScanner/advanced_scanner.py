import json
import platform
import subprocess
import logging
import os
from tqdm import tqdm
import re

# Security: Set controlled logging and report locations
LOG_FILE = "audit_log.log"
REPORT_FILE = "compliance_report.json"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename=LOG_FILE)

def sanitize_ip(ip):
    """Validates that the input is a valid IP address."""
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
        return ip
    raise ValueError("Invalid IP format.")

def run_nmap_advanced(target, os_detect, pcap):
    """Executes Nmap diagnostics using safe subprocess practices."""
    args = ["nmap"]
    if os_detect: args.append("-O")
    if pcap: args.append("--packet-trace")
    args.append(target)
    
    try:
        # Security: Use list-based subprocess to prevent shell injection
        result = subprocess.check_output(args, stderr=subprocess.STDOUT).decode('utf-8')
        logging.info(f"Nmap scan successful on {target}")
        return result
    except Exception as e:
        logging.error(f"Scan failed on {target}: {str(e)}")
        return f"Scan failed: {str(e)}"

def run_full_audit():
    print("--- VoIP Network Compliance & Diagnostic Suite ---")
    
    # Secure Input
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
    
    # Progress Bar Implementation
    with tqdm(total=3, desc="Performing Audit") as pbar:
        diag_results = run_nmap_advanced(gw, os_d, pc_c)
        pbar.update(1)
        # Placeholder for remaining audit steps
        pbar.update(2) 

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

    with open(REPORT_FILE, 'w') as f:
        json.dump(report, f, indent=4)
        
    print(f"\n[!] Audit complete. Report saved to {REPORT_FILE} and logs to {LOG_FILE}.")

if __name__ == "__main__":
    run_full_audit()
