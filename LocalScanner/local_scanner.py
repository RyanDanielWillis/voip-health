import nmap
import json
import logging
import os
import sys
from datetime import datetime
import pytz

# Setup logging
log_path = os.path.join(os.path.dirname(sys.executable), 'scan.log')
logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s EST - %(levelname)s - %(message)s')

def run_audit(enable_os=False, capture_pcap=False):
    # Path to nmap folder
    nmap_bin = os.path.join(os.path.dirname(sys.executable), 'Nmap', 'nmap.exe')
    subnets = ['192.168.1.0/24', '192.168.41.0/24']
    
    # Base arguments
    scan_args = "--unprivileged -sT -sV"
    if enable_os:
        scan_args += " -O"
    if capture_pcap:
        scan_args += " -sU --packet-trace"
    
    print(f"Executing: nmap {scan_args} ...")
    nm = nmap.PortScanner(nmap_path=nmap_bin)
    full_report = {}

    for subnet in subnets:
        print(f"Auditing subnet: {subnet}...")
        try:
            nm.scan(hosts=subnet, arguments=scan_args)
            for host in nm.all_hosts():
                h_data = nm[host]
                full_report[host] = {
                    'os': h_data.get('osmatch', 'Unknown') if enable_os else 'Disabled',
                    'status': h_data.status(),
                    'ports': h_data.all_tcp()
                }
        except Exception as e:
            logging.error(f"Error scanning {subnet}: {e}")
            
    print(json.dumps(full_report, indent=2))
    logging.info(f"Audit Complete. Report: {json.dumps(full_report)}")

if __name__ == "__main__":
    print("--- VoIPScan Local Auditor ---")
    os_choice = input("Enable OS discovery? (y/N): ").lower() == 'y'
    pcap_choice = input("Run deep PCAP capture? (y/N): ").lower() == 'y'
    
    run_audit(enable_os=os_choice, capture_pcap=pcap_choice)
    input("\nScan complete. Press Enter to exit...")
