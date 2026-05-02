import nmap
import json
import logging
import os
import sys
from datetime import datetime

# Tell the script to look for nmap.exe in the same folder where the exe is running
nmap_path = os.path.join(os.path.dirname(sys.executable), "nmap.exe")
nm = nmap.PortScanner(nmap_exe=nmap_path)

# Setup log
logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_local_audit(capture_pcap=False):
    # Path to nmap binary in the portable folder
    nmap_path = os.path.join(os.path.dirname(sys.executable), "nmap", "nmap.exe")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    if capture_pcap:
        # Save PCAP file with timestamp
        pcap_filename = f"capture_{timestamp}.pcap"
        # Nmap arguments for deep capture
        scan_args = f"-sU -sS --packet-trace --send-eth -oG - --script-args=packet-capture.file={pcap_filename}"
        logging.info(f"Starting PCAP capture to: {pcap_filename}")
        print(f"Recording to {pcap_filename}...")
    else:
        # Standard unprivileged scan
        scan_args = "--unprivileged -sT -p 22,80,443,5060,8021,5038,5280,5281,9080,1935,59000-60000,8181,8182,8183"
        logging.info("Starting standard portable scan...")

    try:
        nm = nmap.PortScanner(nmap_exe=nmap_path)
        nm.scan(hosts='192.168.1.0/24', arguments=scan_args)
        
        results = {host: nm[host] for host in nm.all_hosts()}
        json_output = json.dumps(results, indent=2)
        print(json_output)
        logging.info(f"Scan complete. Output saved.")
    except Exception as e:
        error_msg = f"Scan error: {str(e)}"
        logging.error(error_msg)
        print(error_msg)

if __name__ == "__main__":
    choice = input("Run deep PCAP capture? (requires Admin) (y/N): ").lower()
    run_local_audit(capture_pcap=(choice == 'y'))
    input("\nPress Enter to exit...")
