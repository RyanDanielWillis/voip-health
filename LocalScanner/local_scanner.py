import nmap
import json
import logging
import os
import sys
from datetime import datetime

# Setup logging
log_path = os.path.join(os.path.dirname(sys.executable), 'scan.log')
logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_local_audit(capture_pcap=False):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    if capture_pcap:
        pcap_filename = f"capture_{timestamp}.pcap"
        scan_args = f"-sU -sS --packet-trace --send-eth -oG - --script-args=packet-capture.file={pcap_filename}"
        logging.info(f"Starting PCAP capture to: {pcap_filename}")
        print(f"Recording to {pcap_filename}...")
    else:
        scan_args = "--unprivileged -sT -p 22,80,443,5060,8021,5038,5280,5281,9080,1935,59000-60000,8181,8182,8183"
        logging.info("Starting standard portable scan...")

    try:
        # SIMPLEST APPROACH: No arguments, rely on the batch file's PATH modification
        nm = nmap.PortScanner()
        nm.scan(hosts='192.168.1.0/24', arguments=scan_args)
        
        results = {host: nm[host] for host in nm.all_hosts()}
        json_output = json.dumps(results, indent=2)
        print(json_output)
        logging.info(f"Scan complete. Data: {json_output}")
    except Exception as e:
        error_msg = f"Scan error: {str(e)}"
        logging.error(error_msg)
        print(error_msg)

if __name__ == "__main__":
    choice = input("Run deep PCAP capture? (requires Admin) (y/N): ").lower()
    run_local_audit(capture_pcap=(choice == 'y'))
    input("\nPress Enter to exit...")
