import nmap
import json
import logging
import os
import sys
from datetime import datetime
import pytz

# Setup logging with EST
def get_est_time(*args):
    utc_dt = datetime.now(pytz.utc)
    est_dt = utc_dt.astimezone(pytz.timezone('US/Eastern'))
    return est_dt.timetuple()

logging.Formatter.converter = get_est_time
log_path = os.path.join(os.path.dirname(sys.executable), 'scan.log')
logging.basicConfig(filename=log_path, level=logging.INFO, 
                    format='%(asctime)s EST - %(levelname)s - %(message)s')

def get_nmap_path():
    base_dir = os.path.dirname(sys.executable)
    for folder in ['Nmap', 'nmap']:
        path = os.path.join(base_dir, folder, 'nmap.exe')
        if os.path.exists(path): return path
    return None

def run_local_audit(capture_pcap=False):
    logging.info("--- Starting Audit Session ---")
    nmap_bin = get_nmap_path()
    if not nmap_bin:
        msg = "FATAL: Could not find nmap.exe in Nmap/ folder!"
        print(msg); logging.error(msg); return

    try:
        nm = nmap.PortScanner(nmap_path=nmap_bin)
        # Scan just the gateway first to test speed
        hosts = '192.168.1.1' 
        args = "--unprivileged -sT -p 80,443"
        
        logging.info(f"Scanning {hosts} with args: {args}")
        nm.scan(hosts=hosts, arguments=args)
        
        results = {host: nm[host] for host in nm.all_hosts()}
        logging.info(f"Scan Finished. Results: {json.dumps(results)}")
        print(json.dumps(results, indent=2))
        print("\nScan Finished. Check scan.log for details.")
    except Exception as e:
        logging.error(f"Scan Exception: {str(e)}")
        print(f"Exception: {e}")

if __name__ == "__main__":
    run_local_audit()
    input("\nPress Enter to exit...")
