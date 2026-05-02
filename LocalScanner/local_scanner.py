import nmap
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from tqdm import tqdm 

log_path = os.path.join(os.path.dirname(sys.executable), 'scan.log')
logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s EST - %(levelname)s - %(message)s\n')

def get_est_time(*args):
    est_tz = timezone(timedelta(hours=-4))
    return datetime.now(est_tz).timetuple()
logging.Formatter.converter = get_est_time

def analyze_voip_health(host_data):
    all_ports = [int(p) for p in host_data.get('tcp', {}).keys()] + [int(p) for p in host_data.get('udp', {}).keys()]
    checks = [
        {"name": "SIP Gateway", "port": 5060}, 
        {"name": "RTP Audio", "range": (10000, 20000)}, 
        {"name": "SSH Mgmt", "port": 22}
    ]
    analysis = []
    for c in checks:
        found = any(c['range'][0] <= p <= c['range'][1] for p in all_ports) if 'range' in c else c['port'] in all_ports
        analysis.append({"check": c['name'], "status": "PASS" if found else "FAIL"})
    return analysis

def run_audit(enable_os, capture_pcap):
    nmap_bin = os.path.join(os.path.dirname(sys.executable), 'Nmap', 'nmap.exe')
    subnets = ['192.168.1.0/24', '192.168.41.0/24']
    
    nm = nmap.PortScanner()
    nm.nmap_path = nmap_bin
    
    scan_args = "--unprivileged -sT -sV" + (" -O" if enable_os else "") + (" -sU --packet-trace" if capture_pcap else "")
    
    full_report = {}
    print("\nStarting Audit...")
    
    for subnet in subnets:
        print(f"Scanning subnet: {subnet}...")
        nm.scan(hosts=subnet, arguments=scan_args)
        
        # tqdm creates the real-time progress bar
        for host in tqdm(nm.all_hosts(), desc=f"Progress for {subnet}"):
            h_data = nm[host]
            full_report[host] = {'status': h_data.status(), 'analysis': analyze_voip_health(h_data)}
            
    print("\n" + json.dumps(full_report, indent=2))
    logging.info(f"Report: {json.dumps(full_report)}")

if __name__ == "__main__":
    print("--- VoIPScan Local Auditor ---")
    os_c = input("Enable OS discovery? (y/N): ").lower() == 'y'
    pc_c = input("Run deep PCAP capture? (y/N): ").lower() == 'y'
    run_audit(os_c, pc_c)
    input("\nScan complete. Press Enter to exit...")
