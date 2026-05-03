"""LEGACY — DO NOT RUN. Kept for reference only.

This is the pre-2.2.0 ``local_scanner.py`` that drove the broad nmap
sweep across ``192.168.1.0/24`` + ``192.168.41.0/24`` and frequently
took 10+ minutes — the symptom users reported as a hang. The active
client lives under ``LocalScanner/voipscan/`` and is launched from
``LocalScanner/voipscan_app.py``.

This file is kept solely so prior scan logs can be cross-referenced.
Importing or running it now raises ``RuntimeError`` immediately so
the legacy broad-sweep command line cannot be re-introduced.
"""
import sys

raise RuntimeError(
    "LEGACY local_scanner.py is disabled. The broad two-/24 nmap sweep "
    "(192.168.1.0/24 + 192.168.41.0/24) was removed in 2.2.0 because it "
    "appeared to hang. Run LocalScanner/voipscan_app.py instead, which "
    "uses the safe Quick Scan profile."
)


# ---------------------------------------------------------------------------
# Historical reference only — the code below never executes (the raise above
# fires at import time). It is preserved verbatim so old log lines like
# "Running Quick Scan: ... 192.168.1.0/24 192.168.41.0/24 ..." can be
# matched back to the exact arguments that produced them.
# ---------------------------------------------------------------------------
import nmap  # noqa: E402  -- unreachable, kept for historical reference
import json  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
from tqdm import tqdm  # noqa: E402

log_path = os.path.join(os.path.dirname(sys.executable), 'scanlog.log')
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
        
        for host in tqdm(nm.all_hosts(), desc=f"Progress for {subnet}"):
            h_data = nm[host]
            # FIXED: Used .state() here
            full_report[host] = {'status': h_data.state(), 'analysis': analyze_voip_health(h_data)}
            
    print("\n" + json.dumps(full_report, indent=2))
    logging.info(f"Report: {json.dumps(full_report)}")

if __name__ == "__main__":
    os_c = input("Enable OS discovery? (y or n): ").lower() == 'y'
    pc_c = input("Run deep PCAP capture? (y or n): ").lower() == 'y'
    run_audit(os_c, pc_c)
    input("\nScan complete. Press Enter to exit...")
