import nmap
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

log_path = os.path.join(os.path.dirname(sys.executable), 'scan.log')
logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s EST - %(levelname)s - %(message)s\\n')

def get_est_time(*args):
    est_tz = timezone(timedelta(hours=-4))
    return datetime.now(est_tz).timetuple()
logging.Formatter.converter = get_est_time

def start_audit_session():
    with open(log_path, 'a') as f:
        f.write("\\n" + "="*50 + "\\nNEW AUDIT SESSION\\n" + "="*50 + "\\n")

def analyze_voip_health(host_data):
    analysis = []
    tcp_ports = [int(p) for p in host_data.get('tcp', {}).keys()]
    udp_ports = [int(p) for p in host_data.get('udp', {}).keys()]
    all_ports = tcp_ports + udp_ports
    checks = [
        {"name": "SIP Gateway", "port": 5060, "fix": "Ensure SIP ALG disabled, UDP 5060 open."},
        {"name": "RTP Audio Path", "range": (10000, 20000), "fix": "Firewall must allow UDP 10000-20000."},
        {"name": "SSH Mgmt", "port": 22, "fix": "Ensure TCP 22 is open for support."},
        {"name": "App Framework (HTTP)", "port": 80, "fix": "Port 80 required for initial loading."},
        {"name": "App Framework (HTTPS)", "port": 443, "fix": "HTTPS/443 mandatory for API."},
        {"name": "AMI Interface", "port": 5038, "fix": "AMI 5038 required for management."},
        {"name": "Video Conf", "port": 1935, "fix": "Video requires TCP 1935."}
    ]
    for c in checks:
        found = any(c['range'][0] <= p <= c['range'][1] for p in all_ports) if 'range' in c else c['port'] in all_ports
        status = "PASS" if found else "FAIL"
        analysis.append({"check": c['name'], "status": status, "fix": c['fix'] if not found else "N/A"})
    return analysis

def run_audit(enable_os, capture_pcap):
    start_audit_session()
    nmap_bin = os.path.join(os.path.dirname(sys.executable), 'Nmap', 'nmap.exe')
    subnets = ['192.168.1.0/24', '192.168.41.0/24']
    
    nm = nmap.PortScanner()
    nm.nmap_path = nmap_bin
    
    scan_args = "--unprivileged -sT -sV"
    if enable_os: scan_args += " -O"
    if capture_pcap: scan_args += " -sU --packet-trace"
    
    full_report = {}
    total = len(subnets)
    for i, subnet in enumerate(subnets):
        print(f"[{i+1}/{total}] Auditing subnet: {subnet} (This may take a moment)...")
        nm.scan(hosts=subnet, arguments=scan_args)
        for host in nm.all_hosts():
            h_data = nm[host]
            full_report[host] = {'status': h_data.status(), 'analysis': analyze_voip_health(h_data)}
            
    print(json.dumps(full_report, indent=2))
    logging.info(f"Report: {json.dumps(full_report)}\\n\\n")

if __name__ == "__main__":
    print("--- VoIPScan Local Auditor ---")
    os_c = input("Enable OS discovery? (y/N): ").lower() == 'y'
    pc_c = input("Run deep PCAP capture? (y/N): ").lower() == 'y'
    run_audit(os_c, pc_c)
    input("\\nScan complete. Press Enter to exit...")
