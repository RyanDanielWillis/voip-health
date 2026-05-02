import nmap
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

# Use standard lib for EST to avoid dependency issues
def get_est_time(*args):
    est_tz = timezone(timedelta(hours=-4))
    return datetime.now(est_tz).timetuple()

log_path = os.path.join(os.path.dirname(sys.executable), 'scan.log')
# Added \\n to format to ensure spacing
logging.basicConfig(filename=log_path, level=logging.INFO, 
                    format='%(asctime)s EST - %(levelname)s - %(message)s\\n')
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
        {"name": "SIP Gateway", "port": 5060, "proto": "UDP", "fix": "Ensure SIP ALG is disabled; UDP 5060 must be open."},
        {"name": "RTP Audio Path", "range": (10000, 20000), "proto": "UDP", "fix": "Firewall must allow UDP 10000-20000 bi-directional."},
        {"name": "SSH Remote Mgmt", "port": 22, "proto": "TCP", "fix": "Ensure TCP 22 is open for support."},
        {"name": "App Framework (HTTP)", "port": 80, "proto": "TCP", "fix": "Port 80 required for initial loading."},
        {"name": "Secure App Framework (HTTPS)", "port": 443, "proto": "TCP", "fix": "HTTPS/443 mandatory for API."},
        {"name": "AMI Interface", "port": 5038, "proto": "TCP", "fix": "AMI 5038 required for StarCenter."},
        {"name": "Video Conferencing", "port": 1935, "proto": "TCP", "fix": "Video requires TCP 1935."}
    ]

    for c in checks:
        if 'range' in c:
            found = any(c['range'][0] <= p <= c['range'][1] for p in all_ports)
        else:
            found = c['port'] in all_ports
        status = "PASS" if found else "FAIL"
        proof = f"Verified: {c['name']} activity detected." if found else f"CRITICAL: {c['name']} missing."
        analysis.append({"check": c['name'], "proof": proof, "status": status, "fix": c['fix'] if not found else "N/A"})
    return analysis

def run_audit(enable_os=False):
    start_audit_session()
    nmap_bin = os.path.join(os.path.dirname(sys.executable), 'Nmap', 'nmap.exe')
    subnets = ['192.168.1.0/24', '192.168.41.0/24']
    scan_args = "--unprivileged -sT -sV" + (" -O" if enable_os else "")
    
    nm = nmap.PortScanner(nmap_path=nmap_bin)
    full_report = {}

    for subnet in subnets:
        try:
            nm.scan(hosts=subnet, arguments=scan_args)
            for host in nm.all_hosts():
                h_data = nm[host]
                full_report[host] = {'status': h_data.status(), 'analysis': analyze_voip_health(h_data)}
        except Exception as e:
            logging.error(f"Error scanning {subnet}: {e}")
            
    print(json.dumps(full_report, indent=2))
    logging.info(f"Report: {json.dumps(full_report)}\\n\\n")

if __name__ == "__main__":
    os_choice = input("Enable OS discovery? (y/N): ").lower() == 'y'
    run_audit(enable_os=os_choice)
    input("\\nScan complete. Press Enter to exit...")
