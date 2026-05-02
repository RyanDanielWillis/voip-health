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

def analyze_voip_health(host_data):
    analysis = []
    tcp_ports = [int(p) for p in host_data.get('tcp', {}).keys()]
    udp_ports = [int(p) for p in host_data.get('udp', {}).keys()]
    all_ports = tcp_ports + udp_ports

    # Your specific requirements
    checks = [
        {"name": "SIP Gateway", "port": 5060, "proto": "UDP", "fix": "Ensure ISP is not performing SIP ALG and UDP 5060 is open."},
        {"name": "RTP Audio Path", "range": (10000, 20000), "proto": "UDP", "fix": "Firewall must allow UDP 10000-20000 bi-directional."},
        {"name": "SSH Remote Mgmt", "port": 22, "proto": "TCP", "fix": "Ensure TCP 22 is open for remote Starbox support."},
        {"name": "App Framework (HTTP)", "port": 80, "proto": "TCP", "fix": "Port 80 is required for initial loading."},
        {"name": "Secure App Framework (HTTPS)", "port": 443, "proto": "TCP", "fix": "HTTPS/443 is mandatory for API/Softphone."},
        {"name": "AMI Interface", "port": 5038, "proto": "TCP", "fix": "AMI 5038 is required for StarCenter management."},
        {"name": "Video Conferencing", "port": 1935, "proto": "TCP", "fix": "Video framework requires TCP 1935."}
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

def run_audit(enable_os=False, capture_pcap=False):
    nmap_bin = os.path.join(os.path.dirname(sys.executable), 'Nmap', 'nmap.exe')
    subnets = ['192.168.1.0/24', '192.168.41.0/24']
    
    # We must scan BOTH TCP and UDP for the required ports
    scan_args = "-sT -sU -sV"
    if enable_os: scan_args += " -O"
    
    nm = nmap.PortScanner(nmap_path=nmap_bin)
    full_report = {}

    for subnet in subnets:
        nm.scan(hosts=subnet, arguments=scan_args)
        for host in nm.all_hosts():
            h_data = nm[host]
            full_report[host] = {
                'os': h_data.get('osmatch', 'Unknown') if enable_os else 'Disabled',
                'status': h_data.status(),
                'analysis': analyze_voip_health(h_data)
            }
            
    # Output clearly
    print(json.dumps(full_report, indent=2))
    logging.info(f"Report: {json.dumps(full_report)}")

if __name__ == "__main__":
    print("--- VoipScan Professional Audit ---")
    os_choice = input("Enable OS discovery? (y/N): ").lower() == 'y'
    run_audit(enable_os=os_choice)
    input("\nScan complete. Press Enter to exit...")
