import nmap
import json

def run_local_audit():
    nm = nmap.PortScanner()
    # Scans your local subnet for the required ports
    nm.scan(hosts='192.168.1.0/24', arguments='-p 22,80,443,5060,8021,8021,5038,5280,5281,9080,1935,59000-60000,8181,8182,8183')
    
    results = {}
    for host in nm.all_hosts():
        results[host] = nm[host]
        
    # This output should be copied/pasted into the Web Dashboard
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run_local_audit()
