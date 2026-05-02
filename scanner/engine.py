import nmap

def run_nmap_check(target, port_range):
    """Performs an nmap scan on the target for a given port or range."""
    nm = nmap.PortScanner()
    try:
        # -sS: TCP SYN scan, -sU: UDP scan, -sV: Version detection
        scan_data = nm.scan(target, port_range, arguments='-sS -sU -sV')
        return scan_data
    except Exception as e:
        return {"error": str(e)}

def run_traceroute(target):
    """Simple check for network path/hops."""
    # Note: traceroute might require specific OS permissions
    import subprocess
    try:
        result = subprocess.check_output(["traceroute", "-n", target], timeout=10)
        return result.decode('utf-8')
    except Exception as e:
        return str(e)
