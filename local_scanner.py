import nmap
import json
import logging

# Configure logging to save to scan.log in the same folder as the exe
logging.basicConfig(
    filename='scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def run_local_audit():
    nm = nmap.PortScanner()
    
    try:
        logging.info("Starting local network scan...")
        
        # '--unprivileged' avoids the need for Admin rights
        # '-sT' is a standard TCP Connect scan
        scan_args = '--unprivileged -sT -p 22,80,443,5060,8021,5038,5280,5281,9080,1935,59000-60000,8181,8182,8183'
        
        # Scan your local subnet (adjust if your gateway is different)
        nm.scan(hosts='192.168.1.0/24', arguments=scan_args)
        
        results = {}
        for host in nm.all_hosts():
            results[host] = nm[host]
            
        json_output = json.dumps(results, indent=2)
        
        logging.info("Scan completed successfully.")
        logging.info(f"Scan Data Output:\n{json_output}")
        
        # Output the JSON to the terminal for easy copy-pasting into your Web UI
        print(json_output)
        print("\n--- Scan complete. Results also saved to scan.log ---")
        
    except Exception as e:
        error_msg = f"Error during scan: {str(e)}"
        logging.error(error_msg)
        print(error_msg)

if __name__ == "__main__":
    run_local_audit()
    # Keep window open for a moment so you can read results before it closes
    input("\nPress Enter to exit...")
