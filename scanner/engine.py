import subprocess
import re

def run_cmd(cmd, target):
    if not re.match(r'^[a-zA-Z0-9./-]+$', target):
        return "Error: Invalid Target"
    try:
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
        return result.stdout + result.stderr
    except Exception as e:
        return str(e)
