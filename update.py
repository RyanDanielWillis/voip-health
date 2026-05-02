import subprocess
import os

# Configuration
REPO_DIR = "/home/intsh0e/voipscan_api"
SERVICE_NAME = "voipscan"

def run_command(command):
    print(f"Running: {command}")
    subprocess.run(command, shell=True, check=True, cwd=REPO_DIR)

def update_and_restart():
    try:
        # 1. Fetch latest and force overwrite
        print("--- Updating code from Git ---")
        run_command("git fetch origin")
        run_command("git reset --hard origin/main") # Change 'main' to 'master' if needed

        # 2. Restart the systemd service
        print(f"--- Restarting {SERVICE_NAME} ---")
        run_command(f"sudo systemctl restart {SERVICE_NAME}")
        
        print("--- Update complete! ---")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    update_and_restart()
