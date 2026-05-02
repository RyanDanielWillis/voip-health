#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path

APP_DIR = Path.home() / "voipscan_api"
VENV_DIR = APP_DIR / ".venv"
PIP = VENV_DIR / "bin" / "pip"
GUNICORN = VENV_DIR / "bin" / "gunicorn"
LOG_FILE = APP_DIR / "gunicorn.log"

def run(cmd, cwd=APP_DIR, check=True):
    print(f"\n$ {cmd}")
    return subprocess.run(cmd, cwd=cwd, shell=True, check=check)

def main():
    os.chdir(APP_DIR)

    run("git fetch origin main")
    run("git reset --hard origin/main")

    if not VENV_DIR.exists():
        run("python3 -m venv .venv")

    run(f"{PIP} install --upgrade pip")
    run(f"{PIP} install -r requirements.txt")
    run(f"{PIP} install gunicorn")

    run("pkill -f gunicorn || true", check=False)

    run(
        f"nohup {GUNICORN} "
        f"--chdir {APP_DIR} "
        f"--bind 127.0.0.1:5000 "
        f"web.app:app "
        f"> {LOG_FILE} 2>&1 &"
    )

    run("sleep 3")
    run("curl -f http://127.0.0.1:5000 > /dev/null")

    run("sudo nginx -t")
    run("sudo systemctl reload nginx")

    print("\nDeploy complete.")
    print("If browser looks stale, hard refresh with Ctrl+F5 or add ?v=1 to the URL.")

if __name__ == "__main__":
    main()
