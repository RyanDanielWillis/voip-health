#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path

APP_DIR = Path.home() / "voipscan_api"
VENV_DIR = APP_DIR / ".venv"
PIP = VENV_DIR / "bin" / "pip"
GUNICORN = VENV_DIR / "bin" / "gunicorn"
LOG_FILE = APP_DIR / "gunicorn.log"

def run(cmd, cwd=APP_DIR, check=True, capture=False):
    print(f"\n$ {cmd}")
    return subprocess.run(
        cmd, cwd=cwd, shell=True, check=check,
        capture_output=capture, text=capture,
    )

SUDO_PW_HINT = (
    "sudo requires a password and no TTY is available on the deploy SSH session.\n"
    "To enable nginx validation/reload during automated deploys, add a sudoers entry, e.g.:\n"
    "  sudo visudo -f /etc/sudoers.d/voipscan-nginx\n"
    "  <deploy-user> ALL=(root) NOPASSWD: /usr/sbin/nginx -t, /bin/systemctl reload nginx\n"
)

def is_sudo_password_error(stderr):
    if not stderr:
        return False
    s = stderr.lower()
    return "a password is required" in s or "a terminal is required" in s

def nginx_step(cmd, label):
    """Run a sudo nginx step non-interactively. Distinguish password-required
    from real nginx failures so we don't kill an otherwise-good deploy."""
    result = run(f"sudo -n {cmd}", check=False, capture=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="")
    if result.returncode == 0:
        return True
    if is_sudo_password_error(result.stderr):
        print(f"\nWARNING: skipping `{label}` - passwordless sudo not configured.")
        print(SUDO_PW_HINT)
        return False
    raise SystemExit(f"`sudo -n {cmd}` failed (exit {result.returncode}).")

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

    if nginx_step("nginx -t", "nginx -t"):
        nginx_step("systemctl reload nginx", "systemctl reload nginx")

    print("\nDeploy complete.")
    print("If browser looks stale, hard refresh with Ctrl+F5 or add ?v=1 to the URL.")

if __name__ == "__main__":
    main()
