"""Stage a self-identifying VoIPHealthCheck distribution package.

Run from the LocalScanner directory after PyInstaller has produced
``dist/VoIPHealthCheck.exe``. Mirrors the GitHub Actions workflow so a
local developer build is laid out the same way as a CI build:

    package/VoIPHealthCheck/
        VoIPHealthCheck.exe
        VoIPHealthCheck-<version>.exe
        BUILD_INFO.txt
        VERSION.txt
        nmap/                (when LocalScanner/nmap/ exists)
        README.md            (when present)

The staged folder is what we tell operators to extract and launch from.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def _read_init_field(init_path: Path, field: str) -> str:
    text = init_path.read_text(encoding="utf-8")
    match = re.search(rf'{field}\s*=\s*"([^"]+)"', text)
    return match.group(1) if match else "unknown"


def _git(args: list[str], cwd: Path) -> str:
    try:
        out = subprocess.check_output(["git"] + args, cwd=str(cwd), stderr=subprocess.DEVNULL)
        return out.decode("utf-8", errors="replace").strip()
    except Exception:
        return "local"


def main() -> int:
    here = Path(__file__).resolve().parent
    project = here.parent  # LocalScanner/
    repo_root = project.parent
    init_path = project / "voipscan" / "__init__.py"
    if not init_path.exists():
        print(f"[stage] ERROR: {init_path} not found", file=sys.stderr)
        return 1

    version = _read_init_field(init_path, "__version__")
    build_tag = _read_init_field(init_path, "__build_tag__")

    dist_exe = project / "dist" / "VoIPHealthCheck.exe"
    if not dist_exe.exists():
        print(f"[stage] ERROR: {dist_exe} not found — run PyInstaller first.", file=sys.stderr)
        return 1

    pkg = project / "package" / "VoIPHealthCheck"
    if pkg.exists():
        shutil.rmtree(pkg)
    pkg.mkdir(parents=True, exist_ok=True)

    shutil.copy2(dist_exe, pkg / "VoIPHealthCheck.exe")
    shutil.copy2(dist_exe, pkg / f"VoIPHealthCheck-{version}.exe")

    sha = os.environ.get("GITHUB_SHA") or _git(["rev-parse", "HEAD"], repo_root)
    short_sha = sha[:7] if len(sha) >= 7 else sha
    ref_name = os.environ.get("GITHUB_REF_NAME") or _git(["rev-parse", "--abbrev-ref", "HEAD"], repo_root)
    repo = os.environ.get("GITHUB_REPOSITORY", "local")
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    run_number = os.environ.get("GITHUB_RUN_NUMBER", "local")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    build_info = (
        "VoIP Health Check LocalScanner\n"
        f"version:        {version}\n"
        f"build_tag:      {build_tag}\n"
        f"git_sha:        {sha}\n"
        f"git_short_sha:  {short_sha}\n"
        f"git_ref:        {ref_name}\n"
        f"repo:           {repo}\n"
        f"workflow_run:   {run_id}\n"
        f"workflow_run_number: {run_number}\n"
        f"build_utc:      {timestamp}\n"
        f"exe_canonical:  VoIPHealthCheck.exe\n"
        f"exe_versioned:  VoIPHealthCheck-{version}.exe\n"
    )
    (pkg / "BUILD_INFO.txt").write_text(build_info, encoding="utf-8")
    (pkg / "VERSION.txt").write_text(version, encoding="utf-8")

    nmap_dir = project / "nmap"
    if nmap_dir.exists():
        shutil.copytree(nmap_dir, pkg / "nmap")
        print("[stage] Bundled nmap/ folder.")
    else:
        print("[stage] No LocalScanner/nmap/ folder; package will need an adjacent nmap/ on the target machine.")

    project_readme = project / "README.md"
    if project_readme.exists():
        shutil.copy2(project_readme, pkg / "README.md")

    print(f"[stage] Staged {pkg}")
    print(f"[stage] version={version} build_tag={build_tag} sha={short_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
