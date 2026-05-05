"""Top-level entry point for the desktop client.

This file is what PyInstaller is pointed at and what ``run.bat`` calls.
The actual code lives under the ``voipscan/`` package — keeping the
launcher tiny makes it easy to swap out frameworks later.
"""

from voipscan.ui import run


if __name__ == "__main__":
    run()
