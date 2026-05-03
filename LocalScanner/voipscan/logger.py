"""Logging setup.

Writes a rolling log file under ``logs/voipscan.log`` and forwards
INFO/WARNING/ERROR records to any registered GUI sink so the user sees
exception traces in-app instead of a silent failure.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
import traceback
from datetime import datetime
from typing import Callable

from . import paths

_LOG_NAME = "voipscan"
_GUI_SINKS: list[Callable[[str], None]] = []


class _GuiHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:
            msg = record.getMessage()
        for sink in list(_GUI_SINKS):
            try:
                sink(msg)
            except Exception:
                # Never let a GUI failure break logging.
                pass


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOG_NAME)


def init_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure the package logger. Idempotent."""
    logger = logging.getLogger(_LOG_NAME)
    if getattr(logger, "_voipscan_configured", False):
        return logger

    logger.setLevel(level)
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    log_file = paths.logs_dir() / "voipscan.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)

    stream = logging.StreamHandler(stream=sys.stderr)
    stream.setFormatter(fmt)
    stream.setLevel(level)
    logger.addHandler(stream)

    gui = _GuiHandler()
    gui.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    gui.setLevel(logging.INFO)
    logger.addHandler(gui)

    logger._voipscan_configured = True  # type: ignore[attr-defined]

    # Catch otherwise-unhandled exceptions in worker threads / main.
    def _excepthook(exc_type, exc, tb):
        logger.error(
            "Unhandled exception:\n%s",
            "".join(traceback.format_exception(exc_type, exc, tb)),
        )

    sys.excepthook = _excepthook
    logger.info("Logging initialized — file: %s", log_file)
    return logger


def register_gui_sink(sink: Callable[[str], None]) -> None:
    """Register a callable that receives formatted log messages."""
    if sink not in _GUI_SINKS:
        _GUI_SINKS.append(sink)


def unregister_gui_sink(sink: Callable[[str], None]) -> None:
    if sink in _GUI_SINKS:
        _GUI_SINKS.remove(sink)


def log_exception(message: str) -> None:
    """Helper: log current exception with full traceback at ERROR level."""
    logger = get_logger()
    logger.error("%s\n%s", message, traceback.format_exc())


def session_id() -> str:
    """Stable identifier for the current run — useful in report filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def get_session_log_path():
    """Path to the rolling ``voipscan.log`` file. Always upload-safe.

    Used by the GUI's "always upload logs" path so a capture or a failed
    scan can still ship a useful artifact even when no scan JSON / pcap
    exists. The file is created lazily by ``init_logging``.
    """
    return paths.logs_dir() / "voipscan.log"
