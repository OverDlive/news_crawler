

"""
secbot.utils.logger
~~~~~~~~~~~~~~~~~~~

Light‑weight wrapper around :pymod:`logging` that provides:

* Uniform ISO‑8601 timestamps in **Asia/Seoul** timezone.
* Sensible coloured console output (falls back gracefully if colourama is
  missing or the stream is not a TTY).
* Optional file logging with rotation.
* A single public helper – :pyfunc:`setup` – that must be called once
  early in :pyfile:`secbot.main`.

Typical usage
-------------

>>> from secbot.utils.logger import setup, get_logger
>>> setup(level="DEBUG", logfile="logs/secbot.log")
>>> log = get_logger(__name__)
>>> log.info("Logger ready")

Environment variable overrides
------------------------------
* ``SECBOT_LOG_LEVEL`` – Default level (DEBUG, INFO …).
* ``SECBOT_LOG_FILE`` – If set, write logs to this path in addition to
  the console.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


class _KSTFormatter(logging.Formatter):
    """Custom formatter that shows timestamps in Asia/Seoul (KST, UTC+9)."""

    kst = timezone(timedelta(hours=9))

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        dt = datetime.fromtimestamp(record.created, self.kst)
        if datefmt:
            return dt.strftime(datefmt)
        return dt.isoformat(timespec="seconds")


def _supports_color(stream) -> bool:
    if not stream.isatty():
        return False
    try:
        import curses

        curses.setupterm()
        return curses.tigetnum("colors") > 0
    except Exception:
        return False


def _colourise(level: str, msg: str) -> str:
    """Apply basic ANSI colour codes based on log level."""
    if not _supports_color(sys.stderr):
        return msg

    colours = {
        "DEBUG": 37,  # White
        "INFO": 32,  # Green
        "WARNING": 33,  # Yellow
        "ERROR": 31,  # Red
        "CRITICAL": 41,  # Red background
    }
    code = colours.get(level, 37)
    return f"\033[{code}m{msg}\033[0m"


class _ColourHandler(logging.StreamHandler):
    """StreamHandler that colours the levelname."""

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        original = record.levelname
        record.levelname = _colourise(original, original)
        try:
            return super().format(record)
        finally:
            record.levelname = original


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

_ROOT_NAME = "secbot"
_DEFAULT_LEVEL = os.getenv("SECBOT_LOG_LEVEL", "INFO").upper()
_DEFAULT_FILE = os.getenv("SECBOT_LOG_FILE")

_configured = False  # Guard to avoid duplicate handlers


def setup(
    *,
    level: str | int = _DEFAULT_LEVEL,
    logfile: str | os.PathLike | None = _DEFAULT_FILE,
    max_bytes: int = 2_000_000,
    backup_count: int = 3,
    force: bool = False,
) -> None:
    """
    Configure the root logger the first time it is called.

    Parameters
    ----------
    level:
        Minimum log level for the root logger.
    logfile:
        Optional path to a rotating log file.  If ``None`` console only.
    max_bytes:
        Maximum size per log file before rotation.
    backup_count:
        Number of rotated log files to keep.
    force:
        If *True*, reconfigure even if already set up (mainly for testing).
    """
    global _configured
    if _configured and not force:
        return

    root = logging.getLogger(_ROOT_NAME)
    root.setLevel(level)

    formatter = _KSTFormatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = _ColourHandler()
    ch.setLevel(level)
    ch.setFormatter(formatter)
    root.addHandler(ch)

    # Optional file handler
    if logfile:
        Path(logfile).parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(
            logfile, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        fh.setLevel(level)
        fh.setFormatter(formatter)
        root.addHandler(fh)

    _configured = True
    root.debug("Logger configured (level=%s, file=%s)", level, logfile)


def get_logger(name: str | None = None) -> logging.Logger:
    """
    Wrapper around :pyfunc:`logging.getLogger` that enforces the *secbot.*
    namespace to keep log hierarchy tidy.
    """
    if not name:
        return logging.getLogger(_ROOT_NAME)
    if not name.startswith(_ROOT_NAME):
        name = f"{_ROOT_NAME}.{name}"
    return logging.getLogger(name)