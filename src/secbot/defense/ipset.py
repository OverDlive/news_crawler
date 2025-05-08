

"""
secbot.defense.ipset
~~~~~~~~~~~~~~~~~~~~

Utility helpers for managing an *ipset* blacklist that Daily‑SecBot can
feed with newly discovered malicious IPv4/IPv6 addresses.

Design
------
* A single set named ``secbot_bad_ips`` (type ``hash:ip``) is created on
  first use and reused thereafter.
* All modifications are done atomically via **ipset restore -!** so that
  production traffic never sees a half‑updated ruleset.
* The module is intentionally thin and stateless; long‑running daemons
  should call :pyfunc:`block` for each batch of IPs and optionally
  :pyfunc:`flush` during maintenance windows.

Functions
---------
ensure_set()  -> None
    Create the managed set if it doesn't exist.
block(ips)    -> None
    Add an iterable of IP addresses to the set.
flush()       -> None
    Remove all entries from the set.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List

logger = logging.getLogger(__name__)

IPSET_BIN: str = shutil.which("ipset") or "/sbin/ipset"
SET_NAME: str = "secbot_bad_ips"


def _run_ipset_cmd(
    args: List[str],
    *,
    check: bool = True,
    input_: bytes | None = None,
) -> subprocess.CompletedProcess:
    """
    Run the *ipset* binary with *args*.

    Parameters
    ----------
    args:
        List of command‑line arguments to pass after the binary name.
    check:
        Raise :class:`RuntimeError` on non‑zero exit when *True*.
    input_:
        Raw *stdin* payload for commands such as ``ipset restore``.
    """
    if not Path(IPSET_BIN).exists():
        raise RuntimeError(f"ipset binary not found at {IPSET_BIN}")

    cmd = [IPSET_BIN, *args]
    logger.debug("Executing: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        input=input_,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def ensure_set() -> None:
    """
    Create the managed blacklist set if it does not already exist.

    Idempotent; safe to call repeatedly.
    """
    try:
        _run_ipset_cmd(["list", SET_NAME], check=True)
        logger.debug("ipset set %s already exists", SET_NAME)
    except subprocess.CalledProcessError:
        logger.info("Creating ipset set %s", SET_NAME)
        _run_ipset_cmd(
            ["create", SET_NAME, "hash:ip", "timeout", "0"],
            check=True,
        )


def block(ips: Iterable[str]) -> None:
    """
    Atomically add *ips* to the ``secbot_bad_ips`` set.

    Duplicate entries are silently ignored by *ipset*. Invalid addresses
    will cause the entire transaction to fail.

    Parameters
    ----------
    ips:
        Iterable of IPv4/IPv6 address strings.
    """
    ensure_set()
    rules = [f"add {SET_NAME} {ip.strip()}" for ip in ips if ip.strip()]
    if not rules:
        logger.debug("No IPs received for blocking")
        return

    payload = "\n".join(rules).encode()
    logger.info("Blocking %d IPs via ipset", len(rules))
    _run_ipset_cmd(["restore", "-!"], input_=payload)


def flush() -> None:
    """
    Remove **all** entries from the managed set.
    """
    ensure_set()
    logger.info("Flushing all IPs from ipset set %s", SET_NAME)
    _run_ipset_cmd(["flush", SET_NAME])