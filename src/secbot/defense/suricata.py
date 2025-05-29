"""
secbot.defense.suricata
~~~~~~~~~~~~~~~~~~~~~~~

Helpers for feeding Suricata (IDS/IPS) with dynamic IP‑block rules that
Daily‑SecBot extracts from threat‑intel sources.

Strategy
--------
* A dedicated local rules file ``secbot‑blacklist.rules`` is generated.
* Each IP becomes one `drop ip any any -> <ip> any (...)` signature.
* After the file is (over)written, Suricata is hot‑reloaded with
  ``--reload-rules`` or a USR2 signal (fallback).
* SIDs are generated deterministically so duplicate IPs never create
  more than one rule (sid = BASE_SID + index).

Functions
---------
block(ips)  – Rewrite the rules file with *ips*; then reload Suricata.
flush()     – Empty the rules file and reload.

Environment Variables
---------------------
SURICATA_RULES_PATH
    Where to write the blacklist file. Defaults to
    ``/etc/suricata/rules/secbot-blacklist.rules``.

SURICATA_BIN
    Path to Suricata executable (auto‑detected via shutil.which).

SURICATA_PID_FILE
    PID file for sending signals when `--reload-rules` is unavailable.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List

logger = logging.getLogger(__name__)

SURICATA_BIN: str = (
    os.getenv("SURICATA_BIN") or shutil.which("suricata") or "/usr/bin/suricata"
)
RULES_PATH: Path = Path(
    os.getenv("SURICATA_RULES_PATH", "/etc/suricata/rules/secbot-blacklist.rules")
)
PID_FILE: Path | None = (
    Path(os.getenv("SURICATA_PID_FILE"))
    if os.getenv("SURICATA_PID_FILE")
    else Path("/var/run/suricata.pid")
)


BASE_SID = 7000000  # Private range (RFC 7601). Suricata reserves <1M.


def _run_suricata_cmd(args: List[str]) -> subprocess.CompletedProcess:
    """Call the Suricata binary directly (e.g., ``suricata --reload-rules``)."""
    if not Path(SURICATA_BIN).exists():
        raise RuntimeError(f"Suricata binary not found at {SURICATA_BIN}")

    cmd = [SURICATA_BIN, *args]
    logger.debug("Executing: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def _signal_suricata() -> None:
    """Send USR2 to the running Suricata process as a fallback reload method."""
    if PID_FILE and PID_FILE.exists():
        pid = PID_FILE.read_text().strip()
        logger.debug("Sending USR2 to Suricata PID %s via kill", pid)
        subprocess.run(["kill", "-USR2", pid], check=False)
    else:
        logger.warning("Suricata PID file not found; reload may have failed.")


def _reload_suricata() -> None:
    """Try Suricata native reload, fallback to signal if unsupported."""
    try:
        _run_suricata_cmd(["--reload-rules"])
        logger.info("Suricata ruleset reloaded successfully")
    except subprocess.CalledProcessError as exc:
        logger.warning(
            "suricata --reload-rules failed (%s). Falling back to USR2 signal", exc
        )
        _signal_suricata()


def _write_rules_file(ips: Iterable[str]) -> int:
    """
    Overwrite RULES_PATH with drop‑ip rules generated from *ips*.

    Returns
    -------
    int
        The number of rules written.
    """
    RULES_PATH.parent.mkdir(parents=True, exist_ok=True)

    uniq_ips = sorted({ip.strip() for ip in ips if ip.strip()})
    with RULES_PATH.open("a") as fh:
        fh.write("\n")
        for idx, ip in enumerate(uniq_ips, start=1):
            sid = BASE_SID + idx
            fh.write(
                f'drop ip any any -> {ip} any (msg:"SecBot malicious IP {ip}"; '
                f'sid:{sid}; rev:1;)\n'
            )
    logger.info("Wrote %d Suricata IP‑block rules to %s", len(uniq_ips), RULES_PATH)
    return len(uniq_ips)


def block(ips: Iterable[str]) -> None:
    """
    Rewrite the Suricata blacklist rules file with *ips* then reload Suricata.
    """
    count = _write_rules_file(ips)
    if count:
        _reload_suricata()
    else:
        logger.debug("No IPs provided; Suricata not reloaded.")


def flush() -> None:
    """
    Remove all dynamically‑added IP rules and reload Suricata.
    """
    if RULES_PATH.exists():
        RULES_PATH.unlink()
        logger.info("Removed Suricata blacklist file %s", RULES_PATH)
    else:
        logger.debug("Blacklist file %s already absent", RULES_PATH)
    _reload_suricata()