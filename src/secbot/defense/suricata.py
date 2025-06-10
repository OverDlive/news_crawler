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
    os.getenv("SURICATA_RULES_PATH", "/etc/suricata/rules/secbot.rules")
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
    """
    Reload Suricata rules by first testing the configuration,
    then using suricatasc if available, otherwise falling back to USR2 signal.
    """
    try:
        # Test the Suricata configuration
        config_path = os.getenv("SURICATA_CONFIG_PATH", "/etc/suricata/suricata.yaml")
        _run_suricata_cmd(["-T", "-c", config_path])
        logger.info("Suricata configuration test passed")
        # Attempt to reload rules via suricatasc CLI
        sc_tool = shutil.which("suricatasc")
        if sc_tool:
            try:
                subprocess.run([sc_tool, "reload-rules"], check=True)
                logger.info("Suricata rules reloaded via suricatasc")
            except Exception as e:
                logger.warning("suricatasc reload failed (%s); falling back to USR2", e)
                _signal_suricata()
        else:
            _signal_suricata()
    except subprocess.CalledProcessError as e:
        logger.error("Error during Suricata reload: %s", e)


def _write_rules_file(ips: Iterable[str]) -> int:
    """
    *ips*에서 생성된 IP 차단 규칙으로 RULES_PATH를 갱신합니다.
    기존 파일에 있던 IP는 유지하고, 새로운 IP는 하단에 추가하며 중복은 제거합니다.

    반환값
    -------
    int
        최종 파일에 포함된 규칙의 총 IP 개수를 반환합니다.
    """
    RULES_PATH.parent.mkdir(parents=True, exist_ok=True)

    # 1) 입력된 IP 목록 정제
    new_ips = [ip.strip() for ip in ips if ip.strip()]

    # 2) 기존 RULES_PATH에서 이미 기록된 IP 파싱
    existing_ips: list[str] = []
    if RULES_PATH.exists():
        with RULES_PATH.open("r") as fh:
            for line in fh:
                # Generate rules ourselves, so we know the format:
                #   drop ip any any -> <IP> any (...)
                #   drop ip <IP> any -> any any (...)
                parts = line.split()
                if len(parts) >= 7 and parts[0] == "drop" and parts[1] == "ip":
                    if parts[2] == "any":  # incoming rule
                        ip_token = parts[5]
                    else:  # outgoing rule
                        ip_token = parts[2]
                    if ip_token not in existing_ips:
                        existing_ips.append(ip_token)

    # 3) 최종 IP 목록 결정: 기존 순서 유지, 새로운 IP는 뒤에 추가
    final_ips: list[str] = existing_ips.copy()
    for ip in new_ips:
        if ip not in existing_ips:
            final_ips.append(ip)

    # 4) RULES_PATH에 덮어쓰기
    with RULES_PATH.open("w") as fh:
        for idx, ip in enumerate(final_ips, start=1):
            sid_in = BASE_SID + idx
            sid_out = BASE_SID + idx + len(final_ips)
            fh.write(
                f'drop ip any any -> {ip} any '
                f'(msg:"SecBot malicious IP {ip}"; sid:{sid_in}; rev:1;)\n'
            )
            fh.write(
                f'drop ip {ip} any -> any any '
                f'(msg:"SecBot malicious IP {ip} outgoing"; sid:{sid_out}; rev:1;)\n'
            )

    logger.info("Wrote %d Suricata IP‑block rules to %s", len(final_ips), RULES_PATH)
    return len(final_ips)


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