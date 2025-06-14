"""
secbot.defense.suricata
~~~~~~~~~~~~~~~~~~~~~~~

Helpers for feeding Suricata (IDS/IPS) with dynamic IP‑block rules that
Daily‑SecBot extracts from threat‑intel sources.

Strategy
--------
* A dedicated local rules file ``secbot.rules`` is generated.
* Each IP becomes one bidirectional `drop ip <ip> any <> any any (...)` signature.
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
    ``/etc/suricata/rules/secbot.rules``.

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
import ipaddress

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


def _normalize_ip(value: str) -> str | None:
    """Return a clean IP address or ``None`` if invalid."""
    if not value:
        return None
    ip_str = value.strip().replace("[.]", ".")
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        logger.warning("Invalid IP skipped: %s", value)
        return None
    return str(ip)


def _write_rules_file(ips: Iterable[str]) -> int:
    """
    *ips*에서 생성된 IP 차단 규칙으로 RULES_PATH를 갱신합니다.
    기존 파일에 있던 IP는 유지하고, 새로운 IP는 하단에 추가하며 중복은 제거합니다.

    반환값
    -------
    int
        최종 파일에 포함된 규칙의 총 IP 개수를 반환합니다.
    """
    # 디렉터리 존재 보장
    RULES_PATH.parent.mkdir(parents=True, exist_ok=True)

    # 1) 입력된 IP 목록 정제 및 중복 제거
    new_ips: list[str] = []
    for raw in ips:
        clean = _normalize_ip(raw)
        if clean and clean not in new_ips:
            new_ips.append(clean)

    # 2) 기존 파일에서 이미 기록된 IP 파싱
    existing_ips: list[str] = []
    if RULES_PATH.exists():
        with RULES_PATH.open("r") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3 or parts[0] != "drop" or parts[1] != "ip":
                    continue
                # bidirectional ("<>") 또는 unidirectional ("->") 룰 처리
                ip_token = None
                if "<>" in parts:
                    ip_token = parts[2]
                elif "->" in parts:
                    arrow = parts.index("->")
                    ip_token = parts[arrow + 1] if arrow == 3 else parts[2]
                if ip_token:
                    clean = _normalize_ip(ip_token)
                    if clean and clean not in existing_ips:
                        existing_ips.append(clean)

    # 3) 최종 IP 순서 결정 (기존 순서 유지 + 신규 IP 뒤에 추가)
    final_ips = existing_ips.copy()
    for ip in new_ips:
        if ip not in existing_ips:
            final_ips.append(ip)

    # 4) 신규 IP만 append (기존 IP는 유지)
    if not RULES_PATH.exists():
        mode = "w"
        ips_to_write = final_ips
        start_index = 1
    else:
        mode = "a"
        ips_to_write = [ip for ip in final_ips if ip not in existing_ips]
        start_index = len(existing_ips) + 1

    if ips_to_write:
        with RULES_PATH.open(mode) as fh:
            for idx, ip in enumerate(ips_to_write, start=start_index):
                sid = BASE_SID + idx
                fh.write(
                    f'drop ip {ip} any <> any any '
                    f'(msg:"SecBot malicious IP {ip}"; sid:{sid}; rev:1;)\n'
                )
        logger.info("Appended %d new Suricata IP-block rule(s) to %s",
                    len(ips_to_write), RULES_PATH)
    else:
        logger.debug("No new IPs to write; %s unchanged", RULES_PATH)

    return len(existing_ips) + len(ips_to_write)


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