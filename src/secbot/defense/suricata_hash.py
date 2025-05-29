# src/secbot/defense/suricata_hash.py

import logging, os, subprocess, shutil
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

SURICATA_BIN = os.getenv("SURICATA_BIN") or shutil.which("suricata") or "/usr/bin/suricata"
HASH_RULES_PATH = Path(os.getenv("SURICATA_HASH_RULES_PATH", "/etc/suricata/rules/secbot.rules"))
PID_FILE = Path(os.getenv("SURICATA_PID_FILE", "/var/run/suricata.pid"))
BASE_SID_HASH = 7200000

def _reload_suricata():
    try:
        subprocess.run([SURICATA_BIN, "--reload-rules"], check=True)
        logger.info("Suricata reloaded rules successfully")
    except Exception:
        if PID_FILE.exists():
            pid = PID_FILE.read_text().strip()
            subprocess.run(["kill", "-USR2", pid])
            logger.info("Sent USR2 to Suricata PID %s", pid)

def block_hashes(hashes: Iterable[str]) -> None:
    HASH_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    uniq = sorted({h.strip() for h in hashes if h.strip()})
    with HASH_RULES_PATH.open("a") as f:
        f.write("\n")
        for idx, h in enumerate(uniq, start=1):
            sid = BASE_SID_HASH + idx
            # MD5/SHA1/SHA256 키워드를 모두 처리하도록 예시화
            f.write(
                f'drop http any any -> any any (msg:"SecBot malicious hash {h}"; '
                f'filesha256; content:"{h}"; sid:{sid}; rev:1;)\n'
            )
    logger.info("Wrote %d hash-block rules to %s", len(uniq), HASH_RULES_PATH)
    _reload_suricata()