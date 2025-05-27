# src/secbot/defense/suricata_url.py

import logging, os, subprocess, shutil
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse, unquote

logger = logging.getLogger(__name__)

SURICATA_BIN = os.getenv("SURICATA_BIN") or shutil.which("suricata") or "/usr/bin/suricata"
URL_RULES_PATH = Path(os.getenv("SURICATA_URL_RULES_PATH", "/etc/suricata/rules/secbot-url.rules"))
PID_FILE = Path(os.getenv("SURICATA_PID_FILE", "/var/run/suricata.pid"))
BASE_SID_URL = 7100000

def _reload_suricata():
    try:
        subprocess.run([SURICATA_BIN, "--reload-rules"], check=True)
        logger.info("Suricata reloaded rules successfully")
    except Exception:
        if PID_FILE.exists():
            pid = PID_FILE.read_text().strip()
            subprocess.run(["kill", "-USR2", pid])
            logger.info("Sent USR2 to Suricata PID %s", pid)

def block_urls(urls: Iterable[str]) -> None:
    URL_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    uniq = sorted({u.strip() for u in urls if u.strip()})
    with URL_RULES_PATH.open("w") as f:
        for idx, url in enumerate(uniq, start=1):
            sid = BASE_SID_URL + idx
            parsed = urlparse(url.replace("[:]", ":").replace("[.]", "."))
            host = parsed.hostname or ""
            path = unquote(parsed.path or "/")
            uri = path + ("?" + parsed.query if parsed.query else "")
            f.write(
                f'drop http any any -> any any (msg:"SecBot malicious URL {url}"; '
                f'http.host; content:"{host}"; nocase; '
                f'http.uri; content:"{uri}"; nocase; '
                f'sid:{sid}; rev:1;)\n'
            )
    logger.info("Wrote %d URL-block rules to %s", len(uniq), URL_RULES_PATH)
    _reload_suricata()