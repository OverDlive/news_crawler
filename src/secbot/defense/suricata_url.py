# src/secbot/defense/suricata_url.py

import logging, os, subprocess, shutil
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse, unquote

logger = logging.getLogger(__name__)

SURICATA_BIN = os.getenv("SURICATA_BIN") or shutil.which("suricata") or "/usr/bin/suricata"
URL_RULES_PATH = Path(os.getenv("SURICATA_URL_RULES_PATH", "/etc/suricata/rules/secbot.rules"))
PID_FILE = Path(os.getenv("SURICATA_PID_FILE", "/var/run/suricata.pid"))
BASE_SID_URL = 7100000

def _reload_suricata():
    """
    Reload Suricata rules by first testing the configuration,
    then using suricatasc if available, otherwise falling back to USR2 signal.
    """
    try:
        # Test the Suricata configuration
        config_path = os.getenv("SURICATA_CONFIG_PATH", "/etc/suricata/suricata.yaml")
        subprocess.run([SURICATA_BIN, "-T", "-c", config_path], check=True)
        logger.info("Suricata configuration test passed")
        # Attempt to reload rules via suricatasc CLI
        sc_tool = shutil.which("suricatasc")
        if sc_tool:
            subprocess.run([sc_tool, "reload-rules"], check=True)
            logger.info("Suricata rules reloaded via suricatasc")
        else:
            # Fallback to sending USR2 to the running Suricata process
            if PID_FILE.exists():
                pid = PID_FILE.read_text().strip()
                subprocess.run(["kill", "-USR2", pid], check=True)
                logger.info("Sent USR2 signal to Suricata PID %s", pid)
            else:
                logger.error("Cannot reload Suricata rules: PID file %s not found", PID_FILE)
    except subprocess.CalledProcessError as e:
        logger.error("Error during Suricata reload: %s", e)

def block_urls(urls: Iterable[str]) -> None:
    """
    Append URL-block rules to the rule file,
    then reload Suricata.
    """
    # Ensure rules directory exists
    URL_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Deduplicate and sort URLs
    uniq_urls = sorted({u.strip() for u in urls if u.strip()})
    with URL_RULES_PATH.open("a") as f:
        f.write("\n")
        for idx, url in enumerate(uniq_urls, start=1):
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
    logger.info("Wrote %d URL-block rules to %s", len(uniq_urls), URL_RULES_PATH)
    # Reload Suricata to apply new URL-block rules
    _reload_suricata()