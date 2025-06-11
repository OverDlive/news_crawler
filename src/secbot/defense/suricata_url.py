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
        # Attempt to reload rules via suricatasc CLI, with fallback to USR2 signal
        sc_tool = shutil.which("suricatasc")
        if sc_tool:
            try:
                subprocess.run([sc_tool, "reload-rules"], check=True)
                logger.info("Suricata rules reloaded via suricatasc")
            except Exception as e:
                logger.warning("suricatasc reload failed (%s); falling back to USR2", e)
                # Fallback via USR2
                if PID_FILE.exists():
                    pid = PID_FILE.read_text().strip()
                    subprocess.run(["kill", "-USR2", pid], check=True)
                    logger.info("Sent USR2 signal to Suricata PID %s", pid)
                else:
                    logger.error("Cannot reload Suricata rules: PID file %s not found", PID_FILE)
        else:
            # Fallback via USR2
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
    Rewrite URL-block rule file with unique URLs,
    then reload Suricata.
    """
    # Prepare unique, sorted URL list
    uniq_urls = sorted({u.strip() for u in urls if u.strip()})

    # 3) Ensure rules directory exists
    URL_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)

    # 4) Read existing rules to avoid duplicates
    existing_urls = set()
    if URL_RULES_PATH.exists():
        with URL_RULES_PATH.open("r") as f_old:
            for line in f_old:
                # Extract the URL from the msg field: msg:"SecBot malicious URL {url}";
                try:
                    # URL is between 'SecBot malicious URL ' and '";'
                    part = line.split('msg:"SecBot malicious URL ', 1)[1]
                    url_str = part.split('";', 1)[0]
                    existing_urls.add(url_str)
                except Exception:
                    continue

    # 5) Determine new URLs to write
    new_urls = [u for u in uniq_urls if u not in existing_urls]

    if not URL_RULES_PATH.exists():
        # If file does not exist, write all rules
        mode = "w"
        urls_to_write = uniq_urls
    else:
        # Append only new rules
        mode = "a"
        urls_to_write = new_urls

    # 6) Write or append rules
    if urls_to_write:
        with URL_RULES_PATH.open(mode) as f:
            for idx, url in enumerate(urls_to_write, start=BASE_SID_URL + (len(existing_urls) if mode == "a" else 0) - BASE_SID_URL + 1):
                sid = BASE_SID_URL + idx
                parsed = urlparse(url.replace("[:]", ":").replace("[.]", "."))
                host = parsed.hostname or ""
                path = unquote(parsed.path or "/")
                uri = path + (f"?{parsed.query}" if parsed.query else "")
                rule = (
                    f'drop http any any -> any any '
                    f'(msg:"SecBot malicious URL {url}"; '
                    f'http.host; content:"{host}"; '
                    f'http.uri; content:"{uri}"; '
                    f'sid:{sid}; rev:1;)'
                )
                f.write(rule + "\n")
        logger.info("Appended %d new URL-block rule(s) to %s", len(urls_to_write), URL_RULES_PATH)
    else:
        logger.debug("No new URLs to write; %s unchanged", URL_RULES_PATH)

    # Reload Suricata to apply new rules
    _reload_suricata()