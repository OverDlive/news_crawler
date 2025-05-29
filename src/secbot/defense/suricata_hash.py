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

def block_hashes(hashes: Iterable[str]) -> None:
    """
    Append hash-block rules for MD5, SHA1, or SHA256 hashes to the rule file,
    then reload Suricata.
    """
    # Ensure rules directory exists
    HASH_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Deduplicate and sort
    uniq_hashes = sorted({h.strip().lower() for h in hashes if h.strip()})
    with HASH_RULES_PATH.open("a") as f:
        f.write("\n")
        for idx, h in enumerate(uniq_hashes, start=1):
            sid = BASE_SID_HASH + idx
            # Determine hash keyword based on length
            if len(h) == 32:
                keyword = "filemd5"
            elif len(h) == 40:
                keyword = "filesha1"
            elif len(h) == 64:
                keyword = "filesha256"
            else:
                keyword = "filesha256"
            # Write the drop rule
            f.write(
                f'drop tcp any any -> any any (msg:"SecBot malicious hash {h}"; '
                f'{keyword}; content:"{h}"; sid:{sid}; rev:1;)\n'
            )
    logger.info("Wrote %d hash-block rules to %s", len(uniq_hashes), HASH_RULES_PATH)
    # Reload Suricata to apply new rules
    _reload_suricata()