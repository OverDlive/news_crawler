from pathlib import Path
from typing import Iterable
import logging, os, subprocess, shutil

logger = logging.getLogger(__name__)

SURICATA_BIN      = os.getenv("SURICATA_BIN") or shutil.which("suricata") or "/usr/bin/suricata"
HASH_LIST_PATH    = Path(os.getenv("SURICATA_HASH_LIST_PATH", "/etc/suricata/rules/secbot-hash.list"))
HASH_RULES_PATH   = Path(os.getenv("SURICATA_HASH_RULES_PATH", "/etc/suricata/rules/secbot-hash.rules"))
PID_FILE          = Path(os.getenv("SURICATA_PID_FILE", "/var/run/suricata.pid"))
BASE_SID_HASH     = 7200000

def _reload_suricata() -> None:
    """
    Reload Suricata rules by first testing the configuration,
    then using suricatasc if available, otherwise falling back to USR2 signal.
    """
    try:
        # Test configuration syntax
        config_path = os.getenv("SURICATA_CONFIG_PATH", "/etc/suricata/suricata.yaml")
        subprocess.run([SURICATA_BIN, "-T", "-c", config_path], check=True)
        logger.info("Suricata configuration test passed")
        # Attempt hot-reload via suricatasc
        sc_tool = shutil.which("suricatasc")
        if sc_tool:
            try:
                subprocess.run([sc_tool, "reload-rules"], check=True)
                logger.info("Suricata rules reloaded via suricatasc")
            except Exception as e:
                logger.warning("suricatasc reload-rules failed (%s); falling back to USR2", e)
                # Fallback to USR2 signal
                if PID_FILE.exists():
                    pid = PID_FILE.read_text().strip()
                    subprocess.run(["kill", "-USR2", pid], check=True)
                    logger.info("Sent USR2 signal to Suricata PID %s", pid)
                else:
                    logger.error("Cannot reload Suricata: PID file %s not found", PID_FILE)
        else:
            # No suricatasc, fallback to USR2
            if PID_FILE.exists():
                pid = PID_FILE.read_text().strip()
                subprocess.run(["kill", "-USR2", pid], check=True)
                logger.info("Sent USR2 signal to Suricata PID %s", pid)
            else:
                logger.error("Cannot reload Suricata: PID file %s not found", PID_FILE)
    except subprocess.CalledProcessError as e:
        logger.error("Suricata reload failed: %s", e)

def block_hashes(hashes: Iterable[str]) -> None:
    """
    SHA256 해시 리스트 파일과 단일 룰을 생성한 뒤
    Suricata를 재로드합니다.
    """
    # 1) 중복 제거·소문자 정렬
    uniq = sorted({h.strip().lower() for h in hashes if h.strip()})

    # 2) 리스트 파일 덮어쓰기
    HASH_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HASH_LIST_PATH.open("w") as lf:
        for h in uniq:
            lf.write(f"{h}\n")

    # 3) 룰 파일 덮어쓰기 (단일 룰)
    with HASH_RULES_PATH.open("w") as rf:
        rf.write(
            f'drop http any any -> any any '
            f'(msg:"SecBot malicious file download"; '
            f'flow:established; filesha256:{HASH_LIST_PATH.name}; '
            f'sid:{BASE_SID_HASH}; rev:1;)\n'
        )

    logger.info("Generated hash list (%d entries) and rule %s", len(uniq), HASH_RULES_PATH)
    _reload_suricata()