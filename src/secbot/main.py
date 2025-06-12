import time, sys, signal, argparse
from secbot.scheduler import start_scheduler
from secbot.utils.logger import setup as log_setup, get_logger
from secbot.fetchers import news, advisory
# Import the new IOC-extraction function
from secbot.fetchers.asec import get_iocs_from_url
from secbot.mailer.gmail import send_digest
from secbot.defense import suricata
from secbot.defense import suricata_url, suricata_hash
from secbot.config import settings

# Configure root logger (KST timestamps, optional file)
log_setup(level="DEBUG" if settings.debug else "INFO")
log = get_logger(__name__)

# ------------------------------------------------------------------ #
# CLI argument parsing
# ------------------------------------------------------------------ #
_parser = argparse.ArgumentParser(description="SecBot launcher")
_parser.add_argument(
    "--once", "-1",
    action="store_true",
    help="Run one full SecBot cycle immediately and exit."
)
_ARGS = _parser.parse_args()

def job() -> None:
    """Run one full SecBot cycle (news → advisory → IOC → mail → defense)."""
    try:
        log.info("=== SecBot job started ===")

        n   = news.get(limit=settings.news_limit)
        adv = advisory.get(limit=settings.advisory_limit)
        # Fetch IOC directly from ASEC 'Daily Threat' listing (always latest)
        ioc = get_iocs_from_url("https://asec.ahnlab.com/ko/category/threatviews-ko/?latest=")

        # Normalize IOC entries: convert bracketed dot notation to standard format
        normalized_ioc = {
            "ip":   [ip.replace("[.]", ".") for ip in ioc.get("ip", [])],
            "url":  [url.replace("[.]", ".") for url in ioc.get("url", [])],
            "hash": ioc.get("hash", []),
        }

        # Log normalized IOC entries
        log.info(f"Normalized IPs: {normalized_ioc['ip']}")
        log.info(f"Normalized URLs: {normalized_ioc['url']}")
        log.info(f"Normalized Hashes: {normalized_ioc['hash']}")

        send_digest(n, adv, ioc)

        if settings.enable_suricata and normalized_ioc["ip"]:
            suricata.block(normalized_ioc["ip"])
        else:
            log.info("suricata disabled or no IPs – skipping Suricata block")

        if settings.enable_suricata_url and normalized_ioc["url"]:
            suricata_url.block_urls(normalized_ioc["url"])
        else:
            log.info("suricata_url disabled or no URLs – skipping URL block")

        if settings.enable_suricata_hash and normalized_ioc["hash"]:
            suricata_hash.block_hashes(normalized_ioc["hash"])
        else:
            log.info("suricata_hash disabled or no hashes – skipping hash block")

        log.info("SecBot job finished OK")
    except Exception:
        log.exception("SecBot job failed")


if __name__ == "__main__":
    if _ARGS.once:
        job()
    else:
        scheduler = start_scheduler()
        log.info("SecBot scheduler started")
        try:
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            log.info("SecBot scheduler stopping – exiting.")
            scheduler.shutdown()
            sys.exit(0)