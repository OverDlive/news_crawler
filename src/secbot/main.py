import time, sys, signal, argparse
from secbot.scheduler import start_scheduler
from secbot.utils.logger import setup as log_setup, get_logger
from secbot.fetchers import news, advisory, asec
# Import the new IOC-extraction function
from secbot.fetchers.asec import get_iocs_from_url
from secbot.mailer.gmail import send_digest
from secbot.defense import ipset, suricata
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

        send_digest(n, adv, ioc)

        if settings.enable_ipset and ioc["ip"]:
            ipset.block(ioc["ip"])
        else:
            log.info("ipset disabled or no IPs – skipping block()")

        if settings.enable_suricata and ioc["ip"]:
            suricata.block(ioc["ip"])

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