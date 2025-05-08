import schedule, time, sys, signal
from secbot.utils.logger import setup as log_setup, get_logger
from secbot.fetchers import news, advisory, asec
from secbot.mailer.gmail import send_digest
from secbot.defense import ipset, suricata
from secbot.config import settings

# Configure root logger (KST timestamps, optional file)
log_setup(level="DEBUG" if settings.debug else "INFO")
log = get_logger(__name__)

def job() -> None:
    """Run one full SecBot cycle (news → advisory → IOC → mail → defense)."""
    try:
        log.info("=== SecBot job started ===")

        n   = news.get(limit=settings.news_limit)
        adv = advisory.get(limit=settings.advisory_limit)
        ioc = asec.get_iocs(limit=settings.asec_post_limit)

        send_digest(n, adv, ioc)

        if settings.enable_ipset:
            ipset.block(ioc["ip"])
        if settings.enable_suricata:
            suricata.block(ioc["ip"])

        log.info("SecBot job finished OK")
    except Exception:
        log.exception("SecBot job failed")

schedule.every().day.at(settings.cron_time).do(job)
log.info("Scheduled daily job at %s", settings.cron_time)

def _run_loop() -> None:
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("SecBot interrupted by user — exiting.")
        sys.exit(0)

if __name__ == "__main__":
    _run_loop()