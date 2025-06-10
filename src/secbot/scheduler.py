import datetime as _dt
import hashlib
import os
from apscheduler.schedulers.background import BackgroundScheduler

from secbot.config import settings
from secbot.mailer.gmail import (
    send_advisories,
    send_iocs,
    send_security_news,
)
from secbot.fetchers.advisory import get as fetch_advisories
from secbot.fetchers.asec import get_latest_iocs as fetch_asec_ioc
from secbot.fetchers.news import get as fetch_news
from secbot.defense import suricata, suricata_url, suricata_hash


def job_ioc():
    """Send ASEC IOC email and trigger Suricata blocks once per day."""
    iocs = fetch_asec_ioc()

    # Normalise dotted values (e.g. 1[.]2[.]3[.]4)
    normalized = {
        "ip": [ip.replace("[.]", ".") for ip in iocs.get("ip", [])],
        "url": [u.replace("[.]", ".") for u in iocs.get("url", [])],
        "hash": iocs.get("hash", []),
    }

    send_iocs(normalized, subject=f"[SecBot] Malicious IOC {_dt.date.today():%Y-%m-%d}")

    if settings.enable_suricata and normalized["ip"]:
        suricata.block(normalized["ip"])
    if settings.enable_suricata_url and normalized["url"]:
        suricata_url.block_urls(normalized["url"])
    if settings.enable_suricata_hash and normalized["hash"]:
        suricata_hash.block_hashes(normalized["hash"])


def job_news_and_advisories():
    """Fetch news and advisories once per time slot, deduplicate by daily hash record, then send."""
    # Prepare a daily file name for deduplication
    today = _dt.date.today().strftime("%Y%m%d")
    sent_file = f"last_sent_{today}.txt"

    # Load or initialize sent hashes set
    try:
        with open(sent_file, "r") as f:
            sent_hashes = set(f.read().splitlines())
    except FileNotFoundError:
        sent_hashes = set()

    def compute_hash(val: str) -> str:
        return hashlib.sha256(val.encode("utf-8")).hexdigest()

    # Fetch current items
    news_items = fetch_news(limit=settings.news_limit)
    advisories_items = fetch_advisories(limit=settings.advisory_limit)

    # Filter and collect news to send
    filtered_news = []
    for item in news_items:
        key = item.title + "|" + item.link
        h = compute_hash(key)
        if h not in sent_hashes:
            filtered_news.append(item)
            sent_hashes.add(h)

    # Filter and collect advisories to send
    filtered_advisories = []
    for item in advisories_items:
        key = item.id + "|" + item.link
        h = compute_hash(key)
        if h not in sent_hashes:
            filtered_advisories.append(item)
            sent_hashes.add(h)

    # Send emails
    send_security_news(
        filtered_news, subject=f"[SecBot] Security News {_dt.date.today():%Y-%m-%d}"
    )
    send_advisories(
        filtered_advisories,
        subject=f"[SecBot] Vulnerability Advisories {_dt.date.today():%Y-%m-%d}",
    )

    # Persist updated hashes back to daily file
    with open(sent_file, "w") as f:
        for h in sent_hashes:
            f.write(f"{h}\n")


def start_scheduler():
    """Start APScheduler jobs based on configured times."""
    sched = BackgroundScheduler(timezone="Asia/Seoul")

    # IOC 전용 스케줄 (하루에 한 번)
    try:
        h_ioc, m_ioc = map(int, settings.ioc_time.split(":"))
        sched.add_job(job_ioc, "cron", hour=h_ioc, minute=m_ioc, id="job_ioc")
    except ValueError:
        pass

    # 뉴스 + 취약점 스케줄 (리스트의 모든 시간)
    for idx, t in enumerate(settings.cron_time):
        h, m = map(int, t.split(":"))
        sched.add_job(
            job_news_and_advisories, "cron", hour=h, minute=m, id=f"job_news_{idx}"
        )

    sched.start()
    return sched


if __name__ == "__main__":
    scheduler = start_scheduler()
    try:
        import time

        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
