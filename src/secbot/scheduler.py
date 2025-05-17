import datetime as _dt
from apscheduler.schedulers.background import BackgroundScheduler
from secbot.config import settings
from secbot.mailer.gmail import (
    send_security_news,
    send_advisories,
    send_iocs,
)
from secbot.fetchers.news import get as fetch_news
from secbot.fetchers.advisory import get as fetch_advisories
from secbot.fetchers.asec import get_latest_iocs as fetch_asec_ioc

def job_ioc():
    """오전 지정 시간에만 ASEC IOC 전용 메일 발송."""
    iocs = fetch_asec_ioc()   # {'ip': [...], 'hash': [...], 'url': [...]}
    send_iocs(iocs, subject=f"[SecBot] Malicious IOC {_dt.date.today():%Y-%m-%d}")

def job_news_and_advisories():
    """보안뉴스 + KISA 취약점 중복 제거 후 메일 발송."""
    news = fetch_news(limit=settings.news_limit)
    advisories = fetch_advisories(limit=settings.advisory_limit)

    # --- 중복 제거(예시) ---
    # File or DB 등에 “오늘 이미 보낸 ID”를 기록해 두었다가
    # fetch 결과에서 제외시키면 됩니다.
    # 아래는 very-simple 예시: 파일에 저장된 타이틀을 읽어서 필터링
    sent_titles = set(open("last_sent_titles.txt", "a+").read().splitlines())
    filtered_news = [n for n in news         if n.title not in sent_titles]
    filtered_kisa = [a for a in advisories  if a.id    not in sent_titles]

    # 메일 발송
    send_security_news(filtered_news, subject=f"[SecBot] Security News {_dt.date.today():%Y-%m-%d}")
    send_advisories(filtered_kisa, subject=f"[SecBot] Vulnerability Advisories {_dt.date.today():%Y-%m-%d}")

    # 발송한 타이틀을 기록
    with open("last_sent_titles.txt", "a") as f:
        for item in filtered_news + filtered_kisa:
            f.write(item.title + "\n")
def start_scheduler():
    """스케줄러 시작: IOC는 cron_time 리스트의 첫 번째 시간에, 뉴스/취약점은 cron_time 리스트의 모든 시간에 실행."""
    sched = BackgroundScheduler(timezone="Asia/Seoul")

    # IOC 전용 스케줄 (하루에 한 번 첫 번째 시간)
    ioc_times = settings.cron_time
    if isinstance(ioc_times, list) and ioc_times:
        h_ioc, m_ioc = map(int, ioc_times[0].split(":"))
        sched.add_job(job_ioc, 'cron', hour=h_ioc, minute=m_ioc, id="job_ioc")

    # 뉴스 + 취약점 스케줄 (리스트의 모든 시간)
    for idx, t in enumerate(settings.cron_time):
        h, m = map(int, t.split(":"))
        sched.add_job(
            job_news_and_advisories,
            'cron',
            hour=h, minute=m,
            id=f"job_news_{idx}"
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