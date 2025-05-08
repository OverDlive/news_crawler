import schedule, time
from secbot.fetchers import news, advisory, asec
from secbot.mailer.gmail import send_digest
from secbot.defense import ipset, suricata
from secbot.config import settings

def job():
    n   = news.get()
    adv = advisory.get()
    ioc = asec.get_iocs()
    send_digest(n, adv, ioc)
    ipset.block(ioc["ip"])
    suricata.reload(ioc["ip"])

schedule.every().day.at("06:00").do(job)   # 내부 스케줄러  [oai_citation:9‡schedule.readthedocs.io](https://schedule.readthedocs.io/?utm_source=chatgpt.com) [oai_citation:10‡Redwood](https://www.redwood.com/article/python-job-scheduling/?utm_source=chatgpt.com)
while True:
    schedule.run_pending(); time.sleep(30)