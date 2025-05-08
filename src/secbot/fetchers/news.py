"""
secbot.fetchers.news
~~~~~~~~~~~~~~~~~~~~

Fetch security‑related **news headlines** from one or more RSS feeds.

현재 버전은 보안뉴스(https://www.boannews.com)의 통합 RSS 피드를 기본으로
사용하며, 필요 시 RSS URL을 리스트에 추가하면 바로 확장된다.

공용 API
--------
get(limit=10) -> list[NewsItem]
    가장 최신 헤드라인 *limit*개를 NewsItem dataclass 리스트로 반환.
"""

from __future__ import annotations

import datetime as _dt
import logging
from dataclasses import dataclass
from typing import List

import cloudscraper
import time
from urllib.parse import urljoin
from bs4 import BeautifulSoup as _bs

logger = logging.getLogger(__name__)

# Use cloudscraper to bypass Cloudflare/WAF challenges for boannews.com
_SCRAPER = cloudscraper.create_scraper()

# HTML-based feed: 전체기사 목록 page for 보안뉴스
RSS_FEEDS: List[str] = [
    "http://www.boannews.com/media/t_list.asp?Page=1&kind=",
]


@dataclass(slots=True)
class NewsItem:
    """Security news headline container."""

    title: str
    link: str
    published: _dt.date | None = None

    def to_md(self) -> str:
        return f"- [{self.title}]({self.link})" + (
            f" ({self.published.isoformat()})" if self.published else ""
        )


def _fetch_feed(url: str) -> List[NewsItem]:
    """
    Download the 보안뉴스 전체기사 HTML page and return parsed NewsItem objects
    containing title and link of each article.
    """
    logger.debug("Fetching HTML feed: %s", url)
    # Use cloudscraper session to bypass any WAF challenges
    resp = _SCRAPER.get(url, timeout=10, verify=False)
    resp.raise_for_status()
    html = resp.text

    soup = _bs(html, "lxml")
    items: List[NewsItem] = []
    # Article titles are in <span class="news_txt"> under <a>
    for span in soup.select("span.news_txt"):
        a = span.find_parent("a")
        if not a or not a.get("href"):
            continue
        title = span.get_text(strip=True)
        link = urljoin(url, a["href"])
        items.append(NewsItem(title=title, link=link))
    logger.info("Parsed %d items from HTML %s", len(items), url)
    return items



def get(*, limit: int = 10) -> List[NewsItem]:
    """
    Return the latest *limit* security news headlines across all feeds.

    Parameters
    ----------
    limit:
        Max number of items to return (default 10).

    Notes
    -----
    The function merges multiple feeds, sorts by date (fallback to order),
    removes duplicates, and truncates to *limit*.
    """
    all_items: List[NewsItem] = []
    for url in RSS_FEEDS:
        time.sleep(1)
        try:
            all_items.extend(_fetch_feed(url))
        except Exception as exc:  # feedparser returns Exceptions for bad feeds
            logger.warning("Skip feed %s due to error: %s", url, exc)

    # 정렬: published가 있다면 최신순, 없으면 그대로
    all_items.sort(key=lambda n: n.published or _dt.date.min, reverse=True)

    # 링크 중복 제거
    seen = set()
    deduped: List[NewsItem] = []
    for item in all_items:
        if item.link in seen:
            continue
        seen.add(item.link)
        deduped.append(item)
        if len(deduped) >= limit:
            break

    logger.info("Returning %d merged news items", len(deduped))
    return deduped
