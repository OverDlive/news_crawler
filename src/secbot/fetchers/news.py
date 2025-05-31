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

KEYWORDS: List[str] = [
    "해킹",
    "XSS",
    "랜섬웨어",
    "해커 조직",
    "정보 유출",
    "APT",
    "디도스",
    "취약점",
    "익스플로잇",
    "피싱",
    "크리덴셜 스터핑",
    "스피어 피싱",
    "제로데이",
    "버퍼 오버플로우",
    "SQL 인젝션",
    "악성코드",
    "봇넷",
    "트로이목마",
    "백도어",
    "크립토재킹",
    "루트킷",
    "사이버 공격",
    "사이버 침해",
    "유심 해킹",
    "홈페이지 일시 중단",
    "개인정보 유출",
    "HSS",
    "APT41",
    "BPF도어"
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
    containing title, link, and published date of each article.
    """
    logger.debug("Fetching HTML feed: %s", url)
    resp = _SCRAPER.get(url, timeout=10, verify=False)
    resp.raise_for_status()
    html = resp.text

    soup = _bs(html, "lxml")
    items: List[NewsItem] = []
    # Each news article block is within div.news_list
    for div in soup.select("div.news_list"):
        # Title and link
        a_tag = div.find("a")
        if not a_tag or not a_tag.get("href"):
            continue
        title_span = div.select_one("span.news_txt")
        if not title_span:
            continue
        title = title_span.get_text(strip=True)
        link = urljoin(url, a_tag["href"])
        # Published date: find span.news_writer, text format "기자 | YYYY년 MM월 DD일 HH:MM"
        date_span = div.select_one("span.news_writer")
        published_date = None
        if date_span:
            # Extract the part after the "|" and strip whitespace
            parts = date_span.get_text(strip=True).split("|")
            if len(parts) == 2:
                date_str = parts[1].strip()
                try:
                    # Parse Korean date format
                    published_dt = _dt.datetime.strptime(date_str, "%Y년 %m월 %d일 %H:%M")
                    published_date = published_dt.date()
                except ValueError:
                    published_date = None
        items.append(NewsItem(title=title, link=link, published=published_date))
    logger.info("Parsed %d items from HTML %s", len(items), url)
    return items



def get(*, limit: int = 10) -> List[NewsItem]:
    """
    Return today's security news headlines matching keywords, up to *limit* items.
    """
    all_items: List[NewsItem] = []
    for url in RSS_FEEDS:
        time.sleep(1)
        try:
            all_items.extend(_fetch_feed(url))
        except Exception as exc:
            logger.warning("Skip feed %s due to error: %s", url, exc)

    # Filter only today's articles
    today = _dt.date.today()
    all_items = [item for item in all_items if item.published == today]

    # Keyword-based filtering
    all_items = [
        item
        for item in all_items
        if any(keyword.lower() in item.title.lower() for keyword in KEYWORDS)
    ]

    # 정렬: published 날짜 기준 최신순
    all_items.sort(key=lambda n: n.published or _dt.date.min, reverse=True)

    # 링크 중복 제거 및 limit 개수만큼 자르기
    seen = set()
    deduped: List[NewsItem] = []
    for item in all_items:
        if item.link in seen:
            continue
        seen.add(item.link)
        deduped.append(item)
        if len(deduped) >= limit:
            break

    logger.info("Returning %d merged news items after filtering", len(deduped))
    return deduped
