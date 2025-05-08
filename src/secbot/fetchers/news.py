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
import re
from dataclasses import dataclass
from typing import List

import feedparser as _fp

logger = logging.getLogger(__name__)

# 추가 RSS를 넣으려면 여기에 URL을 append
RSS_FEEDS: List[str] = [
    # 보안뉴스 – 전체
    "https://www.boannews.com/media/news_rss.xml",
]

_DATE_RE = re.compile(r"\d{4}/\d{2}/\d{2}")


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


def _parse_date(raw: str | None) -> _dt.date | None:
    if not raw:
        return None
    m = _DATE_RE.search(raw)
    if m:
        # boannews RSS uses 'YYYY/MM/DD HH:MM:SS'
        return _dt.datetime.strptime(m.group(0), "%Y/%m/%d").date()
    return None


def _fetch_feed(url: str) -> List[NewsItem]:
    logger.debug("Fetching RSS feed: %s", url)
    feed = _fp.parse(url)
    items: List[NewsItem] = []

    for entry in feed.entries:
        published = _parse_date(
            entry.get("published") or entry.get("pubDate") or entry.get("updated")
        )
        items.append(
            NewsItem(
                title=entry.get("title", "").strip(),
                link=entry.get("link", "").strip(),
                published=published,
            )
        )

    logger.info("Parsed %d items from %s", len(items), url)
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
