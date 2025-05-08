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
from dateutil import parser as _dtparser
import requests as _req
from bs4 import BeautifulSoup as _bs

import cloudscraper
import time

logger = logging.getLogger(__name__)

# Use cloudscraper to bypass Cloudflare/WAF challenges for boannews.com
_SCRAPER = cloudscraper.create_scraper()

# Domains for which we skip SSL certificate verification
_SKIP_VERIFY_DOMAINS = ["boannews.com"]

# 추가 RSS를 넣으려면 여기에 URL을 append
RSS_FEEDS: List[str] = [
    # 보안뉴스 – 전체 (2024 URL change)
    "https://www.boannews.com/custom/news_rss.asp?kind=all",
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
    # Try YYYY/MM/DD pattern first
    m = _DATE_RE.search(raw)
    if m:
        return _dt.datetime.strptime(m.group(0), "%Y/%m/%d").date()
    # Fallback to RFC-822 style parsing
    try:
        dt = _dtparser.parse(raw)
        return dt.date()
    except Exception:
        logger.warning("Unable to parse date: %s", raw)
        return None


def _fetch_feed(url: str) -> List[NewsItem]:
    """
    Download the given RSS feed and return parsed NewsItem objects.

    • HTTPS + verify=True  → retry verify=False on SSLError
    • If HTTPS still fails, switch to plain HTTP once
    • Always decode as EUC‑KR because BoanNews serves that encoding
    """
    logger.debug("Fetching RSS feed: %s", url)
    headers = {"User-Agent": "SecBot/1.0 (+https://github.com/handonghyeok/secbot)"}
    headers.update({
        "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
        "Referer": "https://www.boannews.com/",
        "Accept-Language": "ko-KR,ko;q=0.9",
    })

    def _try(u: str, verify: bool) -> bytes | None:
        try:
            # Use cloudscraper for boannews domains to bypass WAF/JS challenges
            if any(domain in u for domain in _SKIP_VERIFY_DOMAINS):
                r = _SCRAPER.get(u, timeout=10, headers=headers)
            else:
                r = _req.get(u, timeout=10, headers=headers, verify=verify)
            r.raise_for_status()
            return r.content
        except Exception as exc:
            logger.warning("GET %s (verify=%s) failed: %s", u, verify, exc)
            return None

    # Always skip SSL verification for specified domains
    verify_flag = False if any(domain in url for domain in _SKIP_VERIFY_DOMAINS) else True

    raw = _try(url, verify=verify_flag)
    # If non-XML on first attempt, and it's a HTTPS URL, try plain HTTP (skipping verification)
    if raw is not None and not raw.lstrip().startswith(b"<?xml"):
        logger.warning("Non-XML content received from %s; retrying HTTP fallback", url)
        if url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            raw = _try(http_url, verify=False)

    if raw is None:
        logger.error("Abandoning feed %s – all attempts exhausted", url)
        return []

    # BoanNews uses EUC‑KR; ignore undecodable characters
    xml_text = raw.decode("euc-kr", "ignore")

    feed = _fp.parse(xml_text)
    items: List[NewsItem] = []

    # Try HTML fallback if RSS yields no items (e.g., cert issues despite intermediate)
    if not feed.entries:
        try:
            logger.warning("RSS parse empty, attempting HTML fallback for %s", url)
            # Determine base URL for HTML fallback
            base_url = url.replace("custom/news_rss.asp?kind=all", "")
            # Attempt HTTPS fallback without cert verification
            try:
                resp = _req.get(base_url, timeout=10, headers=headers, verify=False)
                resp.raise_for_status()
                html = resp.text
            except Exception as https_exc:
                logger.warning("HTTPS HTML fallback failed for %s: %s", base_url, https_exc)
                # Retry plain HTTP
                http_url = base_url.replace("https://", "http://", 1)
                resp = _req.get(http_url, timeout=10, headers=headers, verify=False)
                resp.raise_for_status()
                html = resp.text
            soup = _bs(html, "lxml")
            html_links = soup.select("div.newsList dt a")  # BoanNews HTML headline selector
            for a in html_links:
                items.append(
                    NewsItem(
                        title=a.get_text(strip=True),
                        link=a["href"],
                        published=None
                    )
                )
            logger.info("Parsed %d items via HTML fallback from %s", len(items), url)
        except Exception as exc:
            logger.warning("HTML fallback failed for %s: %s", url, exc)

    if feed.entries:
        for entry in feed.entries:
            published = _parse_date(
                entry.get("published") or entry.get("pubDate") or entry.get("updated")
            )
            items.append(
                NewsItem(
                    title=(entry.get("title") or "").strip(),
                    link=(entry.get("link") or "").strip(),
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
