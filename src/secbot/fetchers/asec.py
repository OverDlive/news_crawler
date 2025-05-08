

"""
secbot.fetchers.asec
~~~~~~~~~~~~~~~~~~~~

Scrape 최신 안랩 **ASEC 블로그** 글에서 IOC(악성 IP‧해시‧URL)를 추출하는 모듈.

공개 RSS 피드가 없으므로 HTML 파싱 → 정규식 매칭 방식을 사용한다.  
HTML 구조가 변경될 경우 `CSS_POST_LINK` 선택자 한 줄만 수정하면 된다.

공용 API
--------
* :pyfunc:`get_posts` – 최근 글 메타데이터 반환 (`Post` dataclass).
* :pyfunc:`get_iocs`  – 최근 *n*개 글에서 IOC 딕셔너리 반환.

Example
-------
>>> from secbot.fetchers import asec
>>> iocs = asec.get_iocs(limit=3)
>>> print(iocs["ip"][:5])
"""

from __future__ import annotations

import datetime as _dt
import logging
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Set

import bs4
import requests

logger = logging.getLogger(__name__)

ASEC_BASE_URL: str = "https://asec.ahnlab.com"
CSS_POST_LINK: str = "h2.entry-title > a"

# IOC 정규식
_PATTERNS = {
    "ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
    ),
    # SHA‑256 (64 hex) & SHA‑1/MD5 (optional) – 필요시 추가
    "hash": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url": re.compile(
        r"https?://[A-Za-z0-9\-_\.]+(?:/[^\s\"'<>]*)?",
        flags=re.IGNORECASE,
    ),
}


@dataclass(slots=True)
class Post:
    """ASEC 블로그 글 메타데이터"""

    title: str
    link: str
    published: _dt.date | None = None


def _soup_from_url(url: str) -> bs4.BeautifulSoup:
    headers = {
        "User-Agent": (
            "SecBot/1.0 (+https://github.com/handonghyeok/news_crawler)"
        )
    }
    logger.debug("GET %s", url)
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    return bs4.BeautifulSoup(resp.text, "lxml")


def get_posts(*, limit: int = 5) -> List[Post]:
    """
    최근 *limit*개의 ASEC 글을 반환.

    Parameters
    ----------
    limit:
        추출할 글 개수(기본 5).

    Returns
    -------
    list[Post]
    """
    soup = _soup_from_url(ASEC_BASE_URL)
    links = soup.select(CSS_POST_LINK)[:limit]

    posts: List[Post] = []
    for a in links:
        title = a.get_text(strip=True)
        href = a["href"]
        posts.append(Post(title=title, link=href))
    logger.info("Fetched %d ASEC post links", len(posts))
    return posts


def _extract_iocs_from_html(html: str) -> Dict[str, Set[str]]:
    iocs = {k: set() for k in _PATTERNS}
    for kind, pat in _PATTERNS.items():
        iocs[kind].update(pat.findall(html))
    return iocs


def _merge_iocs(dst: Dict[str, Set[str]], src: Dict[str, Iterable[str]]) -> None:
    for k in dst:
        dst[k].update(src.get(k, []))


def get_iocs(*, limit: int = 5) -> Dict[str, List[str]]:
    """
    최근 *limit*개 ASEC 글에서 IOC를 수집 후 dedup‧정렬해 반환.

    Returns
    -------
    dict[str, list[str]]
        {"ip": [...], "hash": [...], "url": [...]}
    """
    posts = get_posts(limit=limit)
    merged: Dict[str, Set[str]] = {k: set() for k in _PATTERNS}

    for p in posts:
        try:
            soup = _soup_from_url(p.link)
        except requests.RequestException as exc:
            logger.warning("Skip %s due to error: %s", p.link, exc)
            continue
        iocs = _extract_iocs_from_html(soup.get_text(" ", strip=True))
        _merge_iocs(merged, iocs)

    # set → sorted list 로 변환
    cleaned = {k: sorted(v) for k, v in merged.items()}
    logger.info(
        "Collected IOC counts — IP:%d  HASH:%d  URL:%d",
        len(cleaned["ip"]),
        len(cleaned["hash"]),
        len(cleaned["url"]),
    )
    return cleaned