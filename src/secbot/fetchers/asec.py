"""
secbot.fetchers.asec
~~~~~~~~~~~~~~~~~~~~

Scrape 최신 안랩 **ASEC 블로그** 글에서 IOC(악성 IP‧해시‧URL)를 추출하는 모듈.

공개 RSS 피드가 없으므로 HTML 파싱 → 정규식 매칭 방식을 사용한다.  
HTML 구조가 변경될 경우 `CSS_POST_LINK` 선택자 한 줄만 수정하면 된다.

공용 API
--------
* :pyfunc:`get_iocs_from_url` – 특정 글 URL에서 IOC 딕셔너리 반환.

Example
-------
>>> from secbot.fetchers import asec
>>> iocs = asec.get_iocs_from_url("https://asec.ahnlab.com/ko/87814/")
>>> print(iocs["ip"][:5])
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Set, Iterable, Any

import bs4
import requests

logger = logging.getLogger(__name__)

# CSS selector to find daily threat posts on ASEC listing page
CSS_POST_LINK: str = "div.list_cont a.tit"  # adjust selector based on current ASEC list structure
ASEC_LIST_URL: str = "https://asec.ahnlab.com/ko/"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 SecBot/1.0"
    ),
    "Accept-Language": "ko,en;q=0.8",
}

_PATTERNS = {
    "ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.|\[\.\])){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
    ),
    "hash": re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b"),
    "url": re.compile(
        r"(?:https?://[A-Za-z0-9\-_\.]+(?:/[^\s\"'<>]*)?|https?\[:\]//[^\s\"'<>]+)",
        flags=re.IGNORECASE,
    ),
}


def _soup_from_url(url: str) -> bs4.BeautifulSoup:
    headers = HEADERS
    logger.debug("GET %s", url)
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    return bs4.BeautifulSoup(resp.text, "lxml")


def get_posts(limit: int = 1) -> list[str]:
    """
    Fetch the URLs of the latest `limit` ASEC blog posts from the listing page.
    """
    soup = _soup_from_url(ASEC_LIST_URL)
    links = soup.select(CSS_POST_LINK)[:limit]
    urls = []
    for a in links:
        href = a.get("href")
        if href and href.startswith("/"):
            href = ASEC_LIST_URL.rstrip("/") + href
        urls.append(href)
    return urls


def _extract_iocs_from_html(html: str) -> Dict[str, Set[str]]:
    iocs = {k: set() for k in _PATTERNS}
    for kind, pat in _PATTERNS.items():
        iocs[kind].update(pat.findall(html))
    return iocs


def get_iocs_from_url(url: str) -> Dict[str, List[str]]:
    """
    Fetch IOC data (IP, hash, URL) from a specific ASEC blog post URL.
    추가로 통계(카운트)와 네트워크 공격 국가·포트 정보를 함께 가져옵니다.
    """
    try:
        soup = _soup_from_url(url)
    except requests.RequestException as exc:
        logger.error("Failed to fetch ASEC URL %s: %s", url, exc)
        return {k: [] for k in _PATTERNS}

    # 1) 전체 텍스트를 한 줄로 합쳐서 IOC(정규표현식) 추출
    full_text = soup.get_text(" ", strip=True)
    src_iocs = _extract_iocs_from_html(full_text)

    # 2) 앵커 태그 내 URL도 추가 추출
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if _PATTERNS["url"].search(href):
            src_iocs["url"].add(href)

    # 3) AhnLab 내부 링크 제외
    exclude_urls = {
        "https://asec.ahnlab.com/",
        "https://asec.ahnlab.com/ko/87737/",
        "https://asec.ahnlab.com/ko/87750/",
        "https://asec.ahnlab.com/ko/87752/",
        "https://asec.ahnlab.com/ko/87754/",
        "https://asec.ahnlab.com/ko/87756/",
        "https://asec.ahnlab.com/ko/87792/",
        "https://asec.ahnlab.com/ko/87814/",
    }
    src_iocs["url"] = {
        u for u in src_iocs["url"] if u not in exclude_urls and "ahnlab.com" not in u
    }

    # Extract Hash, URL, IP counts which appear as three numbers in a row before "Top1"
    hash_count = ""
    url_count = ""
    ip_count = ""
    counts_match = re.search(
        r"(\d{1,3}(?:,\d{3})*)\s+(\d{1,3}(?:,\d{3})*)\s+(\d{1,3}(?:,\d{3})*)\s+Top1",
        full_text,
        re.IGNORECASE,
    )
    if counts_match:
        hash_count = counts_match.group(1)
        url_count = counts_match.group(2)
        ip_count = counts_match.group(3)
    src_iocs["hash_count"] = {hash_count} if hash_count else set()
    src_iocs["url_count"] = {url_count} if url_count else set()
    src_iocs["ip_count"] = {ip_count} if ip_count else set()

    # Extract all Top1 occurrences for country and port
    top1_matches = re.findall(
        r"Top1\s+([A-Za-z0-9\s]+)\s+(\d{1,3}(?:,\d{3})*)",
        full_text,
        re.IGNORECASE,
    )
    network_countries: Set[str] = set()
    network_ports: Set[str] = set()
    network_country_count = ""
    network_port_count = ""
    if top1_matches:
        # The first Top1 match corresponds to the country
        country_name, country_cnt = top1_matches[0]
        network_countries.add(country_name.strip())
        network_country_count = country_cnt.strip()
        # If there's a second match, it's the port
        if len(top1_matches) >= 2:
            port_name, port_cnt = top1_matches[1]
            network_ports.add(port_name.strip())
            network_port_count = port_cnt.strip()
    src_iocs["network_country"] = network_countries
    src_iocs["country_count"] = {network_country_count} if network_country_count else set()
    src_iocs["network_port"] = network_ports
    src_iocs["port_count"] = {network_port_count} if network_port_count else set()

    # 7) 모든 set 값을 sorted list로 변환하여 반환
    return {
        k: sorted(v) if isinstance(v, set) else v
        for k, v in src_iocs.items()
    }


def get_latest_iocs(post_limit: int = 1) -> Dict[str, List[str]]:
    """
    Fetch IOC data from the latest `post_limit` ASEC posts.
    Aggregates and deduplicates IP, hash, and URL.
    """
    merged: Dict[str, set] = {k: set() for k in _PATTERNS}
    posts = get_posts(limit=post_limit)
    for url in posts:
        try:
            iocs = get_iocs_from_url(url)
        except Exception:
            continue
        for kind, items in iocs.items():
            merged[kind].update(items)
    # Convert to sorted lists
    return {k: sorted(v) for k, v in merged.items()}
