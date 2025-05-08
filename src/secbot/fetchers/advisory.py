

"""
secbot.fetchers.advisory
~~~~~~~~~~~~~~~~~~~~~~~~

Fetch and parse **KISA(한국인터넷진흥원) 보안공지 / 취약점 공지** RSS feed.

The module exposes a single public helper:

* :pyfunc:`get` – return the most recent *n* advisory items as a list of
  :class:`Advisory` dataclass objects.

Example
-------
>>> from secbot.fetchers import advisory
>>> for item in advisory.get(limit=5):
...     print(item.published, item.title)
"""

from __future__ import annotations

import datetime as _dt
import logging
import re
from dataclasses import dataclass
from typing import List

import feedparser as _fp

logger = logging.getLogger(__name__)

KISA_RSS_URL: str = "https://knvd.krcert.or.kr/rss/securityNotice.do"
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


@dataclass(slots=True)
class Advisory:
    """Simple container for a KISA advisory entry."""

    title: str
    link: str
    published: _dt.date
    summary: str

    def to_md(self) -> str:
        """Return a Markdown bullet-line representation."""
        return f"- **{self.published.isoformat()}** — [{self.title}]({self.link})"


def _parse_date(raw: str | None) -> _dt.date:
    """Convert 'YYYY-MM-DD HH:MM:SS' or similar to date."""
    if not raw:
        return _dt.date.today()
    m = _DATE_RE.search(raw)
    if m:
        return _dt.date.fromisoformat(m.group(0))
    # Fallback to today
    return _dt.date.today()


def get(*, limit: int = 10) -> List[Advisory]:
    """
    Fetch the KISA security notice RSS and return up to *limit* items.

    Parameters
    ----------
    limit:
        Maximum number of results to return (default 10).

    Returns
    -------
    list[Advisory]
        Parsed and normalised advisory entries, newest first.
    """
    logger.debug("Fetching KISA advisory RSS from %s", KISA_RSS_URL)
    feed = _fp.parse(KISA_RSS_URL)

    items: List[Advisory] = []
    for entry in feed.entries[:limit]:
        published = _parse_date(entry.get("published") or entry.get("updated"))
        items.append(
            Advisory(
                title=entry.get("title", "").strip(),
                link=entry.get("link", "").strip(),
                published=published,
                summary=(entry.get("summary") or entry.get("description") or "").strip(),
            )
        )

    logger.info("Fetched %d advisory items", len(items))
    return items