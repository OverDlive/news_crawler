"""
Unit‑tests for basic fetcher functionality.

The tests operate entirely offline thanks to the fixtures defined in
``tests/conftest.py``.  Each fetcher is fed deterministic sample data so
that parsing logic can be verified without depending on external servers.
"""

from __future__ import annotations

import pytest

from secbot.fetchers import advisory, news

# --------------------------------------------------------------------------- #
#  News fetcher
# --------------------------------------------------------------------------- #


def test_news_get_parses_items(requests_mock, sample_boan_rss):
    # Patch HTTP call
    requests_mock("boannews.com", sample_boan_rss)

    items = news.get(limit=2)
    assert len(items) == 2
    assert items[0].title == "First headline"
    assert items[1].link.endswith("/2")
    # Ensure published date was parsed
    assert items[0].published.year == 2025


# --------------------------------------------------------------------------- #
#  Advisory fetcher
# --------------------------------------------------------------------------- #


def test_advisory_get_parses_items(requests_mock, sample_kisa_rss):
    requests_mock("krcert.or.kr", sample_kisa_rss)

    items = advisory.get(limit=5)
    assert len(items) == 1
    adv = items[0]
    assert "취약점" in adv.title
    assert adv.link.startswith("https://cert.or.kr")
    assert adv.published.year == 2025


# --------------------------------------------------------------------------- #
#  ASEC IOC fetcher – very light check
# --------------------------------------------------------------------------- #


@pytest.mark.network
def test_asec_fetcher_online():
    """
    Simple smoke‑test that ensures get_iocs() returns the expected keys.

    Marked with @network because it hits the real ASEC site.
    """
    from secbot.fetchers import asec

    iocs = asec.get_iocs(limit=1)
    assert set(iocs) == {"ip", "hash", "url"}
    # We do not assert specific values as the feed is dynamic.
