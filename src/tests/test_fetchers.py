

"""
Unit tests for SecBot fetcher modules.

The tests are designed to run completely offline using fixtures defined in
tests/conftest.py.  Network calls are mocked out, so no external dependency
is required.
"""

from __future__ import annotations

import pytest

from secbot.fetchers import advisory, news

# --------------------------------------------------------------------------- #
# News fetcher                                                                #
# --------------------------------------------------------------------------- #


def test_news_get_parses_items(requests_mock, sample_boan_rss):
    """news.get() should parse two items out of the sample BoanNews RSS."""
    # Mock HTTP response
    requests_mock("boannews.com", sample_boan_rss)

    items = news.get(limit=2)
    assert len(items) == 2
    assert items[0].title == "First headline"
    assert items[1].title == "Second headline"
    # Publication date parsing
    assert items[0].published.year == 2025


# --------------------------------------------------------------------------- #
# Advisory fetcher                                                            #
# --------------------------------------------------------------------------- #


def test_advisory_get_parses_items(requests_mock, sample_kisa_rss):
    """advisory.get() should parse one item from the sample KISA RSS."""
    requests_mock("krcert.or.kr", sample_kisa_rss)

    items = advisory.get(limit=5)
    assert len(items) == 1
    adv = items[0]
    assert "취약점" in adv.title
    assert adv.link.startswith("https://cert.or.kr/")
    assert adv.published.year == 2025


# --------------------------------------------------------------------------- #
# ASEC IOC fetcher (optional online smoke-test)                               #
# --------------------------------------------------------------------------- #


@pytest.mark.network
def test_asec_fetcher_online():
    """
    Smoke‑test ASEC IOC fetcher against the live site.

    Mark with `-m network` to opt‑in, e.g.:

        pytest -m network
    """
    from secbot.fetchers import asec

    iocs = asec.get_iocs(limit=1)
    # Ensure keys exist and each value is a list
    assert set(iocs.keys()) == {"ip", "hash", "url"}
    for v in iocs.values():
        assert isinstance(v, list)