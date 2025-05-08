

"""
secbot.parsers.ioc
~~~~~~~~~~~~~~~~~~

Common helper utilities for extracting **Indicators of Compromise (IOC)**
from arbitrary text blobs.

This module centralises the regular‑expression patterns so that every
fetcher in *secbot* uses the _exact_ same logic.  If you ever need to
tweak a pattern (for example, to support IPv6 or a new hash type), you
only have to update it here.

Public API
----------
PATTERNS : dict[str, Pattern]
    Compiled regex patterns keyed by ``"ip"``, ``"url"``, ``"hash"`` …
extract(text) -> dict[str, list[str]]
    Scan *text* and return all matched IOCs as **deduplicated & sorted**
    lists grouped by kind.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Dict, List, Pattern

# ────────────────────────────────────────────────────────────────────────────
# Regex Patterns (all raw string literals)
# ────────────────────────────────────────────────────────────────────────────

_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1?\d{1,2})"
_IPV4_REGEX = rf"\b(?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET}\b"

# Basic URL – scheme + host + optional path
_URL_REGEX = (
    r"https?://[A-Za-z0-9\-_\.]+"
    r"(?:\:[0-9]{1,5})?"  # optional port
    r"(?:/[^\s'\"<>]*)?"  # optional path/query
)

# Hashes
_MD5_REGEX = r"\b[a-fA-F0-9]{32}\b"
_SHA1_REGEX = r"\b[a-fA-F0-9]{40}\b"
_SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"

PATTERNS: Dict[str, Pattern[str]] = {
    "ip": re.compile(_IPV4_REGEX),
    "url": re.compile(_URL_REGEX, re.IGNORECASE),
    "hash": re.compile(rf"(?:{_SHA256_REGEX}|{_SHA1_REGEX}|{_MD5_REGEX})"),
}

# Order in which kinds are iterated when presenting results
_KIND_ORDER = ("ip", "hash", "url")


# ────────────────────────────────────────────────────────────────────────────
# Public helpers
# ────────────────────────────────────────────────────────────────────────────
@lru_cache(maxsize=128)
def _sorted_unique(matches: tuple[str, ...]) -> List[str]:
    """Helper to deduplicate and sort matches (cached for speed)."""
    return sorted(set(matches))


def extract(text: str) -> Dict[str, List[str]]:
    """
    Extract IOCs from *text*.

    Parameters
    ----------
    text:
        Arbitrary textual content (HTML, plain text, log output …).

    Returns
    -------
    dict[str, list[str]]
        Keys are ``"ip"``, ``"hash"``, ``"url"``.  Missing kinds are included
        with empty lists to keep the structure stable.
    """
    results: Dict[str, List[str]] = {}
    for kind in _KIND_ORDER:
        pat = PATTERNS[kind]
        matches = pat.findall(text)
        results[kind] = _sorted_unique(tuple(matches))
    return results