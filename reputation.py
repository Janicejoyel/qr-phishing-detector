"""
Domain reputation (part of Layer 2, threat intelligence).

Checks whether a URL's registered domain is in the Tranco Top 100k list of the
world's most visited, long-established domains. Works offline.

Exceptions that are NEVER trusted, even if popular:
  - URL shorteners (bit.ly ...): they hide the real destination
  - Free hosting platforms (github.io, pages.dev ...): anyone can publish there.
    These are handled automatically because url_features treats each user's
    site on such platforms as its own domain (Public Suffix List private section).
"""
import os

from url_features import SHORTENERS, _extract

TRANCO_PATH = os.path.join("data", "tranco_top100k.txt")
_ranks = None


def _load():
    global _ranks
    if _ranks is None:
        _ranks = {}
        if os.path.exists(TRANCO_PATH):
            with open(TRANCO_PATH, encoding="utf-8") as f:
                for rank, line in enumerate(f, 1):
                    _ranks.setdefault(line.strip(), rank)
    return _ranks


def available():
    return bool(_load())


def domain_rank(host):
    """Return the Tranco rank of the host's registered domain, or None."""
    ext = _extract(host or "")
    if not ext.suffix:
        return None
    registered = f"{ext.domain}.{ext.suffix}"
    if registered in SHORTENERS:
        return None
    return _load().get(registered)
