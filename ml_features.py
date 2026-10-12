"""
Features for the ML model (Layer 3).

The model only looks at the REGISTERED DOMAIN (e.g. "google.com" out of
"https://docs.google.com/forms"). Two dataset biases in PhiUSIIL make this
necessary:
  Bias 1: every legitimate URL is an https homepage -> a model trained on full
          URLs learns "has a path or uses http = phishing".
  Bias 2: 97% of legitimate URLs start with "www." -> a model that sees
          subdomains learns "no www = phishing", which falsely flags
          docs.google.com, en.wikipedia.org, x.com, t.me ...
          (found during real-world evaluation, Phase 8).
Scheme, path and subdomain tricks are judged by the rules in url_features.py.
"""
import ipaddress
import math
from collections import Counter
from urllib.parse import urlparse

from url_features import (_extract, _normalize, BRANDS, LOOKALIKE_SWAPS,
                          SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS)

VOWELS = set("aeiou")

FEATURE_NAMES = [
    "host_length", "domain_length", "tld_length", "num_dots", "num_hyphens",
    "num_digits", "digit_ratio", "uses_ip", "suspicious_tld",
    "vowel_ratio", "entropy", "max_consonant_run", "brand_in_host",
    "keyword_in_host",
]


def _entropy(text):
    """Shannon entropy: how random the characters look (random = suspicious)."""
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def _max_consonant_run(text):
    """Longest run of consonants, e.g. 'xkqzt' in a random-looking domain."""
    best = run = 0
    for ch in text:
        if ch.isalpha() and ch not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def host_features(url):
    """Turn a URL's domain name into a list of numbers for the model."""
    full_host = (urlparse(_normalize(url)).hostname or "").lower()

    try:
        ipaddress.ip_address(full_host)
        uses_ip = 1
    except ValueError:
        uses_ip = 0

    ext = _extract(full_host)
    domain = ext.domain
    # Registered domain only (subdomains are ignored, see Bias 2 above)
    host = full_host if uses_ip else (f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain)
    letters = [c for c in domain if c.isalpha()]
    swapped = full_host.translate(LOOKALIKE_SWAPS)

    return [
        len(host),
        len(domain),
        len(ext.suffix),
        host.count("."),
        host.count("-"),
        sum(c.isdigit() for c in host),
        sum(c.isdigit() for c in host) / max(len(host), 1),
        uses_ip,
        int(ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS),
        sum(c in VOWELS for c in letters) / max(len(letters), 1),
        _entropy(domain),
        _max_consonant_run(domain),
        int(any(b in swapped and host not in offs for b, offs in BRANDS.items())),
        int(any(k in full_host for k in SUSPICIOUS_KEYWORDS)),
    ]
