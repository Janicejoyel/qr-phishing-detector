import ipaddress
import re
from urllib.parse import urlparse

import tldextract

# Splits domains into parts. suffix_list_urls=() makes it work offline.
# include_psl_private_domains=True: free hosting platforms like github.io,
# pages.dev or vercel.app are treated like domain endings, so every user's site
# on them counts as its own separate domain (anyone can publish there).
_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

# ---------- Threat knowledge lists ----------
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnk.ink",
    "nlink.at", "t.ly", "s.id", "v.gd", "qrco.de", "short.io", "bl.ink",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account", "bank",
    "password", "confirm", "wallet", "payment", "suspend", "unlock", "billing",
]

# Domain endings most abused for phishing/malware because they are cheap or
# free. Based on Spamhaus "most abused TLDs" and Interisle phishing reports.
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "click", "country",
    "work", "rest", "fit", "loan", "cfd", "sbs", "icu", "cyou", "bond", "help",
    "vip", "shop", "live", "online", "site", "store", "buzz", "lol", "mom",
    "today", "ink", "cam", "bar", "support", "pw", "ws", "life", "beauty",
    "hair", "skin", "makeup", "quest", "monster", "win", "bid", "men",
    "review", "date", "stream", "download", "racing", "party", "gdn", "su",
}

# Most-impersonated brands (from industry phishing brand reports, e.g. Check
# Point / APWG, plus major Indian services) -> ALL their official domains
BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.in", "youtube.com", "goo.gl"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com"},
    "outlook": {"outlook.com", "live.com", "office.com"},
    "office365": {"office.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "aws.amazon.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "yahoo": {"yahoo.com"},
    "spotify": {"spotify.com"},
    "roblox": {"roblox.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "ebay": {"ebay.com", "ebay.in"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "onlinesbi": {"onlinesbi.sbi", "sbi.co.in"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
    "airtel": {"airtel.in"},
    "indiapost": {"indiapost.gov.in"},
}
ALL_OFFICIAL = set().union(*BRANDS.values())


def _edit_distance(a, b):
    """Number of single-letter edits to turn a into b (Levenshtein distance)."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_check(host):
    """Return (impersonated_brand, typosquatted_brand) for a hostname."""
    ext = _extract(host)
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    if registered in ALL_OFFICIAL:
        return None, None
    swapped = host.translate(LOOKALIKE_SWAPS)
    impersonated = next((b for b in BRANDS if b in swapped), None)
    # Typosquatting: domain name is one letter away from a brand (robiox ~ roblox)
    label = ext.domain.translate(LOOKALIKE_SWAPS)
    typo = next((b for b in BRANDS if len(b) >= 5 and label != b
                 and _edit_distance(label, b) == 1), None)
    return impersonated, typo


# Characters attackers swap to fake a brand name (paypa1 -> paypal)
LOOKALIKE_SWAPS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a",
                                 "5": "s", "7": "t", "@": "a"})


def _normalize(url):
    """Add http:// if the URL has no scheme, so it can be parsed properly."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def extract_features(url):
    """Turn a URL into a dictionary of numbers describing it."""
    url = _normalize(url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    ext = _extract(host)
    registered = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    # Is the host a raw IP address?
    try:
        ipaddress.ip_address(host)
        uses_ip = 1
    except ValueError:
        uses_ip = 0

    # Brand impersonation and typosquatting
    brand_hit, typo_hit = brand_check(host) if not uses_ip else (None, None)

    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(parsed.path),
        "num_dots": host.count("."),
        "num_hyphens": host.count("-"),
        "num_digits_in_host": sum(c.isdigit() for c in host),
        "num_subdomains": len([s for s in ext.subdomain.split(".") if s]),
        "num_query_params": len([p for p in parsed.query.split("&") if p]),
        "has_at_symbol": int("@" in url),
        "has_https": int(parsed.scheme == "https"),
        "uses_ip": uses_ip,
        "is_shortener": int(registered in SHORTENERS),
        "suspicious_tld": int(ext.suffix in SUSPICIOUS_TLDS),
        "num_suspicious_keywords": sum(k in url.lower() for k in SUSPICIOUS_KEYWORDS),
        "brand_impersonation": int(brand_hit is not None),
        "typosquatting": int(typo_hit is not None),
        "has_double_slash_redirect": int("//" in parsed.path),
    }


# ---------- Rules: (condition, points, explanation) ----------
RULES = [
    (lambda f: f["uses_ip"], 25, "Uses a raw IP address instead of a domain name"),
    (lambda f: f["brand_impersonation"], 30, "Looks like it is impersonating a known brand"),
    (lambda f: f["typosquatting"], 30, "Domain is a misspelling of a known brand (typosquatting)"),
    (lambda f: f["is_shortener"], 15, "Uses a URL shortener that hides the real destination"),
    (lambda f: f["has_at_symbol"], 20, "Contains '@', which can hide the real destination"),
    (lambda f: not f["has_https"], 10, "Does not use HTTPS (connection is not encrypted)"),
    (lambda f: f["suspicious_tld"], 15, "Uses a domain ending often abused by attackers"),
    (lambda f: f["num_suspicious_keywords"] >= 2, 15, "Contains several phishing-style words (login, verify, account...)"),
    (lambda f: f["num_subdomains"] >= 3, 10, "Has an unusually high number of subdomains"),
    (lambda f: f["num_hyphens"] >= 2, 10, "Domain contains many hyphens"),
    (lambda f: f["url_length"] > 75, 10, "URL is unusually long"),
    (lambda f: f["has_double_slash_redirect"], 10, "Contains a hidden redirect ('//' in the path)"),
]


def analyze_url(url):
    """Apply the rules to a URL and return score, verdict and red flags."""
    features = extract_features(url)
    score, red_flags = 0, []
    for condition, points, reason in RULES:
        if condition(features):
            score += points
            red_flags.append(reason)
    score = min(score, 100)

    if score >= 50:
        verdict = "Malicious"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {"features": features, "rule_score": score,
            "verdict": verdict, "red_flags": red_flags}


# Self-test: decode each test QR, then analyze its URL
if __name__ == "__main__":
    import os
    from qr_decoder import decode_qr_from_path

    for name in sorted(os.listdir("test_qrs")):
        url = decode_qr_from_path(os.path.join("test_qrs", name))
        result = analyze_url(url)
        print(f"\n{name}")
        print(f"  URL:   {url}")
        print(f"  Score: {result['rule_score']}/100 -> {result['verdict']}")
        for flag in result["red_flags"]:
            print(f"   - {flag}")