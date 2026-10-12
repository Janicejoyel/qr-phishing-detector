"""
Layer 2: Threat Intelligence lookups.

Checks a URL against external intelligence sources:
  1. VirusTotal      - verdicts from 70+ security vendors
  2. OpenPhish feed  - list of currently active phishing URLs
  3. WHOIS           - how old the domain is (new = risky)
  4. Redirect check  - where a short link really leads
"""
import base64
import ipaddress
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import tldextract
import whois

from url_features import _normalize

_extract = tldextract.TLDExtract(suffix_list_urls=())

DATA_DIR = "data"
OPENPHISH_URL = "https://openphish.com/feed.txt"
OPENPHISH_CACHE = os.path.join(DATA_DIR, "openphish_feed.txt")
FEED_MAX_AGE_HOURS = 6       # re-download the feed after this many hours
VT_MIN_GAP_SECONDS = 15      # free VirusTotal plan allows 4 requests per minute
_last_vt_call = 0.0


# ---------- Helper: read the secret API key from .env ----------
def _load_env(path=".env"):
    """Read KEY=VALUE lines from .env into environment variables."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())


_load_env()
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


def _registered_domain(url):
    host = (urlparse(url).hostname or "").lower()
    ext = _extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------- 1. VirusTotal ----------
def _vt_wait():
    """Pause if needed so we stay inside the free plan's rate limit."""
    global _last_vt_call
    gap = time.time() - _last_vt_call
    if gap < VT_MIN_GAP_SECONDS:
        time.sleep(VT_MIN_GAP_SECONDS - gap)
    _last_vt_call = time.time()


def check_virustotal(url, scan_if_unknown=False):
    """Ask VirusTotal how many security vendors flag this URL."""
    if not VT_API_KEY:
        return {"status": "no_api_key"}

    headers = {"x-apikey": VT_API_KEY}
    # VirusTotal identifies a URL by its base64 encoding (without '=' padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        _vt_wait()
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                         headers=headers, timeout=15)

        if r.status_code == 404:
            if not scan_if_unknown:
                return {"status": "not_in_database"}
            # Unknown URL: submit it for a fresh scan, then fetch the result
            _vt_wait()
            sub = requests.post("https://www.virustotal.com/api/v3/urls",
                                headers=headers, data={"url": url}, timeout=15)
            sub.raise_for_status()
            analysis_id = sub.json()["data"]["id"]
            time.sleep(15)  # give the vendors time to scan
            _vt_wait()
            a = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                             headers=headers, timeout=15)
            a.raise_for_status()
            stats = a.json()["data"]["attributes"]["stats"]
        elif r.status_code == 429:
            return {"status": "rate_limited"}
        else:
            r.raise_for_status()
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]

        return {
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ---------- 2. OpenPhish feed ----------
def _load_openphish():
    """Download the OpenPhish feed (or reuse a recent saved copy)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    fresh = (os.path.exists(OPENPHISH_CACHE) and
             time.time() - os.path.getmtime(OPENPHISH_CACHE) < FEED_MAX_AGE_HOURS * 3600)
    if not fresh:
        try:
            r = requests.get(OPENPHISH_URL, timeout=15)
            r.raise_for_status()
            with open(OPENPHISH_CACHE, "w", encoding="utf-8") as f:
                f.write(r.text)
        except Exception:
            pass  # offline: fall back to whatever copy we have
    if not os.path.exists(OPENPHISH_CACHE):
        return set()
    with open(OPENPHISH_CACHE, encoding="utf-8") as f:
        return {line.strip().rstrip("/").lower() for line in f if line.strip()}


def check_openphish(url):
    """Is this exact URL in the list of currently active phishing sites?"""
    feed = _load_openphish()
    if not feed:
        return {"status": "unavailable"}
    return {"status": "ok", "listed": url.rstrip("/").lower() in feed,
            "feed_size": len(feed)}


# ---------- 3. WHOIS domain age ----------
def check_domain_age(url):
    """How many days ago was this domain registered?"""
    host = (urlparse(url).hostname or "").lower()
    if not host or _is_ip(host):
        return {"status": "not_applicable"}
    try:
        info = whois.whois(_registered_domain(url))
        created = info.creation_date
        if isinstance(created, list):
            created = min(d for d in created if d)
        if not created:
            return {"status": "unknown"}
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - created).days
        return {"status": "ok", "age_days": age,
                "created": created.strftime("%Y-%m-%d")}
    except Exception:
        # Domains that don't exist (or WHOIS refuses) land here
        return {"status": "unknown"}


# ---------- 4. Redirect check ----------
def check_redirects(url):
    """Follow redirects WITHOUT loading the page, to see the final destination."""
    host = (urlparse(url).hostname or "").lower()
    if _is_ip(host) and ipaddress.ip_address(host).is_private:
        return {"status": "not_applicable"}  # private network address
    try:
        r = requests.head(url, allow_redirects=True, timeout=6,
                          headers={"User-Agent": "Mozilla/5.0 (QR-Phishing-Detector)"})
        chain = [resp.url for resp in r.history] + [r.url]
        return {"status": "ok", "final_url": r.url, "hops": len(r.history),
                "chain": chain,
                "domain_changed": _registered_domain(r.url) != _registered_domain(url)}
    except Exception:
        return {"status": "unreachable"}


# ---------- Combine into one threat-intel score ----------
def analyze_threat_intel(url, scan_if_unknown=False):
    url = _normalize(url)
    vt = check_virustotal(url, scan_if_unknown)
    op = check_openphish(url)
    age = check_domain_age(url)
    redir = check_redirects(url)

    score, findings = 0, []

    if vt.get("status") == "ok":
        bad = vt["malicious"] + vt["suspicious"]
        if vt["malicious"] >= 3:
            score += 60
            findings.append(f"VirusTotal: {vt['malicious']} security vendors flag this URL as malicious")
        elif bad >= 1:
            score += 30
            findings.append(f"VirusTotal: {bad} security vendor(s) flag this URL")
    elif vt.get("status") == "not_in_database":
        findings.append("VirusTotal: URL has never been reported (no reputation history)")

    if op.get("listed"):
        score += 60
        findings.append("OpenPhish: URL is on the list of active phishing sites")

    if age.get("status") == "ok":
        if age["age_days"] < 30:
            score += 25
            findings.append(f"WHOIS: domain registered only {age['age_days']} days ago")
        elif age["age_days"] < 180:
            score += 10
            findings.append(f"WHOIS: domain is fairly new ({age['age_days']} days old)")
    elif age.get("status") == "unknown":
        score += 10
        findings.append("WHOIS: no registration record found for this domain")

    if redir.get("status") == "ok" and redir["domain_changed"]:
        score += 10
        findings.append(f"Redirect: link actually leads to {redir['final_url']}")

    return {"intel_score": min(score, 100), "findings": findings,
            "sources": {"virustotal": vt, "openphish": op,
                        "whois": age, "redirects": redir}}


# Self-test
if __name__ == "__main__":
    from qr_decoder import decode_qr_from_path

    urls = []
    for name in sorted(os.listdir("test_qrs")):
        urls.append((name, decode_qr_from_path(os.path.join("test_qrs", name))))
    # Google's official harmless test URL - security tools are meant to flag it
    urls.append(("google_test_url", "http://malware.testing.google.test/testing/malware/"))

    print(f"VirusTotal key loaded: {'yes' if VT_API_KEY else 'NO - check your .env file'}")
    print("Checking URLs (about 15 seconds each because of the free API limit)...")
    for name, url in urls:
        result = analyze_threat_intel(url)
        print(f"\n{name}")
        print(f"  URL:         {url}")
        print(f"  Intel score: {result['intel_score']}/100")
        for f in result["findings"]:
            print(f"   - {f}")
