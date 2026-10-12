"""
Phase 6: Risk Engine - combines all three detection layers into one verdict.

  Layer 1  Rules (url_features.py)         -> rule_score   0-100
  Layer 2  Threat intel (threat_intel.py)  -> intel_score  0-100
           + domain reputation (reputation.py, offline Tranco Top 100k)
  Layer 3  ML model (ml_features.py)       -> ml_score     0-100

final score = weighted average of the three layers
REPUTATION: if the domain is a long-established top site, the ML model's
"looks like phishing" guess is ignored (the ML model only sees the domain name
and cannot know that e.g. x.com is famous). Rules and threat intel still apply.
OVERRIDE: confirmed threat intelligence (3+ VirusTotal vendors, or listed on
OpenPhish) makes the verdict Malicious no matter what the other layers say.
"""
import csv
import os
from datetime import datetime
from urllib.parse import urlparse

import joblib
import pandas as pd

from ml_features import FEATURE_NAMES, host_features
from reputation import domain_rank
from threat_intel import analyze_threat_intel
from url_features import _normalize, analyze_url

MODEL_PATH = os.path.join("models", "phishing_model.joblib")
LOG_PATH = os.path.join("data", "scan_log.csv")

# How much each layer counts towards the final score
WEIGHTS_WITH_INTEL = {"rules": 0.35, "ml": 0.35, "intel": 0.30}
WEIGHTS_OFFLINE = {"rules": 0.50, "ml": 0.50}  # when threat intel is switched off

SAFE_BELOW = 25        # final score  0-24  -> Safe
MALICIOUS_FROM = 50    # final score 25-49  -> Suspicious, 50+ -> Malicious

_bundle = None


def _model():
    """Load the trained model once and reuse it."""
    global _bundle
    if _bundle is None:
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def ml_score(url):
    bundle = _model()
    X = pd.DataFrame([host_features(url)], columns=bundle["features"])
    return round(float(bundle["model"].predict_proba(X)[0][1]) * 100)


def _verdict(score):
    if score >= MALICIOUS_FROM:
        return "Malicious"
    if score >= SAFE_BELOW:
        return "Suspicious"
    return "Safe"


def assess(url, use_intel=True, scan_if_unknown=False):
    """Run every layer on a URL and return the combined verdict with reasons."""
    url = _normalize(url)

    rules = analyze_url(url)
    ml = ml_score(url)
    reasons = list(rules["red_flags"])
    rank = domain_rank(urlparse(url).hostname)
    ml_used = ml
    if rank:
        ml_used = 0  # trusted domain: ignore the ML model's guess
        reasons.append(f"Reputation: domain is ranked #{rank:,} among the world's most "
                       f"visited sites (Tranco list), so it is well established")
    elif ml >= 70:
        reasons.append(f"ML model: domain looks like known phishing domains ({ml}% probability)")

    intel = None
    if use_intel:
        intel = analyze_threat_intel(url, scan_if_unknown)
        reasons.extend(intel["findings"])
        w = WEIGHTS_WITH_INTEL
        score = (w["rules"] * rules["rule_score"] + w["ml"] * ml_used
                 + w["intel"] * intel["intel_score"])
    else:
        w = WEIGHTS_OFFLINE
        score = w["rules"] * rules["rule_score"] + w["ml"] * ml_used
    score = round(score)

    # Override: confirmed intelligence beats everything else
    confirmed = False
    if intel:
        vt = intel["sources"]["virustotal"]
        op = intel["sources"]["openphish"]
        if (vt.get("status") == "ok" and vt["malicious"] >= 3) or op.get("listed"):
            confirmed = True
            score = max(score, 80)

    return {
        "url": url,
        "domain": (urlparse(url).hostname or "").lower(),
        "final_score": min(score, 100),
        "verdict": _verdict(score),
        "confirmed_by_intel": confirmed,
        "reputation_rank": rank,
        "layer_scores": {"rules": rules["rule_score"], "ml": ml,
                         "intel": intel["intel_score"] if intel else None},
        "reasons": reasons,
        "intel_sources": intel["sources"] if intel else None,
    }


def log_scan(result, source="upload"):
    """Append the scan to data/scan_log.csv (used by the analytics dashboard)."""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    new_file = not os.path.exists(LOG_PATH)
    with open(LOG_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["timestamp", "source", "url", "domain", "verdict",
                             "final_score", "rule_score", "ml_score", "intel_score",
                             "confirmed_by_intel", "top_reason"])
        ls = result["layer_scores"]
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source,
                         result["url"], result["domain"], result["verdict"],
                         result["final_score"], ls["rules"], ls["ml"],
                         "" if ls["intel"] is None else ls["intel"],
                         int(result["confirmed_by_intel"]),
                         result["reasons"][0] if result["reasons"] else ""])


# Self-test: the full pipeline QR image -> decode -> 3 layers -> verdict
if __name__ == "__main__":
    import sys
    from qr_decoder import decode_qr_from_path

    use_intel = "--offline" not in sys.argv
    print(f"Threat intel: {'ON (about 15 s per URL)' if use_intel else 'OFF'}\n")

    for name in sorted(os.listdir("test_qrs")):
        url = decode_qr_from_path(os.path.join("test_qrs", name))
        r = assess(url, use_intel=use_intel)
        log_scan(r, source="self-test")
        ls = r["layer_scores"]
        print(f"{name}")
        print(f"  URL:     {r['url']}")
        print(f"  Layers:  rules={ls['rules']}  ml={ls['ml']}  intel={ls['intel']}")
        print(f"  VERDICT: {r['verdict'].upper()}  (final score {r['final_score']}/100)")
        for reason in r["reasons"]:
            print(f"   - {reason}")
        print()
    print(f"All scans saved to {LOG_PATH}")
