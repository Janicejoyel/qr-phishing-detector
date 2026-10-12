"""
Phase 8: System evaluation on real-world data.

Test set
  - Phishing:   live URLs from the OpenPhish feed (data/openphish_feed.txt),
                captured at test time, so the ML model has never seen them
  - Legitimate: real everyday URLs with full paths (data/legit_urls.txt)

Every URL goes through the FULL pipeline:
  URL -> QR image -> decoded back -> judged by Rules, ML, and the Combined engine

Threat intelligence is switched OFF here on purpose: the phishing URLs come from
OpenPhish, so the intel layer would catch them trivially. Testing without it
measures the "zero-day" case - how well the system catches phishing that no
blacklist knows about yet.

HELD-OUT MODE:  python evaluate.py --heldout
  Downloads a FRESH OpenPhish feed and keeps only URLs that were NOT in the
  snapshot used while improving the rules (data/openphish_feed.txt). This is a
  fair, never-seen-before test. Results go to the "evaluation_heldout" folder.
"""
import io
import json
import os
import sys
import time

import requests

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import qrcode
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, ConfusionMatrixDisplay)

from qr_decoder import decode_qr_from_bytes
from reputation import available as reputation_available
from risk_engine import SAFE_BELOW, _verdict, assess

HELDOUT = "--heldout" in sys.argv
OUT_DIR = "evaluation_heldout" if HELDOUT else "evaluation"
os.makedirs(OUT_DIR, exist_ok=True)


def read_list(path):
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


feed_path = os.path.join("data", "openphish_feed.txt")
if HELDOUT:
    print("Downloading a fresh OpenPhish feed for the held-out test...")
    fresh = requests.get("https://openphish.com/feed.txt", timeout=30).text.split()
    tuning_set = set(read_list(feed_path))
    phishing = sorted({u.strip() for u in fresh if u.strip()} - tuning_set)
    feed_time = time.strftime("%Y-%m-%d %H:%M")
    with open(os.path.join("data", "openphish_heldout.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(phishing))
    print(f"  fresh feed: {len(fresh)} URLs, of which {len(phishing)} are NEW "
          f"(not in the snapshot used for tuning)")
    if len(phishing) < 30:
        sys.exit("Too few new phishing URLs yet - the feed has not refreshed. Try again in a few hours.")
else:
    phishing = read_list(feed_path)
    feed_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(feed_path)))
legit = read_list(os.path.join("data", "legit_urls.txt"))
samples = [(u, 1) for u in phishing] + [(u, 0) for u in legit]
print(f"Test set: {len(phishing)} phishing (OpenPhish snapshot {feed_time}) "
      f"+ {len(legit)} legitimate = {len(samples)} URLs")
print(f"Domain reputation list: {'loaded' if reputation_available() else 'NOT FOUND - run download_reputation.py'}")
print("Running the full QR pipeline on every URL...")

rows, decode_ok = [], 0
t0 = time.time()
for i, (url, label) in enumerate(samples, 1):
    # 1. Encode the URL as a QR code image (in memory)
    buf = io.BytesIO()
    qrcode.make(url).save(buf, format="PNG")
    # 2. Decode it back, exactly as the app does with an uploaded image
    decoded = decode_qr_from_bytes(buf.getvalue())
    if decoded == url:
        decode_ok += 1
    # 3. Judge it
    r = assess(decoded or url, use_intel=False)
    ls = r["layer_scores"]
    rows.append({
        "url": url, "is_phishing": label, "decoded_ok": int(decoded == url),
        "rule_score": ls["rules"], "ml_score": ls["ml"], "final_score": r["final_score"],
        "reputation_rank": r["reputation_rank"], "verdict": r["verdict"],
    })
    if i % 50 == 0:
        print(f"  {i}/{len(samples)} done")
elapsed = time.time() - t0

df = pd.DataFrame(rows)
# A URL counts as "flagged" if the verdict is Suspicious or Malicious (score >= 25)
df["flag_rules"] = (df["rule_score"] >= SAFE_BELOW).astype(int)
df["flag_ml"] = (df["ml_score"] >= 50).astype(int)
df["flag_rules_ml"] = ((0.5 * df["rule_score"] + 0.5 * df["ml_score"]).round() >= SAFE_BELOW).astype(int)
df["flag_combined"] = (df["final_score"] >= SAFE_BELOW).astype(int)
df.to_csv(os.path.join(OUT_DIR, "evaluation_results.csv"), index=False)

y = df["is_phishing"]
methods = {"Rules only": "flag_rules", "ML only": "flag_ml", "Rules + ML": "flag_rules_ml",
           "Full system (+ reputation)": "flag_combined"}
metrics = {}
for name, col in methods.items():
    metrics[name] = {
        "accuracy": accuracy_score(y, df[col]),
        "precision": precision_score(y, df[col], zero_division=0),
        "recall": recall_score(y, df[col]),
        "f1": f1_score(y, df[col]),
        "false_positive_rate": float(((df[col] == 1) & (y == 0)).sum() / (y == 0).sum()),
    }

summary = {
    "test_set": {"phishing": len(phishing), "legitimate": len(legit), "total": len(samples),
                 "openphish_snapshot": feed_time, "held_out": HELDOUT},
    "reputation_list_loaded": reputation_available(),
    "qr_decode_success_rate": decode_ok / len(samples),
    "avg_seconds_per_url": elapsed / len(samples),
    "verdict_counts": {
        "phishing": df[df.is_phishing == 1]["verdict"].value_counts().to_dict(),
        "legitimate": df[df.is_phishing == 0]["verdict"].value_counts().to_dict(),
    },
    "methods": metrics,
}
with open(os.path.join(OUT_DIR, "evaluation_metrics.json"), "w") as f:
    json.dump(summary, f, indent=2)

# ---------- Print results ----------
print(f"\nQR decoding success: {decode_ok}/{len(samples)} ({decode_ok / len(samples):.1%})")
print(f"Average analysis time: {elapsed / len(samples) * 1000:.0f} ms per QR code (offline mode)")
print("\n=== Detection results on real-world URLs ===")
print(f"{'Method':28}{'Accuracy':>10}{'Precision':>11}{'Recall':>9}{'F1':>8}{'False alarms':>14}")
for name, m in metrics.items():
    print(f"{name:28}{m['accuracy']:>10.3f}{m['precision']:>11.3f}{m['recall']:>9.3f}"
          f"{m['f1']:>8.3f}{m['false_positive_rate']:>13.1%}")

print("\nVerdicts for PHISHING URLs:   ", summary["verdict_counts"]["phishing"])
print("Verdicts for LEGITIMATE URLs: ", summary["verdict_counts"]["legitimate"])

# ---------- Charts ----------
names = list(metrics)
fig, ax = plt.subplots(figsize=(10, 5))
for i, key in enumerate(["accuracy", "precision", "recall", "f1"]):
    vals = [metrics[n][key] for n in names]
    bars = ax.bar([p + i * 0.2 for p in range(len(names))], vals, width=0.2, label=key.capitalize())
    ax.bar_label(bars, fmt="%.2f", fontsize=7)
ax.set_xticks([p + 0.3 for p in range(len(names))])
ax.set_xticklabels(names, fontsize=9)
ax.set_ylim(0, 1.08)
ax.set_ylabel("Score")
ax.set_title("Each detection layer's contribution (real-world URLs, live feeds off)")
ax.legend(loc="lower right", fontsize=8)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "layer_comparison.png"), dpi=150)
plt.close()

cm = confusion_matrix(y, df["flag_combined"])
ConfusionMatrixDisplay(cm, display_labels=["Legitimate", "Phishing"]).plot(cmap="Blues")
plt.title("Confusion Matrix - Full System (real-world test)")
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "confusion_matrix_system.png"), dpi=150)
plt.close()

print(f"\nSaved results and charts to the '{OUT_DIR}' folder")
