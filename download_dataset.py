"""
Downloads the PhiUSIIL Phishing URL Dataset (UCI Machine Learning Repository).
Source: Prasad & Chandra (2024), https://archive.ics.uci.edu/dataset/967
~235,000 URLs labelled phishing (0) or legitimate (1).
"""
import io
import os
import zipfile

import requests

URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
OUT_DIR = "data"

os.makedirs(OUT_DIR, exist_ok=True)
print("Downloading dataset (about 50 MB, may take a minute)...")
r = requests.get(URL, timeout=300)
r.raise_for_status()

with zipfile.ZipFile(io.BytesIO(r.content)) as z:
    for name in z.namelist():
        if name.lower().endswith(".csv"):
            target = os.path.join(OUT_DIR, "phiusiil_dataset.csv")
            with open(target, "wb") as f:
                f.write(z.read(name))
            size_mb = os.path.getsize(target) / 1_000_000
            print(f"Saved {target} ({size_mb:.1f} MB)")
