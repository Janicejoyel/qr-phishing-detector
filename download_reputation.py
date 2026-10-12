"""
Downloads the Tranco Top Sites list - a research-grade ranking of the world's
most popular domains, designed to be hard to manipulate.
Source: Le Pochat et al., "Tranco: A Research-Oriented Top Sites Ranking
Hardened Against Manipulation", NDSS 2019. https://tranco-list.eu

We keep the top 100,000 domains as a domain REPUTATION source:
a domain that has been among the most visited sites for a long time is very
unlikely to be a throwaway phishing domain.
"""
import csv
import io
import os
import zipfile

import requests

URL = "https://tranco-list.eu/top-1m.csv.zip"
OUT = os.path.join("data", "tranco_top100k.txt")
KEEP = 100_000

os.makedirs("data", exist_ok=True)
print("Downloading Tranco top sites list (about 10 MB)...")
r = requests.get(URL, timeout=300)
r.raise_for_status()

with zipfile.ZipFile(io.BytesIO(r.content)) as z:
    name = z.namelist()[0]
    with z.open(name) as f:
        reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
        domains = [row[1].strip().lower() for _, row in zip(range(KEEP), reader)]

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(domains))
print(f"Saved top {len(domains):,} domains to {OUT}")
print(f"Top 5: {', '.join(domains[:5])}")
