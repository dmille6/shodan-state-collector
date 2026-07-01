#!/usr/bin/env python3
"""
refresh_reference.py — refresh the public enrichment feeds used for triage/store.

Fetches the CISA KEV catalog and the FIRST EPSS daily scores into reference/.
These change over time (new known-exploited CVEs, updated EPSS), so run weekly.
Both are free, public, and refreshable — reference/ is gitignored.
"""
import csv
import gzip
import io
import json
import os
import sys
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REF = os.path.join(SCRIPT_DIR, "reference")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URLS = ["https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
             "https://epss.cyentia.com/epss_scores-current.csv.gz"]


def refresh_kev():
    with urllib.request.urlopen(KEV_URL, timeout=30) as r:
        data = json.load(r)
    cves = [v["cveID"] for v in data.get("vulnerabilities", [])]
    json.dump({"count": len(cves), "cves": cves}, open(os.path.join(REF, "kev.json"), "w"))
    print(f"KEV: {len(cves)} known-exploited CVEs")


def refresh_epss():
    for url in EPSS_URLS:
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                raw = gzip.decompress(r.read()).decode()
            scores = {}
            for row in csv.reader(io.StringIO(raw)):
                if not row or row[0].startswith("#") or row[0] == "cve":
                    continue
                try:
                    scores[row[0]] = float(row[1])
                except (IndexError, ValueError):
                    pass
            json.dump(scores, open(os.path.join(REF, "epss.json"), "w"))
            print(f"EPSS: {len(scores):,} CVE scores")
            return
        except Exception as e:
            print(f"  {url} failed: {e}")
    print("EPSS refresh failed (all sources)")


def main():
    os.makedirs(REF, exist_ok=True)
    try:
        refresh_kev()
    except Exception as e:
        print(f"KEV refresh failed: {e}")
    refresh_epss()
    return 0


if __name__ == "__main__":
    sys.exit(main())
