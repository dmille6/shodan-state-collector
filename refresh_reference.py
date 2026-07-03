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
import subprocess
import sys
import tarfile
import tempfile
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


def load_env():
    """Read MAXMIND_* creds from .env (gitignored) into os.environ."""
    path = os.path.join(SCRIPT_DIR, ".env")
    if not os.path.isfile(path):
        return
    for raw in open(path):
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def refresh_geoip():
    """Update the MaxMind GeoLite2-City DB (state-level geolocation). Uses curl to
    handle the auth redirect cleanly; skips gracefully without creds."""
    acct, key = os.environ.get("MAXMIND_ACCOUNT_ID"), os.environ.get("MAXMIND_LICENSE_KEY")
    if not (acct and key):
        print("GeoIP: no MaxMind creds in .env; skipping")
        return
    url = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
    tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False).name
    try:
        rc = subprocess.run(["curl", "-sL", "-u", f"{acct}:{key}", url, "-o", tmp],
                            timeout=180).returncode
        if rc != 0:
            print(f"GeoIP: download failed (curl rc={rc})")
            return
        with tarfile.open(tmp) as tar:
            for m in tar.getmembers():
                if m.name.endswith(".mmdb"):
                    m.name = os.path.basename(m.name)
                    tar.extract(m, REF, filter="data")
                    print(f"GeoIP: updated {m.name}")
                    return
        print("GeoIP: no .mmdb found in archive")
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main():
    os.makedirs(REF, exist_ok=True)
    load_env()
    try:
        refresh_kev()
    except Exception as e:
        print(f"KEV refresh failed: {e}")
    refresh_epss()
    try:
        refresh_geoip()
    except Exception as e:
        print(f"GeoIP refresh failed: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
