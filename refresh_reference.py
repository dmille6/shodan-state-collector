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
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from datetime import datetime

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


UA = {"User-Agent": "shodan-state-collector/1.0 (Louisiana exposure census; passive)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# --- Exploit availability -----------------------------------------------------
# Public indices of CVEs with a working public exploit or detection template.
# A KEV entry says "exploited in the wild"; these say "anyone can run it today".
# Tiebreaker for triage, never a gate.

def parse_metasploit(raw):
    """modules_metadata_base.json -> {cve: ['metasploit']} from module references."""
    out = {}
    data = json.loads(raw)
    for mod in data.values():
        for ref in (mod.get("references") or []):
            for cve in CVE_RE.findall(str(ref)):
                out.setdefault(cve.upper(), set()).add("metasploit")
    return out


def parse_nuclei(raw):
    """nuclei-templates cves.json (newline-delimited objects with an ID) -> {cve: ['nuclei']}."""
    out = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        cve = str(obj.get("ID") or "").upper()
        if CVE_RE.fullmatch(cve):
            out.setdefault(cve, set()).add("nuclei")
    return out


EXPLOIT_SOURCES = [
    ("metasploit", "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json", parse_metasploit),
    ("nuclei", "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json", parse_nuclei),
]


def refresh_exploits():
    merged = {}
    for name, url, parser in EXPLOIT_SOURCES:
        try:
            part = parser(fetch(url, timeout=120))
            for cve, srcs in part.items():
                merged.setdefault(cve, set()).update(srcs)
            print(f"exploits/{name}: {len(part):,} CVEs")
        except Exception as e:
            print(f"exploits/{name} failed: {e}")
    if not merged:
        print("exploit index: nothing fetched; keeping the previous file")
        return
    out = {cve: sorted(srcs) for cve, srcs in sorted(merged.items())}
    out["_meta"] = {"as_of": datetime.now().strftime("%Y-%m-%d"), "sources": [n for n, _, _ in EXPLOIT_SOURCES]}
    json.dump(out, open(os.path.join(REF, "exploits.json"), "w"))
    print(f"exploit index: {len(out) - 1:,} CVEs with a public exploit/template")


# --- Free IOC feeds ---------------------------------------------------------------
# Matched LOCALLY against Louisiana IPs (nothing leaves the box). A hit means the IP
# is on a C2/malware/abuse list — a lead that the host is compromised or hostile.
# Residential matches are only ever reported as ISP aggregates (see leads.py).

def parse_ip_lines(raw, source):
    out = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if IPV4_RE.match(line):
            out.setdefault(line, set()).add(source)
    return out


def parse_cidr_lines(raw, source):
    """Spamhaus DROP: '1.2.3.0/24 ; SBL123'. Returned under the '_cidrs' key."""
    out = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        cidr = line.split(";")[0].strip()
        if "/" in cidr and IPV4_RE.match(cidr.split("/")[0]):
            out.setdefault(cidr, set()).add(source)
    return out


def parse_threatfox(raw):
    """ThreatFox ip-port CSV: quoted columns, ioc_value = ip:port."""
    out = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.startswith("#"):
            continue
        row = next(csv.reader([line], skipinitialspace=True), None)   # ThreatFox writes '", "'.
        if not row or len(row) < 3:
            continue
        ip = row[2].strip().split(":")[0]
        if IPV4_RE.match(ip):
            out.setdefault(ip, set()).add("threatfox")
    return out


def parse_urlhaus(raw):
    """URLhaus online URLs: keep only URLs whose host is a literal IPv4."""
    out = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        m = re.match(r"^https?://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?[/?#]?", line.strip())
        if m:
            out.setdefault(m.group(1), set()).add("urlhaus")
    return out


IOC_SOURCES = [
    ("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", lambda r: parse_ip_lines(r, "feodo")),
    ("sslbl", "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", lambda r: parse_ip_lines(r, "sslbl")),
    ("threatfox", "https://threatfox.abuse.ch/export/csv/ip-port/recent/", parse_threatfox),
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/text_online/", parse_urlhaus),
    ("cins", "https://cinsscore.com/list/ci-badguys.txt", lambda r: parse_ip_lines(r, "cins")),
    ("spamhaus_drop", "https://www.spamhaus.org/drop/drop.txt", lambda r: parse_cidr_lines(r, "spamhaus_drop")),
]


def refresh_iocs():
    ips, cidrs = {}, {}
    for name, url, parser in IOC_SOURCES:
        try:
            part = parser(fetch(url, timeout=90))
            target = cidrs if name == "spamhaus_drop" else ips
            for k, srcs in part.items():
                target.setdefault(k, set()).update(srcs)
            print(f"ioc/{name}: {len(part):,} entries")
        except Exception as e:
            print(f"ioc/{name} failed: {e}")
    if not ips and not cidrs:
        print("ioc feeds: nothing fetched; keeping the previous file")
        return
    out = {ip: sorted(v) for ip, v in sorted(ips.items())}
    out["_cidrs"] = {c: sorted(v) for c, v in sorted(cidrs.items())}
    out["_meta"] = {"as_of": datetime.now().strftime("%Y-%m-%d"), "sources": [n for n, _, _ in IOC_SOURCES]}
    json.dump(out, open(os.path.join(REF, "ioc_ips.json"), "w"))
    print(f"ioc feeds: {len(ips):,} IPs + {len(cidrs):,} CIDRs")


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
    for step in (refresh_exploits, refresh_iocs):
        try:
            step()
        except Exception as e:
            print(f"{step.__name__} failed: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
