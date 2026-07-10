#!/usr/bin/env python3
"""
triage_report.py — turn a daily Shodan archive into a sector-tiered triage brief.

Buckets EVERY unique host into a consequence-ordered tier (critical infrastructure
> government > education > small business > residential > unclassified), enriches
its CVEs with CISA KEV (known-exploited) and FIRST EPSS (exploit probability), and
ranks hosts by an actionability score. Nothing is dropped — every host is
accounted for in exactly one tier.

PASSIVE ONLY. This reads archived Shodan banners; it does not contact any host.
Findings are LEADS TO VERIFY, not confirmed vulnerabilities (Shodan maps software
versions to every CVE they *could* have — see README lesson on version inference).

Usage:
    triage_report.py daily_downloads/<file>.json.gz [--out reports/triage-<date>.md]
"""
import argparse
import gzip
import json
import os
import sys
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Signals -----------------------------------------------------------------
ICS_PORTS = {502: "Modbus", 20000: "DNP3", 47808: "BACnet", 102: "S7comm",
             44818: "EtherNet/IP", 1911: "Niagara/Tridium", 2404: "IEC-104",
             789: "Red Lion", 1962: "PCWorx", 9600: "OMRON-FINS", 20547: "ProconOS"}
ADMIN_PORTS = {23: "telnet", 3389: "RDP", 5900: "VNC", 21: "FTP", 512: "rexec",
               513: "rlogin", 514: "rsh"}
DB_PORTS = {3306: "MySQL", 5432: "Postgres", 27017: "MongoDB", 6379: "Redis",
            9200: "Elasticsearch", 1433: "MSSQL", 11211: "memcached",
            5984: "CouchDB", 9042: "Cassandra"}

CRIT_KW = ["water", "sewer", "sewage", "wastewater", "electric", "power", "energy",
           "utility", "utilities", "co-op", "coop", "pipeline", "port of", "airport",
           "transit", "levee", "hospital", "health", "medical", "clinic", "healthcare",
           "emergency", "dispatch", "scada", "treatment", "substation", "natural gas",
           "waterworks", "sewerage", "ambulance", "911"]
GOV_KW = ["parish", "city of", "town of", "village of", "municipal", "sheriff",
          "police", "court", "clerk of", "assessor", "registrar", "department of",
          "dept of", "governor", "legislature", "council", "district attorney",
          "coroner", "detention", "fire dept", "fire district", "state of louisiana",
          "office of", "secretary of state", "dmv", "dotd", "dhh"]
EDU_KW = ["school", "university", "college", "academy", "isd", "campus",
          "board of education", "community college", "lsu", "tulane",
          "southern university", "louisiana tech", "mcneese", "nicholls", "k-12"]
# Major consumer-broadband providers (the residential haystack)
RESI_ORG_KW = ["cox", "charter", "spectrum", "comcast", "at&t", "att internet",
               "verizon", "centurylink", "lumen", "sparklight", "cable one",
               "optimum", "altice", "t-mobile", "rev", "eatel", "lus fiber",
               "volt broadband", "uniti", "catcomm", "vexus", "allo"]
RESI_HOST_RE = ("dhcp", "dyn", "cpe.", "res.", "client.", "pool", "broadband",
                "biz.rr", ".rr.com", "hsd1", "static.", "customer")
# Transit / CDN / cloud / hosting providers. Like the consumer ISPs above, the
# `org` field here names the NETWORK OPERATOR, not the end customer — so its text
# must NOT drive gov/edu/critical keyword matching (that mis-tiered customers,
# e.g. an "AT&T Enterprises" host landing in 'education'). Kept deliberately
# specific/multi-word to avoid substring false positives on real business names.
TRANSIT_HOST_KW = ["level 3", "level3", "cogent", "hurricane electric", "he.net",
                   "zayo", "gtt communications", "tata communications",
                   "ntt america", "windstream", "frontier communications",
                   "consolidated communications", "amazon", "aws", "google llc",
                   "google cloud", "microsoft corporation", "azure", "cloudflare",
                   "akamai", "fastly", "digitalocean", "linode", "ovh", "hetzner",
                   "vultr", "hostgator", "bluehost", "godaddy", "unified layer",
                   "namecheap", "leaseweb", "immense networks", "psychz", "quadranet"]
# Any org name that describes a bulk network rather than a specific customer.
BULK_NETWORK_KW = RESI_ORG_KW + TRANSIT_HOST_KW
PARISHES = ["acadia", "allen", "ascension", "assumption", "avoyelles", "beauregard",
            "bienville", "bossier", "caddo", "calcasieu", "caldwell", "cameron",
            "catahoula", "claiborne", "concordia", "desoto", "east baton rouge",
            "east carroll", "east feliciana", "evangeline", "franklin", "grant",
            "iberia", "iberville", "jackson", "jefferson", "lafayette", "lafourche",
            "lasalle", "lincoln", "livingston", "madison", "morehouse", "natchitoches",
            "orleans", "ouachita", "plaquemines", "pointe coupee", "rapides",
            "red river", "richland", "sabine", "st bernard", "st charles", "st helena",
            "st james", "st john", "st landry", "st martin", "st mary", "st tammany",
            "tangipahoa", "tensas", "terrebonne", "union", "vermilion", "vernon",
            "washington", "webster", "west baton rouge", "west carroll",
            "west feliciana", "winn"]

TIERS = ["critical_infrastructure", "government", "education",
         "small_business", "residential", "unclassified"]


def load_json(path, default):
    try:
        return json.load(open(path))
    except Exception:
        return default


def classify(host):
    """Consequence-ordered cascade. Returns (tier, reason).

    Attribution rule: the customer's OWN identity (hostnames + domains) is the
    trusted signal. The `org` field is trusted for keyword matching only when it
    is NOT a bulk network operator (consumer ISP / transit / cloud / hosting),
    because those name the carrier, not the end customer — matching keywords in
    them produced false tiers. Authoritative domain suffixes (.gov/.edu/...) are
    always honoured regardless of the network."""
    org_text = (host["org"] or "").lower()
    identity_text = " ".join(filter(None, [
        " ".join(host["hostnames"]),
        " ".join(host["domains"]),
    ])).lower()
    ports = host["ports"]

    bulk_network = any(kw in org_text for kw in BULK_NETWORK_KW)
    consumer_isp = any(kw in org_text for kw in RESI_ORG_KW)
    # Keyword search space: customer identity always; org text only when the org
    # is a specific customer (not a bulk network).
    kw_text = identity_text if bulk_network else (identity_text + " " + org_text)
    via = " (via customer domain)" if bulk_network else ""

    # 1. Critical infrastructure — ICS ports are a hard signal; then keywords.
    ics = [name for p, name in ICS_PORTS.items() if p in ports]
    if ics:
        return "critical_infrastructure", f"ICS protocol exposed: {', '.join(ics)}"
    for kw in CRIT_KW:
        if kw in kw_text:
            return "critical_infrastructure", f"keyword '{kw}'{via}"

    # 2. Government (state/local) — authoritative domains first, then keywords.
    if any(d.endswith(".gov") or d.endswith(".state.la.us") for d in host["domains"]):
        return "government", "gov domain"
    for kw in GOV_KW:
        if kw in kw_text:
            return "government", f"keyword '{kw}'{via}"
    for par in PARISHES:
        if par in kw_text:
            return "government", f"parish '{par}'{via}"

    # 3. Education
    if any(d.endswith(".edu") or d.endswith(".k12.la.us") for d in host["domains"]):
        return "education", "edu domain"
    for kw in EDU_KW:
        if kw in kw_text:
            return "education", f"keyword '{kw}'{via}"

    # 4/5. Residential vs small business vs unattributable.
    looks_dynamic = any(pat in identity_text for pat in RESI_HOST_RE)
    has_identity = bool(host["hostnames"] or host["domains"])
    # A consumer-broadband IP with dynamic rDNS or no customer identity: residential.
    if consumer_isp and (looks_dynamic or not has_identity):
        return "residential", "consumer ISP / dynamic rDNS"
    # A real customer identity, or a non-bulk org name: a specific (small) business.
    if identity_text.strip() or (org_text.strip() and not bulk_network):
        return "small_business", "commercial org, not gov/edu/infra"
    # Only a bulk-network name and nothing else — we cannot attribute the customer.
    if org_text.strip():
        return "unclassified", "bulk network address space, no customer identity"
    return "unclassified", "no attribution signal"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("infile")
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=15, help="hosts to list per tier")
    args = ap.parse_args()

    kev = set(load_json(os.path.join(SCRIPT_DIR, "reference/kev.json"), {}).get("cves", []))
    epss = load_json(os.path.join(SCRIPT_DIR, "reference/epss.json"), {})

    # Aggregate banners into one record per unique IP.
    hosts = {}
    with gzip.open(args.infile, "rt") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except Exception:
                continue
            ip = r.get("ip_str")
            if not ip:
                continue
            h = hosts.setdefault(ip, {"org": None, "ports": set(), "products": set(),
                                      "hostnames": set(), "domains": set(),
                                      "cves": set(), "city": None})
            h["org"] = h["org"] or r.get("org")
            h["ports"].add(r.get("port"))
            if r.get("product"):
                h["products"].add(r["product"])
            h["hostnames"].update(r.get("hostnames") or [])
            h["domains"].update(r.get("domains") or [])
            loc = r.get("location") or {}
            h["city"] = h["city"] or loc.get("city")
            for c in (r.get("vulns") or {}):
                h["cves"].add(c)

    # Normalize sets -> sorted lists for stable output.
    for h in hosts.values():
        h["hostnames"] = sorted(h["hostnames"])
        h["domains"] = sorted(h["domains"])

    # Honeypot guard: drop IPs exposing >100 ports from triage (data pollution).
    honeypots = {ip for ip, h in hosts.items() if len(h["ports"]) > 100}

    tiered = defaultdict(list)
    for ip, h in hosts.items():
        if ip in honeypots:
            continue
        tier, reason = classify(h)
        kev_hits = sorted(h["cves"] & kev)
        max_epss = max((epss.get(c, 0.0) for c in h["cves"]), default=0.0)
        admin = sorted({ADMIN_PORTS[p] for p in h["ports"] if p in ADMIN_PORTS})
        dbs = sorted({DB_PORTS[p] for p in h["ports"] if p in DB_PORTS})
        ics = sorted({ICS_PORTS[p] for p in h["ports"] if p in ICS_PORTS})
        # Actionability score: KEV dominates, then ICS, exposed admin/db, EPSS.
        score = (len(kev_hits) * 100 + len(ics) * 40 + len(admin) * 15 +
                 len(dbs) * 25 + int(max_epss * 50))
        tiered[tier].append({
            "ip": ip, "org": h["org"], "city": h["city"], "score": score,
            "kev": kev_hits, "ics": ics, "admin": admin, "dbs": dbs,
            "epss": round(max_epss, 3), "n_cves": len(h["cves"]),
            "reason": reason, "products": sorted(h["products"])[:3],
        })

    lines = []
    w = lines.append
    date = os.path.basename(args.infile).replace(".json.gz", "").split("events-")[-1]
    total = sum(len(v) for v in tiered.values())
    w(f"# Louisiana exposure triage — {date}")
    w("")
    w(f"**{total:,} unique hosts** classified (+{len(honeypots)} honeypot host(s) "
      f"excluded). Findings are PASSIVE LEADS TO VERIFY, not confirmed vulnerabilities.")
    w("")
    w("## Accounting — every host bucketed (consequence order)")
    w("")
    w("| Tier | Hosts | w/ KEV CVE | w/ exposed admin | w/ ICS |")
    w("|---|--:|--:|--:|--:|")
    for t in TIERS:
        rows = tiered.get(t, [])
        w(f"| {t.replace('_',' ')} | {len(rows):,} | "
          f"{sum(1 for x in rows if x['kev']):,} | "
          f"{sum(1 for x in rows if x['admin']):,} | "
          f"{sum(1 for x in rows if x['ics']):,} |")
    w("")
    for t in TIERS:
        rows = sorted(tiered.get(t, []), key=lambda x: -x["score"])
        if not rows:
            continue
        flagged = [x for x in rows if x["score"] > 0]
        w(f"## {t.replace('_',' ').title()} — {len(rows):,} hosts "
          f"({len(flagged):,} with a risk signal)")
        w("")
        if not flagged:
            w("_No KEV/ICS/admin/db signals in this tier today._")
            w("")
            continue
        w("| score | IP | org | city | KEV | ICS | admin | DB | EPSS | reason |")
        w("|--:|---|---|---|---|---|---|---|--:|---|")
        for x in flagged[:args.top]:
            w(f"| {x['score']} | {x['ip']} | {(x['org'] or '')[:24]} | "
              f"{(x['city'] or '')[:14]} | {' '.join(x['kev'][:3]) or '—'} | "
              f"{' '.join(x['ics']) or '—'} | {' '.join(x['admin']) or '—'} | "
              f"{' '.join(x['dbs']) or '—'} | {x['epss'] or '—'} | {x['reason'][:28]} |")
        w("")

    report = "\n".join(lines)
    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        open(args.out, "w").write(report)
        print(f"Wrote {args.out}")
    else:
        print(report)


if __name__ == "__main__":
    sys.exit(main())
