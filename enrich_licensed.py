#!/usr/bin/env python3
"""
enrich_licensed.py — licensed / keyed intelligence for an ALLOWLIST of hosts
(the verified top-hosts list), read-only, one lookup per IP per source, cached.

Never run this over the whole state: residential IPs and unattributed space
must not be sent to third parties. The input is the verification file from
verify_hosts.py (which is itself built from the top-hosts report).

Sources (each optional — skipped with a log line when its key is absent):
  GTI / VirusTotal v3   GTI_API_KEY               /ip_addresses/{ip} (+ resolutions,
                        communicating files) — reputation, passive DNS names, malware
                        that talked to the IP, GTI threat context when licensed.
  CrowdStrike Falcon    CS_CLIENT_ID / CS_CLIENT_SECRET / CS_BASE_URL
                        (also accepts CROWDSTRIKE_*)  OAuth2 → Intel indicators
                        matching the IP (type ip_address), with actors/malware/
                        labels/published date. GovCloud base URLs are honoured.
  AbuseIPDB             ABUSEIPDB_API_KEY         /check — abuse confidence score,
                        report count, ISP/usage type, last reported.
  AlienVault OTX        OTX_API_KEY               /indicators/IPv4/{ip}/general —
                        pulse count and names (community reporting).
  Team Cymru Scout      CYMRU_SCOUT_API_KEY       stub until a key exists: the API
                        shape depends on the licensed tier (Scout vs Recon).

Output: the verification JSON is extended in place with a "licensed" block per
IP, plus reference/verification/enrich_<date>.json. top_hosts_report.py
--verify renders it. Every source is fail-soft and rate-limited.

Usage:
    enrich_licensed.py --verify reference/verification/verify_2026-09-16.json
    enrich_licensed.py --verify ... --sources gti,crowdstrike --limit 20
"""
import argparse
import base64
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from shodan_collect import load_dotenv, log as _log  # noqa: E402
from verify_hosts import Cache, OUT_DIR  # noqa: E402

UA = "shodan-state-collector/1.0 (Louisiana exposure census; allowlisted enrichment)"


def log(msg):
    _log(f"enrich: {msg}")


def http(method, url, headers=None, data=None, timeout=30):
    h = {"User-Agent": UA, "Accept": "application/json"}
    h.update(headers or {})
    body = None
    if data is not None:
        body = data if isinstance(data, (bytes, bytearray)) else urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, headers=h, data=body, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        return r.status, (json.loads(raw.decode("utf-8", "replace")) if raw else {})


def env(*names):
    for n in names:
        v = (os.environ.get(n) or "").strip()
        if v:
            return v
    return ""


# --- GTI / VirusTotal ------------------------------------------------------------

def gti_ip(ip, key):
    h = {"x-apikey": key}
    _, d = http("GET", f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", h)
    a = (d.get("data") or {}).get("attributes") or {}
    stats = a.get("last_analysis_stats") or {}
    out = {"ok": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
           "harmless": stats.get("harmless", 0), "reputation": a.get("reputation"),
           "as_owner": a.get("as_owner"), "asn": a.get("asn"), "country": a.get("country"),
           "network": a.get("network"), "tags": a.get("tags") or [],
           "last_analysis_date": a.get("last_analysis_date"),
           # IP objects carry GTI's threat_severity block (gti_assessment is only
           # on files/URLs/domains); keep both in case the API adds it.
           "gti_assessment": (a.get("gti_assessment") or {}).get("verdict", {}).get("value") if a.get("gti_assessment") else None,
           "threat_severity": (a.get("threat_severity") or {}).get("threat_severity_level"),
           "threat_severity_data": (a.get("threat_severity") or {}).get("threat_severity_data") or {},
           "threat_severity_note": (a.get("threat_severity") or {}).get("level_description"),
           "resolutions": [], "communicating_files": 0, "communicating_sample": []}
    try:
        _, r = http("GET", f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions?limit=20", h)
        out["resolutions"] = sorted({(x.get("attributes") or {}).get("host_name") for x in r.get("data") or []
                                     if (x.get("attributes") or {}).get("host_name")})[:20]
    except Exception as exc:
        out["resolutions_error"] = str(exc)[:80]
    try:
        _, c = http("GET", f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/communicating_files?limit=5", h)
        out["communicating_files"] = (c.get("meta") or {}).get("count", len(c.get("data") or []))
        out["communicating_sample"] = [{"sha256": x.get("id"),
                                        "malicious": ((x.get("attributes") or {}).get("last_analysis_stats") or {}).get("malicious"),
                                        "name": ((x.get("attributes") or {}).get("meaningful_name"))}
                                       for x in (c.get("data") or [])[:5]]
    except Exception as exc:
        out["communicating_error"] = str(exc)[:80]
    return out


def gti_vuln(cve, key):
    """GTI (Mandiant) vulnerability intelligence for one CVE: risk rating,
    exploitation state, exploit availability, actors. Needs the
    'vulnerabilities' privilege (GTI Enterprise)."""
    h = {"x-apikey": key}
    q = urllib.parse.quote(f"collection_type:vulnerability name:{cve}")
    _, d = http("GET", f"https://www.virustotal.com/api/v3/collections?filter={q}&limit=1", h)
    items = d.get("data") or []
    if not items:
        return {"ok": True, "found": False}
    a = items[0].get("attributes") or {}
    ex = a.get("exploitation") or {}
    kev = a.get("cisa_known_exploited") or {}
    def day(ts):
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).date().isoformat() if ts else None
    summary = (a.get("executive_summary") or "").strip()
    first_line = summary.split("\n")[0].lstrip("* ").strip() if summary else ""
    return {"ok": True, "found": True, "id": items[0].get("id"), "risk_rating": a.get("risk_rating") or None,
            "predicted_risk_rating": a.get("predicted_risk_rating") or None, "priority": a.get("priority") or None,
            "exploitation_state": a.get("exploitation_state") or None,
            "exploit_availability": a.get("exploit_availability") or None,
            "exploitation_consequence": a.get("exploitation_consequence") or None,
            "exploitation_vectors": a.get("exploitation_vectors") or [],
            "first_exploitation": day(ex.get("first_exploitation")), "exploit_release": day(ex.get("exploit_release_date")),
            "ransomware_use": kev.get("ransomware_use"), "kev_due": day(kev.get("due_date")),
            "available_mitigation": a.get("available_mitigation") or [], "days_to_patch": a.get("days_to_patch"),
            "actors": [x.get("name") or x.get("id") for x in (a.get("merged_actors") or [])][:8],
            "targeted_industries": a.get("targeted_industries") or [],
            "epss": ((a.get("epss") or {}).get("score")), "summary": first_line[:300]}


# --- CrowdStrike Falcon Intelligence --------------------------------------------------

class Falcon:
    def __init__(self, cid, secret, base):
        self.base = base.rstrip("/")
        self.cid, self.secret = cid, secret
        self.token, self.exp = None, 0

    def auth(self):
        if self.token and time.time() < self.exp - 60:
            return self.token
        _, d = http("POST", f"{self.base}/oauth2/token",
                    {"Content-Type": "application/x-www-form-urlencoded"},
                    {"client_id": self.cid, "client_secret": self.secret})
        self.token = d["access_token"]
        self.exp = time.time() + int(d.get("expires_in", 1799))
        return self.token

    def indicators_for_ip(self, ip):
        h = {"Authorization": f"Bearer {self.auth()}"}
        q = urllib.parse.quote(f"type:'ip_address'+indicator:'{ip}'")
        _, d = http("GET", f"{self.base}/intel/combined/indicators/v1?filter={q}&limit=20", h)
        out = []
        for r in d.get("resources") or []:
            out.append({"indicator": r.get("indicator"), "malicious_confidence": r.get("malicious_confidence"),
                        "published": r.get("published_date"), "last_updated": r.get("last_updated"),
                        "actors": r.get("actors") or [], "malware_families": r.get("malware_families") or [],
                        "kill_chains": r.get("kill_chains") or [], "labels": [x.get("name") for x in (r.get("labels") or [])][:8],
                        "threat_types": r.get("threat_types") or []})
        return {"ok": True, "matches": out}


# --- AbuseIPDB / OTX / Cymru --------------------------------------------------------------

def abuseipdb(ip, key):
    _, d = http("GET", f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose",
                {"Key": key})
    a = d.get("data") or {}
    return {"ok": True, "abuse_confidence": a.get("abuseConfidenceScore"), "reports": a.get("totalReports"),
            "distinct_reporters": a.get("numDistinctUsers"), "last_reported": a.get("lastReportedAt"),
            "usage_type": a.get("usageType"), "isp": a.get("isp"), "domain": a.get("domain"),
            "is_tor": a.get("isTor"), "country": a.get("countryCode"),
            "categories": sorted({c for r in (a.get("reports") or [])[:50] for c in (r.get("categories") or [])})[:12]}


def otx(ip, key):
    _, d = http("GET", f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", {"X-OTX-API-KEY": key})
    p = d.get("pulse_info") or {}
    return {"ok": True, "pulses": p.get("count", 0),
            "pulse_names": [x.get("name") for x in (p.get("pulses") or [])[:6]],
            "asn": d.get("asn"), "country": d.get("country_code"), "city": d.get("city"),
            "reputation": d.get("reputation"), "validation": [v.get("source") for v in (d.get("validation") or [])]}


def cymru(ip, key):
    return {"ok": False, "note": "Team Cymru Scout/Recon client not implemented until the licensed tier is known"}


# --- driver -----------------------------------------------------------------------------

SOURCES = ("gti", "crowdstrike", "abuseipdb", "otx", "cymru")


def main():
    load_dotenv(os.path.join(SCRIPT_DIR, ".env"))
    ap = argparse.ArgumentParser(description="Allowlisted licensed enrichment for verified hosts.")
    ap.add_argument("--verify", required=True, help="verify_<date>.json from verify_hosts.py")
    ap.add_argument("--sources", default=",".join(SOURCES))
    ap.add_argument("--limit", type=int, default=0, help="only the first N hosts (testing)")
    ap.add_argument("--sleep", type=float, default=0.6, help="seconds between calls per source")
    args = ap.parse_args()

    ver = json.load(open(args.verify))
    ips = sorted(ver["results"])
    if args.limit:
        ips = ips[:args.limit]
    wanted = [s for s in args.sources.split(",") if s in SOURCES]

    keys = {"gti": env("GTI_API_KEY", "VT_API_KEY", "VIRUSTOTAL_API_KEY"),
            "abuseipdb": env("ABUSEIPDB_API_KEY"), "otx": env("OTX_API_KEY"),
            "cymru": env("CYMRU_SCOUT_API_KEY", "CYMRU_API_KEY")}
    cs_id, cs_secret = env("CS_CLIENT_ID", "CROWDSTRIKE_CLIENT_ID"), env("CS_CLIENT_SECRET", "CROWDSTRIKE_CLIENT_SECRET")
    cs_base = env("CS_BASE_URL", "CROWDSTRIKE_BASE_URL") or "https://api.crowdstrike.com"
    falcon = Falcon(cs_id, cs_secret, cs_base) if (cs_id and cs_secret) else None
    available = {s for s in wanted if (s == "crowdstrike" and falcon) or (s != "crowdstrike" and keys.get(s))}
    for s in wanted:
        if s not in available:
            log(f"{s}: no key in .env — skipped")
    if not available:
        log("no licensed sources available; nothing to do")
        return 0
    log(f"enriching {len(ips)} allowlisted hosts with: {', '.join(sorted(available))}")

    caches = {s: Cache(os.path.join(OUT_DIR, f"{s}_cache.json"), ttl_days=7) for s in available}
    fetchers = {"gti": lambda ip: gti_ip(ip, keys["gti"]), "abuseipdb": lambda ip: abuseipdb(ip, keys["abuseipdb"]),
                "otx": lambda ip: otx(ip, keys["otx"]), "cymru": lambda ip: cymru(ip, keys["cymru"]),
                "crowdstrike": lambda ip: falcon.indicators_for_ip(ip)}
    counts = {s: {"ok": 0, "err": 0, "cached": 0} for s in available}
    for n, ip in enumerate(ips, 1):
        block = ver["results"][ip].setdefault("licensed", {})
        for s in sorted(available):
            hit = caches[s].get(ip)
            if hit:
                block[s] = hit; counts[s]["cached"] += 1
                continue
            try:
                rec = fetchers[s](ip)
                counts[s]["ok"] += 1
            except urllib.error.HTTPError as exc:
                rec = {"ok": False, "error": f"HTTP {exc.code}"}
                counts[s]["err"] += 1
                if exc.code in (401, 403):
                    log(f"{s}: HTTP {exc.code} — key rejected or scope missing; disabling for this run")
                    available.discard(s)
            except Exception as exc:
                rec = {"ok": False, "error": str(exc)[:120]}
                counts[s]["err"] += 1
            block[s] = caches[s].put(ip, rec)
            time.sleep(args.sleep)
        if n % 25 == 0:
            log(f"  {n}/{len(ips)}")
            for c in caches.values():
                c.save()
    for c in caches.values():
        c.save()

    # GTI vulnerability intelligence for every KEV CVE seen on these hosts
    # (one call per CVE, cached a week; the host count does not matter).
    if "gti" in available:
        cves = sorted({c for ip in ips for c in ((ver["results"][ip].get("risk") or {}).get("kev_due_dates") or {})}
                      | {c for ip in ips for c in ((ver["results"][ip].get("currency") or {}).get("kev_still_listed") or [])})
        vcache = Cache(os.path.join(OUT_DIR, "gti_vuln_cache.json"), ttl_days=7)
        vulns = ver.setdefault("vulnerabilities", {})
        fetched = 0
        for cve in cves:
            hit = vcache.get(cve)
            if not hit:
                try:
                    hit = gti_vuln(cve, keys["gti"])
                    fetched += 1
                except Exception as exc:
                    hit = {"ok": False, "error": str(exc)[:120]}
                vcache.put(cve, hit)
                time.sleep(args.sleep)
            vulns[cve] = hit
        vcache.save()
        log(f"gti vulnerabilities: {len(cves)} KEV CVEs, {fetched} fetched, "
            f"{sum(1 for c in cves if vulns[c].get('found'))} with GTI records")
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        for ip in ips:
            r = ver["results"][ip]
            mine = sorted({c for c in (r.get("risk") or {}).get("kev_due_dates") or {}}
                          | set((r.get("currency") or {}).get("kev_still_listed") or []))
            recs = [(c, vulns.get(c) or {}) for c in mine if (vulns.get(c) or {}).get("found")]
            if not recs:
                continue
            def key_fn(cr):
                c, v = cr
                return (rank.get((v.get("risk_rating") or "").upper(), 0), 1 if v.get("priority") == "P0" else 0,
                        1 if v.get("exploit_availability") == "Publicly Available" else 0, c)
            worst_cve, worst = max(recs, key=key_fn)
            r.setdefault("risk", {})["gti_vulns"] = {
                "cve": worst_cve, "risk_rating": worst.get("risk_rating"), "priority": worst.get("priority"),
                "exploitation_state": worst.get("exploitation_state"),
                "exploit_availability": worst.get("exploit_availability"),
                "consequence": worst.get("exploitation_consequence"), "ransomware_use": worst.get("ransomware_use"),
                "first_exploitation": worst.get("first_exploitation"),
                "p0": sum(1 for _, v in recs if v.get("priority") == "P0"),
                "high_or_critical": sum(1 for _, v in recs if rank.get((v.get("risk_rating") or "").upper(), 0) >= 3),
                "public_exploit": sum(1 for _, v in recs if v.get("exploit_availability") == "Publicly Available"),
                "actors": sorted({a for _, v in recs for a in v.get("actors") or []})[:6],
                "rated": len(recs)}

    # Roll-up flags per IP for the report.
    for ip in ips:
        lic = ver["results"][ip].get("licensed") or {}
        g, a, o, c = lic.get("gti") or {}, lic.get("abuseipdb") or {}, lic.get("otx") or {}, lic.get("crowdstrike") or {}
        flags = []
        if g.get("ok") and (g.get("malicious") or 0) >= 2:
            flags.append(f"GTI/VT: {g['malicious']} engines malicious")
        if g.get("ok") and g.get("gti_assessment") in ("MALICIOUS", "SUSPICIOUS"):
            flags.append(f"GTI verdict {g['gti_assessment']}")
        ts, tsd = g.get("threat_severity"), g.get("threat_severity_data") or {}
        if g.get("ok") and ts and ts != "SEVERITY_NONE":
            flags.append(f"GTI threat severity {ts.replace('SEVERITY_', '')}")
        if g.get("ok") and tsd.get("belongs_to_threat_actor"):
            flags.append("GTI: tied to a tracked threat actor")
        elif g.get("ok") and tsd.get("belongs_to_bad_collection"):
            flags.append("GTI: in a malicious collection")
        # Communicating files: only samples that engines actually call malicious
        # count (benign tools also phone home to public servers).
        bad = [x for x in (g.get("communicating_sample") or []) if (x.get("malicious") or 0) >= 5]
        if g.get("ok") and bad:
            worst = max(x.get("malicious") or 0 for x in bad)
            flags.append(f"{len(bad)} MALWARE sample{'s' if len(bad) > 1 else ''} communicated with it "
                         f"(up to {worst} engines): {', '.join((x.get('sha256') or '')[:12] for x in bad[:3])}")
        if a.get("ok") and (a.get("abuse_confidence") or 0) >= 50:
            flags.append(f"AbuseIPDB {a['abuse_confidence']}% ({a.get('reports')} reports)")
        if o.get("ok") and (o.get("pulses") or 0) >= 3:
            flags.append(f"OTX {o['pulses']} pulses")
        if c.get("ok") and c.get("matches"):
            m = c["matches"][0]
            flags.append(f"CrowdStrike indicator ({m.get('malicious_confidence')}; {', '.join(m.get('actors') or m.get('malware_families') or [])[:60]})")
        ver["results"][ip]["licensed_flags"] = flags
        # extra owner evidence: passive DNS names from GTI/VT
        if g.get("resolutions"):
            ver["results"][ip]["owner"]["passive_dns"] = g["resolutions"][:10]

    ver["licensed_run"] = {"date": dt.date.today().isoformat(), "sources": sorted(available), "counts": counts}
    tmp = args.verify + ".tmp"
    json.dump(ver, open(tmp, "w"), indent=1, default=str)
    os.replace(tmp, args.verify)
    flagged = sum(1 for ip in ips if ver["results"][ip].get("licensed_flags"))
    log(f"done: {counts}; hosts with a licensed-intel flag: {flagged}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
