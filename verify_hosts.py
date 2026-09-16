#!/usr/bin/env python3
"""
verify_hosts.py — second-opinion verification for a short list of hosts
(typically the top-hosts report): is it really in Louisiana, is the exposure
still current, who do we tell, and what else is known.

Per IP it gathers, each source fail-soft and cached under reference/verification/:
  * ARIN RDAP netblock  — the IP's own allocation (not just the ASN): name, range,
                          registrant, registrant postal state, abuse + technical
                          contacts, and the city code many carriers embed in the
                          netblock name (NETBLK-BR-... = Baton Rouge).            [free]
  * Shodan InternetDB   — Shodan's CURRENT summary: ports, CVEs, hostnames, CPEs,
                          tags. Keyless, no credits. "Still on Shodan today?"     [free]
  * Shodan host lookup  — the full current record incl. last_update timestamp,
                          location, org. 1 query credit per IP (--shodan-credits). [1 credit]
  * MaxMind geo         — independent country/state for the IP (geo.py).          [free]
  * rDNS city codes     — Cox/AT&T style hostnames carry the metro (br.br.cox.net). [free]
  * KEV metadata        — ransomware-campaign use and CISA due date per KEV CVE
                          (reference/kev.json, refreshed weekly).                  [free]
  * Store facts         — dwell (lifecycle first_seen), certificate issuer/expiry,
                          Louisiana votes: Shodan region, MaxMind, netblock state,
                          rDNS city, registry attribution.
  * --rescan            — submit the IPs to Shodan for an on-demand rescan
                          (Shodan's scanner, initiated by us: needs unit approval;
                          uses scan credits). Results land in Shodan within minutes;
                          re-run the report afterwards.

Licensed sources (GTI/VirusTotal, Team Cymru Scout, CrowdStrike Falcon) are
looked up ONLY for the hosts given here (an allowlist), only when their keys
exist in .env, and only read-only. See enrich_licensed.py.

Output: reference/verification/verify_<date>.json (per-IP dict) — consumed by
top_hosts_report.py --verify to add the verification block to PDF/CSV.

Usage:
    verify_hosts.py --from-report reports/top_hosts_2026-09-15.csv
    verify_hosts.py --ips 70.169.70.86,8.29.72.62 --shodan-credits 0
    verify_hosts.py --from-report ... --rescan        # after approval
"""
import argparse
import csv
import datetime as dt
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from shodan_collect import load_dotenv, get_api_key, log as _log  # noqa: E402

OUT_DIR = os.path.join(SCRIPT_DIR, "reference", "verification")
UA = {"User-Agent": "shodan-state-collector/1.0 (Louisiana exposure census; passive verification)",
      "Accept": "application/json, application/rdap+json"}
LA_STATE_WORDS = ("la", "louisiana")
# Metro codes carriers put in reverse DNS and netblock names.
CITY_CODES = {"br": "Baton Rouge", "no": "New Orleans", "lf": "Lafayette", "lft": "Lafayette", "lc": "Lake Charles",
              "sh": "Shreveport", "shv": "Shreveport", "mn": "Monroe", "al": "Alexandria", "hm": "Houma",
              "bsr": "Bossier City", "hou": "Houma", "slid": "Slidell", "mtry": "Metairie", "nola": "New Orleans",
              "btr": "Baton Rouge"}
LA_CITIES = ("baton rouge", "new orleans", "lafayette", "lake charles", "shreveport", "monroe", "alexandria",
             "houma", "bossier", "slidell", "metairie", "kenner", "hammond", "covington", "mandeville",
             "thibodaux", "ruston", "natchitoches", "opelousas", "gretna", "sulphur", "zachary", "gonzales",
             "denham springs", "prairieville", "marrero", "harvey", "chalmette", "laplace", "west monroe",
             "pineville", "morgan city", "new iberia", "abbeville", "crowley", "eunice", "jennings", "minden",
             "bogalusa", "leesville", "deridder", "baker", "plaquemine", "donaldsonville", "franklin", "bastrop")


def log(msg):
    _log(f"verify: {msg}")


def fetch_json(url, timeout=25, headers=None):
    req = urllib.request.Request(url, headers=headers or UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


class Cache:
    def __init__(self, path, ttl_days):
        self.path, self.ttl = path, ttl_days
        try:
            self.data = json.load(open(path))
        except Exception:
            self.data = {}

    def get(self, key):
        rec = self.data.get(key)
        if not rec:
            return None
        try:
            age = (dt.date.today() - dt.date.fromisoformat(rec["_fetched"])).days
        except Exception:
            return None
        return rec if age <= self.ttl else None

    def put(self, key, value):
        value = dict(value)
        value["_fetched"] = dt.date.today().isoformat()
        self.data[key] = value
        return value

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = f"{self.path}.{os.getpid()}.tmp"
        json.dump(self.data, open(tmp, "w"))
        os.replace(tmp, self.path)


# --- ARIN RDAP per-IP netblock ----------------------------------------------------

def _vcard(entity):
    v = (entity.get("vcardArray") or [None, []])[1] or []
    out = {"fn": None, "email": None, "adr": None}
    for item in v:
        if not item:
            continue
        if item[0] == "fn":
            out["fn"] = item[3]
        elif item[0] == "email" and not out["email"]:
            out["email"] = item[3]
        elif item[0] == "adr":
            val = item[3]
            if isinstance(val, list):
                out["adr"] = val
            label = (item[1] or {}).get("label")
            if label:
                out["adr_label"] = label
    return out


def parse_rdap_ip(doc):
    """RDAP ip document -> netblock summary with registrant state and contacts."""
    out = {"netblock": doc.get("name"), "handle": doc.get("handle"), "start": doc.get("startAddress"),
           "end": doc.get("endAddress"), "alloc_type": doc.get("type"), "registrant": None,
           "registrant_state": None, "registrant_city": None, "abuse": [], "technical": [], "city_code": None}
    name = (doc.get("name") or "")
    m = re.search(r"NETBLK-([A-Z]{2,4})-", name.upper()) or re.search(r"^([A-Z]{2,4})-", name.upper())
    if m and m.group(1).lower() in CITY_CODES:
        out["city_code"] = CITY_CODES[m.group(1).lower()]

    def walk(ents):
        for ent in ents or []:
            roles = set(ent.get("roles") or [])
            card = _vcard(ent)
            if "registrant" in roles and not out["registrant"]:
                out["registrant"] = card["fn"]
                adr = card.get("adr") or []
                label = card.get("adr_label") or ""
                # jCard adr: [pobox, ext, street, locality, region, postcode, country]
                if len(adr) >= 5 and adr[4]:
                    out["registrant_state"] = str(adr[4]).strip()
                    out["registrant_city"] = str(adr[3]).strip() or None
                elif label:
                    # ARIN labels are one field per line: street / city / ST / zip / country
                    parts = [p.strip() for p in label.replace("\r", "").split("\n") if p.strip()]
                    for i, p in enumerate(parts):
                        if re.fullmatch(r"[A-Z]{2}", p) and i + 1 < len(parts) and re.match(r"\d{5}", parts[i + 1]):
                            out["registrant_state"] = p
                            out["registrant_city"] = parts[i - 1] if i >= 1 else None
                            break
                        mm = re.search(r",\s*([A-Z]{2})\s+\d{5}", p)
                        if mm:
                            out["registrant_state"] = mm.group(1)
                            out["registrant_city"] = p.split(",")[0].strip()
                            break
            if "abuse" in roles and card["email"]:
                out["abuse"].append(card["email"])
            if ("technical" in roles or "administrative" in roles) and card["email"]:
                out["technical"].append(card["email"])
            walk(ent.get("entities"))
    walk(doc.get("entities"))
    out["abuse"] = sorted(set(out["abuse"]))
    out["technical"] = sorted(set(out["technical"]))[:4]
    return out


def rdap_ip(ip, cache):
    hit = cache.get(ip)
    if hit:
        return hit
    try:
        doc = fetch_json(f"https://rdap.arin.net/registry/ip/{ip}")
        rec = parse_rdap_ip(doc)
        rec["ok"] = True
    except Exception as exc:
        rec = {"ok": False, "error": str(exc)[:120]}
    time.sleep(0.5)
    return cache.put(ip, rec)


# --- Shodan InternetDB + host lookup --------------------------------------------------

def internetdb(ip, cache):
    hit = cache.get(ip)
    if hit:
        return hit
    try:
        d = fetch_json(f"https://internetdb.shodan.io/{ip}", timeout=20)
        rec = {"ok": True, "ports": sorted(d.get("ports") or []), "vulns": sorted(d.get("vulns") or []),
               "hostnames": sorted(d.get("hostnames") or []), "cpes": sorted(d.get("cpes") or [])[:12],
               "tags": sorted(d.get("tags") or [])}
    except urllib.error.HTTPError as exc:
        rec = {"ok": exc.code == 404, "ports": [], "vulns": [], "hostnames": [], "cpes": [], "tags": [],
               "note": "not in InternetDB" if exc.code == 404 else f"HTTP {exc.code}"}
    except Exception as exc:
        rec = {"ok": False, "error": str(exc)[:120]}
    return cache.put(ip, rec)


def shodan_host(api, ip, cache):
    hit = cache.get(ip)
    if hit:
        return hit
    try:
        h = api.host(ip)
        rec = {"ok": True, "last_update": h.get("last_update"), "ports": sorted(h.get("ports") or []),
               "vulns": sorted(h.get("vulns") or []), "hostnames": sorted(h.get("hostnames") or []),
               "city": h.get("city"), "region_code": h.get("region_code"), "country": h.get("country_code"),
               "org": h.get("org"), "isp": h.get("isp"), "asn": h.get("asn"), "tags": sorted(h.get("tags") or []),
               "os": h.get("os"),
               "banner_ts": sorted({(b.get("timestamp") or "")[:19] for b in (h.get("data") or [])}, reverse=True)[:1]}
    except Exception as exc:
        rec = {"ok": False, "error": str(exc)[:120]}
    return cache.put(ip, rec)


def shodan_rescan(api, ips):
    try:
        res = api.scan(ips)
        return {"ok": True, "id": res.get("id"), "count": res.get("count"), "credits_left": res.get("credits_left")}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:160]}


# --- rDNS / KEV / store ------------------------------------------------------------------

def rdns_city(hostnames):
    for h in hostnames or []:
        hl = h.lower()
        m = re.search(r"\.([a-z]{2,4})\.\1\.(cox|rr)\.net$", hl) or re.search(r"\.([a-z]{2,4})\.[a-z]{2}\.(cox|rr)\.net$", hl)
        if m and m.group(1) in CITY_CODES:
            return CITY_CODES[m.group(1)]
        for c in LA_CITIES:
            if c.replace(" ", "") in hl.replace("-", "").replace("_", ""):
                return c.title()
    return None


def load_kev_meta():
    try:
        d = json.load(open(os.path.join(SCRIPT_DIR, "reference", "kev.json")))
    except Exception:
        return {}
    return d.get("meta") or {}


def store_facts(ips):
    import duckdb
    con = duckdb.connect(os.path.join(SCRIPT_DIR, "store", "exposure.duckdb"), read_only=True)
    placeholders = ",".join("?" for _ in ips)
    rows = con.execute(f"""
        SELECT cs.ip, any_value(cs.region_code), any_value(cs.city), any_value(cs.tier), any_value(cs.org),
               any_value(cs.attr_org_name), any_value(cs.attr_method), any_value(cs.attr_confidence),
               string_agg(DISTINCT coalesce(cs.hostnames,''), ','), max(cs.date),
               string_agg(DISTINCT coalesce(cs.cert_issuer,''), ','), max(cs.cert_expires), bool_or(cs.cert_expired),
               string_agg(DISTINCT CASE WHEN v.in_kev THEN v.cve END, ' '),
               (SELECT min(first_seen) FROM lifecycle l WHERE l.ip = cs.ip)
        FROM current_state cs LEFT JOIN vulns v ON v.observation_id = cs.observation_id AND v.date = cs.date
        WHERE cs.ip IN ({placeholders}) GROUP BY cs.ip""", ips).fetchall()
    con.close()
    out = {}
    for r in rows:
        out[r[0]] = {"shodan_region": r[1], "shodan_city": r[2], "tier": r[3], "org": r[4], "attr_org": r[5],
                     "attr_method": r[6], "attr_conf": r[7],
                     "hostnames": sorted({h for h in (r[8] or "").split(",") if h}), "last_seen": str(r[9]),
                     "cert_issuer": ",".join(sorted({x for x in (r[10] or "").split(",") if x}))[:60],
                     "cert_expires": r[11], "cert_expired": r[12],
                     "kev": sorted((r[13] or "").split()), "first_seen": str(r[14]) if r[14] else None}
    return out


def maxmind(ip):
    try:
        import geo
        g = geo.GeoGate()
        cc, sub = g.locate(ip)
        return {"country": cc, "region": sub}
    except Exception:
        return {"country": None, "region": None}


# --- assemble ---------------------------------------------------------------------------

def verify_ip(ip, facts, rd, idb, sh, mm, kev_meta):
    f = facts.get(ip, {})
    votes = {}
    votes["shodan_region"] = (f.get("shodan_region") == "LA") if f else None
    votes["maxmind"] = (mm.get("country") == "US" and mm.get("region") == "LA")
    votes["netblock_state"] = ((rd.get("registrant_state") or "").upper() in ("LA",)) if rd.get("ok") else None
    city = rdns_city(f.get("hostnames", []) + (idb.get("hostnames") or []) + ((sh or {}).get("hostnames") or []))
    votes["rdns_city"] = bool(city) or bool(rd.get("city_code"))
    votes["registry"] = (f.get("attr_conf") in ("high", "medium")) and bool(f.get("attr_org"))
    yes = [k for k, v in votes.items() if v]
    no = [k for k, v in votes.items() if v is False]
    la_confidence = ("high" if len(yes) >= 3 else "medium" if len(yes) == 2 else "low")
    if votes["netblock_state"] is False and (rd.get("registrant_state") or "").upper() not in ("", "LA"):
        la_note = f"netblock registrant address is {rd.get('registrant_state')} (carrier HQ is normal)"
    else:
        la_note = ""
    # currency
    store_kev = set(f.get("kev") or [])
    idb_vulns = set(idb.get("vulns") or [])
    sh_vulns = set((sh or {}).get("vulns") or [])
    current_src = sh if (sh and sh.get("ok")) else idb
    cur_vulns = sh_vulns if (sh and sh.get("ok")) else idb_vulns
    still_kev = sorted(store_kev & cur_vulns) if cur_vulns else None
    gone_kev = sorted(store_kev - cur_vulns) if cur_vulns else None
    ransomware = sorted(c for c in store_kev if (kev_meta.get(c) or {}).get("ransomware"))
    due = {c: (kev_meta.get(c) or {}).get("dueDate") for c in store_kev if (kev_meta.get(c) or {}).get("dueDate")}
    return {
        "ip": ip,
        "louisiana": {"confidence": la_confidence, "votes_for": yes, "votes_against": no, "note": la_note,
                      "maxmind": mm, "netblock_state": rd.get("registrant_state"), "netblock_city_code": rd.get("city_code"),
                      "rdns_city": city, "shodan_city": (sh or {}).get("city") or f.get("shodan_city")},
        "owner": {"netblock": rd.get("netblock"), "range": f"{rd.get('start')}-{rd.get('end')}" if rd.get("start") else None,
                  "registrant": rd.get("registrant"), "registrant_city": rd.get("registrant_city"),
                  "abuse_contacts": rd.get("abuse") or [], "technical_contacts": rd.get("technical") or [],
                  "registry_attribution": f.get("attr_org"), "registry_confidence": f.get("attr_conf"),
                  "current_hostnames": sorted(set((idb.get("hostnames") or []) + ((sh or {}).get("hostnames") or [])))[:6]},
        "currency": {"source": "shodan_host" if (sh and sh.get("ok")) else ("internetdb" if idb.get("ok") else "none"),
                     "shodan_last_update": (sh or {}).get("last_update"),
                     "current_ports": (current_src or {}).get("ports"),
                     "kev_still_listed": still_kev, "kev_no_longer_listed": gone_kev,
                     "current_cve_count": len(cur_vulns) if cur_vulns is not None else None,
                     "store_last_seen": f.get("last_seen"), "first_seen": f.get("first_seen"),
                     "dwell_days": ((dt.date.fromisoformat(f["last_seen"]) - dt.date.fromisoformat(f["first_seen"])).days
                                    if f.get("first_seen") and f.get("last_seen") else None)},
        "risk": {"ransomware_kev": ransomware, "kev_due_dates": due,
                 "cert_issuer": f.get("cert_issuer"), "cert_expires": f.get("cert_expires"), "cert_expired": f.get("cert_expired"),
                 "current_tags": sorted(set((idb.get("tags") or []) + ((sh or {}).get("tags") or []))),
                 "cpes": (idb.get("cpes") or [])[:8], "os": (sh or {}).get("os")},
    }


def main():
    load_dotenv(os.path.join(SCRIPT_DIR, ".env"))
    ap = argparse.ArgumentParser(description="Verify Louisiana location, currency, owner and risk context for a host list.")
    ap.add_argument("--from-report", help="CSV from top_hosts_report.py (column ip)")
    ap.add_argument("--ips", help="comma-separated IPs")
    ap.add_argument("--shodan-credits", type=int, default=200, help="max Shodan host lookups (1 credit each); 0 = InternetDB only")
    ap.add_argument("--rescan", action="store_true", help="submit the IPs to Shodan for an on-demand rescan (needs unit approval)")
    ap.add_argument("--out", default=OUT_DIR)
    args = ap.parse_args()

    ips = []
    if args.from_report:
        with open(args.from_report, newline="") as fh:
            ips = [r["ip"] for r in csv.DictReader(fh) if r.get("ip")]
    if args.ips:
        ips += [x.strip() for x in args.ips.split(",") if x.strip()]
    ips = sorted({str(ipaddress.ip_address(i)) for i in ips})
    if not ips:
        ap.error("give --from-report or --ips")
    log(f"verifying {len(ips)} hosts")

    os.makedirs(args.out, exist_ok=True)
    rdap_cache = Cache(os.path.join(args.out, "rdap_ip_cache.json"), ttl_days=30)
    idb_cache = Cache(os.path.join(args.out, "internetdb_cache.json"), ttl_days=1)
    sh_cache = Cache(os.path.join(args.out, "shodan_host_cache.json"), ttl_days=1)
    api = None
    if args.shodan_credits > 0 or args.rescan:
        try:
            import shodan
            api = shodan.Shodan(get_api_key())
        except Exception as exc:
            log(f"Shodan API unavailable ({exc}); InternetDB only")

    facts = store_facts(ips)
    kev_meta = load_kev_meta()
    results, credits = {}, 0
    for n, ip in enumerate(ips, 1):
        rd = rdap_ip(ip, rdap_cache)
        idb = internetdb(ip, idb_cache)
        sh = sh_cache.get(ip)                 # a cached record costs nothing
        if sh is None and api and credits < args.shodan_credits:
            sh = shodan_host(api, ip, sh_cache)
            credits += 1
        results[ip] = verify_ip(ip, facts, rd, idb, sh, maxmind(ip), kev_meta)
        if n % 25 == 0:
            log(f"  {n}/{len(ips)} done")
            rdap_cache.save(); idb_cache.save(); sh_cache.save()
    rdap_cache.save(); idb_cache.save(); sh_cache.save()

    rescan = None
    if args.rescan:
        if not api:
            log("rescan requested but the Shodan API is unavailable")
        else:
            rescan = shodan_rescan(api, ips)
            log(f"rescan submitted: {rescan}")

    out = {"generated": dt.date.today().isoformat(), "hosts": len(ips), "shodan_credits_used": credits,
           "rescan": rescan, "results": results}
    path = os.path.join(args.out, f"verify_{dt.date.today().isoformat()}.json")
    json.dump(out, open(path, "w"), indent=1, default=str)
    conf = {}
    still = sum(1 for r in results.values() if r["currency"]["kev_still_listed"])
    for r in results.values():
        conf[r["louisiana"]["confidence"]] = conf.get(r["louisiana"]["confidence"], 0) + 1
    log(f"done -> {path}; Louisiana confidence {conf}; hosts with KEV still listed today: {still}; "
        f"ransomware-KEV hosts: {sum(1 for r in results.values() if r['risk']['ransomware_kev'])}; "
        f"Shodan credits used: {credits}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
