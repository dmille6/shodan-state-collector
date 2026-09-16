#!/usr/bin/env python3
"""
build_store.py — parse daily Shodan .gz archives into a queryable DuckDB/Parquet
analytical store.

The raw daily_downloads/*.json.gz files remain the immutable system of record.
This projects them into a columnar store you can query with SQL:

  store/observations/date=<ISO>/data.parquet   one row per banner per day
  store/vulns/date=<ISO>/data.parquet           one row per (ip,port,cve) per day
  store/exposure.duckdb                          DuckDB with views over the parquet

Because the parquet is derived, it is always safe to delete and rebuild from the
.gz archive (e.g. after a schema change): `build_store.py --all --rebuild`.

Enrichment (tier, KEV, EPSS) reuses the reference caches and classifier from
triage_report.py. PASSIVE data; findings are leads to verify.

Usage:
    build_store.py --date 2026-06-30      # (re)build one day's partition + views
    build_store.py --all                  # build every day found in daily_downloads/
    build_store.py path/to/file.json.gz   # build a specific file
"""
import argparse
import glob
import gzip
import hashlib
import json
import os
import re
import sys
import tempfile

import duckdb
import triage_report as tr   # reuse classify() + signal maps + load_json()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STORE = os.path.join(SCRIPT_DIR, "store")
OBS_DIR = os.path.join(STORE, "observations")
VULN_DIR = os.path.join(STORE, "vulns")
DB_PATH = os.path.join(STORE, "exposure.duckdb")
DAILY_DIR = os.path.join(SCRIPT_DIR, "daily_downloads")


def load_enrichment():
    kev = set(tr.load_json(os.path.join(SCRIPT_DIR, "reference/kev.json"), {}).get("cves", []))
    epss = tr.load_json(os.path.join(SCRIPT_DIR, "reference/epss.json"), {})
    return kev, epss


def load_exploits():
    """{cve: [sources]} of CVEs with a public exploit / detection template."""
    d = tr.load_json(os.path.join(SCRIPT_DIR, "reference/exploits.json"), {})
    return {k: v for k, v in d.items() if not k.startswith("_")}


# Registry-driven sector -> tier. High-confidence attribution from the owner
# registry (Phase 2) beats the keyword classifier; see registry.py.
SECTOR_TIER = {"critical_infrastructure": "critical_infrastructure", "healthcare": "critical_infrastructure",
               "energy": "critical_infrastructure", "water": "critical_infrastructure",
               "telecom": "critical_infrastructure", "government": "government",
               "education": "education", "out_of_state": "out_of_state_gov",
               "finance": "small_business", "small_business": "small_business", "other": "small_business"}


# Attribution methods that establish NETWORK OWNERSHIP of the whole IP. Only
# these may set a host's tier. A domain or certificate match says "this name
# is served here", which on shared hosting is not ownership of every service.
OWNERSHIP_METHODS = {"ots_cidr", "registry_network"}


def load_attributor():
    """registry.Attributor over store/registry/*.parquet, or None when the
    registry has not been built yet. A failure to load is reported loudly:
    silently running without the registry hid a broken call once."""
    try:
        import registry
    except ImportError:
        print("Registry: registry.py not present; using the keyword classifier only")
        return None
    try:
        a = registry.Attributor().load()          # default: <store>/registry
        n = len(a.attribution)
        print(f"Registry: loaded {len(a.orgs):,} orgs, {n:,} attributed IPs" if n or a.orgs
              else "Registry: no data yet (run build_registry.py); keyword classifier only")
        return a if (n or a.orgs) else None
    except Exception as exc:
        print(f"Registry: FAILED to load ({exc!r}); using the keyword classifier only", file=sys.stderr)
        return None


def registry_tier(a):
    """The tier a registry attribution may impose, or None. Requires HIGH
    confidence, a named org, a network-OWNERSHIP method, and no competing
    candidate in the evidence."""
    if not a or a.get("confidence") != "high" or not a.get("org_id"):
        return None
    if a.get("method") not in OWNERSHIP_METHODS:
        return None
    if "also matches" in (a.get("evidence") or "") or (a.get("conflict") or "").strip():
        return None                     # competing evidence: an analyst decides, not the store
    sector = (a.get("sector") or "").split("|")[0]
    return SECTOR_TIER.get(sector)


def date_from_name(path):
    base = os.path.basename(path)
    return base.replace(".json.gz", "").split("events-")[-1]


def iter_banners(path):
    """Stream one banner (parsed JSON) at a time from a daily .gz — bounded memory
    even when a day decompresses to many GB (full HTTP bodies can be 10-15 MB each)."""
    with gzip.open(path, "rt") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("ip_str"):
                yield r


_SAN_RE = re.compile(r"DNS:([^,\s]+)")
_IPISH = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def observation_id(r):
    """Stable identity of ONE banner observation. Shodan assigns every banner
    record a unique id (_shodan.id); fall back to a digest of the fields that
    make an observation distinct. vulns rows join on (date, observation_id):
    the SAME cached record can be re-served on several delta days, so the id
    alone is not unique across partitions — the date makes the pair unique."""
    sid = (r.get("_shodan") or {}).get("id")
    if sid:
        return str(sid)
    key = f"{r.get('ip_str')}|{r.get('port')}|{r.get('transport')}|{r.get('timestamp')}|{r.get('hash')}"
    return hashlib.sha1(key.encode()).hexdigest()[:24]


def cert_fields(r):
    """Flatten the TLS certificate: subject CN / O, issuer CN, SAN DNS names,
    expiry, SHA-256, plus JARM. The subject and SANs are the strongest owner
    signal in the whole banner (a hospital's cert on a carrier IP names the
    hospital) — which is why they also feed classification."""
    ssl = r.get("ssl") or {}
    cert = ssl.get("cert") or {}
    subj = cert.get("subject") or {}
    iss = cert.get("issuer") or {}
    san_raw = next((e.get("data") for e in (cert.get("extensions") or [])
                    if e.get("name") == "subjectAltName"), "") or ""
    sans = sorted({n.lower().rstrip(".") for n in _SAN_RE.findall(san_raw)})
    fp = cert.get("fingerprint") or {}
    return {
        "cert_cn": (subj.get("CN") or None),
        "cert_org": (subj.get("O") or None),
        "cert_issuer": (iss.get("CN") or iss.get("O") or None),
        "cert_sans": ",".join(sans),
        "cert_expired": cert.get("expired"),
        "cert_expires": cert.get("expires"),
        "cert_sha256": fp.get("sha256"),
        "jarm": ssl.get("jarm"),
    }


# Certificate subject organisations that name the DEVICE VENDOR or a shared
# platform, not the operator: a factory or platform cert must never attribute
# the host. Matched as whole words / prefixes, lower-case.
VENDOR_CERT_ORGS = ("fortinet", "cisco", "ubiquiti", "mikrotik", "synology", "qnap", "hp",
                    "hewlett", "dell", "schneider", "siemens", "honeywell", "axis", "hikvision",
                    "dahua", "sonicwall", "palo alto", "juniper", "netgear", "tp-link", "zyxel",
                    "draytek", "peplink", "cradlepoint", "digi", "lantronix", "apc", "eaton",
                    "vmware", "microsoft", "apple", "google", "amazon", "cloudflare", "akamai",
                    "fastly", "plesk", "cpanel", "sophos", "watchguard", "barracuda", "citrix",
                    "f5", "aruba", "ruckus", "cambium", "grandstream", "polycom", "yealink",
                    "avaya", "lenovo", "supermicro", "asus", "d-link", "linksys", "brother",
                    "canon", "xerox", "ricoh", "konica", "lexmark", "epson", "kyocera",
                    "default", "example", "test", "internal", "localhost")


def cert_is_trustworthy(r):
    """A certificate attributes an owner only if it was issued by someone other
    than the subject (not self-signed / not a factory default) and its subject
    organisation is not a device vendor or shared platform. Self-signed and
    vendor certs are still STORED (cert_* columns) — they just do not classify."""
    ssl = r.get("ssl") or {}
    cert = ssl.get("cert") or {}
    if not cert:
        return False
    tags = {t.lower() for t in (r.get("tags") or [])}
    if "self-signed" in tags:
        return False
    subj = cert.get("subject") or {}
    iss = cert.get("issuer") or {}
    if subj and iss and subj == iss:
        return False
    if subj.get("CN") and iss.get("CN") and subj.get("CN") == iss.get("CN"):
        return False
    o = (subj.get("O") or "").lower().strip()
    if o and any(o == v or o.startswith(v + " ") or o.startswith(v + ",") for v in VENDOR_CERT_ORGS):
        return False
    return True


def identity_names(r):
    """DNS names a TRUSTWORTHY certificate (see cert_is_trustworthy) reveals
    about the owner: CN and SANs, wildcards stripped. Fed to classify() as
    hostnames so a hospital cert on Cox space attributes the hospital. The HTTP
    Host header is deliberately NOT used: it is the name Shodan chose for its
    request, not evidence of ownership (it is still stored as http_host)."""
    if not cert_is_trustworthy(r):
        return set()
    names = set()
    cf = cert_fields(r)
    for n in ([cf["cert_cn"]] if cf["cert_cn"] else []) + cf["cert_sans"].split(","):
        n = (n or "").lower().strip().rstrip(".")
        if n.startswith("*."):
            n = n[2:]
        if n and "." in n and " " not in n and not _IPISH.match(n):
            names.add(n)
    return names


def build_day(path, kev, epss, obs_fh, vuln_fh, geokeep, exploits=None, attributor=None):
    """Two streaming passes over a daily .gz, writing flattened rows to the open
    temp files obs_fh / vuln_fh. Never holds the full day in memory. Only records
    passing `geokeep(banner)` enter the store — this is the geo gate that keeps
    non-target-state pollution out of DuckDB even from already-polluted archives.
    Returns (date, n_obs, n_vuln, n_dropped)."""
    date = date_from_name(path)

    # Pass 1: per-IP aggregate (small) to classify sector tier — geo-filtered.
    hosts = {}
    for r in iter_banners(path):
        if not geokeep(r):
            continue
        h = hosts.setdefault(r["ip_str"], {"org": None, "ports": set(),
                                           "hostnames": set(), "domains": set(),
                                           "tags": set(), "cert_orgs": set()})
        h["org"] = h["org"] or r.get("org")
        h["ports"].add(r.get("port"))
        h["hostnames"].update(r.get("hostnames") or [])
        h["hostnames"].update(identity_names(r))    # cert CN/SANs + HTTP Host
        h["domains"].update(r.get("domains") or [])
        h["tags"].update(r.get("tags") or [])       # honeypot tag feeds classify()
        co = cert_fields(r)["cert_org"]
        if co and cert_is_trustworthy(r):
            h["cert_orgs"].add(co)                  # CA-issued, non-vendor cert O = owner
    tier_of = {}
    reason_of = {}
    attr_of = {}
    for ip, h in hosts.items():
        h["hostnames"] = sorted(h["hostnames"])
        h["domains"] = sorted(h["domains"])
        tier_of[ip], reason_of[ip] = tr.classify(h)     # reason kept as an audit trail
        a = attributor.lookup(ip) if attributor else None
        if a:
            attr_of[ip] = a
            rt = registry_tier(a)
            # The registry OWNS this address space: its sector wins over keywords,
            # but honeypot evidence still wins over everything.
            if rt and tier_of[ip] != "honeypot":
                kw_tier = tier_of[ip]
                tier_of[ip] = rt
                reason_of[ip] = (f"registry: {a.get('org_name')} ({a.get('method')}, high)"
                                 + (f" [keyword said {kw_tier}]" if kw_tier != rt else ""))

    # Pass 2: stream banners → write obs + vuln rows straight to temp files.
    # We keep ONLY the exposure-relevant fields (never the giant http body), so
    # the store stays tiny regardless of how large the raw banners are.
    n_obs = n_vuln = n_dropped = 0
    for r in iter_banners(path):
        if not geokeep(r):
            n_dropped += 1
            continue
        ip = r["ip_str"]
        port = r.get("port")
        loc = r.get("location") or {}
        oid = observation_id(r)
        http = r.get("http") or {}
        obs_fh.write(json.dumps({
            "observation_id": oid,
            "date": date, "ip": ip, "port": port,
            "transport": r.get("transport"), "asn": r.get("asn"),
            "org": r.get("org"), "isp": r.get("isp"),
            "product": r.get("product"), "version": r.get("version"),
            # cpe23 (structured product id) recovers identity for hosts with no
            # free-text product; fall back to legacy cpe when cpe23 is absent.
            "cpe23": ",".join(r.get("cpe23") or r.get("cpe") or []),
            # service = the Shodan scan module that answered (snmp, rtsp, sip, ssh,
            # ike/l2tp/openvpn VPNs, siemens_s7 ICS, …). Present on ~100% of hosts,
            # so it recovers a SERVICE CLASS for the ~half with no product/cpe.
            # `info` is a sparse free-text service hint when Shodan supplies one.
            "service": (r.get("_shodan") or {}).get("module"),
            "info": r.get("info"),
            "city": loc.get("city"), "region_code": loc.get("region_code"),
            "hostnames": ",".join(r.get("hostnames") or []),
            "domains": ",".join(r.get("domains") or []),
            # Shodan's curated tags (ics, eol-product, self-signed, vpn, honeypot…).
            "tags": ",".join(r.get("tags") or []),
            # The banner's OWN scan time, distinct from the collection `date` — lets
            # us tell a fresh observation from a re-served cached banner.
            "banner_ts": r.get("timestamp"),
            "hash": str(r.get("hash")), "tier": tier_of.get(ip),
            "tier_reason": reason_of.get(ip),
            # Owner registry attribution (Phase 2), any confidence, for the record.
            "attr_org_id": (attr_of.get(ip) or {}).get("org_id"),
            "attr_org_name": (attr_of.get(ip) or {}).get("org_name"),
            "attr_method": (attr_of.get(ip) or {}).get("method"),
            "attr_confidence": (attr_of.get(ip) or {}).get("confidence"),
            "attr_conflict": (attr_of.get(ip) or {}).get("conflict") or None,
            # HTTP identity + TLS certificate (owner evidence; see cert_fields)
            "http_title": http.get("title"), "http_host": http.get("host"),
            "http_server": http.get("server"),
            **cert_fields(r),
        }) + "\n")
        n_obs += 1
        for cve, meta in (r.get("vulns") or {}).items():
            cvss = meta.get("cvss") if isinstance(meta, dict) else None
            try:
                cvss = float(cvss) if cvss is not None else None
            except (TypeError, ValueError):
                cvss = None
            vuln_fh.write(json.dumps({
                "observation_id": oid,
                "date": date, "ip": ip, "port": port, "transport": r.get("transport"),
                "cve": cve, "cvss": cvss, "in_kev": cve in kev, "epss": epss.get(cve),
                # Shodan's own flag: it actually confirmed the CVE on this host
                # (rare — ~0.01% of rows — but it outranks every version inference).
                "verified": bool(meta.get("verified")) if isinstance(meta, dict) else False,
                # A public exploit / template exists (Metasploit, Nuclei): tiebreaker.
                "has_exploit": cve in (exploits or {}),
            }) + "\n")
            n_vuln += 1
    return date, n_obs, n_vuln, n_dropped


def copy_to_partition(con, tmp_path, n_rows, out_dir, date, select_sql):
    """COPY an already-written temp NDJSON into that date's parquet partition."""
    part_dir = os.path.join(out_dir, f"date={date}")
    os.makedirs(part_dir, exist_ok=True)
    out_parquet = os.path.join(part_dir, "data.parquet")
    if n_rows == 0:
        # No rows for this table today — drop any stale partition so the glob
        # doesn't try to read an empty file.
        if os.path.exists(out_parquet):
            os.remove(out_parquet)
        return None
    con.execute(f"COPY ({select_sql.format(src=repr(tmp_path))}) "
                f"TO '{out_parquet}' (FORMAT PARQUET)")
    return out_parquet


# Explicit schemas: every column is declared, so an NDJSON row that lacks a key
# (older temp files, tests, future optional fields) reads as NULL instead of
# failing the COPY. Keep these in step with build_day()'s dict keys.
OBS_COLUMNS = {
    "observation_id": "VARCHAR", "date": "VARCHAR", "ip": "VARCHAR", "port": "INTEGER",
    "transport": "VARCHAR", "asn": "VARCHAR", "org": "VARCHAR", "isp": "VARCHAR",
    "product": "VARCHAR", "version": "VARCHAR", "cpe23": "VARCHAR", "service": "VARCHAR",
    "info": "VARCHAR", "city": "VARCHAR", "region_code": "VARCHAR", "hostnames": "VARCHAR",
    "domains": "VARCHAR", "tags": "VARCHAR", "banner_ts": "VARCHAR", "hash": "VARCHAR",
    "tier": "VARCHAR", "tier_reason": "VARCHAR",
    "attr_org_id": "VARCHAR", "attr_org_name": "VARCHAR", "attr_method": "VARCHAR",
    "attr_confidence": "VARCHAR", "attr_conflict": "VARCHAR",
    "http_title": "VARCHAR", "http_host": "VARCHAR", "http_server": "VARCHAR",
    "cert_cn": "VARCHAR", "cert_org": "VARCHAR", "cert_issuer": "VARCHAR", "cert_sans": "VARCHAR",
    "cert_expired": "BOOLEAN", "cert_expires": "VARCHAR", "cert_sha256": "VARCHAR", "jarm": "VARCHAR",
}
VULN_COLUMNS = {
    "observation_id": "VARCHAR", "date": "VARCHAR", "ip": "VARCHAR", "port": "INTEGER",
    "transport": "VARCHAR", "cve": "VARCHAR", "cvss": "DOUBLE", "in_kev": "BOOLEAN",
    "epss": "DOUBLE", "verified": "BOOLEAN", "has_exploit": "BOOLEAN",
}


def _cols(spec):
    # Doubled braces: the SELECT strings go through str.format(src=...) later.
    return "{{" + ", ".join(f"'{k}': '{v}'" for k, v in spec.items()) + "}}"


OBS_SELECT = f"""
SELECT * REPLACE (CAST(date AS DATE) AS date, CAST(banner_ts AS TIMESTAMP) AS banner_ts)
FROM read_json({{src}}, format='newline_delimited', maximum_object_size=100000000,
               columns={_cols(OBS_COLUMNS)})
"""
VULN_SELECT = f"""
SELECT * REPLACE (CAST(date AS DATE) AS date)
FROM read_json({{src}}, format='newline_delimited', columns={_cols(VULN_COLUMNS)})
"""

# Internet-facing edge appliances: exploited-in-the-wild population regardless of
# what CVE mapping Shodan attaches. Regex applied to product / cpe23 / http_title
# (lower-cased, whole-word where a word is meant). A match is a LEAD to verify.
APPLIANCE_PATTERNS = [
    ("Fortinet FortiGate/FortiOS", r"forti(gate|os|web|mail|manager|analyzer)"),
    ("Ivanti/Pulse Connect Secure", r"\b(ivanti|pulse secure|pulse connect|connect secure)\b"),
    ("Citrix NetScaler/Gateway", r"\b(netscaler|citrix (gateway|adc))\b"),
    ("Cisco ASA/FTD/AnyConnect", r"\b(cisco asa|adaptive security appliance|anyconnect|firepower)\b"),
    ("Cisco IOS XE web UI", r"\bios[ -]xe\b"),
    ("Palo Alto GlobalProtect/PAN-OS", r"\b(globalprotect|pan-os|palo alto)\b"),
    ("SonicWall", r"\bsonicwall\b"),
    ("F5 BIG-IP", r"\bbig-?ip\b"),
    ("ManageEngine", r"\bmanageengine\b"),
    ("Microsoft Exchange/OWA", r"\b(outlook web app|exchange server|owa)\b"),
    ("Zyxel", r"\bzyxel\b"),
    ("Juniper Junos/SRX", r"\b(junos|juniper)\b"),
    ("WatchGuard", r"\bwatchguard\b"),
    ("Barracuda", r"\bbarracuda\b"),
    ("Check Point", r"\bcheck ?point\b"),
    ("VMware Horizon/vCenter/ESXi", r"\b(vcenter|esxi|horizon)\b"),
    ("Progress MOVEit/WS_FTP", r"\b(moveit|ws_ftp)\b"),
    ("Atlassian Confluence/Jira", r"\b(confluence|jira)\b"),
    ("GitLab", r"\bgitlab\b"),
    ("Veeam Backup", r"\bveeam\b"),
    ("ConnectWise ScreenConnect", r"\b(screenconnect|connectwise)\b"),
]

# How long an observation counts as "current". The daily query is a DELTA
# (hosts re-scanned in the window), so a host not seen for a while is UNKNOWN,
# not remediated — but it is also not "exposed right now". Measured: banner_ts
# minus collection date is 0-1 days at p99, so `date` is a reliable last-seen.
ACTIVE_DAYS = 14      # current_state: seen within this many days of the newest day
STALE_DAYS = 45       # exposure_status: 'stale' up to here, 'gone' after


def refresh_views(con):
    """(Re)define views over all parquet partitions + derived analytics."""
    obs_glob = os.path.join(OBS_DIR, "date=*", "*.parquet")
    vuln_glob = os.path.join(VULN_DIR, "date=*", "*.parquet")

    def empty_view(name, spec):
        # A store with no partitions of this kind (fresh store, or no CVEs at
        # all) still gets a correctly typed, empty view so every join works.
        cols = ", ".join(f"CAST(NULL AS {t}) AS {c}" for c, t in spec.items())
        con.execute(f"CREATE OR REPLACE VIEW {name} AS SELECT {cols} WHERE false")

    if glob.glob(obs_glob):
        con.execute(f"CREATE OR REPLACE VIEW observations AS "
                    f"SELECT * FROM read_parquet('{obs_glob}', union_by_name=true)")
    else:
        empty_view("observations", {**OBS_COLUMNS, "date": "DATE", "banner_ts": "TIMESTAMP"})
    if glob.glob(vuln_glob):
        con.execute(f"CREATE OR REPLACE VIEW vulns AS "
                    f"SELECT * FROM read_parquet('{vuln_glob}', union_by_name=true)")
    else:
        empty_view("vulns", {**VULN_COLUMNS, "date": "DATE"})
    # Mixed-schema guard: partitions written before Phase 1 have no
    # observation_id and cannot join to vulns. Say so loudly.
    legacy = con.execute("SELECT count(*) FROM observations WHERE observation_id IS NULL").fetchone()[0]
    if legacy:
        print(f"WARNING: {legacy:,} observation rows predate the observation_id schema — "
              f"their CVEs will not join. Run ./rebuild_store.sh to migrate the whole store.",
              file=sys.stderr)
    # Latest banner per ip:port:transport, ALL-TIME, with a deterministic order:
    # collection date first (the authoritative "last seen" — a banner_ts can be
    # missing or an ancient cached scan), then banner scan time, then record id.
    con.execute("""
        CREATE OR REPLACE VIEW latest_observed AS
        SELECT * EXCLUDE (rn) FROM (
          SELECT *, row_number() OVER (
                   PARTITION BY ip, port, transport
                   ORDER BY date DESC, banner_ts DESC NULLS LAST, observation_id DESC) AS rn
          FROM observations
        ) WHERE rn = 1
    """)
    # Freshness. current_state = "exposed right now" = latest observation seen
    # within ACTIVE_DAYS of the newest day in the store. exposure_status keeps
    # every latest observation and labels it active / stale / gone. The clock
    # is the newest day IN THE STORE: if ingestion stops, nothing ages — that
    # is what the nightly dead-man ping is for, and days_since_seen is exposed
    # so a report can also state how old the newest day itself is.
    con.execute(f"""
        CREATE OR REPLACE VIEW exposure_status AS
        SELECT *,
               date_diff('day', date, (SELECT max(date) FROM observations)) AS days_since_seen,
               CASE WHEN date_diff('day', date, (SELECT max(date) FROM observations)) <= {ACTIVE_DAYS} THEN 'active'
                    WHEN date_diff('day', date, (SELECT max(date) FROM observations)) <= {STALE_DAYS} THEN 'stale'
                    ELSE 'gone' END AS status
        FROM latest_observed
    """)
    con.execute("""
        CREATE OR REPLACE VIEW current_state AS
        SELECT * EXCLUDE (days_since_seen, status) FROM exposure_status WHERE status = 'active'
    """)
    # Edge appliances currently exposed (Phase 2 appliance-first triage).
    cases = " ".join(
        f"WHEN regexp_matches(lower(coalesce(product,'') || ' ' || coalesce(cpe23,'') || ' ' || coalesce(http_title,'')), '{rx}') THEN '{name}'"
        for name, rx in APPLIANCE_PATTERNS)
    con.execute(f"""
        CREATE OR REPLACE VIEW appliance_exposure AS
        SELECT * FROM (
          SELECT *, CASE {cases} ELSE NULL END AS appliance FROM current_state
        ) WHERE appliance IS NOT NULL
    """)
    # Free IOC feeds matched locally (reference/ioc_ips.json, refreshed weekly).
    ioc = tr.load_json(os.path.join(SCRIPT_DIR, "reference", "ioc_ips.json"), {})
    rows = [(ip, ",".join(srcs)) for ip, srcs in ioc.items() if not ip.startswith("_")]
    con.execute("CREATE OR REPLACE TABLE ioc_ips (ip VARCHAR, sources VARCHAR)")
    if rows:
        con.executemany("INSERT INTO ioc_ips VALUES (?, ?)", rows)
    # CIDR lists (Spamhaus DROP) matched by IPv4 range.
    import ipaddress
    crows = []
    for cidr, srcs in (ioc.get("_cidrs") or {}).items():
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            crows.append((cidr, int(net.network_address), int(net.broadcast_address), ",".join(srcs)))
    con.execute("CREATE OR REPLACE TABLE ioc_cidrs (cidr VARCHAR, lo UBIGINT, hi UBIGINT, sources VARCHAR)")
    if crows:
        con.executemany("INSERT INTO ioc_cidrs VALUES (?, ?, ?, ?)", crows)
    con.execute("""
        CREATE OR REPLACE VIEW ioc_matches AS
        WITH cs AS (
          SELECT *, CASE WHEN ip NOT LIKE '%:%' AND regexp_matches(ip, '^[0-9.]+$') THEN
              CAST(split_part(ip,'.',1) AS UBIGINT)*16777216 + CAST(split_part(ip,'.',2) AS UBIGINT)*65536
            + CAST(split_part(ip,'.',3) AS UBIGINT)*256 + CAST(split_part(ip,'.',4) AS UBIGINT) END AS ip_int
          FROM current_state)
        SELECT cs.* EXCLUDE (ip_int), i.sources AS ioc_sources, NULL AS ioc_cidr FROM cs JOIN ioc_ips i ON i.ip = cs.ip
        UNION ALL
        SELECT cs.* EXCLUDE (ip_int), c.sources, c.cidr FROM cs JOIN ioc_cidrs c ON cs.ip_int BETWEEN c.lo AND c.hi
    """)
    # Exposure lifecycle: first/last seen + dwell for each ip:port:transport.
    con.execute("""
        CREATE OR REPLACE VIEW lifecycle AS
        SELECT ip, port, transport,
               min(date) AS first_seen, max(date) AS last_seen,
               count(DISTINCT date) AS days_observed,
               date_diff('day', min(date), max(date)) + 1 AS span_days
        FROM observations GROUP BY ip, port, transport
    """)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?", help="a specific .gz to load")
    ap.add_argument("--date", help="load daily_downloads/<state>-events-<date>.json.gz")
    ap.add_argument("--all", action="store_true", help="load every daily file")
    ap.add_argument("--rebuild", action="store_true", help="wipe the store first")
    args = ap.parse_args()

    if args.rebuild:
        import shutil
        for d in (OBS_DIR, VULN_DIR):
            shutil.rmtree(d, ignore_errors=True)
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)

    files = []
    if args.file:
        files = [args.file]
    elif args.all:
        files = sorted(glob.glob(os.path.join(DAILY_DIR, "*-events-*.json.gz")))
    elif args.date:
        files = glob.glob(os.path.join(DAILY_DIR, f"*-events-{args.date}.json.gz"))
    else:
        ap.error("give a file, --date, or --all")
    files = [f for f in files if ".backup" not in f]
    if not files:
        print("No matching files.")
        return 1

    os.makedirs(STORE, exist_ok=True)
    kev, epss = load_enrichment()
    exploits = load_exploits()
    attributor = load_attributor()

    # Geo gate: only records that geolocate to the target state (or match a
    # state-named org, for org-rescue) enter the store. Independent MaxMind lookup
    # if available, else the banner's own region_code. This keeps DuckDB clean
    # even when reprocessing an already-polluted archive (e.g. the 07-01 file).
    state_code = os.environ.get("SHODAN_STATE_CODE", "LA")
    state_name = (os.environ.get("SHODAN_STATE_NAME", "louisiana")).lower()
    gate = None
    try:
        import geo
        gate = geo.GeoGate(country="US", region=state_code)
        print(f"Geo gate: MaxMind {os.path.basename(gate.db_path)}")
    except Exception as exc:
        print(f"Geo gate: MaxMind unavailable ({exc}); using banner region_code")

    def geokeep(r):
        loc = r.get("location") or {}
        if gate is not None:
            if gate.keep(r.get("ip_str"), loc.get("country_code"), loc.get("region_code")):
                return True
        elif loc.get("country_code") == "US" and loc.get("region_code") == state_code:
            return True
        return state_name in (r.get("org") or "").lower()   # org-rescue records

    con = duckdb.connect(DB_PATH)
    for path in files:
        of = tempfile.NamedTemporaryFile("w", suffix=".obs.ndjson", delete=False)
        vf = tempfile.NamedTemporaryFile("w", suffix=".vuln.ndjson", delete=False)
        try:
            date, n_obs, n_vuln, n_drop = build_day(path, kev, epss, of, vf, geokeep, exploits, attributor)
            of.close(); vf.close()
            copy_to_partition(con, of.name, n_obs, OBS_DIR, date, OBS_SELECT)
            copy_to_partition(con, vf.name, n_vuln, VULN_DIR, date, VULN_SELECT)
            print(f"{date}: {n_obs:,} observations, {n_vuln:,} vuln rows"
                  f"{f' ({n_drop:,} off-target dropped)' if n_drop else ''}")
        finally:
            of.close(); vf.close()
            os.unlink(of.name); os.unlink(vf.name)
    refresh_views(con)
    n_obs = con.execute("SELECT count(*) FROM observations").fetchone()[0]
    n_days = con.execute("SELECT count(DISTINCT date) FROM observations").fetchone()[0]
    con.close()
    print(f"Store ready: {n_obs:,} observations across {n_days} day(s) -> {DB_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
