#!/usr/bin/env python3
"""
leads.py — the persisted LEADS table: what we would actually notify someone about.

The store (build_store.py) answers "what is exposed right now?" for ~30k services.
Almost none of that is a notification. A LEAD is a service (ip:port:transport) that
carries one specific, evidence-graded reason to contact its owner:

  evidence_type    confidence  rule (see generate_candidates)
  kev_verified     high        a CISA-KEV CVE that Shodan itself VERIFIED on the host (one lead per CVE)
  compromise_tag   high        the host is in compromise_hits/seen_ledger.json (Shodan's
                               compromised/malware/c2/botnet flags) seen in the last 30 days
  shadowserver     high|medium a Shadowserver report event for the ip in the last 14 days —
                               COMPROMISE-class reports (sinkhole/drone/spam/compromised_website/
                               malware_url …) are high, host-level; EXPOSURE-class reports
                               (scan_*/vulnerable_*/exposed_*/open_*/ics …) are medium, per port
  ics              medium      an ICS protocol module or ICS port answering (non-honeypot)
  appliance        medium      an internet-edge appliance per build_store.APPLIANCE_PATTERNS (the
                               same definitions as the appliance_exposure view) — priority tiers only
  kev_inferred     medium      a KEV CVE inferred from the banner version, NOT verified — priority
                               tiers only (one lead per CVE)
  ioc_match        medium      the ip is on a threat-intel list in reference/ioc_ips.json
  cred_leak        (reserved for a later feed; accepted by `set`, never generated here)

Eligibility is decided ONCE per ip per refresh from the host's CURRENT tier (its
newest observation in latest_observed; for hosts not in the store, the registry's
sector). `residential` and `honeypot` hosts are never leads — an existing lead
whose host has become residential/honeypot is auto-suppressed (analyst history kept)
and reinstated if the host becomes eligible again.

Identity: lead_id = sha1(ip|port|transport|evidence_type[|cve])[:16] — the CVE is
part of the identity for the two KEV types, so suppressing one inferred CVE never
suppresses a different one. Host-level evidence (a threat-intel listing, a
compromise report that names no exposed port) uses port 0 / transport 'host'.

Attribution is carried separately from evidence: org_id/org_name/sector plus
attr_method/attr_confidence (registry ip_attribution.parquet, else the store's
attr_* columns, else the Shodan org field as method 'shodan_org'/low, else
'unattributed'/none).

Lifecycle (status):
  new -> queued -> notified -> acknowledged -> remediated -> (newer evidence) -> new
                 '-> disputed | false_positive | suppressed     (analyst decisions)
`refresh` moves: new->new (update); notified/acknowledged -> remediated ONLY when the
specific service's exposure_status is 'gone' (host-level: every service of the host
gone); remediated -> new ONLY when a NEWER observation (date > last_seen) shows the
evidence again — this starts a new notification episode (notified_on cleared, the old
one kept in notes and lead_events); eligible -> auto-suppressed when the host turns
residential/honeypot. Every other status is analyst-set and never overwritten.
last_seen = newest observation date supporting the lead; last_evaluated = the refresh
date that last looked at it.

Storage (survives a store rebuild): the AUTHORITATIVE state is store/leads/leads.duckdb
(tables leads — lead_id PRIMARY KEY — and lead_events), which rebuild_store.sh never
touches. After every committed change it is mirrored to store/leads/leads.parquet and
lead_events.parquet (temp file + atomic rename), and the `leads` table inside
store/exposure.duckdb is re-published as a COPY for SQL convenience — that copy is
disposable. `set` writes the mirror BEFORE committing; a mirror failure rolls back.

PASSIVE. Every lead is a lead to verify; nothing here touches a host.

Usage:
    leads.py refresh [--dry-run] [--today YYYY-MM-DD]
    leads.py list [--tier T] [--status S] [--sector X] [--evidence E] [--org NAME] [--ip IP] [--limit N]
    leads.py set <lead_id> --status notified [--via MS-ISAC] [--analyst jd] [--note "..."]
    leads.py digest [--weekly] [--out reports/leads_digest.md]
"""
import argparse
import glob
import gzip
import hashlib
import json
import os
import re
import statistics
import sys
from datetime import date, datetime, timedelta

import duckdb

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import triage_report as tr    # ICS_PORTS
import build_store as bs      # APPLIANCE_PATTERNS (shared with the appliance_exposure view), SECTOR_TIER

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "store", "exposure.duckdb")
LEADS_DIR = os.path.join(SCRIPT_DIR, "store", "leads")
LEADS_DB = os.path.join(LEADS_DIR, "leads.duckdb")
LEADS_PARQUET = os.path.join(LEADS_DIR, "leads.parquet")
EVENTS_PARQUET = os.path.join(LEADS_DIR, "lead_events.parquet")
LEDGER_PATH = os.path.join(SCRIPT_DIR, "compromise_hits", "seen_ledger.json")
HITS_DIR = os.path.join(SCRIPT_DIR, "compromise_hits")
IOC_PATH = os.path.join(SCRIPT_DIR, "reference", "ioc_ips.json")
ATTRIBUTION_PARQUET = os.path.join(SCRIPT_DIR, "store", "registry", "ip_attribution.parquet")
SS_EVENTS_PARQUET = os.path.join(SCRIPT_DIR, "store", "shadowserver", "events.parquet")

LEAD_COLUMNS = ["lead_id", "ip", "port", "transport", "org_id", "org_name", "tier", "sector",
                "evidence_type", "evidence_key", "evidence", "confidence", "severity",
                "attr_method", "attr_confidence",
                "first_seen", "last_seen", "last_evaluated", "status",
                "notified_via", "notified_on", "analyst", "notes", "updated_at"]
LEAD_TYPES = {"port": "INTEGER", "first_seen": "DATE", "last_seen": "DATE", "last_evaluated": "DATE",
              "notified_on": "DATE", "updated_at": "TIMESTAMP"}
LEADS_DDL = "CREATE TABLE IF NOT EXISTS leads (" + ", ".join(
    f"{c} {LEAD_TYPES.get(c, 'VARCHAR')}" + (" PRIMARY KEY" if c == "lead_id" else "")
    for c in LEAD_COLUMNS) + ")"
EVENTS_DDL = ("CREATE TABLE IF NOT EXISTS lead_events (ts TIMESTAMP, lead_id VARCHAR, "
              "event VARCHAR, detail VARCHAR)")

STATUSES = ["new", "queued", "notified", "acknowledged", "remediated", "disputed",
            "false_positive", "suppressed"]
ANALYST_STATUSES = {"queued", "notified", "acknowledged", "disputed", "false_positive", "suppressed"}
EVIDENCE_TYPES = ["kev_verified", "kev_inferred", "appliance", "ics", "compromise_tag",
                  "shadowserver", "ioc_match", "cred_leak"]
CVE_TYPES = {"kev_verified", "kev_inferred"}
EVIDENCE_RANK = {"kev_verified": 0, "compromise_tag": 1, "shadowserver": 2, "ics": 3,
                 "appliance": 4, "kev_inferred": 5, "ioc_match": 6, "cred_leak": 7}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
TIER_RANK = {"critical_infrastructure": 0, "government": 1, "education": 2,
             "small_business": 3, "unclassified": 4, "out_of_state_gov": 5}
PRIORITY_TIERS = {"government", "education", "critical_infrastructure"}
NEVER_LEAD_TIERS = {"residential", "honeypot"}
TIER_TO_SECTOR = {"critical_infrastructure": "critical_infrastructure", "government": "government",
                  "education": "education", "small_business": "small_business",
                  "out_of_state_gov": "out_of_state", "residential": "other",
                  "unclassified": "other", "honeypot": "other"}
SECTOR_TIER = getattr(bs, "SECTOR_TIER", {"critical_infrastructure": "critical_infrastructure",
                                          "healthcare": "critical_infrastructure",
                                          "energy": "critical_infrastructure", "water": "critical_infrastructure",
                                          "government": "government", "education": "education",
                                          "small_business": "small_business", "out_of_state": "out_of_state_gov"})
UNATTRIBUTED = "unattributed"
AUTO_SUPPRESS_TAG = "auto-suppressed: host now"

COMPROMISE_WINDOW_DAYS = 30
SHADOWSERVER_WINDOW_DAYS = 14
HOST_PORT, HOST_TRANSPORT = 0, "host"

ICS_MODULES = {"modbus", "s7", "siemens_s7", "dnp3", "bacnet", "ethernetip", "fox", "iec-104",
               "iec104", "codesys", "omron", "pcworx", "proconos", "ge-srtp", "hart-ip", "melsec",
               "redlion-crimson3", "crestron", "unitronics-pcom", "automated-tank-gauge",
               "vertx-edge", "lantronix-udp", "moxa-nport", "niagara-fox", "bacnet-ip", "iec-61850",
               "mms", "opc-ua", "opcua", "profinet", "cspv4", "fins", "koyo", "kamstrup"}

# The SAME definitions the appliance_exposure view uses (build_store.APPLIANCE_PATTERNS:
# (label, regex) over lower(product || ' ' || cpe23 || ' ' || http_title)).
APPLIANCE_PATTERNS = bs.APPLIANCE_PATTERNS
_APPLIANCE_RX = [(label, re.compile(rx)) for label, rx in APPLIANCE_PATTERNS]


def log(msg):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} - {msg}", flush=True)


def lead_id(ip, port, transport, evidence_type, key=""):
    """sha1(ip|port|transport|evidence_type[|cve])[:16]. The key is part of the
    identity only for CVE-based types."""
    base = f"{ip}|{port}|{transport}|{evidence_type}"
    if evidence_type in CVE_TYPES and key:
        base += f"|{key}"
    return hashlib.sha1(base.encode()).hexdigest()[:16]


def _parse_date(s):
    if isinstance(s, datetime):
        return s.date()
    if isinstance(s, date):
        return s
    try:
        return datetime.strptime(str(s)[:10], "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


# --- connections -------------------------------------------------------------

class Ctx:
    """A connection to the authoritative leads DB with the exposure store
    ATTACHed as `store` (read-only unless the copy is to be published)."""

    def __init__(self, con, store_path, store_writable):
        self.con = con
        self.store_path = store_path
        self.store_writable = store_writable

    def close(self):
        try:
            self.con.close()
        except duckdb.Error:
            pass


def open_ctx(store_path=DB_PATH, leads_db=LEADS_DB, write=False):
    if not os.path.exists(store_path):
        raise SystemExit(f"ERROR: store {store_path} does not exist — run build_store.py first")
    if write or not os.path.exists(leads_db):
        os.makedirs(os.path.dirname(leads_db), exist_ok=True)
    try:
        con = duckdb.connect(leads_db, read_only=(not write and os.path.exists(leads_db)))
    except duckdb.Error as exc:
        raise SystemExit(f"ERROR: cannot open {leads_db} ({exc}); another leads.py may be running")
    writable = False
    if write:
        try:
            con.execute(f"ATTACH '{store_path}' AS store")
            writable = True
        except duckdb.Error:
            writable = False
    if not writable:
        try:
            con.execute(f"ATTACH '{store_path}' AS store (READ_ONLY)")
        except duckdb.Error as exc:
            con.close()
            raise SystemExit(f"ERROR: cannot open the store {store_path} ({exc}). If a store rebuild "
                             f"is running, wait for it and re-run.")
    return Ctx(con, store_path, writable)


def table_exists(con, name, catalog=None):
    sql = "SELECT count(*) FROM information_schema.tables WHERE table_name = ?"
    params = [name]
    if catalog:
        sql += " AND table_catalog = ?"
        params.append(catalog)
    return con.execute(sql, params).fetchone()[0] > 0


def columns_of(con, name, catalog=None):
    sql = "SELECT column_name FROM information_schema.columns WHERE table_name = ?"
    params = [name]
    if catalog:
        sql += " AND table_catalog = ?"
        params.append(catalog)
    return [r[0] for r in con.execute(sql + " ORDER BY ordinal_position", params).fetchall()]


def fetch_dicts(con, sql, params=None):
    cur = con.execute(sql, params or [])
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


def ensure_leads_db(ctx, parquet=LEADS_PARQUET, events_parquet=EVENTS_PARQUET):
    """Create the authoritative tables; if `leads` is empty and a parquet mirror
    exists (the leads.duckdb file itself was lost), restore from the mirror.
    Returns 'existing' | 'restored' | 'created'."""
    con = ctx.con
    cat = con.execute("SELECT current_database()").fetchone()[0]
    existed = table_exists(con, "leads", cat)
    if not existed:
        con.execute(LEADS_DDL)
    if not table_exists(con, "lead_events", cat):
        con.execute(EVENTS_DDL)
    n = con.execute("SELECT count(*) FROM leads").fetchone()[0]
    if n == 0 and parquet and os.path.exists(parquet):
        cols_in = [r[0] for r in con.execute(f"DESCRIBE SELECT * FROM read_parquet('{parquet}')").fetchall()]
        sel = ", ".join(c if c in cols_in else f"NULL AS {c}" for c in LEAD_COLUMNS)
        con.execute(f"INSERT INTO leads SELECT {sel} FROM read_parquet('{parquet}')")
        if events_parquet and os.path.exists(events_parquet):
            con.execute(f"INSERT INTO lead_events SELECT * FROM read_parquet('{events_parquet}')")
        return "restored"
    return "existing" if existed else "created"


def _copy_atomic(con, sql, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    con.execute(f"COPY ({sql}) TO '{tmp}' (FORMAT PARQUET)")
    os.replace(tmp, path)


def mirror_leads(ctx, parquet=LEADS_PARQUET, events_parquet=EVENTS_PARQUET):
    """Parquet mirror of both tables (temp + atomic rename). Sees the current
    transaction's uncommitted rows, so `set` can mirror before it commits."""
    if parquet:
        _copy_atomic(ctx.con, "SELECT * FROM leads ORDER BY lead_id", parquet)
    if events_parquet:
        _copy_atomic(ctx.con, "SELECT * FROM lead_events ORDER BY ts, lead_id", events_parquet)


def publish_copy(ctx):
    """Re-create the disposable `leads` table inside the exposure store from the
    authoritative table. Best effort: a locked store just means the copy lags."""
    if not ctx.store_writable:
        log("store is read-only right now — the leads copy in exposure.duckdb was not refreshed")
        return False
    try:
        ctx.con.execute("CREATE OR REPLACE TABLE store.leads AS SELECT * FROM leads")
        return True
    except duckdb.Error as exc:
        log(f"could not publish the leads copy into the store ({exc}); authoritative state is intact")
        return False


def add_event(con, lid, event, detail, ts=None):
    con.execute("INSERT INTO lead_events VALUES (?, ?, ?, ?)", [ts or datetime.now(), lid, event, detail])


# --- store reads ---------------------------------------------------------------

def _select_adaptive(con, view, wanted, catalog="store", where=""):
    have = set(columns_of(con, view, catalog))
    cols = ", ".join(c if c in have else f"NULL AS {c}" for c in wanted)
    return fetch_dicts(con, f"SELECT {cols} FROM {catalog}.{view} {where}")


CS_COLS = ["date", "ip", "port", "transport", "org", "product", "version", "cpe23", "service", "info",
           "city", "hostnames", "tags", "banner_ts", "tier", "tier_reason", "observation_id",
           "http_title", "http_server", "cert_cn", "cert_org",
           "attr_org_id", "attr_org_name", "attr_method", "attr_confidence"]


def select_current_state(con):
    return _select_adaptive(con, "current_state", CS_COLS)


def host_tiers(con):
    """ip -> {tier, org, attr_*, newest} from the NEWEST observation of each host
    (any port, any freshness)."""
    have = set(columns_of(con, "latest_observed", "store"))
    extra = ", ".join(c if c in have else f"NULL AS {c}" for c in
                      ("attr_org_id", "attr_org_name", "attr_method", "attr_confidence"))
    rows = fetch_dicts(con, f"""
        SELECT ip, tier, org, date AS newest, {extra} FROM (
          SELECT *, row_number() OVER (PARTITION BY ip ORDER BY date DESC, banner_ts DESC NULLS LAST,
                                       observation_id DESC) AS rn
          FROM store.latest_observed) WHERE rn = 1""")
    return {r["ip"]: r for r in rows}


def kev_by_service(con):
    """(ip, port, transport, verified) -> [{cve, epss, cvss}] on CURRENT observations."""
    rows = fetch_dicts(con, """
        SELECT cs.ip, cs.port, cs.transport, v.verified, v.cve, v.epss, v.cvss
        FROM store.current_state cs
        JOIN store.vulns v ON v.observation_id = cs.observation_id AND v.date = cs.date
        WHERE v.in_kev""")
    out = {}
    for r in rows:
        out.setdefault((r["ip"], r["port"], r["transport"], bool(r["verified"])), []).append(r)
    return out


def load_attribution(con, parquet=ATTRIBUTION_PARQUET):
    if not parquet or not os.path.exists(parquet):
        return {}
    try:
        rows = fetch_dicts(con, f"SELECT * FROM read_parquet('{parquet}')")
    except duckdb.Error as exc:
        log(f"WARNING: registry attribution unreadable ({exc})")
        return {}
    return {r["ip"]: r for r in rows if r.get("ip")}


# --- evidence rules ------------------------------------------------------------

def appliance_match(row):
    """(label, regex) per build_store.APPLIANCE_PATTERNS over the same text the
    appliance_exposure view scans."""
    text = " ".join(str(row.get(k) or "") for k in ("product", "cpe23", "http_title")).lower()
    if not text.strip():
        return None
    for label, rx in _APPLIANCE_RX:
        if rx.search(text):
            return label, rx.pattern
    return None


def ics_match(row):
    svc = (row.get("service") or "").lower()
    tags = {t.strip().lower() for t in (row.get("tags") or "").split(",") if t.strip()}
    reasons = []
    if svc in ICS_MODULES:
        reasons.append(f"Shodan ICS module '{svc}'")
    if row.get("port") in tr.ICS_PORTS:
        reasons.append(f"ICS port {row['port']} ({tr.ICS_PORTS[row['port']]})")
    if "ics" in tags:
        reasons.append("Shodan tag 'ics'")
    return "; ".join(reasons) if reasons else None


def service_desc(row):
    bits = [str(row.get("product") or row.get("service") or "?")]
    if row.get("version"):
        bits.append(str(row["version"]))
    return " ".join(bits)


def load_ledger(path):
    try:
        with open(path) as fh:
            return json.load(fh).get("hosts", {})
    except (OSError, ValueError):
        return {}


def load_hit_ports(hits_dir, since):
    out = {}
    for path in sorted(glob.glob(os.path.join(hits_dir or "", "*-compromise-*.json.gz"))):
        d = _parse_date(os.path.basename(path).split("-compromise-")[-1][:10])
        if d is None or d < since:
            continue
        try:
            with gzip.open(path, "rt") as fh:
                for line in fh:
                    try:
                        b = json.loads(line)
                    except ValueError:
                        continue
                    ip, port = b.get("ip_str"), b.get("port")
                    if not ip or port is None:
                        continue
                    key = (int(port), b.get("transport") or "tcp")
                    e = out.setdefault(ip, {}).setdefault(key, {"tags": set(), "selectors": set(), "banner_ts": ""})
                    e["tags"].update(b.get("tags") or [])
                    if b.get("_compromise_selector"):
                        e["selectors"].add(b["_compromise_selector"])
                    e["banner_ts"] = max(e["banner_ts"], b.get("timestamp") or "")
        except OSError:
            continue
    return out


def load_ioc(path):
    try:
        with open(path) as fh:
            d = json.load(fh)
        return {ip: list(v) if isinstance(v, (list, tuple)) else [str(v)] for ip, v in d.items()}
    except (OSError, ValueError, AttributeError):
        return {}


def shadowserver_recent(con, today, parquet=SS_EVENTS_PARQUET):
    """ip -> recent shadowserver events, from the store table or — after a store
    rebuild wiped it — straight from the authoritative parquet."""
    since = today - timedelta(days=SHADOWSERVER_WINDOW_DAYS)
    if table_exists(con, "shadowserver_events", "store"):
        src = "store.shadowserver_events"
    elif parquet and os.path.exists(parquet):
        src = f"read_parquet('{parquet}')"
    else:
        return {}
    rows = fetch_dicts(con, f"SELECT report_type, timestamp, ip, port, protocol, tag, severity FROM {src} "
                            f"WHERE CAST(timestamp AS DATE) >= ?", [since])
    out = {}
    for r in rows:
        out.setdefault(r["ip"], []).append(r)
    return out


def _fmt_epss(e):
    return f"{e:.3f}" if isinstance(e, (int, float)) else "n/a"


def sector_to_tier(sector):
    for s in str(sector or "").split("|"):
        if s.strip() in SECTOR_TIER:
            return SECTOR_TIER[s.strip()]
    return "unclassified"


def generate_candidates(ctx, today, ledger_path=LEDGER_PATH, hits_dir=HITS_DIR, ioc_path=IOC_PATH,
                        attribution_parquet=ATTRIBUTION_PARQUET, ss_parquet=SS_EVENTS_PARQUET):
    """Apply every evidence rule to the current picture.
    Returns (candidates {lead_id: dict}, excluded {reason: n}, host_info {ip: {tier, known}})."""
    con = ctx.con
    registry = load_attribution(con, attribution_parquet)
    hosts = host_tiers(con)
    cs_rows = select_current_state(con)
    kev = kev_by_service(con)
    excluded = {"residential": 0, "honeypot": 0, "kev_inferred_non_priority": 0,
                "appliance_non_priority": 0, "ioc_unknown_ip": 0}
    cands = {}
    host_info = {}

    def host(ip):
        """Current tier + attribution for a host, decided once per refresh."""
        if ip in host_info:
            return host_info[ip]
        h = hosts.get(ip)
        reg = registry.get(ip)
        if h:
            tier = h["tier"] or "unclassified"
        elif reg and (reg.get("sector") or "").strip():
            tier = sector_to_tier(reg.get("sector"))
        else:
            tier = "unclassified"
        # attribution: registry -> store attr_* -> Shodan org -> unattributed
        org_id = org_name = sector = method = None
        conf = "none"
        if reg and ((reg.get("org_name") or "").strip() or (reg.get("org_id") or "").strip()):
            org_id, org_name = (reg.get("org_id") or "").strip() or None, (reg.get("org_name") or "").strip() or None
            sector, method, conf = reg.get("sector") or None, reg.get("method"), reg.get("confidence") or "low"
        elif h and (h.get("attr_org_name") or h.get("attr_org_id")):
            org_id, org_name = h.get("attr_org_id") or None, h.get("attr_org_name") or None
            method, conf = h.get("attr_method") or "store", h.get("attr_confidence") or "low"
        elif h and (h.get("org") or "").strip():
            org_name, method, conf = h["org"].strip(), "shodan_org", "low"
        if not org_name:
            org_name = org_id or UNATTRIBUTED
        info = {"tier": tier, "known": bool(h or reg), "in_store": bool(h),
                "org_id": org_id, "org_name": org_name, "sector": sector or TIER_TO_SECTOR.get(tier, "other"),
                "attr_method": method, "attr_confidence": conf,
                "newest": h["newest"] if h else None}
        host_info[ip] = info
        return info

    def eligible(ip):
        t = host(ip)["tier"]
        if t in NEVER_LEAD_TIERS:
            excluded[t] += 1
            return False
        return True

    def add(ip, port, transport, etype, conf, evidence, key="", severity=None, obs_date=None):
        hi = host(ip)
        lid = lead_id(ip, port, transport, etype, key)
        cands[lid] = {"lead_id": lid, "ip": ip, "port": int(port), "transport": transport,
                      "org_id": hi["org_id"], "org_name": hi["org_name"], "tier": hi["tier"],
                      "sector": hi["sector"], "evidence_type": etype, "evidence_key": key or None,
                      "evidence": evidence, "confidence": conf, "severity": severity,
                      "attr_method": hi["attr_method"], "attr_confidence": hi["attr_confidence"],
                      "obs_date": _parse_date(obs_date)}

    for row in cs_rows:
        ip, port, tp = row["ip"], row["port"], row["transport"] or "tcp"
        if not eligible(ip):
            continue
        tier = host(ip)["tier"]
        desc = service_desc(row)
        age = f"; banner {str(row['banner_ts'])[:10]}" if row.get("banner_ts") else ""
        d = row["date"]
        for v in kev.get((ip, port, tp, True), []):
            add(ip, port, tp, "kev_verified", "high",
                f"{v['cve']} (CISA KEV) VERIFIED by Shodan on {desc}; EPSS {_fmt_epss(v['epss'])}, "
                f"CVSS {v['cvss'] or 'n/a'}{age}", key=v["cve"], severity="high", obs_date=d)
        for v in kev.get((ip, port, tp, False), []):
            if tier in PRIORITY_TIERS:
                add(ip, port, tp, "kev_inferred", "medium",
                    f"{v['cve']} (CISA KEV) inferred from banner version of {desc} (NOT verified); "
                    f"EPSS {_fmt_epss(v['epss'])}, CVSS {v['cvss'] or 'n/a'}{age}",
                    key=v["cve"], severity="medium", obs_date=d)
            else:
                excluded["kev_inferred_non_priority"] += 1
        ics = ics_match(row)
        if ics:
            add(ip, port, tp, "ics", "medium", f"{ics}; service {desc}{age}", key="ics",
                severity="medium", obs_date=d)
        app = appliance_match(row)
        if app:
            if tier in PRIORITY_TIERS:
                label, _ = app
                add(ip, port, tp, "appliance", "medium",
                    f"Internet-edge appliance {label}: {desc}"
                    f"{'; title ' + repr(str(row['http_title'])[:60]) if row.get('http_title') else ''}{age}",
                    key=label, severity="medium", obs_date=d)
            else:
                excluded["appliance_non_priority"] += 1

    # compromise_tag — Shodan's own threat flags (tripwire ledger).
    since = today - timedelta(days=COMPROMISE_WINDOW_DAYS)
    hit_ports = load_hit_ports(hits_dir, since)
    for ip, rec in load_ledger(ledger_path).items():
        last = _parse_date(rec.get("last_seen"))
        if last is None or last < since or not eligible(ip):
            continue
        base = (f"Shodan threat flag(s) {', '.join(rec.get('selectors') or ['?'])}; ledger first_seen "
                f"{rec.get('first_seen')}, last_seen {rec.get('last_seen')}; last flagged banner "
                f"{str(rec.get('last_banner_ts') or '?')[:19]}")
        for (port, tp), info in (hit_ports.get(ip) or {(HOST_PORT, HOST_TRANSPORT): None}).items():
            extra = f"; tags [{', '.join(sorted(info['tags']))}]" if info else ""
            add(ip, port, tp, "compromise_tag", "high", base + extra,
                key=",".join(rec.get("selectors") or []), severity="high", obs_date=last)

    # shadowserver — compromise-class reports are host-level (their `port` is the
    # infected host's SOURCE port); exposure-class reports name the exposed port.
    from ingest_shadowserver import classify_report
    for ip, events in shadowserver_recent(con, today, ss_parquet).items():
        if not eligible(ip):
            continue
        by = {}
        for e in events:
            cls = classify_report(e["report_type"])
            if cls == "compromise":
                key = (HOST_PORT, HOST_TRANSPORT)
            else:
                key = (int(e["port"]) if e.get("port") is not None else HOST_PORT,
                       (e.get("protocol") or HOST_TRANSPORT).lower())
            by.setdefault((cls,) + key, []).append(e)
        for (cls, port, tp), evs in by.items():
            types = sorted({e["report_type"] for e in evs})
            newest = max(str(e["timestamp"]) for e in evs)
            tags = sorted({e["tag"] for e in evs if e.get("tag")})
            sev = min((str(e.get("severity") or "medium").lower() for e in evs),
                      key=lambda s: SEVERITY_RANK.get(s, 9))
            word = "COMPROMISE" if cls == "compromise" else "EXPOSURE"
            add(ip, port, tp, "shadowserver", "high" if cls == "compromise" else "medium",
                f"Shadowserver {word} report(s) {', '.join(types)}; {len(evs)} event(s), newest {newest[:19]}"
                f"{'; tag ' + ', '.join(tags) if tags else ''}; severity {sev}",
                key=f"{cls}:{','.join(types)}", severity=sev, obs_date=newest[:10])

    # ioc_match — host-level; the ip must be known (store or registry) to be ours.
    # A host whose every service is GONE gets no new candidate, so a notified
    # host-level lead can remediate (a feed listing is not an observation).
    all_gone = {r["ip"] for r in fetch_dicts(
        con, "SELECT ip FROM store.exposure_status GROUP BY ip HAVING bool_and(status = 'gone')")}
    for ip, feeds in load_ioc(ioc_path).items():
        hi = host(ip)
        if not hi["known"]:
            excluded["ioc_unknown_ip"] += 1
            continue
        if not eligible(ip) or (hi["in_store"] and ip in all_gone):
            continue
        svcs = sorted({f"{r['port']}/{r['transport']}" for r in cs_rows if r["ip"] == ip})[:8]
        add(ip, HOST_PORT, HOST_TRANSPORT, "ioc_match", "medium",
            f"IP listed by threat-intel feed(s) {', '.join(feeds)}"
            f"{'; active services ' + ', '.join(svcs) if svcs else '; no active service in the store'}",
            key=",".join(sorted(feeds)), severity="medium", obs_date=hi["newest"])
    # every existing lead's host also gets a decision (for auto-suppression)
    return cands, excluded, host_info, host


# --- refresh -----------------------------------------------------------------

def _stamp(today, msg):
    return f"[{today.isoformat()}] {msg}"


def _append_note(old, new):
    return (old + "\n" if old else "") + new


def _last_note(notes):
    return (notes or "").strip().split("\n")[-1] if notes else ""


def refresh(ctx, today, dry_run=False, parquet=LEADS_PARQUET, events_parquet=EVENTS_PARQUET, **paths):
    """Reconcile candidates against the authoritative table in ONE transaction,
    then mirror and publish. Idempotent."""
    con = ctx.con
    state = ensure_leads_db(ctx, parquet, events_parquet)
    if state != "existing":
        log(f"leads table {state}")
    existing = {r["lead_id"]: r for r in fetch_dicts(con, "SELECT * FROM leads")}
    cands, excluded, host_info, host = generate_candidates(ctx, today, **paths)
    now = datetime.now()
    counts = {"inserted": 0, "updated": 0, "reopened": 0, "remediated": 0, "preserved": 0,
              "auto_suppressed": 0, "reinstated": 0}
    ops = []

    def upd(sql, params):
        ops.append((sql, params))

    for lid, c in cands.items():
        old = existing.get(lid)
        obs = c["obs_date"]
        if old is None:
            counts["inserted"] += 1
            row = dict(c, first_seen=today, last_seen=obs or today, last_evaluated=today, status="new",
                       notified_via=None, notified_on=None, analyst=None, notes="", updated_at=now)
            upd(f"INSERT INTO leads ({', '.join(LEAD_COLUMNS)}) VALUES ({', '.join('?' * len(LEAD_COLUMNS))})",
                [row[c_] for c_ in LEAD_COLUMNS])
            upd("INSERT INTO lead_events VALUES (?, ?, ?, ?)", [now, lid, "created", c["evidence"]])
            continue
        status, notes = old["status"], old.get("notes") or ""
        notified_on, notified_via = old.get("notified_on"), old.get("notified_via")
        newer = obs is not None and (old.get("last_seen") is None or obs > old["last_seen"])
        last_seen = max(x for x in (old.get("last_seen"), obs) if x is not None) if (old.get("last_seen") or obs) else None
        if status == "remediated":
            if newer:
                status = "new"
                notes = _append_note(notes, _stamp(today, f"reopened: newer observation {obs} shows the evidence "
                                                          f"again (previous episode notified "
                                                          f"{notified_on or 'never'} via {notified_via or '-'})"))
                upd("INSERT INTO lead_events VALUES (?, ?, ?, ?)",
                    [now, lid, "reopened", f"obs {obs}; prior notified_on {notified_on}"])
                notified_on = notified_via = None
                counts["reopened"] += 1
            else:
                counts["preserved"] += 1        # unchanged cached evidence: stays remediated
        elif status == "suppressed" and AUTO_SUPPRESS_TAG in _last_note(notes):
            status = "new"
            notes = _append_note(notes, _stamp(today, f"reinstated: host tier now {c['tier']}"))
            upd("INSERT INTO lead_events VALUES (?, ?, ?, ?)", [now, lid, "reinstated", c["tier"]])
            counts["reinstated"] += 1
        elif status in ANALYST_STATUSES:
            counts["preserved"] += 1
        else:
            counts["updated"] += 1
        upd("UPDATE leads SET last_seen = ?, last_evaluated = ?, evidence = ?, evidence_key = ?, confidence = ?, "
            "severity = ?, tier = ?, sector = ?, org_id = ?, org_name = ?, attr_method = ?, attr_confidence = ?, "
            "status = ?, notes = ?, notified_on = ?, notified_via = ?, updated_at = ? WHERE lead_id = ?",
            [last_seen, today, c["evidence"], c["evidence_key"], c["confidence"], c["severity"], c["tier"],
             c["sector"], c["org_id"], c["org_name"], c["attr_method"], c["attr_confidence"], status, notes,
             notified_on, notified_via, now, lid])

    # Existing leads without a candidate: eligibility, then remediation.
    es = {(r["ip"], r["port"], r["transport"]): r["status"] for r in
          fetch_dicts(con, "SELECT ip, port, transport, status FROM store.exposure_status")}
    by_ip = {}
    for (ip, port, tp), st in es.items():
        by_ip.setdefault(ip, []).append(st)
    for lid, old in existing.items():
        if lid in cands:
            continue
        hi = host(old["ip"])
        upd("UPDATE leads SET last_evaluated = ? WHERE lead_id = ?", [today, lid])
        if hi["known"] and hi["tier"] in NEVER_LEAD_TIERS and old["status"] != "suppressed":
            counts["auto_suppressed"] += 1
            upd("UPDATE leads SET status = 'suppressed', tier = ?, notes = ?, updated_at = ? WHERE lead_id = ?",
                [hi["tier"], _append_note(old.get("notes") or "",
                                          _stamp(today, f"{AUTO_SUPPRESS_TAG} {hi['tier']} (was {old['status']})")),
                 now, lid])
            upd("INSERT INTO lead_events VALUES (?, ?, ?, ?)", [now, lid, "auto_suppressed", hi["tier"]])
            continue
        if old["status"] not in ("notified", "acknowledged"):
            continue
        if old["transport"] == HOST_TRANSPORT:
            sts = by_ip.get(old["ip"], [])
            is_gone = bool(sts) and all(s == "gone" for s in sts)
        else:
            is_gone = es.get((old["ip"], old["port"], old["transport"])) == "gone"
        if is_gone:
            counts["remediated"] += 1
            upd("UPDATE leads SET status = 'remediated', notes = ?, updated_at = ? WHERE lead_id = ?",
                [_append_note(old.get("notes") or "",
                              _stamp(today, f"remediated: service gone from exposure_status (was {old['status']})")),
                 now, lid])
            upd("INSERT INTO lead_events VALUES (?, ?, ?, ?)", [now, lid, "remediated", old["status"]])

    if dry_run:
        log(f"DRY-RUN: {len(ops)} change(s) not applied")
    else:
        con.begin()
        try:
            for sql, params in ops:
                con.execute(sql, params)
            con.commit()
        except Exception:
            con.rollback()
            raise
        mirror_leads(ctx, parquet, events_parquet)
        publish_copy(ctx)
    log(f"refresh {today}: {len(cands)} candidate(s); inserted {counts['inserted']}, updated {counts['updated']}, "
        f"reopened {counts['reopened']}, reinstated {counts['reinstated']}, remediated {counts['remediated']}, "
        f"auto-suppressed {counts['auto_suppressed']}, analyst/remediated status preserved {counts['preserved']}")
    log("excluded (aggregate only): " + (", ".join(f"{k}={v}" for k, v in excluded.items() if v) or "none"))
    return counts, excluded


def print_summary(con):
    rows = con.execute("SELECT tier, evidence_type, status, count(*) FROM leads GROUP BY 1, 2, 3 ORDER BY 1, 2, 3").fetchall()
    print(f"\n{'tier':24} {'evidence_type':16} {'status':16} {'leads':>6}")
    for tier, et, st, n in rows:
        print(f"{tier:24} {et:16} {st:16} {n:6}")
    tot = con.execute("SELECT count(*), count(DISTINCT ip), count(DISTINCT org_name) FROM leads").fetchone()
    attr = con.execute("SELECT attr_confidence, count(*) FROM leads GROUP BY 1 ORDER BY 2 DESC").fetchall()
    print(f"\ntotal {tot[0]} lead(s) on {tot[1]} host(s) / {tot[2]} org(s); attribution confidence: "
          + ", ".join(f"{c or 'none'}={n}" for c, n in attr))


# --- list / set / digest -----------------------------------------------------

RANK_SQL = """
WITH svc AS (
  SELECT lo.ip, lo.port, lo.transport, max(v.epss) AS epss
  FROM store.latest_observed lo JOIN store.vulns v ON v.observation_id = lo.observation_id AND v.date = lo.date
  GROUP BY 1, 2, 3),
cve AS (
  SELECT lo.ip, lo.port, lo.transport, v.cve, max(v.epss) AS epss
  FROM store.latest_observed lo JOIN store.vulns v ON v.observation_id = lo.observation_id AND v.date = lo.date
  GROUP BY 1, 2, 3, 4)
SELECT l.*, COALESCE(c.epss, s.epss) AS epss
FROM leads l
LEFT JOIN cve c ON c.ip = l.ip AND c.port = l.port AND c.transport = l.transport AND c.cve = l.evidence_key
LEFT JOIN svc s ON s.ip = l.ip AND s.port = l.port AND s.transport = l.transport
{where}
ORDER BY {rank_case}, {sev_case}, COALESCE(c.epss, s.epss) DESC NULLS LAST, {tier_case}, l.first_seen, l.ip, l.port
{limit}
"""


def _case(col, mapping, default):
    return ("CASE " + " ".join(f"WHEN {col} = '{k}' THEN {v}" for k, v in mapping.items()) + f" ELSE {default} END")


def ranked_leads(ctx, tier=None, status=None, sector=None, evidence=None, org=None, limit=None, ip=None,
                 statuses=None):
    conds, params = [], []
    for col, val in (("l.tier", tier), ("l.status", status), ("l.sector", sector),
                     ("l.evidence_type", evidence), ("l.ip", ip)):
        if val:
            conds.append(f"{col} = ?")
            params.append(val)
    if org:
        conds.append("(lower(l.org_name) = lower(?) OR lower(l.org_id) = lower(?))")
        params += [org, org]
    if statuses:
        conds.append("l.status IN (" + ", ".join("?" * len(statuses)) + ")")
        params += list(statuses)
    sql = RANK_SQL.format(where=("WHERE " + " AND ".join(conds)) if conds else "",
                          rank_case=_case("l.evidence_type", EVIDENCE_RANK, 9),
                          sev_case=_case("l.severity", SEVERITY_RANK, 9),
                          tier_case=_case("l.tier", TIER_RANK, 9),
                          limit=f"LIMIT {int(limit)}" if limit else "")
    return fetch_dicts(ctx.con, sql, params)


def print_list(rows):
    print(f"{'lead_id':16} {'tier':22} {'evidence':14} {'conf':6} {'ip':15} {'port':>5} {'tp':4} "
          f"{'status':12} {'first':10} {'last':10} {'epss':>5} {'attr':16}  org")
    for r in rows:
        attr = f"{r.get('attr_confidence') or 'none'}/{(r.get('attr_method') or '-')[:9]}"
        print(f"{r['lead_id']:16} {(r['tier'] or ''):22} {r['evidence_type']:14} {r['confidence']:6} "
              f"{r['ip']:15} {r['port']:5} {(r['transport'] or ''):4} {r['status']:12} "
              f"{r['first_seen']} {r['last_seen']} {_fmt_epss(r.get('epss')):>5} {attr:16}  "
              f"{(r['org_name'] or UNATTRIBUTED)[:36]}")
    print(f"{len(rows)} lead(s)")


def set_status(ctx, lid, status, via=None, analyst=None, note=None, today=None, parquet=LEADS_PARQUET,
               events_parquet=EVENTS_PARQUET, dry_run=False):
    """Analyst status change: UPDATE + event + parquet mirror in ONE transaction;
    the mirror is written before commit and a mirror failure rolls everything back."""
    if status not in STATUSES:
        raise SystemExit(f"ERROR: status must be one of {', '.join(STATUSES)}")
    con = ctx.con
    today = today or date.today()
    old = fetch_dicts(con, "SELECT * FROM leads WHERE lead_id = ?", [lid])
    if not old:
        raise SystemExit(f"ERROR: no lead {lid}")
    old = old[0]
    notes = _append_note(old.get("notes") or "",
                         _stamp(today, f"{old['status']} -> {status}" + (f" via {via}" if via else "")
                                + (f" by {analyst}" if analyst else "") + (f": {note}" if note else "")))
    sets, params = ["status = ?", "notes = ?", "updated_at = ?"], [status, notes, datetime.now()]
    if via:
        sets.append("notified_via = ?"); params.append(via)
    if analyst:
        sets.append("analyst = ?"); params.append(analyst)
    if status == "notified" and not old.get("notified_on"):
        sets.append("notified_on = ?"); params.append(today)
    params.append(lid)
    if dry_run:
        log(f"DRY-RUN: would set {lid} {old['status']} -> {status}")
        return
    con.begin()
    try:
        con.execute(f"UPDATE leads SET {', '.join(sets)} WHERE lead_id = ?", params)
        add_event(con, lid, "status", f"{old['status']} -> {status}" + (f" via {via}" if via else ""))
        mirror_leads(ctx, parquet, events_parquet)
        con.commit()
    except Exception as exc:
        con.rollback()
        raise SystemExit(f"ERROR: status change NOT saved (mirror/DB write failed: {exc}); rolled back")
    publish_copy(ctx)
    log(f"{lid} {old['status']} -> {status} ({old['ip']}:{old['port']} {old['evidence_type']}, "
        f"{old.get('org_name') or UNATTRIBUTED})")


def _stats(vals):
    if not vals:
        return "n/a"
    return (f"n={len(vals)}, median {statistics.median(vals):.0f}d, mean {statistics.mean(vals):.1f}d, "
            f"min {min(vals)}d, max {max(vals)}d")


def digest(ctx, today, weekly=False):
    con = ctx.con
    since = today - timedelta(days=7) if weekly else None
    leads = fetch_dicts(con, "SELECT * FROM leads WHERE tier NOT IN ('residential', 'honeypot')")
    life = {(r["ip"], r["port"], r["transport"]): r for r in
            fetch_dicts(con, "SELECT ip, port, transport, first_seen, last_seen FROM store.lifecycle")}
    es = {(r["ip"], r["port"], r["transport"]): r["status"] for r in
          fetch_dicts(con, "SELECT ip, port, transport, status FROM store.exposure_status")}
    newest = con.execute("SELECT max(date) FROM store.observations").fetchone()[0]
    per = {}
    for l in leads:
        s = per.setdefault(l["sector"] or "other", {"new": 0, "queued": 0, "notified": 0, "acknowledged": 0,
                                                    "remediated": 0, "other": 0, "gone_days": [],
                                                    "notified_to_gone": [], "open_age": [], "leads": 0,
                                                    "attr": {}})
        s["leads"] += 1
        s["attr"][l.get("attr_confidence") or "none"] = s["attr"].get(l.get("attr_confidence") or "none", 0) + 1
        st = l["status"]
        in_window = True
        if since:
            if st == "new":
                in_window = l["first_seen"] >= since
            elif st == "notified":
                in_window = (l.get("notified_on") or l["first_seen"]) >= since
            elif st == "remediated":
                in_window = (l.get("updated_at") or datetime.min).date() >= since
        if in_window:
            s[st if st in s else "other"] += 1
        key = (l["ip"], l["port"], l["transport"])
        lf = life.get(key)
        if lf and es.get(key) == "gone":
            s["gone_days"].append((lf["last_seen"] - l["first_seen"]).days + 1)
            if l.get("notified_on"):
                s["notified_to_gone"].append(max(0, (lf["last_seen"] - l["notified_on"]).days))
        elif st in ("new", "queued", "notified", "acknowledged"):
            s["open_age"].append(max(0, (today - l["first_seen"]).days))
    out = [f"# Leads digest — {'week ending ' if weekly else 'as of '}{today}", "",
           f"Store newest day: {newest}. Residential/honeypot tiers excluded (aggregate only). "
           f"{'Counts are for the last 7 days; ' if weekly else ''}"
           "days-to-disappear = days a lead's service stayed visible after we raised the lead "
           "(lifecycle/exposure_status = 'gone'); notified-to-gone = days from notification to the "
           "service disappearing. A disappeared service is *no longer observed* — the best passive proxy "
           "for remediation we have, not proof of it.", "",
           "| sector | leads | new | queued | notified | acknowledged | remediated | other | attribution (conf=n) |",
           "|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    for sec in sorted(per):
        s = per[sec]
        attr = ", ".join(f"{k}={v}" for k, v in sorted(s["attr"].items()))
        out.append(f"| {sec} | {s['leads']} | {s['new']} | {s['queued']} | {s['notified']} | "
                   f"{s['acknowledged']} | {s['remediated']} | {s['other']} | {attr} |")
    out += ["", "## Remediation measurement", ""]
    for sec in sorted(per):
        s = per[sec]
        out.append(f"- **{sec}** — days-to-disappear: {_stats(s['gone_days'])}; notified-to-gone: "
                   f"{_stats(s['notified_to_gone'])}; still-open lead age: {_stats(s['open_age'])}")
    if not per:
        out.append("- no leads yet — run `leads.py refresh`")
    ev = con.execute("SELECT evidence_type, confidence, count(*) FROM leads WHERE tier NOT IN ('residential', 'honeypot') "
                     "GROUP BY 1, 2 ORDER BY 3 DESC").fetchall()
    out += ["", "## By evidence type", "", "| evidence_type | confidence | leads |", "|---|---|---:|"]
    out += [f"| {e} | {c} | {n} |" for e, c, n in ev]
    return "\n".join(out) + "\n"


# --- CLI ---------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Persisted leads over the exposure store.")
    ap.add_argument("--db", default=DB_PATH, help="exposure store (read; leads copy published into it)")
    ap.add_argument("--leads-db", default=LEADS_DB, help="authoritative leads DuckDB")
    ap.add_argument("--today", help="YYYY-MM-DD (default: today)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("refresh")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--ledger", default=LEDGER_PATH)
    r.add_argument("--hits-dir", default=HITS_DIR)
    r.add_argument("--ioc", default=IOC_PATH)
    r.add_argument("--attribution", default=ATTRIBUTION_PARQUET)
    r.add_argument("--ss-parquet", default=SS_EVENTS_PARQUET)
    r.add_argument("--parquet", default=LEADS_PARQUET)
    ls = sub.add_parser("list")
    for opt in ("--tier", "--status", "--sector", "--evidence", "--org", "--ip"):
        ls.add_argument(opt)
    ls.add_argument("--limit", type=int, default=50)
    st = sub.add_parser("set")
    st.add_argument("lead_id")
    st.add_argument("--status", required=True, choices=STATUSES)
    st.add_argument("--via")
    st.add_argument("--analyst")
    st.add_argument("--note")
    st.add_argument("--dry-run", action="store_true")
    st.add_argument("--parquet", default=LEADS_PARQUET)
    dg = sub.add_parser("digest")
    dg.add_argument("--weekly", action="store_true")
    dg.add_argument("--out")
    args = ap.parse_args(argv)
    today = _parse_date(args.today) if args.today else date.today()
    if args.today and today is None:
        ap.error("--today must be YYYY-MM-DD")

    if args.cmd == "refresh":
        ctx = open_ctx(args.db, args.leads_db, write=not args.dry_run)
        try:
            refresh(ctx, today, dry_run=args.dry_run, parquet=args.parquet, ledger_path=args.ledger,
                    hits_dir=args.hits_dir, ioc_path=args.ioc, attribution_parquet=args.attribution,
                    ss_parquet=args.ss_parquet)
            print_summary(ctx.con)
        finally:
            ctx.close()
        return 0
    if args.cmd == "set":
        ctx = open_ctx(args.db, args.leads_db, write=True)
        try:
            ensure_leads_db(ctx, args.parquet)
            set_status(ctx, args.lead_id, args.status, args.via, args.analyst, args.note, today,
                       parquet=args.parquet, dry_run=args.dry_run)
        finally:
            ctx.close()
        return 0
    if not os.path.exists(args.leads_db):
        log("no leads yet — run `leads.py refresh`")
        return 1
    ctx = open_ctx(args.db, args.leads_db, write=False)
    try:
        if args.cmd == "list":
            print_list(ranked_leads(ctx, args.tier, args.status, args.sector, args.evidence, args.org,
                                    args.limit, ip=args.ip))
        elif args.cmd == "digest":
            md = digest(ctx, today, weekly=args.weekly)
            if args.out:
                os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
                with open(args.out, "w") as fh:
                    fh.write(md)
                log(f"wrote {args.out}")
            else:
                print(md)
    finally:
        ctx.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
