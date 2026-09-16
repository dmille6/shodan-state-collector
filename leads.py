#!/usr/bin/env python3
"""
leads.py — the persisted LEADS table: what we would actually notify someone about.

The store (build_store.py) answers "what is exposed right now?" for ~30k services.
Almost none of that is a notification. A LEAD is a service (ip:port:transport) that
carries one specific, evidence-graded reason to contact its owner:

  evidence_type    confidence  rule (see generate_candidates)
  kev_verified     high        a CISA-KEV CVE that Shodan itself VERIFIED on the host (one lead per CVE)
  compromise_tag   high        the host is in compromise_hits/seen_ledger.json (Shodan's
                               compromised/malware/c2/botnet flags) seen in the last 30 days;
                               per-service leads carry that service's banner_ts, the host-level
                               lead the ledger's last_banner_ts
  shadowserver     high|medium a Shadowserver event for the ip in the last 14 days, read from the
                               authoritative store/shadowserver/events.parquet — COMPROMISE-class
                               reports are high and host-level; EXPOSURE-class are medium, per port;
                               the class is part of the lead identity
  ics              medium      an ICS protocol module or ICS port answering (non-honeypot)
  appliance        medium      an internet-edge appliance per build_store.APPLIANCE_PATTERNS — priority tiers
  kev_inferred     medium      a KEV CVE inferred from the banner version, NOT verified — priority tiers
  ioc_match        medium      the host appears in the store's ioc_matches view (exact ip AND CIDR hits)
  cred_leak        (reserved for a later feed; accepted by `set`, never generated here)

ELIGIBILITY (`eligible`, `eligibility_reason`, `prior_status`) is separate from
status: residential/honeypot hosts are never notification targets, but an
ineligible lead keeps its status and is only hidden from list/packets/digest.

ATTRIBUTION comes from the PUBLISHED registry generation (store/registry/CURRENT via
registry.Attributor). Three distinct outcomes:
  * registry UNAVAILABLE (no generation / no rows): every lead keeps its previous
    org fields untouched; a brand-new lead gets the network-operator label, low
    confidence, needs_attribution_review — and the run says so;
  * an explicit row with NO org (e.g. a lone arin_rdap observation) is
    authoritative: it replaces older store-derived ownership — the lead shows the
    operator label as org_name, attr_confidence low, needs_attribution_review;
  * an attributed row: whole-address methods (ots_cidr / registry_network) bind
    every service on the address. Any other method binds a lead only if the
    lead's OWN observation carries a hostname / certificate name under one of the
    org's registry domains (Attributor.lookup_domain) or the org name in cert_org;
    otherwise the lead keeps the operator label, attr_method 'unbound(<method>)',
    low confidence, needs_attribution_review. Host-level evidence on a
    non-ownership attribution is always flagged for review.
The registry's `conflict` column is carried as attr_conflict; any conflict sets
needs_attribution_review. Ownership is reconciled for EVERY existing lead each
refresh (candidates or not, eligible or not); a change of org_id — including
empty <-> non-empty — or a confidence drop closes the notification episode
(`owner_changed` event, status new, prior_status, notified/analyst cleared,
review flag). org_at_first_seen keeps the ownership recorded when the lead was raised.

LIFECYCLE (status): new -> queued -> notified -> acknowledged -> remediated -> new
(only on a NEWER SCAN: banner_ts, collection date only when banner_ts is null);
disputed | false_positive | suppressed are analyst decisions. notified/acknowledged
-> remediated ONLY when the specific service's exposure_status is 'gone'
(host-level: every service of the host gone). Host-level leads carry last_event.

STORAGE: authoritative store/leads/leads.duckdb (leads — lead_id PRIMARY KEY —,
lead_events, migrations); snapshots in store/leads/snapshots/<generation>/ with a
CURRENT pointer published only after commit (newest 5 kept); the `leads` table in
exposure.duckdb is a re-published COPY. Migrations are recorded in the
`migrations` table: legacy_import_v1 (import a legacy store table, map old KEV ids
onto per-CVE leads only where the legacy evidence names exactly that CVE, keep and
flag legacy rows with no target) and shadowserver_class_id_v1 (re-key shadowserver
leads in place). PASSIVE. Every lead is a lead to verify.

Usage:
    leads.py refresh [--dry-run] [--today YYYY-MM-DD]
    leads.py list [--tier T] [--status S] [--sector X] [--evidence E] [--org NAME] [--ip IP]
                  [--limit N] [--include-ineligible]
    leads.py set <lead_id> [--status notified] [--via ...] [--analyst ...] [--note ...]
                  [--review-cleared | --needs-review]
    leads.py digest [--weekly] [--out reports/leads_digest.md]
"""
import argparse
import glob
import gzip
import hashlib
import ipaddress
import json
import os
import re
import shutil
import statistics
import sys
from datetime import date, datetime, timedelta, timezone

import duckdb

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import triage_report as tr    # ICS_PORTS
import build_store as bs      # APPLIANCE_PATTERNS (shared with the appliance_exposure view), SECTOR_TIER
import registry as rg         # Attributor: published generation, lookup, lookup_domain

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "store", "exposure.duckdb")
LEADS_DIR = os.path.join(SCRIPT_DIR, "store", "leads")
REGISTRY_DIR = os.path.join(SCRIPT_DIR, "store", "registry")
LEDGER_PATH = os.path.join(SCRIPT_DIR, "compromise_hits", "seen_ledger.json")
HITS_DIR = os.path.join(SCRIPT_DIR, "compromise_hits")
IOC_PATH = os.path.join(SCRIPT_DIR, "reference", "ioc_ips.json")
SS_EVENTS_PARQUET = os.path.join(SCRIPT_DIR, "store", "shadowserver", "events.parquet")
KEEP_SNAPSHOTS = 5

LEAD_COLUMNS = ["lead_id", "ip", "port", "transport", "org_id", "org_name", "tier", "sector",
                "evidence_type", "evidence_key", "evidence", "confidence", "severity",
                "attr_method", "attr_confidence", "attr_conflict", "org_at_first_seen",
                "eligible", "eligibility_reason", "prior_status", "needs_attribution_review",
                "first_seen", "last_seen", "last_scan_ts", "last_event", "last_evaluated", "status",
                "notified_via", "notified_on", "analyst", "notes", "updated_at"]
LEAD_TYPES = {"port": "INTEGER", "first_seen": "DATE", "last_seen": "DATE", "last_evaluated": "DATE",
              "last_event": "DATE", "notified_on": "DATE", "updated_at": "TIMESTAMP", "last_scan_ts": "TIMESTAMP",
              "eligible": "BOOLEAN DEFAULT TRUE", "needs_attribution_review": "BOOLEAN DEFAULT FALSE"}
LEADS_DDL = "CREATE TABLE IF NOT EXISTS leads (" + ", ".join(
    f"{c} {LEAD_TYPES.get(c, 'VARCHAR')}" + (" PRIMARY KEY" if c == "lead_id" else "") for c in LEAD_COLUMNS) + ")"
EVENTS_DDL = "CREATE TABLE IF NOT EXISTS lead_events (ts TIMESTAMP, lead_id VARCHAR, event VARCHAR, detail VARCHAR)"
MIGRATIONS_DDL = "CREATE TABLE IF NOT EXISTS migrations (name VARCHAR PRIMARY KEY, applied_at TIMESTAMP, detail VARCHAR)"

STATUSES = ["new", "queued", "notified", "acknowledged", "remediated", "disputed", "false_positive", "suppressed"]
ANALYST_STATUSES = {"queued", "notified", "acknowledged", "disputed", "false_positive", "suppressed"}
EVIDENCE_TYPES = ["kev_verified", "kev_inferred", "appliance", "ics", "compromise_tag", "shadowserver", "ioc_match", "cred_leak"]
CVE_TYPES = {"kev_verified", "kev_inferred"}
EVIDENCE_RANK = {"kev_verified": 0, "compromise_tag": 1, "shadowserver": 2, "ics": 3, "appliance": 4,
                 "kev_inferred": 5, "ioc_match": 6, "cred_leak": 7}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
TIER_RANK = {"critical_infrastructure": 0, "government": 1, "education": 2, "small_business": 3,
             "unclassified": 4, "out_of_state_gov": 5}
ATTR_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
WHOLE_ADDRESS_METHODS = {"ots_cidr", "registry_network"}
PRIORITY_TIERS = {"government", "education", "critical_infrastructure"}
NEVER_LEAD_TIERS = {"residential", "honeypot"}
TIER_TO_SECTOR = {"critical_infrastructure": "critical_infrastructure", "government": "government",
                  "education": "education", "small_business": "small_business", "out_of_state_gov": "out_of_state",
                  "residential": "other", "unclassified": "other", "honeypot": "other"}
SECTOR_TIER = getattr(bs, "SECTOR_TIER", {"critical_infrastructure": "critical_infrastructure",
                                          "healthcare": "critical_infrastructure", "energy": "critical_infrastructure",
                                          "water": "critical_infrastructure", "government": "government",
                                          "education": "education", "small_business": "small_business",
                                          "out_of_state": "out_of_state_gov"})
UNATTRIBUTED = "unattributed"
TRANSPORTS = {"tcp", "udp", "icmp", "other", "host"}
COMPROMISE_WINDOW_DAYS = 30
SHADOWSERVER_WINDOW_DAYS = 14
HOST_EVENT_FRESH_DAYS = 30
HOST_PORT, HOST_TRANSPORT = 0, "host"

ICS_MODULES = {"modbus", "s7", "siemens_s7", "dnp3", "bacnet", "ethernetip", "fox", "iec-104", "iec104", "codesys",
               "omron", "pcworx", "proconos", "ge-srtp", "hart-ip", "melsec", "redlion-crimson3", "crestron",
               "unitronics-pcom", "automated-tank-gauge", "vertx-edge", "lantronix-udp", "moxa-nport", "niagara-fox",
               "bacnet-ip", "iec-61850", "mms", "opc-ua", "opcua", "profinet", "cspv4", "fins", "koyo", "kamstrup"}
APPLIANCE_PATTERNS = bs.APPLIANCE_PATTERNS
_APPLIANCE_RX = [(label, re.compile(rx)) for label, rx in APPLIANCE_PATTERNS]
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def log(msg):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} - {msg}", flush=True)


def canon_ip(s):
    """Canonical spelling (IPv6 compressed) so keys match the store; non-addresses pass through."""
    try:
        return ipaddress.ip_address(str(s).strip()).compressed
    except ValueError:
        return str(s).strip()


def lead_id(ip, port, transport, evidence_type, key=""):
    """sha1(ip|port|transport|evidence_type[|cve | class])[:16]: the CVE for the KEV
    types, the report class (compromise|exposure) for shadowserver."""
    base = f"{canon_ip(ip)}|{port}|{transport}|{evidence_type}"
    if evidence_type in CVE_TYPES and key:
        base += f"|{key}"
    elif evidence_type == "shadowserver" and key:
        base += f"|{str(key).split(':')[0]}"
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


def _parse_ts(s):
    if isinstance(s, datetime):
        return s.replace(tzinfo=None)
    if isinstance(s, date):
        return datetime(s.year, s.month, s.day)
    if not s:
        return None
    t = str(s).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(t.replace(" ", "T", 1) if " " in t and "T" not in t else t)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        d = _parse_date(t)
        return datetime(d.year, d.month, d.day) if d else None


def norm_transport(t):
    t = (t or "").strip().lower()
    return t if t in TRANSPORTS else ("other" if t else "tcp")


def is_host_level(evidence_type, transport, evidence_key=None):
    return transport == HOST_TRANSPORT


# --- connections / storage ---------------------------------------------------------

class Ctx:
    def __init__(self, con, store_path, leads_dir, store_writable):
        self.con, self.store_path, self.leads_dir, self.store_writable = con, store_path, leads_dir, store_writable

    def close(self):
        try:
            self.con.close()
        except duckdb.Error:
            pass


def open_ctx(store_path=DB_PATH, leads_dir=LEADS_DIR, write=False):
    if not os.path.exists(store_path):
        raise SystemExit(f"ERROR: store {store_path} does not exist — run build_store.py first")
    db = os.path.join(leads_dir, "leads.duckdb")
    if not os.path.exists(db) and not write:
        raise SystemExit("no leads yet — run `leads.py refresh`")
    os.makedirs(leads_dir, exist_ok=True)
    try:
        con = duckdb.connect(db, read_only=not write)
    except duckdb.Error as exc:
        raise SystemExit(f"ERROR: cannot open {db} ({exc}); another leads.py may be running")
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
            raise SystemExit(f"ERROR: cannot open the store {store_path} ({exc}). If a store rebuild is running, "
                             f"wait for it and re-run.")
    return Ctx(con, store_path, leads_dir, writable)


def table_exists(con, name, catalog=None):
    sql, params = "SELECT count(*) FROM information_schema.tables WHERE table_name = ?", [name]
    if catalog:
        sql += " AND table_catalog = ?"
        params.append(catalog)
    return con.execute(sql, params).fetchone()[0] > 0


def columns_of(con, name, catalog=None):
    sql, params = "SELECT column_name FROM information_schema.columns WHERE table_name = ?", [name]
    if catalog:
        sql += " AND table_catalog = ?"
        params.append(catalog)
    return [r[0] for r in con.execute(sql + " ORDER BY ordinal_position", params).fetchall()]


def fetch_dicts(con, sql, params=None):
    cur = con.execute(sql, params or [])
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


def current_snapshot(leads_dir):
    try:
        with open(os.path.join(leads_dir, "CURRENT")) as fh:
            gen = fh.read().strip()
        d = os.path.join(leads_dir, "snapshots", gen)
        return d if gen and os.path.isdir(d) else None
    except OSError:
        return None


def write_snapshot(ctx):
    gen = f"{datetime.now():%Y%m%dT%H%M%S%f}-{os.getpid()}"
    d = os.path.join(ctx.leads_dir, "snapshots", gen)
    os.makedirs(d, exist_ok=True)
    for name, sql in (("leads.parquet", "SELECT * FROM leads ORDER BY lead_id"),
                      ("lead_events.parquet", "SELECT * FROM lead_events ORDER BY ts, lead_id"),
                      ("migrations.parquet", "SELECT * FROM migrations ORDER BY name")):
        tmp = os.path.join(d, f"{name}.tmp-{os.getpid()}")
        ctx.con.execute(f"COPY ({sql}) TO '{tmp}' (FORMAT PARQUET)")
        os.replace(tmp, os.path.join(d, name))
    return gen


def discard_snapshot(ctx, gen):
    shutil.rmtree(os.path.join(ctx.leads_dir, "snapshots", gen), ignore_errors=True)


def publish_pointer(ctx, gen, keep=KEEP_SNAPSHOTS):
    ptr = os.path.join(ctx.leads_dir, "CURRENT")
    tmp = f"{ptr}.tmp-{os.getpid()}"
    with open(tmp, "w") as fh:
        fh.write(gen + "\n")
    os.replace(tmp, ptr)
    root = os.path.join(ctx.leads_dir, "snapshots")
    gens = sorted(g for g in os.listdir(root) if os.path.isdir(os.path.join(root, g)))
    if len(gens) > keep:
        for old in [g for g in gens if g != gen][:len(gens) - keep]:
            shutil.rmtree(os.path.join(root, old), ignore_errors=True)


def ensure_leads_db(ctx):
    """Create/upgrade the authoritative tables; restore from the CURRENT snapshot when empty."""
    con = ctx.con
    cat = con.execute("SELECT current_database()").fetchone()[0]
    existed = table_exists(con, "leads", cat)
    if not existed:
        con.execute(LEADS_DDL)
    else:
        have = set(columns_of(con, "leads", cat))
        for c in LEAD_COLUMNS:
            if c not in have:
                con.execute(f"ALTER TABLE leads ADD COLUMN {c} {LEAD_TYPES.get(c, 'VARCHAR')}")
    for ddl, name in ((EVENTS_DDL, "lead_events"), (MIGRATIONS_DDL, "migrations")):
        if not table_exists(con, name, cat):
            con.execute(ddl)
    if con.execute("SELECT count(*) FROM leads").fetchone()[0] == 0:
        snap = current_snapshot(ctx.leads_dir)
        if snap and os.path.exists(os.path.join(snap, "leads.parquet")):
            lp = os.path.join(snap, "leads.parquet")
            cols_in = [r[0] for r in con.execute(f"DESCRIBE SELECT * FROM read_parquet('{lp}')").fetchall()]
            sel = ", ".join(c if c in cols_in else
                            ("TRUE" if c == "eligible" else "FALSE" if c == "needs_attribution_review" else "NULL") + f" AS {c}"
                            for c in LEAD_COLUMNS)
            con.execute(f"INSERT INTO leads SELECT {sel} FROM read_parquet('{lp}')")
            for name, tbl in (("lead_events.parquet", "lead_events"), ("migrations.parquet", "migrations")):
                p = os.path.join(snap, name)
                if os.path.exists(p):
                    con.execute(f"INSERT INTO {tbl} SELECT * FROM read_parquet('{p}')")
            return "restored"
    return "existing" if existed else "created"


def publish_copy(ctx):
    if not ctx.store_writable:
        log("store is read-only right now — the leads copy in exposure.duckdb was not refreshed")
        return False
    try:
        ctx.con.execute("CREATE OR REPLACE TABLE store.leads AS SELECT * FROM leads")
        return True
    except duckdb.Error as exc:
        log(f"could not publish the leads copy into the store ({exc}); authoritative state is intact")
        return False


def commit_with_snapshot(ctx, ops, snapshot_before_commit=False):
    con = ctx.con
    con.begin()
    gen = None
    try:
        for sql, params in ops:
            con.execute(sql, params)
        if snapshot_before_commit:
            gen = write_snapshot(ctx)
        con.commit()
    except Exception as exc:
        con.rollback()
        if gen:
            discard_snapshot(ctx, gen)
        raise SystemExit(f"ERROR: change NOT saved ({exc}); rolled back")
    if gen is None:
        gen = write_snapshot(ctx)
    publish_pointer(ctx, gen)
    publish_copy(ctx)
    return gen


def migration_applied(con, name):
    return con.execute("SELECT count(*) FROM migrations WHERE name = ?", [name]).fetchone()[0] > 0


# --- store reads -------------------------------------------------------------------

def _adaptive_cols(con, view, wanted, catalog="store"):
    have = set(columns_of(con, view, catalog))
    return ", ".join(c if c in have else f"NULL AS {c}" for c in wanted)


CS_COLS = ["date", "ip", "port", "transport", "org", "product", "version", "cpe23", "service", "info", "city",
           "hostnames", "tags", "banner_ts", "tier", "tier_reason", "observation_id", "http_title", "http_server",
           "cert_cn", "cert_org", "cert_sans"]
SVC_COLS = ["ip", "port", "transport", "org", "hostnames", "cert_cn", "cert_org", "cert_sans", "banner_ts", "date"]


def select_current_state(con):
    rows = fetch_dicts(con, f"SELECT {_adaptive_cols(con, 'current_state', CS_COLS)} FROM store.current_state")
    for r in rows:
        r["ip"] = canon_ip(r["ip"])
    return rows


def host_tiers(con):
    extra = _adaptive_cols(con, "latest_observed", ["attr_org_id", "attr_org_name", "attr_method", "attr_confidence"])
    rows = fetch_dicts(con, f"""
        SELECT ip, tier, org, date AS newest, banner_ts, {extra} FROM (
          SELECT *, row_number() OVER (PARTITION BY ip ORDER BY date DESC, banner_ts DESC NULLS LAST, observation_id DESC) AS rn
          FROM store.latest_observed) WHERE rn = 1""")
    return {canon_ip(r["ip"]): r for r in rows}


def service_rows(con, ips):
    """(ip, port, transport) -> latest observation identity fields, for the ips given."""
    if not ips:
        return {}
    ph = ", ".join("?" * len(ips))
    rows = fetch_dicts(con, f"SELECT {_adaptive_cols(con, 'latest_observed', SVC_COLS)} FROM store.latest_observed "
                            f"WHERE ip IN ({ph})", sorted(ips))
    return {(canon_ip(r["ip"]), r["port"], norm_transport(r["transport"])): r for r in rows}


def kev_by_service(con):
    rows = fetch_dicts(con, """
        SELECT cs.ip, cs.port, cs.transport, v.verified, v.cve, v.epss, v.cvss
        FROM store.current_state cs JOIN store.vulns v ON v.observation_id = cs.observation_id AND v.date = cs.date
        WHERE v.in_kev""")
    out = {}
    for r in rows:
        out.setdefault((canon_ip(r["ip"]), r["port"], norm_transport(r["transport"]), bool(r["verified"])), []).append(r)
    return out


# --- registry attribution ----------------------------------------------------------

class Registry:
    """The published registry generation, or an explicit UNAVAILABLE state."""

    def __init__(self, store_dir=REGISTRY_DIR):
        self.att, self.available, self.generation = None, False, None
        try:
            self.att = rg.Attributor().load(store_dir)
            self.generation = self.att.generation
            self.available = bool(self.att.attribution) or len(self.att.networks) > 0
        except Exception as exc:          # registry code/data broken: never take the run down
            log(f"WARNING: registry could not be loaded ({exc}) — attribution UNAVAILABLE this run")
        if not self.available:
            log(f"registry attribution UNAVAILABLE (generation {self.generation or 'none'}): existing org fields are "
                f"kept untouched; new leads carry the network-operator label and need review")

    def lookup(self, ip):
        return self.att.lookup(ip) if self.available else None

    def lookup_domain(self, name):
        return self.att.lookup_domain(name) if self.available else None

    def org_name(self, org_id):
        o = self.att.orgs.get(org_id) if (self.available and org_id) else None
        return (o or {}).get("name") or None


def _names_of(row):
    names = [n.strip() for n in str(row.get("hostnames") or "").split(",") if n.strip()]
    for k in ("cert_cn", "cert_sans"):
        names += [n.strip() for n in str(row.get(k) or "").split(",") if n.strip()]
    return names


def service_bound(reg, org_id, org_name, obs):
    """Does this lead's OWN observation name the org (registry domain of a hostname
    / cert name, or the org name in cert_org)?"""
    if not obs:
        return False
    for n in _names_of(obs):
        hit = reg.lookup_domain(n)
        if hit and (hit.get("org_id") or "") == (org_id or ""):
            return True
    co = str(obs.get("cert_org") or "").strip().lower()
    return bool(co) and bool(org_name) and co == org_name.strip().lower()


def resolve_attribution(reg, ip, hi, obs, host_level, prev=None):
    """Attribution for ONE lead. Returns dict(org_id, org_name, sector, attr_method,
    attr_confidence, attr_conflict, review, reason)."""
    label = ((hi or {}).get("org") or "").strip() or None          # Shodan org = network-operator label
    out = {"org_id": None, "org_name": label or UNATTRIBUTED, "sector": None, "attr_method": "shodan_org" if label else None,
           "attr_confidence": "low" if label else "none", "attr_conflict": "", "review": bool(label), "reason": "operator label"}
    if not reg.available:
        if prev is not None:
            return dict(prev, reason="registry unavailable — previous attribution kept")
        return dict(out, reason="registry unavailable")
    row = reg.lookup(ip)
    if row is None:
        # unknown to the registry: the store's own attr_* columns, else the label
        if hi and (hi.get("attr_org_id") or hi.get("attr_org_name")):
            row = {"org_id": hi.get("attr_org_id") or "", "org_name": hi.get("attr_org_name") or "",
                   "sector": "", "method": hi.get("attr_method") or "store", "confidence": hi.get("attr_confidence") or "low",
                   "conflict": ""}
        else:
            return dict(out, reason="ip unknown to the registry")
    org_id = (row.get("org_id") or "").strip() or None
    org_name = (row.get("org_name") or "").strip() or (reg.org_name(org_id) if org_id else None)
    method, conf = row.get("method") or "unknown", row.get("confidence") or "low"
    conflict = str(row.get("conflict") or "").strip()
    if not org_id and not org_name:
        return dict(out, attr_method=method, attr_confidence="low", attr_conflict=conflict,
                    review=bool(label) or bool(conflict), reason="explicit registry row without an organisation")
    sector = (row.get("sector") or "").strip() or None
    if method in WHOLE_ADDRESS_METHODS:
        return {"org_id": org_id, "org_name": org_name, "sector": sector, "attr_method": method, "attr_confidence": conf,
                "attr_conflict": conflict, "review": bool(conflict), "reason": "whole-address ownership"}
    if host_level:
        return {"org_id": org_id, "org_name": org_name, "sector": sector, "attr_method": method, "attr_confidence": conf,
                "attr_conflict": conflict, "review": True, "reason": "host-level evidence on a non-ownership attribution"}
    if service_bound(reg, org_id, org_name, obs):
        return {"org_id": org_id, "org_name": org_name, "sector": sector, "attr_method": method, "attr_confidence": conf,
                "attr_conflict": conflict, "review": bool(conflict), "reason": "service names the org"}
    return {"org_id": None, "org_name": label or org_name, "sector": sector, "attr_method": f"unbound({method})",
            "attr_confidence": "low", "attr_conflict": conflict, "review": True,
            "reason": f"service does not name {org_name}: label kept"}


# --- evidence rules ------------------------------------------------------------------

def appliance_match(row):
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
            return {canon_ip(k): v for k, v in json.load(fh).get("hosts", {}).items()}
    except (OSError, ValueError, AttributeError):
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
                    key = (int(port), norm_transport(b.get("transport")))
                    e = out.setdefault(canon_ip(ip), {}).setdefault(key, {"tags": set(), "selectors": set(), "banner_ts": ""})
                    e["tags"].update(b.get("tags") or [])
                    if b.get("_compromise_selector"):
                        e["selectors"].add(b["_compromise_selector"])
                    e["banner_ts"] = max(e["banner_ts"], b.get("timestamp") or "")
        except OSError:
            continue
    return out


def _is_ip(s):
    try:
        ipaddress.ip_address(str(s))
        return True
    except ValueError:
        return False


def ioc_hits(con, ioc_path):
    out = {}
    if table_exists(con, "ioc_matches", "store"):
        cols = _adaptive_cols(con, "ioc_matches", ["ip", "port", "transport", "ioc_sources", "ioc_cidr", "banner_ts", "date"])
        rows = fetch_dicts(con, f"SELECT {cols} FROM store.ioc_matches")
    else:
        rows = []
        try:
            with open(ioc_path) as fh:
                d = json.load(fh)
        except (OSError, ValueError):
            d = {}
        keys = {canon_ip(k) for k in d if not str(k).startswith("_") and _is_ip(k)}
        if keys:
            for r in select_current_state(con):
                if r["ip"] in keys:
                    v = d.get(r["ip"]) or next((v for k, v in d.items() if canon_ip(k) == r["ip"]), [])
                    rows.append(dict(r, ioc_sources=",".join(v) if isinstance(v, list) else str(v), ioc_cidr=None))
    for r in rows:
        ip = canon_ip(r["ip"])
        e = out.setdefault(ip, {"sources": set(), "cidrs": set(), "services": set(), "scan_ts": None})
        e["sources"].update(s.strip() for s in str(r.get("ioc_sources") or "").split(",") if s.strip())
        if r.get("ioc_cidr"):
            e["cidrs"].add(r["ioc_cidr"])
        e["services"].add(f"{r.get('port')}/{norm_transport(r.get('transport'))}")
        ts = _parse_ts(r.get("banner_ts")) or _parse_ts(r.get("date"))
        if ts and (e["scan_ts"] is None or ts > e["scan_ts"]):
            e["scan_ts"] = ts
    return out


def shadowserver_recent(con, today, parquet=SS_EVENTS_PARQUET):
    if not parquet or not os.path.exists(parquet):
        return {}
    since = today - timedelta(days=SHADOWSERVER_WINDOW_DAYS)
    rows = fetch_dicts(con, f"SELECT report_type, timestamp, ip, port, protocol, tag, severity FROM read_parquet('{parquet}') "
                            f"WHERE CAST(timestamp AS DATE) >= ?", [since])
    out = {}
    for r in rows:
        out.setdefault(canon_ip(r["ip"]), []).append(r)
    return out


def _fmt_epss(e):
    return f"{e:.3f}" if isinstance(e, (int, float)) else "n/a"


def sector_to_tier(sector):
    for s in str(sector or "").split("|"):
        if s.strip() in SECTOR_TIER:
            return SECTOR_TIER[s.strip()]
    return "unclassified"


def generate_candidates(ctx, today, reg, ledger_path=LEDGER_PATH, hits_dir=HITS_DIR, ioc_path=IOC_PATH,
                        ss_parquet=SS_EVENTS_PARQUET):
    """Evidence only (attribution is resolved per lead in refresh).
    Returns (candidates {lead_id: dict}, excluded, host(ip) -> info, hosts)."""
    con = ctx.con
    hosts = host_tiers(con)
    cs_rows = select_current_state(con)
    kev = kev_by_service(con)
    excluded = {"residential": 0, "honeypot": 0, "kev_inferred_non_priority": 0, "appliance_non_priority": 0}
    cands, host_info = {}, {}

    def host(ip):
        if ip in host_info:
            return host_info[ip]
        h = hosts.get(ip)
        row = reg.lookup(ip)
        if h:
            tier, basis = h["tier"] or "unclassified", "newest observation"
        elif row and (row.get("sector") or "").strip():
            tier, basis = sector_to_tier(row.get("sector")), "registry sector"
        else:
            tier, basis = "unclassified", "unknown host"
        known = bool(h or row)
        info = {"tier": tier, "known": known, "in_store": bool(h), "org": (h or {}).get("org"),
                "attr_org_id": (h or {}).get("attr_org_id"), "attr_org_name": (h or {}).get("attr_org_name"),
                "attr_method": (h or {}).get("attr_method"), "attr_confidence": (h or {}).get("attr_confidence"),
                "eligible": tier not in NEVER_LEAD_TIERS,
                "eligibility_reason": f"host tier {tier} ({basis})" if known else "host unknown to store and registry",
                "newest": h["newest"] if h else None}
        host_info[ip] = info
        return info

    def eligible(ip):
        hi = host(ip)
        if not hi["eligible"]:
            excluded[hi["tier"]] = excluded.get(hi["tier"], 0) + 1
        return hi["eligible"]

    def add(ip, port, transport, etype, conf, evidence, key="", severity=None, scan_ts=None, obs=None, event=None):
        hi = host(ip)
        lid = lead_id(ip, port, transport, etype, key)
        ts = _parse_ts(scan_ts)
        cands[lid] = {"lead_id": lid, "ip": ip, "port": int(port), "transport": norm_transport(transport),
                      "tier": hi["tier"], "sector_default": TIER_TO_SECTOR.get(hi["tier"], "other"),
                      "evidence_type": etype, "evidence_key": key or None, "evidence": evidence, "confidence": conf,
                      "severity": severity, "eligible": hi["eligible"], "eligibility_reason": hi["eligibility_reason"],
                      "scan_ts": ts, "obs_date": ts.date() if ts else None, "obs": obs,
                      "last_event": _parse_date(event), "host_level": norm_transport(transport) == HOST_TRANSPORT}

    for row in cs_rows:
        ip, port, tp = row["ip"], row["port"], norm_transport(row["transport"])
        if not eligible(ip):
            continue
        tier = host(ip)["tier"]
        desc = service_desc(row)
        scan = row.get("banner_ts") or row["date"]
        age = f"; banner {str(row['banner_ts'])[:19]}" if row.get("banner_ts") else f"; collected {row['date']}"
        for v in kev.get((ip, port, tp, True), []):
            add(ip, port, tp, "kev_verified", "high",
                f"{v['cve']} (CISA KEV) VERIFIED by Shodan on {desc}; EPSS {_fmt_epss(v['epss'])}, CVSS {v['cvss'] or 'n/a'}{age}",
                key=v["cve"], severity="high", scan_ts=scan, obs=row)
        for v in kev.get((ip, port, tp, False), []):
            if tier in PRIORITY_TIERS:
                add(ip, port, tp, "kev_inferred", "medium",
                    f"{v['cve']} (CISA KEV) inferred from banner version of {desc} (NOT verified); EPSS "
                    f"{_fmt_epss(v['epss'])}, CVSS {v['cvss'] or 'n/a'}{age}", key=v["cve"], severity="medium", scan_ts=scan, obs=row)
            else:
                excluded["kev_inferred_non_priority"] += 1
        ics = ics_match(row)
        if ics:
            add(ip, port, tp, "ics", "medium", f"{ics}; service {desc}{age}", key="ics", severity="medium", scan_ts=scan, obs=row)
        app = appliance_match(row)
        if app:
            if tier in PRIORITY_TIERS:
                add(ip, port, tp, "appliance", "medium",
                    f"Internet-edge appliance {app[0]}: {desc}"
                    f"{'; title ' + repr(str(row['http_title'])[:60]) if row.get('http_title') else ''}{age}",
                    key=app[0], severity="medium", scan_ts=scan, obs=row)
            else:
                excluded["appliance_non_priority"] += 1

    since = today - timedelta(days=COMPROMISE_WINDOW_DAYS)
    hit_ports = load_hit_ports(hits_dir, since)
    for ip, rec in load_ledger(ledger_path).items():
        last = _parse_date(rec.get("last_seen"))
        if last is None or last < since or not eligible(ip):
            continue
        base = (f"Shodan threat flag(s) {', '.join(rec.get('selectors') or ['?'])}; ledger first_seen {rec.get('first_seen')}, "
                f"last_seen {rec.get('last_seen')}; last flagged banner {str(rec.get('last_banner_ts') or '?')[:19]}")
        key = ",".join(rec.get("selectors") or [])
        ports = hit_ports.get(ip)
        if ports:
            for (port, tp), info in ports.items():
                add(ip, port, tp, "compromise_tag", "high", base + f"; tags [{', '.join(sorted(info['tags']))}]",
                    key=key, severity="high", scan_ts=info["banner_ts"] or last, event=last)      # THIS service's banner
        else:
            add(ip, HOST_PORT, HOST_TRANSPORT, "compromise_tag", "high", base, key=key, severity="high",
                scan_ts=rec.get("last_banner_ts") or last, event=last)                             # host-level: ledger

    from ingest_shadowserver import classify_report
    for ip, events in shadowserver_recent(con, today, ss_parquet).items():
        if not eligible(ip):
            continue
        by = {}
        for e in events:
            cls = classify_report(e["report_type"])
            k = (HOST_PORT, HOST_TRANSPORT) if cls == "compromise" else (
                int(e["port"]) if e.get("port") is not None else HOST_PORT,
                norm_transport(e.get("protocol")) if e.get("protocol") else HOST_TRANSPORT)
            by.setdefault((cls,) + k, []).append(e)
        for (cls, port, tp), evs in by.items():
            types = sorted({e["report_type"] for e in evs})
            newest = max(evs, key=lambda e: str(e["timestamp"]))["timestamp"]
            tags = sorted({e["tag"] for e in evs if e.get("tag")})
            sev = min((str(e.get("severity") or "medium").lower() for e in evs), key=lambda s: SEVERITY_RANK.get(s, 9))
            add(ip, port, tp, "shadowserver", "high" if cls == "compromise" else "medium",
                f"Shadowserver {'COMPROMISE' if cls == 'compromise' else 'EXPOSURE'} report(s) {', '.join(types)}; "
                f"{len(evs)} event(s), newest {str(newest)[:19]}{'; tag ' + ', '.join(tags) if tags else ''}; severity {sev}",
                key=f"{cls}:{','.join(types)}", severity=sev, scan_ts=newest, event=_parse_ts(newest))

    for ip, e in ioc_hits(con, ioc_path).items():
        if not eligible(ip):
            continue
        add(ip, HOST_PORT, HOST_TRANSPORT, "ioc_match", "medium",
            f"Host listed by threat-intel feed(s) {', '.join(sorted(e['sources'])) or '?'}"
            f"{'; CIDR range(s) ' + ', '.join(sorted(e['cidrs'])) if e['cidrs'] else ''}; active services "
            f"{', '.join(sorted(e['services'])[:8])}", key=",".join(sorted(e["sources"])), severity="medium",
            scan_ts=e["scan_ts"], event=e["scan_ts"])
    return cands, excluded, host


# --- migrations ----------------------------------------------------------------------

def migrate_legacy_import(ctx, now):
    """legacy_import_v1: copy a legacy `leads` table from the store (rows whose ids
    are not present yet), transactionally, recorded in `migrations`."""
    con = ctx.con
    if migration_applied(con, "legacy_import_v1"):
        return 0
    n = 0
    con.begin()
    try:
        if table_exists(con, "leads", "store") and "lead_id" in columns_of(con, "leads", "store"):
            cols_in = set(columns_of(con, "leads", "store"))
            sel = ", ".join(c if c in cols_in else
                            ("TRUE" if c == "eligible" else "FALSE" if c == "needs_attribution_review" else "NULL") + f" AS {c}"
                            for c in LEAD_COLUMNS)
            con.execute(f"CREATE TEMP TABLE _legacy AS SELECT {sel} FROM store.leads WHERE lead_id IS NOT NULL "
                        f"AND lead_id NOT IN (SELECT lead_id FROM leads)")
            n = con.execute("SELECT count(*) FROM _legacy").fetchone()[0]
            con.execute("INSERT INTO leads SELECT * FROM _legacy")
            con.execute("INSERT INTO lead_events SELECT ?, lead_id, 'imported_legacy', status FROM _legacy", [now])
            con.execute("DROP TABLE _legacy")
        con.execute("INSERT INTO migrations VALUES ('legacy_import_v1', ?, ?)", [now, f"imported {n} row(s)"])
        con.commit()
    except Exception:
        con.rollback()
        raise
    if n:
        log(f"migration legacy_import_v1: imported {n} legacy lead(s) from the store's leads table")
    return n


def migrate_shadowserver_ids(ctx, now):
    """shadowserver_class_id_v1: re-key shadowserver leads in place (class in the id)."""
    con = ctx.con
    if migration_applied(con, "shadowserver_class_id_v1"):
        return 0
    rows = fetch_dicts(con, "SELECT lead_id, ip, port, transport, evidence_key FROM leads WHERE evidence_type = 'shadowserver'")
    con.begin()
    n = 0
    try:
        for r in rows:
            cls = str(r.get("evidence_key") or "").split(":")[0] or "exposure"
            new = lead_id(r["ip"], r["port"], r["transport"], "shadowserver", cls)
            if new == r["lead_id"]:
                continue
            if con.execute("SELECT count(*) FROM leads WHERE lead_id = ?", [new]).fetchone()[0]:
                continue                                    # already re-keyed by a newer row
            con.execute("UPDATE leads SET lead_id = ? WHERE lead_id = ?", [new, r["lead_id"]])
            con.execute("UPDATE lead_events SET lead_id = ? WHERE lead_id = ?", [new, r["lead_id"]])
            con.execute("INSERT INTO lead_events VALUES (?, ?, 'id_migrated', ?)", [now, new, f"was {r['lead_id']} (class {cls})"])
            n += 1
        con.execute("INSERT INTO migrations VALUES ('shadowserver_class_id_v1', ?, ?)", [now, f"re-keyed {n}"])
        con.commit()
    except Exception:
        con.rollback()
        raise
    if n:
        log(f"migration shadowserver_class_id_v1: re-keyed {n} lead(s) in place")
    return n


# --- refresh -------------------------------------------------------------------------

def _stamp(today, msg):
    return f"[{today.isoformat()}] {msg}"


def _append_note(old, new):
    return (old + "\n" if old else "") + new


def _ev(ops, now, lid, event, detail):
    ops.append(("INSERT INTO lead_events VALUES (?, ?, ?, ?)", [now, lid, event, detail]))


def _org_label(org_id, org_name):
    return f"{org_name} [{org_id}]" if org_id else (org_name or UNATTRIBUTED)


def refresh(ctx, today, dry_run=False, registry_dir=REGISTRY_DIR, **paths):
    con = ctx.con
    now = datetime.now()
    state = ensure_leads_db(ctx)
    if state != "existing":
        log(f"leads table {state}")
    if not dry_run:
        migrate_legacy_import(ctx, now)
        migrate_shadowserver_ids(ctx, now)
    reg = Registry(registry_dir)
    existing = {r["lead_id"]: r for r in fetch_dicts(con, "SELECT * FROM leads")}
    cands, excluded, host = generate_candidates(ctx, today, reg, **paths)
    svc = service_rows(con, {c["ip"] for c in cands.values()} | {r["ip"] for r in existing.values()})
    counts = {"inserted": 0, "updated": 0, "reopened": 0, "remediated": 0, "preserved": 0, "owner_changed": 0,
              "ineligible": 0, "eligible_again": 0, "migrated": 0, "review_flagged": 0}
    ops = []

    def attribution_for(ip, port, tp, host_level, prev_row):
        hi = host(ip)
        obs = svc.get((ip, port, tp))
        prev = None
        if prev_row is not None:
            prev = {k: prev_row.get(k) for k in ("org_id", "org_name", "sector", "attr_method", "attr_confidence", "attr_conflict")}
            prev["review"] = bool(prev_row.get("needs_attribution_review"))
        a = resolve_attribution(reg, ip, hi, obs, host_level, prev)
        a["sector"] = a.get("sector") or TIER_TO_SECTOR.get(hi["tier"], "other")
        return a

    def ownership_change(old, a):
        old_key, new_key = (old.get("org_id") or ""), (a["org_id"] or "")
        if old_key != new_key:
            return f"org_id {old_key or '(none)'} -> {new_key or '(none)'}"
        if ATTR_RANK.get(a["attr_confidence"] or "none", 0) < ATTR_RANK.get(old.get("attr_confidence") or "none", 0):
            return f"attribution confidence {old.get('attr_confidence')} -> {a['attr_confidence']}"
        return None

    # --- legacy KEV ids (no CVE in the hash): map only where the evidence names the CVE ---
    legacy_map, legacy_keep = {}, {}
    for lid, old in list(existing.items()):
        if old["evidence_type"] in CVE_TYPES and not old.get("evidence_key") and lid not in cands:
            named = set(_CVE_RE.findall(old.get("evidence") or ""))
            targets = [c for c in cands.values() if (c["ip"], c["port"], c["transport"], c["evidence_type"]) ==
                       (old["ip"], old["port"], old["transport"], old["evidence_type"])]
            mapped = 0
            for c in targets:
                if c["evidence_key"] in named:
                    legacy_map[c["lead_id"]] = dict(old, _multi=len(named) > 1)
                    mapped += 1
                else:
                    legacy_keep[c["lead_id"]] = old["lead_id"]           # new per-CVE lead: review, legacy kept
            if mapped and mapped == len(targets):
                ops.append(("DELETE FROM leads WHERE lead_id = ?", [lid]))
                _ev(ops, now, lid, "migrated_legacy_id", f"mapped to {mapped} per-CVE lead(s)")
                del existing[lid]
                counts["migrated"] += 1
            else:
                reason = "no per-CVE lead names its CVE(s)" if not mapped else "some per-CVE leads not named"
                ops.append(("UPDATE leads SET needs_attribution_review = TRUE, notes = ?, last_evaluated = ?, updated_at = ? "
                            "WHERE lead_id = ?", [_append_note(old.get("notes") or "", _stamp(today, f"legacy lead kept: {reason}")),
                                                 today, now, lid]))
                _ev(ops, now, lid, "legacy_kept", reason)
                del existing[lid]          # nothing else to reconcile for it this run

    for lid, c in cands.items():
        old = existing.get(lid)
        if old is None:
            a = attribution_for(c["ip"], c["port"], c["transport"], c["host_level"], None)
            row = dict(c, org_id=a["org_id"], org_name=a["org_name"], sector=a["sector"], attr_method=a["attr_method"],
                       attr_confidence=a["attr_confidence"], attr_conflict=a["attr_conflict"],
                       org_at_first_seen=_org_label(a["org_id"], a["org_name"]), prior_status=None,
                       needs_attribution_review=a["review"], first_seen=today, last_seen=c["obs_date"] or today,
                       last_scan_ts=c["scan_ts"], last_evaluated=today, status="new", notified_via=None, notified_on=None,
                       analyst=None, notes="", updated_at=now)
            if a["review"]:
                row["notes"] = _stamp(today, f"attribution review: {a['reason']}")
                counts["review_flagged"] += 1
            leg = legacy_map.get(lid)
            if leg:
                row.update(status=leg["status"], notified_via=leg.get("notified_via"), notified_on=leg.get("notified_on"),
                           analyst=leg.get("analyst"), first_seen=leg.get("first_seen") or today,
                           prior_status=leg.get("prior_status"),
                           needs_attribution_review=row["needs_attribution_review"] or bool(leg["_multi"]),
                           notes=_append_note(leg.get("notes") or "", _stamp(today, f"migrated from legacy lead {leg['lead_id']} "
                                                                            f"(status {leg['status']} mapped"
                                                                            f"{'; legacy lead covered several CVEs — review' if leg['_multi'] else ''})")))
                _ev(ops, now, lid, "migrated_from", f"{leg['lead_id']} status {leg['status']}")
            elif lid in legacy_keep:
                row["needs_attribution_review"] = True
                row["notes"] = _append_note(row["notes"], _stamp(today, f"legacy lead {legacy_keep[lid]} for this service did not "
                                                                        f"name this CVE — review"))
                _ev(ops, now, lid, "legacy_unmapped", legacy_keep[lid])
            counts["inserted"] += 1
            ops.append((f"INSERT INTO leads ({', '.join(LEAD_COLUMNS)}) VALUES ({', '.join('?' * len(LEAD_COLUMNS))})",
                        [row[k] for k in LEAD_COLUMNS]))
            _ev(ops, now, lid, "created", c["evidence"])
            continue
        status, notes = old["status"], old.get("notes") or ""
        prior, review = old.get("prior_status"), bool(old.get("needs_attribution_review"))
        notified_on, notified_via, analyst = old.get("notified_on"), old.get("notified_via"), old.get("analyst")
        old_ts = old.get("last_scan_ts") or _parse_ts(old.get("last_seen"))
        newer = c["scan_ts"] is not None and (old_ts is None or c["scan_ts"] > old_ts)
        last_scan = max(x for x in (old_ts, c["scan_ts"]) if x is not None) if (old_ts or c["scan_ts"]) else None
        last_seen = last_scan.date() if last_scan else old.get("last_seen")
        a = attribution_for(c["ip"], c["port"], c["transport"], c["host_level"], old)
        why = ownership_change(old, a)
        if why:
            _ev(ops, now, lid, "owner_changed", json.dumps({"reason": why, "old_org_id": old.get("org_id"),
                                                             "old_org_name": old.get("org_name"), "old_status": status,
                                                             "notified_on": str(notified_on) if notified_on else None,
                                                             "notified_via": notified_via, "analyst": analyst}))
            notes = _append_note(notes, _stamp(today, f"attribution changed ({why}); episode closed — was {status}"
                                                      f"{', notified ' + str(notified_on) + ' via ' + str(notified_via) if notified_on else ''}"
                                                      f"; needs attribution review"))
            prior, status, review = status, "new", True
            notified_on = notified_via = analyst = None
            counts["owner_changed"] += 1
        elif status == "remediated":
            if newer:
                notes = _append_note(notes, _stamp(today, f"reopened: newer scan {c['scan_ts']} shows the evidence again "
                                                          f"(previous episode notified {notified_on or 'never'} via {notified_via or '-'})"))
                _ev(ops, now, lid, "reopened", f"scan {c['scan_ts']}; prior notified_on {notified_on}")
                prior, status = status, "new"
                notified_on = notified_via = None
                counts["reopened"] += 1
            else:
                counts["preserved"] += 1
        elif status in ANALYST_STATUSES:
            counts["preserved"] += 1
        else:
            counts["updated"] += 1
        attr_changed = (old.get("attr_method"), old.get("attr_conflict") or "", old.get("org_id") or "") != \
            (a["attr_method"], a["attr_conflict"] or "", a["org_id"] or "")
        if a["review"] and not review and (attr_changed or why):
            review = True
            counts["review_flagged"] += 1
            notes = _append_note(notes, _stamp(today, f"attribution review: {a['reason']}"))
        if bool(old.get("eligible", True)) != c["eligible"]:
            if not c["eligible"]:
                prior, counts["ineligible"] = status, counts["ineligible"] + 1
                _ev(ops, now, lid, "ineligible", c["eligibility_reason"])
            else:
                counts["eligible_again"] += 1
                _ev(ops, now, lid, "eligible_again", c["eligibility_reason"])
            notes = _append_note(notes, _stamp(today, f"{'ineligible' if not c['eligible'] else 'eligible again'}: "
                                                      f"{c['eligibility_reason']} (status {status} kept)"))
        last_event = c["last_event"] or old.get("last_event")
        ops.append(("UPDATE leads SET last_seen = ?, last_scan_ts = ?, last_event = ?, last_evaluated = ?, evidence = ?, "
                    "evidence_key = ?, confidence = ?, severity = ?, tier = ?, sector = ?, org_id = ?, org_name = ?, "
                    "attr_method = ?, attr_confidence = ?, attr_conflict = ?, eligible = ?, eligibility_reason = ?, "
                    "prior_status = ?, needs_attribution_review = ?, status = ?, notes = ?, notified_on = ?, "
                    "notified_via = ?, analyst = ?, updated_at = ? WHERE lead_id = ?",
                    [last_seen, last_scan, last_event, today, c["evidence"], c["evidence_key"], c["confidence"], c["severity"],
                     c["tier"], a["sector"], a["org_id"], a["org_name"], a["attr_method"], a["attr_confidence"],
                     a["attr_conflict"], c["eligible"], c["eligibility_reason"], prior, review, status, notes,
                     notified_on, notified_via, analyst, now, lid]))

    # --- existing leads without a candidate: ownership + eligibility + remediation ---
    es = {(canon_ip(r["ip"]), r["port"], norm_transport(r["transport"])): r["status"] for r in
          fetch_dicts(con, "SELECT ip, port, transport, status FROM store.exposure_status")}
    by_ip = {}
    for (ip, port, tp), st in es.items():
        by_ip.setdefault(ip, []).append(st)
    for lid, old in existing.items():
        if lid in cands:
            continue
        hi = host(old["ip"])
        status, notes, prior = old["status"], old.get("notes") or "", old.get("prior_status")
        review = bool(old.get("needs_attribution_review"))
        notified_on, notified_via, analyst = old.get("notified_on"), old.get("notified_via"), old.get("analyst")
        a = attribution_for(old["ip"], old["port"], norm_transport(old["transport"]), old["transport"] == HOST_TRANSPORT, old)
        why = ownership_change(old, a)
        if why:
            _ev(ops, now, lid, "owner_changed", json.dumps({"reason": why, "old_org_id": old.get("org_id"),
                                                             "old_org_name": old.get("org_name"), "old_status": status,
                                                             "notified_on": str(notified_on) if notified_on else None,
                                                             "notified_via": notified_via, "analyst": analyst}))
            notes = _append_note(notes, _stamp(today, f"attribution changed ({why}); episode closed — was {status}; "
                                                      f"needs attribution review"))
            prior, status, review = status, "new", True
            notified_on = notified_via = analyst = None
            counts["owner_changed"] += 1
        elif a["review"] and not review and (old.get("attr_method"), old.get("attr_conflict") or "") != \
                (a["attr_method"], a["attr_conflict"] or ""):
            review = True
            counts["review_flagged"] += 1
            notes = _append_note(notes, _stamp(today, f"attribution review: {a['reason']}"))
        elig, reason = bool(old.get("eligible", True)), old.get("eligibility_reason")
        if hi["known"] and hi["eligible"] != elig:
            if not hi["eligible"]:
                prior, counts["ineligible"] = status, counts["ineligible"] + 1
                _ev(ops, now, lid, "ineligible", hi["eligibility_reason"])
            else:
                counts["eligible_again"] += 1
                _ev(ops, now, lid, "eligible_again", hi["eligibility_reason"])
            notes = _append_note(notes, _stamp(today, f"{'ineligible' if not hi['eligible'] else 'eligible again'}: "
                                                      f"{hi['eligibility_reason']} (status {status} kept)"))
            elig, reason = hi["eligible"], hi["eligibility_reason"]
        if status in ("notified", "acknowledged"):
            if old["transport"] == HOST_TRANSPORT:
                sts = by_ip.get(old["ip"], [])
                is_gone = bool(sts) and all(s == "gone" for s in sts)
            else:
                is_gone = es.get((old["ip"], old["port"], norm_transport(old["transport"]))) == "gone"
            if is_gone:
                counts["remediated"] += 1
                prior, status = status, "remediated"
                notes = _append_note(notes, _stamp(today, f"remediated: service gone from exposure_status (was {prior})"))
                _ev(ops, now, lid, "remediated", prior)
        ops.append(("UPDATE leads SET last_evaluated = ?, eligible = ?, eligibility_reason = ?, prior_status = ?, notes = ?, "
                    "org_id = ?, org_name = ?, sector = ?, attr_method = ?, attr_confidence = ?, attr_conflict = ?, "
                    "needs_attribution_review = ?, status = ?, notified_on = ?, notified_via = ?, analyst = ?, updated_at = ? "
                    "WHERE lead_id = ?",
                    [today, elig, reason, prior, notes, a["org_id"], a["org_name"], a["sector"], a["attr_method"],
                     a["attr_confidence"], a["attr_conflict"], review, status, notified_on, notified_via, analyst, now, lid]))

    if dry_run:
        log(f"DRY-RUN: {len(ops)} change(s) not applied")
    else:
        commit_with_snapshot(ctx, ops)
    log(f"refresh {today}: {len(cands)} candidate(s); inserted {counts['inserted']}, updated {counts['updated']}, "
        f"reopened {counts['reopened']}, remediated {counts['remediated']}, owner-changed {counts['owner_changed']}, "
        f"review-flagged {counts['review_flagged']}, newly ineligible {counts['ineligible']}, eligible again "
        f"{counts['eligible_again']}, migrated legacy ids {counts['migrated']}, analyst/remediated status preserved "
        f"{counts['preserved']}; registry {'generation ' + str(reg.generation) if reg.available else 'UNAVAILABLE'}")
    log("excluded (aggregate only): " + (", ".join(f"{k}={v}" for k, v in excluded.items() if v) or "none"))
    return counts, excluded


def print_summary(con):
    rows = con.execute("SELECT tier, evidence_type, status, count(*) FROM leads WHERE eligible GROUP BY 1, 2, 3 ORDER BY 1, 2, 3").fetchall()
    print(f"\n{'tier':24} {'evidence_type':16} {'status':16} {'leads':>6}")
    for tier, et, st, n in rows:
        print(f"{tier:24} {et:16} {st:16} {n:6}")
    tot = con.execute("SELECT count(*), count(DISTINCT ip), count(DISTINCT org_name), sum((NOT eligible)::int), "
                      "sum(needs_attribution_review::int), sum((coalesce(attr_conflict, '') <> '')::int) FROM leads").fetchone()
    attr = con.execute("SELECT attr_confidence, count(*) FROM leads WHERE eligible GROUP BY 1 ORDER BY 2 DESC").fetchall()
    meth = con.execute("SELECT attr_method, count(*) FROM leads WHERE eligible GROUP BY 1 ORDER BY 2 DESC").fetchall()
    print(f"\ntotal {tot[0]} lead(s) on {tot[1]} host(s) / {tot[2]} org(s); ineligible (hidden) {tot[3] or 0}; needs attribution "
          f"review {tot[4] or 0} (registry conflicts {tot[5] or 0}); attribution confidence: "
          + ", ".join(f"{c or 'none'}={n}" for c, n in attr) + "; methods: " + ", ".join(f"{m or '-'}={n}" for m, n in meth))


# --- list / set / digest ---------------------------------------------------------------

RANK_SQL = """
WITH svc AS (
  SELECT lo.ip, lo.port, lo.transport, max(v.epss) AS epss
  FROM store.latest_observed lo JOIN store.vulns v ON v.observation_id = lo.observation_id AND v.date = lo.date GROUP BY 1, 2, 3),
cve AS (
  SELECT lo.ip, lo.port, lo.transport, v.cve, max(v.epss) AS epss
  FROM store.latest_observed lo JOIN store.vulns v ON v.observation_id = lo.observation_id AND v.date = lo.date GROUP BY 1, 2, 3, 4)
SELECT l.*, COALESCE(c.epss, s.epss) AS epss
FROM leads l
LEFT JOIN cve c ON c.ip = l.ip AND c.port = l.port AND c.transport = l.transport AND c.cve = l.evidence_key
LEFT JOIN svc s ON s.ip = l.ip AND s.port = l.port AND s.transport = l.transport
{where}
ORDER BY {rank_case}, {sev_case}, COALESCE(c.epss, s.epss) DESC NULLS LAST, {tier_case}, l.first_seen, l.ip, l.port, l.lead_id
{limit}
"""


def _case(col, mapping, default):
    return "CASE " + " ".join(f"WHEN {col} = '{k}' THEN {v}" for k, v in mapping.items()) + f" ELSE {default} END"


def ranked_leads(ctx, tier=None, status=None, sector=None, evidence=None, org=None, limit=None, ip=None, statuses=None,
                 include_ineligible=False):
    conds, params = [], []
    if not include_ineligible:
        conds.append("l.eligible")
    for col, val in (("l.tier", tier), ("l.status", status), ("l.sector", sector), ("l.evidence_type", evidence),
                     ("l.ip", canon_ip(ip) if ip else None)):
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
                          rank_case=_case("l.evidence_type", EVIDENCE_RANK, 9), sev_case=_case("l.severity", SEVERITY_RANK, 9),
                          tier_case=_case("l.tier", TIER_RANK, 9), limit=f"LIMIT {int(limit)}" if limit else "")
    return fetch_dicts(ctx.con, sql, params)


def print_list(rows):
    print(f"{'lead_id':16} {'tier':22} {'evidence':14} {'conf':6} {'ip':15} {'port':>5} {'tp':4} {'status':12} {'first':10} "
          f"{'last':10} {'epss':>5} {'attr':22} {'flags':5}  org")
    for r in rows:
        attr = f"{r.get('attr_confidence') or 'none'}/{(r.get('attr_method') or '-')[:16]}"
        flags = ("R" if r.get("needs_attribution_review") else "") + ("C" if r.get("attr_conflict") else "") + \
                ("" if r.get("eligible", True) else "X")
        print(f"{r['lead_id']:16} {(r['tier'] or ''):22} {r['evidence_type']:14} {r['confidence']:6} {r['ip']:15} {r['port']:5} "
              f"{norm_transport(r.get('transport')):4} {r['status']:12} {r['first_seen']} {r['last_seen']} "
              f"{_fmt_epss(r.get('epss')):>5} {attr:22} {flags:5}  {(r['org_name'] or UNATTRIBUTED)[:36]}")
    print(f"{len(rows)} lead(s)")


def set_status(ctx, lid, status=None, via=None, analyst=None, note=None, today=None, review_cleared=False,
               needs_review=False, dry_run=False):
    if status is not None and status not in STATUSES:
        raise SystemExit(f"ERROR: status must be one of {', '.join(STATUSES)}")
    if status is None and not (review_cleared or needs_review or note):
        raise SystemExit("ERROR: nothing to set (give --status, --note, --review-cleared or --needs-review)")
    con = ctx.con
    today = today or date.today()
    old = fetch_dicts(con, "SELECT * FROM leads WHERE lead_id = ?", [lid])
    if not old:
        raise SystemExit(f"ERROR: no lead {lid}")
    old = old[0]
    new_status = status or old["status"]
    msg = (f"{old['status']} -> {new_status}" if status else "note") + (f" via {via}" if via else "") \
        + (f" by {analyst}" if analyst else "") + (f": {note}" if note else "") \
        + ("; attribution review cleared" if review_cleared else "") + ("; flagged for attribution review" if needs_review else "")
    notes = _append_note(old.get("notes") or "", _stamp(today, msg))
    sets, params = ["status = ?", "notes = ?", "updated_at = ?"], [new_status, notes, datetime.now()]
    if status and status != old["status"]:
        sets.append("prior_status = ?"); params.append(old["status"])
    if via:
        sets.append("notified_via = ?"); params.append(via)
    if analyst:
        sets.append("analyst = ?"); params.append(analyst)
    if status == "notified" and not old.get("notified_on"):
        sets.append("notified_on = ?"); params.append(today)
    if review_cleared:
        sets.append("needs_attribution_review = FALSE")
    if needs_review:
        sets.append("needs_attribution_review = TRUE")
    params.append(lid)
    if dry_run:
        log(f"DRY-RUN: would apply '{msg}' to {lid}")
        return
    kind = "status" if status else ("review_cleared" if review_cleared else "review_flagged" if needs_review else "note")
    ops = [(f"UPDATE leads SET {', '.join(sets)} WHERE lead_id = ?", params),
           ("INSERT INTO lead_events VALUES (?, ?, ?, ?)", [datetime.now(), lid, kind, msg])]
    commit_with_snapshot(ctx, ops, snapshot_before_commit=True)
    log(f"{lid}: {msg} ({old['ip']}:{old['port']} {old['evidence_type']}, {old.get('org_name') or UNATTRIBUTED})")


def _stats(vals):
    if not vals:
        return "n/a"
    return (f"n={len(vals)}, median {statistics.median(vals):.0f}d, mean {statistics.mean(vals):.1f}d, min {min(vals)}d, "
            f"max {max(vals)}d")


def digest(ctx, today, weekly=False):
    con = ctx.con
    since = today - timedelta(days=7) if weekly else None
    leads = fetch_dicts(con, "SELECT * FROM leads WHERE eligible AND tier NOT IN ('residential', 'honeypot')")
    life = {(canon_ip(r["ip"]), r["port"], norm_transport(r["transport"])): r for r in
            fetch_dicts(con, "SELECT ip, port, transport, first_seen, last_seen FROM store.lifecycle")}
    es = {(canon_ip(r["ip"]), r["port"], norm_transport(r["transport"])): r["status"] for r in
          fetch_dicts(con, "SELECT ip, port, transport, status FROM store.exposure_status")}
    newest = con.execute("SELECT max(date) FROM store.observations").fetchone()[0]
    hidden = con.execute("SELECT count(*) FROM leads WHERE NOT eligible").fetchone()[0]
    per = {}
    for l in leads:
        s = per.setdefault(l["sector"] or "other", {"new": 0, "queued": 0, "notified": 0, "acknowledged": 0, "remediated": 0,
                                                    "other": 0, "gone_days": [], "notified_to_gone": [], "open_age": [],
                                                    "leads": 0, "attr": {}, "review": 0})
        s["leads"] += 1
        s["review"] += int(bool(l.get("needs_attribution_review")))
        ac = l.get("attr_confidence") or "none"
        s["attr"][ac] = s["attr"].get(ac, 0) + 1
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
           f"Store newest day: {newest}. Residential/honeypot tiers excluded; {hidden} ineligible lead(s) hidden. "
           f"{'Counts are for the last 7 days; ' if weekly else ''}days-to-disappear = days a lead's service stayed visible "
           "after we raised the lead (lifecycle / exposure_status = 'gone'); notified-to-gone = days from notification to the "
           "service disappearing. A disappeared service is *no longer observed* — the best passive proxy for remediation we "
           "have, not proof of it.", "",
           "| sector | leads | new | queued | notified | acknowledged | remediated | other | needs review | attribution (conf=n) |",
           "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|"]
    for sec in sorted(per):
        s = per[sec]
        attr = ", ".join(f"{k}={v}" for k, v in sorted(s["attr"].items()))
        out.append(f"| {sec} | {s['leads']} | {s['new']} | {s['queued']} | {s['notified']} | {s['acknowledged']} | "
                   f"{s['remediated']} | {s['other']} | {s['review']} | {attr} |")
    out += ["", "## Remediation measurement", ""]
    for sec in sorted(per):
        s = per[sec]
        out.append(f"- **{sec}** — days-to-disappear: {_stats(s['gone_days'])}; notified-to-gone: {_stats(s['notified_to_gone'])}; "
                   f"still-open lead age: {_stats(s['open_age'])}")
    if not per:
        out.append("- no leads yet — run `leads.py refresh`")
    ev = con.execute("SELECT evidence_type, confidence, count(*) FROM leads WHERE eligible GROUP BY 1, 2 ORDER BY 3 DESC").fetchall()
    out += ["", "## By evidence type", "", "| evidence_type | confidence | leads |", "|---|---|---:|"]
    out += [f"| {e} | {c} | {n} |" for e, c, n in ev]
    return "\n".join(out) + "\n"


# --- CLI ---------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Persisted leads over the exposure store.")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--leads-dir", default=LEADS_DIR)
    ap.add_argument("--today")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("refresh")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--ledger", default=LEDGER_PATH)
    r.add_argument("--hits-dir", default=HITS_DIR)
    r.add_argument("--ioc", default=IOC_PATH)
    r.add_argument("--registry-dir", default=REGISTRY_DIR, help="store/registry (CURRENT pointer + generations)")
    r.add_argument("--ss-parquet", default=SS_EVENTS_PARQUET)
    ls = sub.add_parser("list")
    for opt in ("--tier", "--status", "--sector", "--evidence", "--org", "--ip"):
        ls.add_argument(opt)
    ls.add_argument("--limit", type=int, default=50)
    ls.add_argument("--include-ineligible", action="store_true")
    st = sub.add_parser("set")
    st.add_argument("lead_id")
    st.add_argument("--status", choices=STATUSES)
    st.add_argument("--via")
    st.add_argument("--analyst")
    st.add_argument("--note")
    st.add_argument("--review-cleared", action="store_true")
    st.add_argument("--needs-review", action="store_true")
    st.add_argument("--dry-run", action="store_true")
    dg = sub.add_parser("digest")
    dg.add_argument("--weekly", action="store_true")
    dg.add_argument("--out")
    args = ap.parse_args(argv)
    today = _parse_date(args.today) if args.today else date.today()
    if args.today and today is None:
        ap.error("--today must be YYYY-MM-DD")
    if args.cmd == "refresh":
        ctx = open_ctx(args.db, args.leads_dir, write=True)
        try:
            refresh(ctx, today, dry_run=args.dry_run, registry_dir=args.registry_dir, ledger_path=args.ledger,
                    hits_dir=args.hits_dir, ioc_path=args.ioc, ss_parquet=args.ss_parquet)
            print_summary(ctx.con)
        finally:
            ctx.close()
        return 0
    if args.cmd == "set":
        ctx = open_ctx(args.db, args.leads_dir, write=True)
        try:
            ensure_leads_db(ctx)
            set_status(ctx, args.lead_id, args.status, args.via, args.analyst, args.note, today,
                       review_cleared=args.review_cleared, needs_review=args.needs_review, dry_run=args.dry_run)
        finally:
            ctx.close()
        return 0
    ctx = open_ctx(args.db, args.leads_dir, write=False)
    try:
        if args.cmd == "list":
            print_list(ranked_leads(ctx, args.tier, args.status, args.sector, args.evidence, args.org, args.limit, ip=args.ip,
                                    include_ineligible=args.include_ineligible))
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
