#!/usr/bin/env python3
"""
build_registry.py — assemble the owner registry (Phase 2) into store/registry/.

Inputs
  reference/registry/orgs.csv, networks.csv, domains.csv   hand-curated seed (see docs/REGISTRY.md)
  reference/registry/ots_cidrs.csv   OPTIONAL drop-in from OTS: prefix, agency, contact
                                     (state-owned space; absent is fine)
  store/exposure.duckdb  view latest_observed (read-only): every IP + rDNS + cert names
  Team Cymru bulk whois  (TCP whois.cymru.com:43)  asn / as_name / bgp prefix per IP
  ARIN RDAP              (https://rdap.arin.net/registry/autnum/<n>)  AS name + registrant org,
                         only for ASNs seen on government / education / critical_infrastructure hosts

Outputs (Parquet, DuckDB-readable)
  store/registry/registry_orgs.parquet, registry_networks.parquet, registry_domains.parquet
  store/registry/ip_attribution.parquet   one row per IP: ip, org_id, org_name, sector,
                                          jurisdiction, method, confidence, evidence, as_of

Attribution precedence per IP (first hit wins, see attribute_ip):
  ots_cidr high > registry_network high > domain_dns high > cert high > registry_asn medium
  > arin_rdap medium (RDAP registrant name must match a registry org/alias; otherwise the
  RDAP org is recorded as evidence only, confidence low, org_id empty) > cymru_asn low.

External calls are cached (reference/registry/cymru_cache.json, rdap_cache.json, each
entry with an as_of) and fail-soft: a feed being down degrades the run, never aborts it.
PASSIVE: nothing here contacts any host in the store.

Usage:
    build_registry.py                 # full build
    build_registry.py --dry-run       # everything except writing store/registry/
    build_registry.py --skip-network  # no Cymru / RDAP calls (cache only)
    build_registry.py --limit 500     # first 500 IPs only (testing)
"""
import argparse
import csv
import glob
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta

import registry as rg
from triage_report import BULK_NETWORK_KW, first_kw

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "store", "exposure.duckdb")
CYMRU_CACHE = os.path.join(rg.REGISTRY_REF, "cymru_cache.json")
RDAP_CACHE = os.path.join(rg.REGISTRY_REF, "rdap_cache.json")
OTS_CIDRS = os.path.join(rg.REGISTRY_REF, "ots_cidrs.csv")
OTS_COLS = ["prefix", "agency", "contact"]
OTS_DEFAULT_ORG = "la-ots"          # state space whose agency we cannot name maps to OTS itself

CYMRU_HOST, CYMRU_PORT = "whois.cymru.com", 43
CYMRU_BATCH = 1000                  # IPs per TCP session
CYMRU_TTL_DAYS = 30                 # re-query an IP's ASN after this long
RDAP_URL = "https://rdap.arin.net/registry/autnum/{asn}"
RDAP_SLEEP = 0.5                    # seconds between RDAP calls (be a polite client)
RDAP_TTL_DAYS = 90                  # registrant data is slow-moving
RDAP_ERROR_TTL_DAYS = 3             # retry a failed ASN after this long
USER_AGENT = "shodan_query-registry/0.1 (passive exposure pipeline)"
TIERED = ("government", "education", "critical_infrastructure")
UNATTRIBUTED = ""                   # org_id when no registry org is known

# Corporate suffix words dropped from the END of a name (repeatedly) before
# comparing an RDAP registrant / OTS agency / roster name to a registry alias.
# Punctuation is removed first, so 'L.L.C.' -> 'l l c' -> 'llc' -> dropped.
CORP_SUFFIXES = {"inc", "incorporated", "llc", "llp", "lp", "corp", "corporation", "company",
                 "co", "ltd", "limited", "plc"}
_SPACED_ABBREV = {"l l c": "llc", "l l p": "llp", "l p": "lp", "p l c": "plc"}


def log(msg):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} - {msg}", flush=True)


# --- registry CSVs -----------------------------------------------------------

def load_registry_csvs(ref_dir=rg.REGISTRY_REF):
    """orgs, networks, domains from the three seed CSVs. Domains listed on an
    org row (orgs.domains) are merged into the domain table when domains.csv
    does not already carry them, so a single edit to orgs.csv is enough."""
    orgs = rg.load_orgs(os.path.join(ref_dir, "orgs.csv"))
    networks = rg.load_networks(os.path.join(ref_dir, "networks.csv"))
    domains = rg.load_domains(os.path.join(ref_dir, "domains.csv"))
    # Duplicate domains: the FIRST row wins (domains.csv order, then orgs.csv);
    # a duplicate pointing at another org is logged as a conflict and dropped.
    known, unique = {}, []
    for d in domains:
        if d["domain"] in known:
            if known[d["domain"]] != d["org_id"]:
                log(f"domains.csv: {d['domain']} listed for {known[d['domain']]} and {d['org_id']}; "
                    f"keeping the first ({known[d['domain']]})")
            continue
        known[d["domain"]] = d["org_id"]
        unique.append(d)
    domains = unique
    for o in orgs:
        for d in rg.split_multi(o["domains"], ";"):
            if d in known:
                if known[d] != o["org_id"]:
                    log(f"orgs.csv: {o['org_id']} lists {d}, already owned by {known[d]} in domains.csv; ignored")
                continue
            domains.append({"domain": d, "org_id": o["org_id"], "source": "orgs.csv",
                            "confidence": "high", "as_of": o["as_of"]})
            known[d] = o["org_id"]
    by_id = {o["org_id"]: o for o in orgs}
    for row in networks + domains:
        if row["org_id"] and row["org_id"] not in by_id:
            raise ValueError(f"unknown org_id {row['org_id']!r} in networks/domains")
    # An ASN-only row for a carrier org would attribute that carrier's whole
    # customer base to it: dropped with a log line (a prefix row is fine).
    kept = []
    for n in networks:
        org = by_id.get(n["org_id"], {})
        if not n["prefix"] and any(is_carrier_name(a) for a in org_aliases(org) if org):
            log(f"networks.csv: ASN-only row {n['asn']} for carrier org {n['org_id']} skipped")
            continue
        kept.append(n)
    return orgs, kept, domains


def load_ots_cidrs(path, orgs, as_of):
    """OTS drop-in (prefix, agency, contact) -> network rows, source='ots_cidrs',
    confidence high. The agency text is matched against org names/aliases; when
    no org matches, the prefix is attributed to OTS itself (la-ots) and the
    agency is kept on the row as evidence. Absent file -> []."""
    if not os.path.isfile(path):
        return []
    rows = []
    for r in rg.read_csv(path, OTS_COLS):
        try:
            prefix = str(ipaddress.ip_network(r["prefix"], strict=False))
        except ValueError:
            log(f"ots_cidrs.csv: skipping bad prefix {r['prefix']!r}")
            continue
        org_id = match_org_name(r["agency"], orgs) or OTS_DEFAULT_ORG
        rows.append({"prefix": prefix, "asn": "", "org_id": org_id, "source": "ots_cidrs",
                     "confidence": "high", "as_of": as_of,
                     "agency": r["agency"], "contact": r["contact"]})
    return rows


# --- org-name matching (RDAP registrant / OTS agency -> registry org) -----------

def norm_org_name(name):
    """Comparable form of an organisation name, in this order: lower-case;
    punctuation -> spaces ('L.L.C.' -> 'l l c', then 'llc'); a LEADING 'the'
    dropped; corporate suffix words dropped from the END, repeatedly ('Acme
    Holdings Co Inc' -> 'acme holdings'); whitespace collapsed. 'Acme LLC' and
    'Acme Inc' therefore both become 'acme' — such collisions are detected by
    NameIndex and treated as ambiguous, never matched."""
    words = re.sub(r"[^a-z0-9]+", " ", (name or "").lower()).split()
    t = " ".join(words)
    for spaced, joined in _SPACED_ABBREV.items():
        t = re.sub(rf"\b{spaced}\b", joined, t)
    words = t.split()
    if words and words[0] == "the":
        words = words[1:]
    while words and words[-1] in CORP_SUFFIXES:
        words.pop()
    return " ".join(words)


def org_aliases(org):
    return [org["name"]] + rg.split_multi(org.get("aliases", ""), ";")


def is_carrier_name(name):
    """True when an organisation name is a consumer ISP / transit / cloud /
    hosting operator (triage_report.BULK_NETWORK_KW = RESI_ORG_KW +
    TRANSIT_HOST_KW, whole-word). Its address space holds CUSTOMERS, so a
    registrant match on it must never attribute an IP — 'LUS Fiber' subscribers
    are not Lafayette Utilities System — and a customer name seen on it is
    only medium evidence."""
    return first_kw(BULK_NETWORK_KW, norm_org_name(name)) is not None


class NameIndex:
    """normalised name -> org_id over every registry org name and alias.
    A key that two DIFFERENT orgs share ('Acme LLC' / 'Acme Inc') is AMBIGUOUS:
    it is logged once and never matches. Carrier names are never indexed."""

    def __init__(self, orgs):
        self.index, self.ambiguous = {}, set()
        for o in orgs:
            for alias in org_aliases(o):
                key = norm_org_name(alias)
                if not key or is_carrier_name(alias):
                    continue
                owner = self.index.setdefault(key, o["org_id"])
                if owner != o["org_id"]:
                    self.ambiguous.add(key)
        for key in sorted(self.ambiguous):
            log(f"registry: name '{key}' is claimed by more than one org — ambiguous, never matched")
            self.index.pop(key, None)

    def match(self, name):
        """org_id whose name/alias EQUALS `name` after normalisation, else None."""
        key = norm_org_name(name)
        if not key or key in self.ambiguous or is_carrier_name(name):
            return None
        return self.index.get(key)


def match_org_name(name, orgs):
    """org_id whose name or an alias EQUALS `name` after normalisation, else
    None. Equality only, deliberately: 'St. Tammany Parish' must not claim
    'St. Tammany Parish School Board', 'Dow' must not claim 'Dow Jones'. Add
    the exact registrant name as an alias instead. Carrier names and ambiguous
    names never match. `orgs` may be a list of org rows or a NameIndex."""
    idx = orgs if isinstance(orgs, NameIndex) else NameIndex(orgs)
    return idx.match(name)


# --- Team Cymru bulk whois ---------------------------------------------------

def parse_cymru(text):
    """Parse a verbose bulk-whois reply into {ip: {asn, as_name, prefix, cc,
    registry, allocated}}. Format per line:
        AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    Header/'Error' lines are ignored; 'NA' fields become ''. A multi-origin
    prefix lists several ASes ('2055 32440'); the first is kept."""
    out = {}
    for line in text.splitlines():
        if "|" not in line or line.lower().startswith(("bulk mode", "error", "as ")):
            continue
        f = [p.strip() for p in line.split("|")]
        if len(f) < 7 or not f[1]:
            continue
        asn = rg.norm_asn(f[0].split()[0] if f[0] and f[0] != "NA" else "")
        out[f[1]] = {"asn": asn, "prefix": "" if f[2] == "NA" else f[2],
                     "cc": "" if f[3] == "NA" else f[3], "registry": "" if f[4] == "NA" else f[4],
                     "allocated": "" if f[5] == "NA" else f[5],
                     "as_name": "" if f[6] == "NA" else f[6]}
    return out


def cymru_query(ips, timeout=90):
    """One bulk session: 'begin / verbose / <ips> / end' -> raw reply text.
    Raises on socket trouble; the caller decides how soft to fail."""
    payload = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    with socket.create_connection((CYMRU_HOST, CYMRU_PORT), timeout=timeout) as s:
        s.sendall(payload.encode())
        chunks = []
        while True:
            d = s.recv(65536)
            if not d:
                break
            chunks.append(d)
    return b"".join(chunks).decode("utf-8", "replace")


class JsonCache:
    """{"as_of": date, "entries": {key: {..., "as_of": date}}} on disk.
    Entries older than ttl_days count as missing. Corrupt/absent file -> empty."""

    def __init__(self, path, ttl_days):
        self.path, self.ttl = path, timedelta(days=ttl_days)
        self.entries = {}
        try:
            data = json.load(open(path))
            self.entries = data.get("entries", {})
        except (OSError, ValueError):
            pass

    def fresh(self, key, today, ttl_days=None):
        """The cached entry for `key` if it is younger than the TTL (the cache's
        default, or `ttl_days`), else None."""
        e = self.entries.get(key)
        if not e:
            return None
        ttl = self.ttl if ttl_days is None else timedelta(days=ttl_days)
        try:
            if today - date.fromisoformat(e.get("as_of", "1970-01-01")) > ttl:
                return None
        except ValueError:
            return None
        return e

    def get(self, key):
        """The cached entry whatever its age (None if absent)."""
        return self.entries.get(key)

    def usable(self, key, today, ttl_days=None):
        """Fresh entry if there is one; otherwise the EXPIRED entry marked
        stale=True, stale_as_of=<its date> — old evidence beats no evidence
        when a source could not be re-queried. None only when never cached."""
        rec = self.fresh(key, today, ttl_days)
        if rec is not None:
            return rec
        rec = self.entries.get(key)
        if rec is None:
            return None
        return dict(rec, stale=True, stale_as_of=rec.get("as_of", ""))

    def put(self, key, value, today):
        self.entries[key] = dict(value, as_of=today.isoformat())

    def save(self, today):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        json.dump({"as_of": today.isoformat(), "entries": self.entries}, open(tmp, "w"))
        os.replace(tmp, self.path)


def fill_cymru(cache, ips, today, network=True, query=cymru_query, status=None):
    """Ensure `cache` holds a fresh Cymru record for every IP. Batches the
    misses; a failed batch is logged and skipped (fail-soft). Returns
    {ip: record}: a fresh record where one exists, else the EXPIRED cached
    record marked stale (old evidence beats none; it is replaced only by
    fresher data). `status`, if given, receives {"attempted", "failed"} batch
    counts so the caller can tell an outage from a clean run."""
    status = status if status is not None else {}
    status.update(attempted=0, failed=0)
    missing = [ip for ip in dict.fromkeys(ips) if cache.fresh(ip, today) is None]
    if missing and network:
        log(f"Cymru: {len(missing):,} IP(s) to look up in batches of {CYMRU_BATCH}")
        for i in range(0, len(missing), CYMRU_BATCH):
            batch = missing[i:i + CYMRU_BATCH]
            status["attempted"] += 1
            try:
                got = parse_cymru(query(batch))
            except Exception as exc:               # DNS, timeout, refused, ...
                status["failed"] += 1
                log(f"Cymru: batch {i // CYMRU_BATCH + 1} failed ({exc}); continuing")
                continue
            for ip, rec in got.items():
                cache.put(ip, rec, today)
        cache.save(today)
    elif missing:
        log(f"Cymru: --skip-network; {len(missing):,} IP(s) have no fresh cached ASN")
    out = {}
    for ip in ips:
        rec = cache.usable(ip, today)
        if rec:
            out[ip] = rec
    n_stale = sum(1 for r in out.values() if r.get("stale"))
    if n_stale:
        log(f"Cymru: {n_stale:,} IP(s) kept an expired cached record (stale) — not re-queried")
    return out


# --- ARIN RDAP ---------------------------------------------------------------

def _vcard_fn(entity):
    for item in (entity.get("vcardArray") or [None, []])[1] or []:
        if item and item[0] == "fn" and len(item) > 3:
            return item[3]
    return ""


def parse_rdap_autnum(doc):
    """RDAP autnum JSON -> {handle, name, org_handle, org_name}. ONLY an entity
    whose roles include 'registrant' is the owner; technical / abuse /
    administrative / noc entities (contacts, resellers) are never used, so a
    document without a registrant yields org_name ''."""
    ents = doc.get("entities") or []
    reg = next((e for e in ents if "registrant" in (e.get("roles") or [])), None) or {}
    return {"handle": doc.get("handle") or "", "name": doc.get("name") or "",
            "org_handle": reg.get("handle") or "", "org_name": _vcard_fn(reg)}


def rdap_fetch(asn, timeout=20):
    """GET the ARIN RDAP autnum document for 'AS<n>'. Raises on failure."""
    req = urllib.request.Request(RDAP_URL.format(asn=asn[2:]),
                                 headers={"Accept": "application/rdap+json",
                                          "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _rdap_cached(cache, asn, today):
    """Fresh cached RDAP record: a good record lives RDAP_TTL_DAYS, an error
    record only RDAP_ERROR_TTL_DAYS (so a registry outage is retried soon but
    not hammered)."""
    rec = cache.fresh(asn, today)
    if rec and "error" in rec:
        rec = cache.fresh(asn, today, ttl_days=RDAP_ERROR_TTL_DAYS)
    return rec


def fill_rdap(cache, asns, today, network=True, fetch=rdap_fetch, sleep=time.sleep, status=None):
    """Ensure `cache` holds a fresh RDAP record for every ASN, sleeping
    RDAP_SLEEP between live calls. A failure is cached as {"error": ..., "prev":
    <last good record>} with a short TTL, so the last good registrant survives
    an outage and is returned marked stale. Returns {asn: record} for ASNs with
    a good (fresh or stale) record. `status` receives {"attempted", "failed"}."""
    status = status if status is not None else {}
    status.update(attempted=0, failed=0)
    missing = [a for a in dict.fromkeys(asns) if a and _rdap_cached(cache, a, today) is None]
    if missing and network:
        log(f"RDAP: {len(missing)} ASN(s) to look up at {RDAP_SLEEP}s spacing")
        for n, asn in enumerate(missing):
            status["attempted"] += 1
            try:
                cache.put(asn, parse_rdap_autnum(fetch(asn)), today)
            except Exception as exc:
                status["failed"] += 1
                log(f"RDAP: {asn} failed ({exc})")
                old = cache.get(asn) or {}
                prev = old.get("prev") if "error" in old else old      # keep the last GOOD record
                cache.put(asn, {"error": str(exc)[:200], "prev": prev or None}, today)
            if n < len(missing) - 1:
                sleep(RDAP_SLEEP)
        cache.save(today)
    elif missing:
        log(f"RDAP: --skip-network; {len(missing)} ASN(s) have no fresh cached record")
    out = {}
    for asn in asns:
        rec = cache.usable(asn, today)
        if rec and "error" in rec:                  # outage: fall back to the last good record
            prev = rec.get("prev")
            rec = dict(prev, stale=True, stale_as_of=prev.get("as_of", "")) if prev else None
        if rec:
            out[asn] = rec
    n_stale = sum(1 for r in out.values() if r.get("stale"))
    if n_stale:
        log(f"RDAP: {n_stale} ASN(s) kept an expired/previous record (stale)")
    return out


# --- the store ---------------------------------------------------------------

# One record per IP. asn / org / tier come from the NEWEST observation of that
# IP (collection date, then banner scan time, then record id — the same order
# latest_observed itself uses), never from an arbitrary row: a host re-tiered
# yesterday must be judged by yesterday's tier. Names are unioned over all ports.
HOSTS_SQL = """
WITH ranked AS (
  SELECT *, row_number() OVER (PARTITION BY ip
             ORDER BY date DESC, banner_ts DESC NULLS LAST, observation_id DESC) AS ip_rn
  FROM {latest}
)
SELECT ip,
       max(CASE WHEN ip_rn = 1 THEN asn END) AS asn,
       max(CASE WHEN ip_rn = 1 THEN org END) AS org,
       max(CASE WHEN ip_rn = 1 THEN tier END) AS tier,
       string_agg(DISTINCT hostnames, ',') AS hostnames,
       string_agg(DISTINCT CASE WHEN coalesce(tags,'') NOT LIKE '%self-signed%'
                                THEN cert_sans END, ',') AS cert_sans,
       string_agg(DISTINCT CASE WHEN coalesce(tags,'') NOT LIKE '%self-signed%'
                                THEN cert_cn END, ',') AS cert_cn,
       string_agg(DISTINCT CASE WHEN coalesce(tags,'') NOT LIKE '%self-signed%'
                                THEN cert_org END, '|') AS cert_org
FROM ranked
GROUP BY ip ORDER BY ip
"""


# Same definition as build_store.refresh_views' latest_observed, over the raw
# partitions — used when exposure.duckdb is locked by a running build_store.
LATEST_FROM_PARQUET = """(
  SELECT * EXCLUDE (rn) FROM (
    SELECT *, row_number() OVER (PARTITION BY ip, port, transport
             ORDER BY date DESC, banner_ts DESC NULLS LAST, observation_id DESC) AS rn
    FROM read_parquet('{glob}', union_by_name=true)
  ) WHERE rn = 1
)"""


def _query_hosts(db_path, sql):
    """Run `sql` (with a `{latest}` placeholder) against the store: the DuckDB
    file's latest_observed view first (read-only), else — when another process
    holds its lock — the observation parquet partitions beside it. Raises only
    if both fail."""
    import duckdb
    try:
        con = duckdb.connect(db_path, read_only=True)
        sql = sql.format(latest="latest_observed")
    except Exception as exc:
        glob_ = os.path.join(os.path.dirname(db_path), "observations", "date=*", "*.parquet")
        log(f"store: exposure.duckdb unavailable ({str(exc).splitlines()[0][:90]}); "
            f"reading observation partitions directly")
        con = duckdb.connect()
        sql = sql.format(latest=LATEST_FROM_PARQUET.format(glob=glob_))
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def read_hosts(db_path, limit=None):
    """One record per IP from latest_observed: Shodan asn/org, tier, rDNS
    names and the DNS names of NON-self-signed certificates (a self-signed
    cert asserts nothing about ownership). Read-only. Returns None when the
    store cannot be read at all (the caller must then keep the previous
    ip_attribution.parquet); {} when it is readable but empty."""
    sql = HOSTS_SQL + (f" LIMIT {int(limit)}" if limit else "")
    try:
        rows = _query_hosts(db_path, sql)
    except Exception as exc:
        log(f"store: cannot read latest_observed ({exc}); attribution will be skipped")
        return None
    hosts = {}
    for ip, asn, org, tier, hostnames, sans, cns, cert_org in rows:
        names = {rg.domain_key(n) for n in (hostnames or "").split(",") if n.strip()}
        certs = {rg.domain_key(n) for n in ((sans or "") + "," + (cns or "")).split(",")
                 if n.strip()}
        hosts[ip] = {"asn": rg.norm_asn(asn), "org": org or "", "tier": tier or "",
                     "hostnames": sorted(names), "cert_names": sorted(certs),
                     "cert_orgs": sorted({o.strip() for o in (cert_org or "").split("|") if o.strip()})}
    return hosts


# --- attribution -------------------------------------------------------------

def _org_fields(org):
    return {"org_name": org.get("name", ""), "sector": org.get("sector", ""),
            "jurisdiction": org.get("jurisdiction", "")}


def _row(ip, org_id, orgs_by_id, method, confidence, evidence, as_of, conflict=""):
    """One ip_attribution row. A non-empty `conflict` (structured: 'rdns=la-x;
    cert=la-y', 'duplicate domain d: a vs b', 'prefix=la-a;rdns=la-b') means
    the evidence disagrees, and confidence is then capped at medium."""
    org = orgs_by_id.get(org_id, {}) if org_id else {}
    if conflict:
        confidence = rg.min_conf(confidence, "medium")
    return {"ip": ip, "org_id": org_id or UNATTRIBUTED, **_org_fields(org),
            "method": method, "confidence": confidence, "evidence": evidence, "as_of": as_of,
            "conflict": conflict}


def _domain_hit(names, domain_table):
    """Best registry-domain match among `names`: the org matched by most names
    wins; ties go to the longest matched domain.
    -> (org_id, name, domain, others, row_confidence) or None; `others` are the
    other orgs whose domains also appear in `names`, best first."""
    hits = defaultdict(list)
    for n in names:
        h = domain_table.lookup(n)
        if h:
            hits[h[1]["org_id"]].append((n, h[0], h[1].get("confidence") or "high"))
    if not hits:
        return None
    order = sorted(hits, key=lambda o: (-len(hits[o]), -max(len(d) for _, d, _ in hits[o]), o))
    best = order[0]
    name, dom, conf = max(hits[best], key=lambda t: len(t[1]))
    return best, name, dom, order[1:], conf


def _name_conflicts(dh, ch, dups, prefix_org=None):
    """Structured conflict notes from the rDNS hit `dh` and the cert hit `ch`
    evaluated TOGETHER with the org of a matched prefix, if any: ONE note of the
    form 'prefix=la-p;rdns=la-a,la-b;cert=la-c' (parts present only when they
    exist) whenever those sources point at more than one org, plus a note for
    every matched domain that was a discarded duplicate in domains.csv."""
    notes = []
    rdns_orgs = ([dh[0]] + dh[3]) if dh else []
    cert_orgs = ([ch[0]] + ch[3]) if ch else []
    if len(set(rdns_orgs) | set(cert_orgs) | ({prefix_org} if prefix_org else set())) > 1:
        parts = [("prefix", [prefix_org] if prefix_org else []), ("rdns", rdns_orgs), ("cert", cert_orgs)]
        notes.append(";".join(f"{k}={','.join(v)}" for k, v in parts if v))
    for h in (dh, ch):
        if h and h[2] in dups.get("domain", {}):
            notes.append(f"duplicate domain {h[2]}: {dups['domain'][h[2]]}")
    return notes


def _stale_note(rec):
    return f" (stale as_of {rec.get('stale_as_of') or rec.get('as_of', '?')})" if rec and rec.get("stale") else ""


def attribute_ip(ip, host, ctx):
    """One ip_attribution row for `ip`, by precedence:
      1 ots_cidr / registry_network (longest prefix in ctx.prefixes)  row confidence (high)
      2 domain_dns: an rDNS hostname under a registry domain               high*
      3 cert: a non-self-signed certificate CN/SAN under a registry domain  high*
           * = the domain row's confidence, lowered to medium when the IP sits on
             carrier / hosting space (a customer name on shared hosting proves the
             tenant, not the address)
      4 registry_asn: the IP's ASN (Cymru, else Shodan) is on networks.csv  row confidence (<= medium)
      5 arin_rdap: RDAP registrant name equals a registry org/alias        medium
                   (no match -> evidence only, org_id empty, low)
      6 cymru_asn / shodan_asn: only the routing origin is known           low
      7 nothing at all: method 'none', low.
    rDNS and certificate names are evaluated TOGETHER first: when they (or the
    prefix that won) point at different orgs, or a matched prefix / domain / ASN
    was a discarded duplicate, the row carries a structured `conflict` and its
    confidence is capped at medium (see _row). Evidence from an expired cache
    record that could not be refreshed is marked '(stale as_of <date>)'.
    `ctx` is a dict: prefixes (PrefixTable), asn_orgs ({asn: network row}),
    domains (DomainTable), orgs ({org_id: org}), names (NameIndex, optional),
    dups ({'prefix'|'domain'|'asn': {key: 'la-a vs la-b'}}, optional),
    cymru ({ip: rec}), rdap ({asn: rec}), as_of (str)."""
    orgs, as_of, dups = ctx["orgs"], ctx["as_of"], ctx.get("dups") or {}
    cy = ctx["cymru"].get(ip) or {}
    net_name = cy.get("as_name") or host.get("org") or ""
    shared_net = net_name if is_carrier_name(net_name) else ""
    dh = _domain_hit(host.get("hostnames") or [], ctx["domains"])
    ch = _domain_hit(host.get("cert_names") or [], ctx["domains"])
    hit = ctx["prefixes"].lookup(ip)
    notes = _name_conflicts(dh, ch, dups, prefix_org=hit[1]["org_id"] if hit else None)

    if hit:
        prefix, row = hit
        method = "ots_cidr" if row["source"].startswith("ots") else "registry_network"
        ev = f"prefix {prefix} ({row['source']})" + (f" agency={row['agency']}" if row.get("agency") else "")
        if prefix in dups.get("prefix", {}):
            notes.append(f"duplicate prefix {prefix}: {dups['prefix'][prefix]}")
        return _row(ip, row["org_id"], orgs, method, row.get("confidence") or "high", ev, as_of,
                    ";".join(notes))
    for h, what, method in ((dh, "rDNS", "domain_dns"), (ch, "cert name", "cert")):
        if not h:
            continue
        org_id, name, dom, others, conf = h
        conf = rg.min_conf(conf, "high")
        ev = f"{what} {name} under {dom}"
        if others:
            ev += f"; SHARED IP: names of {', '.join(others)} also present"
        if shared_net:
            conf = rg.min_conf(conf, "medium")
            ev += f"; on shared/carrier network '{shared_net}'"
        return _row(ip, org_id, orgs, method, conf, ev, as_of, ";".join(notes))
    asn = cy.get("asn") or host.get("asn") or ""
    asn_src = "Cymru" if cy.get("asn") else "Shodan"
    net_ev = f"{asn} {net_name}".strip()
    if cy.get("prefix"):
        net_ev += f" prefix {cy['prefix']}"
    net_ev += _stale_note(cy)
    if asn and asn in ctx["asn_orgs"]:
        row = ctx["asn_orgs"][asn]
        if asn in dups.get("asn", {}):
            notes.append(f"duplicate asn {asn}: {dups['asn'][asn]}")
        return _row(ip, row["org_id"], orgs, "registry_asn",
                    rg.min_conf(row.get("confidence") or "medium", "medium"),
                    f"{net_ev} ({asn_src}); ASN on networks.csv ({row['source']})", as_of, ";".join(notes))
    rd = ctx["rdap"].get(asn) if asn else None
    if rd and (rd.get("org_name") or rd.get("name")):
        rdap_ev = (f"{net_ev} ({asn_src}); ARIN RDAP {rd.get('name', '')} registrant "
                   f"{rd.get('org_handle', '')} '{rd.get('org_name', '')}'{_stale_note(rd)}")
        names = ctx.get("names") or NameIndex(list(orgs.values()))
        org_id = names.match(rd.get("org_name", "")) if rd.get("org_name") else None
        if org_id:
            return _row(ip, org_id, orgs, "arin_rdap", "medium", rdap_ev + " matches registry alias", as_of)
        return _row(ip, UNATTRIBUTED, orgs, "arin_rdap", "low", rdap_ev + " (no registry org)", as_of)
    if asn:
        return _row(ip, UNATTRIBUTED, orgs, "cymru_asn" if cy.get("asn") else "shodan_asn",
                    "low", net_ev, as_of)
    return _row(ip, UNATTRIBUTED, orgs, "none", "low", "no ASN, prefix, rDNS or certificate evidence", as_of)


# --- sector rosters (Phase 2: refresh_rosters.py) --------------------------------
# Authoritative NAME lists per sector (EPA SDWIS water systems, NPPES healthcare
# orgs, NCES/IPEDS schools, EIA/BSEE energy, Census governments). They carry no
# addresses, so they attribute a host only when a name the host asserts about
# itself matches EXACTLY (after normalisation): a CA-issued certificate subject O
# (medium) or, weaker, the Shodan org field when it is not a carrier (low).

ROSTER_DIR = os.path.join(SCRIPT_DIR, "reference", "rosters")
ROSTER_JURISDICTION = {"parish": "parish", "municipal_city": "municipal", "municipal_town": "municipal",
                       "municipal_village": "municipal"}


def load_rosters(roster_dir=ROSTER_DIR):
    """{normalised name: roster row} across reference/rosters/*.csv. The same
    name+sector listed twice keeps the first row; a key that two DIFFERENT
    names or sectors normalise to ('Acme LLC' / 'Acme Inc', or one name on two
    sector rosters) is AMBIGUOUS: logged once and never matched."""
    index, ambiguous = {}, set()
    for path in sorted(glob.glob(os.path.join(roster_dir, "*.csv"))):
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                name = row.get("name") or ""
                key = norm_org_name(name)
                if len(key) < 6 or is_carrier_name(name):
                    continue
                prev = index.setdefault(key, row)
                if prev is not row and ((prev.get("sector"), (prev.get("name") or "").lower())
                                        != (row.get("sector"), name.lower())):
                    ambiguous.add(key)
    n_amb = len(ambiguous)
    for key in ambiguous:
        index.pop(key, None)
    if n_amb:
        log(f"rosters: {n_amb} name(s) normalise to a key shared by different rows — ambiguous, never matched"
            f" (e.g. {sorted(ambiguous)[:3]})")
    return index


def roster_attribution(ip, host, rosters, as_of):
    """ip_attribution row from a roster-name match, or None."""
    if not rosters:
        return None
    for conf, names, what in (("medium", host.get("cert_orgs") or [], "cert O"),
                              ("low", [host.get("org") or ""], "Shodan org")):
        for name in names:
            if not name or is_carrier_name(name):
                continue
            row = rosters.get(norm_org_name(name))
            if not row:
                continue
            sector, sub = row.get("sector", ""), row.get("subsector", "")
            org_id = f"roster:{sector}:{norm_org_name(name)}"
            return {"ip": ip, "org_id": org_id, "org_name": row.get("name", name), "sector": sector,
                    "jurisdiction": ROSTER_JURISDICTION.get(sub, "private"),
                    "method": "roster_name", "confidence": conf,
                    "evidence": f"{what} '{name}' = {sector}/{sub} roster ({row.get('source', '')[:60]})",
                    "as_of": as_of}
    return None


def build_context(orgs, networks, domains, cymru, rdap, as_of):
    """Index the registry tables for attribute_ip(). Precedence on duplicates
    is explicit and logged: the FIRST row wins for an equal prefix, ASN or
    domain — networks are passed OTS rows first, so an OTS prefix always beats
    a curated row for the same prefix."""
    prefixes = rg.PrefixTable()
    asn_orgs = {}
    dups = {"prefix": {}, "domain": {}, "asn": {}}     # key -> 'kept vs dropped' (different orgs only)
    for n in networks:
        if n.get("prefix"):
            if not prefixes.add(n["prefix"], n):
                first = prefixes.get(n["prefix"])
                if first["org_id"] != n["org_id"]:
                    dups["prefix"][n["prefix"]] = f"{first['org_id']} vs {n['org_id']}"
                if first["org_id"] != n["org_id"] or first["source"] != n["source"]:
                    log(f"networks: prefix {n['prefix']} also listed for {n['org_id']} ({n['source']}); "
                        f"keeping {first['org_id']} ({first['source']})")
        elif n.get("asn"):
            first = asn_orgs.setdefault(n["asn"], n)
            if first is not n and first["org_id"] != n["org_id"]:
                dups["asn"][n["asn"]] = f"{first['org_id']} vs {n['org_id']}"
                log(f"networks: ASN {n['asn']} also listed for {n['org_id']}; keeping {first['org_id']}")
    dt = rg.DomainTable()
    for d in domains:
        if not dt.add(d["domain"], d):
            first = dt.get(d["domain"])
            if first["org_id"] != d["org_id"]:
                dups["domain"][d["domain"]] = f"{first['org_id']} vs {d['org_id']}"
                log(f"domains: {d['domain']} also listed for {d['org_id']}; keeping {first['org_id']}")
    return {"prefixes": prefixes, "asn_orgs": asn_orgs, "domains": dt, "dups": dups,
            "orgs": {o["org_id"]: o for o in orgs}, "names": NameIndex(orgs),
            "cymru": cymru, "rdap": rdap, "as_of": as_of}


# --- parquet output ----------------------------------------------------------

def write_parquet(con, rows, cols, out_path, stage=None):
    """rows (dicts) -> Parquet with exactly `cols` as VARCHAR columns, via a
    temp NDJSON + COPY (no pandas on the server). Written to `stage` (default:
    out_path + '.tmp') and renamed onto out_path atomically — unless `stage` is
    given, in which case the caller renames (see write_generation). Zero rows
    still produce a file with the right schema so DuckDB views never break."""
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    tmp = tempfile.NamedTemporaryFile("w", suffix=".ndjson", delete=False)
    try:
        for r in rows:
            tmp.write(json.dumps({c: ("" if r.get(c) is None else str(r.get(c))) for c in cols}) + "\n")
        tmp.close()
        sel = ", ".join(f"CAST({c} AS VARCHAR) AS {c}" for c in cols)
        out_tmp = stage or (out_path + ".tmp")
        if rows:
            con.execute(f"COPY (SELECT {sel} FROM read_json_auto('{tmp.name}', "
                        f"format='newline_delimited') ) TO '{out_tmp}' (FORMAT PARQUET)")
        else:
            empty = ", ".join(f"CAST(NULL AS VARCHAR) AS {c}" for c in cols)
            con.execute(f"COPY (SELECT {empty} WHERE false) TO '{out_tmp}' (FORMAT PARQUET)")
        if stage is None:
            os.replace(out_tmp, out_path)
    finally:
        os.unlink(tmp.name)


KEEP_GENERATIONS = 3


def write_generation(out_dir, tables, carry=(), keep=KEEP_GENERATIONS, now=None):
    """Publish parquet tables as ONE generation: a fresh
    out_dir/gen-<YYYYmmddTHHMMSS>/ receives every table (and a copy of each
    `carry` file from the live generation, e.g. ip_attribution when the store
    was unreadable); only when all files are complete is the CURRENT pointer
    switched to it with an atomic rename, so a reader (registry.Attributor)
    always sees one consistent set. The newest `keep` generations are retained,
    older gen-* directories are removed. A failure while writing leaves the
    live generation and pointer untouched and removes the half-built
    directory. Returns the new generation directory."""
    os.makedirs(out_dir, exist_ok=True)
    stamp = (now or datetime.now()).strftime("%Y%m%dT%H%M%S")
    gen_name = f"gen-{stamp}"
    gen = os.path.join(out_dir, gen_name)
    if os.path.exists(gen):                                 # two builds in one second
        gen_name += f"-{os.getpid()}"
        gen = os.path.join(out_dir, gen_name)
    live = rg.resolve_generation(out_dir)
    os.makedirs(gen)
    import duckdb
    con = duckdb.connect()
    try:
        for name, (rows, cols) in tables.items():
            write_parquet(con, rows, cols, os.path.join(gen, name))
        for name in carry:
            src = os.path.join(live, name)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(gen, name))
            else:
                log(f"generation: no previous {name} to carry forward")
    except Exception:
        shutil.rmtree(gen, ignore_errors=True)
        raise
    finally:
        con.close()
    pointer = os.path.join(out_dir, rg.CURRENT_POINTER)
    with open(pointer + ".tmp", "w") as fh:
        fh.write(gen_name + "\n")
    os.replace(pointer + ".tmp", pointer)
    gens = sorted(d for d in os.listdir(out_dir)
                  if d.startswith("gen-") and os.path.isdir(os.path.join(out_dir, d)))
    for old in gens[:-keep] if keep and len(gens) > keep else []:
        if old != gen_name:
            shutil.rmtree(os.path.join(out_dir, old), ignore_errors=True)
    return gen


def keep_stronger_previous(attribution, previous, reason):
    """When the network step failed, an IP whose NEW row is weaker than its row
    in the previous generation keeps the previous row (evidence annotated), so
    an outage never silently downgrades attribution. Returns the count kept."""
    kept = 0
    for i, row in enumerate(attribution):
        prev = previous.get(row["ip"])
        if not prev:
            continue
        if rg.CONF_RANK.get(str(prev.get("confidence")), 0) > rg.CONF_RANK.get(row["confidence"], 0):
            old = {c: ("" if prev.get(c) is None else str(prev.get(c))) for c in rg.ATTR_COLS}
            old["evidence"] += f" (kept from previous build as_of {old['as_of']}: {reason})"
            attribution[i] = old
            kept += 1
    return kept


def cymru_candidates(hosts):
    """IPs that may be sent to Team Cymru: every NON-residential host. The bulk
    whois is plain TCP/43 and the list leaves the box, so consumer-broadband
    subscribers (tier 'residential') are never sent — they keep Shodan's ASN."""
    return sorted(ip for ip, h in hosts.items() if h.get("tier") != "residential")


def summarize(attribution, orgs_by_id, n_orgs, n_nets, n_doms, unreached):
    """Human summary of one build, for the log / the final reply."""
    by_mc = Counter((r["method"], r["confidence"]) for r in attribution)
    by_org = Counter(r["org_id"] for r in attribution if r["org_id"])
    lines = [f"Registry: {n_orgs} orgs, {n_nets} network rows, {n_doms} domains; "
             f"{len(attribution):,} IPs attributed, "
             f"{sum(by_org.values()):,} to a registry org"]
    lines.append("  by method / confidence:")
    for (m, c), n in sorted(by_mc.items(), key=lambda kv: -kv[1]):
        lines.append(f"    {m:18s} {c:7s} {n:>8,}")
    lines.append("  top orgs:")
    for org_id, n in by_org.most_common(15):
        lines.append(f"    {n:>6,}  {org_id:22s} {orgs_by_id.get(org_id, {}).get('name', '')}")
    n_conflict = sum(1 for r in attribution if r.get("conflict"))
    n_stale = sum(1 for r in attribution if "(stale as_of" in r.get("evidence", ""))
    lines.append(f"  rows with a conflict flag: {n_conflict:,}; rows on stale cached evidence: {n_stale:,}")
    if unreached:
        lines.append("  sources not reached: " + "; ".join(unreached))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="build everything, write nothing to store/")
    ap.add_argument("--skip-network", action="store_true", help="no Cymru / RDAP calls; caches only")
    ap.add_argument("--limit", type=int, help="attribute only the first N IPs (testing)")
    ap.add_argument("--db", default=DB_PATH, help="path to exposure.duckdb")
    ap.add_argument("--out", default=rg.REGISTRY_STORE, help="output dir for the parquet files")
    args = ap.parse_args()
    today = date.today()
    as_of = today.isoformat()
    network = not args.skip_network

    orgs, networks, domains = load_registry_csvs()
    ots = load_ots_cidrs(OTS_CIDRS, orgs, as_of)
    log(f"registry CSVs: {len(orgs)} orgs, {len(networks)} network rows, {len(domains)} domains"
        + (f"; OTS drop-in: {len(ots)} prefixes" if ots else "; no ots_cidrs.csv (optional)"))
    networks = ots + networks           # OTS rows first so equal prefixes prefer the OTS row

    hosts = read_hosts(args.db, args.limit)
    store_ok = hosts is not None
    hosts = hosts or {}
    log(f"store: {len(hosts):,} IP(s) from latest_observed" + (f" (limit {args.limit})" if args.limit else ""))

    unreached = []
    cymru_cache = JsonCache(CYMRU_CACHE, CYMRU_TTL_DAYS)
    cymru_ips = cymru_candidates(hosts)          # residential subscribers never leave the box
    cy_status = {}
    cymru = fill_cymru(cymru_cache, cymru_ips, today, network=network, status=cy_status)
    if cy_status.get("failed"):
        unreached.append(f"Team Cymru whois.cymru.com:43 ({cy_status['failed']}/{cy_status['attempted']} batches failed)")
    log(f"Cymru: {len(cymru):,}/{len(cymru_ips):,} non-residential IPs have an ASN record "
        f"({len(hosts) - len(cymru_ips):,} residential IPs kept Shodan's ASN, not sent)")

    tiered_asns = sorted({(cymru.get(ip) or {}).get("asn") or h["asn"]
                          for ip, h in hosts.items() if h["tier"] in TIERED} - {""})
    rdap_cache = JsonCache(RDAP_CACHE, RDAP_TTL_DAYS)
    rd_status = {}
    rdap = fill_rdap(rdap_cache, tiered_asns, today, network=network, status=rd_status)
    if rd_status.get("failed") and rd_status["failed"] == rd_status.get("attempted"):
        unreached.append(f"ARIN RDAP rdap.arin.net (all {rd_status['failed']} lookups failed)")
    log(f"RDAP: {len(rdap)}/{len(tiered_asns)} tiered ASNs resolved")

    ctx = build_context(orgs, networks, domains, cymru, rdap, as_of)
    attribution = [attribute_ip(ip, hosts[ip], ctx) for ip in sorted(hosts)]
    # Roster names fill in where the registry could not name an owner.
    rosters = load_rosters()
    n_roster = 0
    for i, row in enumerate(attribution):
        if row["org_id"] == UNATTRIBUTED:
            alt = roster_attribution(row["ip"], hosts[row["ip"]], rosters, as_of)
            if alt:
                attribution[i] = alt
                n_roster += 1
    log(f"rosters: {len(rosters):,} names loaded; {n_roster:,} IPs attributed by roster_name")

    # A network outage must not downgrade what the last build already knew.
    if unreached and store_ok:
        previous = rg.Attributor().load(args.out).attribution
        kept = keep_stronger_previous(attribution, previous, "; ".join(unreached))
        log(f"network sources failed: {kept:,} IP(s) keep their stronger previous attribution")

    if args.dry_run:
        log("--dry-run: not writing store/registry/")
    else:
        tables = {"registry_orgs.parquet": (orgs, rg.ORG_COLS),
                  "registry_networks.parquet": (networks, rg.NET_COLS + ["agency", "contact"]),
                  "registry_domains.parquet": (domains, rg.DOM_COLS)}
        carry = ()
        if store_ok:
            tables["ip_attribution.parquet"] = (attribution, rg.ATTR_COLS)
        else:
            carry = ("ip_attribution.parquet",)
            log("store unreadable: ip_attribution.parquet NOT rebuilt — previous generation's copy carried forward")
        gen = write_generation(args.out, tables, carry=carry)
        log(f"published generation {os.path.basename(gen)} ({len(tables) + len(carry)} parquet files) -> {args.out}/CURRENT")

    print(summarize(attribution, ctx["orgs"], len(orgs), len(networks), len(domains), unreached))
    return 0


if __name__ == "__main__":
    sys.exit(main())
