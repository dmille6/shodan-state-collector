#!/usr/bin/env python3
"""
registry.py — owner registry lookups (Phase 2).

Pure, in-memory, no network. Loads the registry Parquet files written by
build_registry.py (store/registry/*.parquet) and answers two questions fast
enough for ~100k calls in a report run:

    Attributor().load().lookup("130.39.1.1")
        -> {"org_id": "la-lsu", "org_name": "Louisiana State University", "sector": ...,
            "jurisdiction": ..., "method": "registry_network", "confidence": "high",
            "evidence": "prefix 130.39.0.0/16 (curated ...)", "as_of": "2026-09-15"}
    Attributor().load().lookup_domain("vpn.ochsner.org")
        -> the la-ochsner org row (+ "domain": "ochsner.org")

Order of evidence in lookup(): a live longest-prefix match on registry_networks
(OTS CIDR or curated prefix — both high) beats the precomputed ip_attribution
row, which already encodes the full precedence of build_registry.attribute_ip().

This module also holds the small pure helpers build_registry.py and the tests
share: CSV loading/validation, label-boundary domain suffix matching and the
longest-prefix table. Nothing here touches the network or the DuckDB store
(read_parquet only).
"""
import csv
import ipaddress
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REGISTRY_REF = os.path.join(SCRIPT_DIR, "reference", "registry")
REGISTRY_STORE = os.path.join(SCRIPT_DIR, "store", "registry")

# Column contracts (PHASE2_INTERFACES.md). Order matters: it is the Parquet order.
ORG_COLS = ["org_id", "name", "sector", "jurisdiction", "aliases", "domains",
            "contact_route", "notes", "source", "as_of"]
NET_COLS = ["prefix", "asn", "org_id", "source", "confidence", "as_of"]
DOM_COLS = ["domain", "org_id", "source", "confidence", "as_of"]
ATTR_COLS = ["ip", "org_id", "org_name", "sector", "jurisdiction", "method",
             "confidence", "evidence", "as_of"]
SECTORS = {"critical_infrastructure", "government", "education", "healthcare", "energy",
           "water", "telecom", "finance", "small_business", "out_of_state", "other"}
JURISDICTIONS = {"state", "parish", "municipal", "federal", "private", "out_of_state"}
CONFIDENCES = {"high", "medium", "low"}


# --- CSV loading -------------------------------------------------------------

def read_csv(path, required):
    """Rows of a UTF-8 CSV as stripped dicts. Blank lines are skipped; a header
    missing any `required` column raises ValueError (a registry file with the
    wrong columns must fail loudly, not attribute silently)."""
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.DictReader(fh)
        missing = [c for c in required if c not in (rd.fieldnames or [])]
        if missing:
            raise ValueError(f"{path}: missing column(s) {', '.join(missing)}")
        rows = []
        for raw in rd:
            row = {k: (v or "").strip() for k, v in raw.items() if k is not None}
            if any(row.values()):
                rows.append(row)
    return rows


def load_orgs(path):
    """orgs.csv -> list of org dicts, validated: unique org_id, known sector and
    jurisdiction values, lower-cased domains."""
    rows = read_csv(path, ORG_COLS)
    seen = set()
    for r in rows:
        if not r["org_id"] or r["org_id"] in seen:
            raise ValueError(f"{path}: missing or duplicate org_id {r['org_id']!r}")
        seen.add(r["org_id"])
        bad = {s for s in split_multi(r["sector"], "|")} - SECTORS
        if bad:
            raise ValueError(f"{path}: {r['org_id']}: unknown sector {sorted(bad)}")
        if r["jurisdiction"] and r["jurisdiction"] not in JURISDICTIONS:
            raise ValueError(f"{path}: {r['org_id']}: unknown jurisdiction {r['jurisdiction']!r}")
        r["domains"] = ";".join(domain_key(d) for d in split_multi(r["domains"], ";"))
    return rows


CONF_RANK = {"high": 3, "medium": 2, "low": 1}


def min_conf(*levels):
    """The weakest of several confidence levels ('high','medium') -> 'medium'.
    Unknown/blank levels count as 'low'."""
    return min(levels, key=lambda c: CONF_RANK.get(c, 0))


def load_networks(path):
    """networks.csv -> rows. A row needs a prefix (CIDR) or an ASN; the prefix
    is normalised to its network form ('10.1.2.3/24' -> '10.1.2.0/24') and the
    ASN to 'AS<n>'. Invalid prefixes raise. Confidence: a prefix row defaults
    to high; an ASN-only row is CAPPED at medium (an ASN hosts tenants, so it
    never proves ownership of one address) whatever the CSV says."""
    rows = read_csv(path, NET_COLS)
    for r in rows:
        if r["prefix"]:
            r["prefix"] = str(ipaddress.ip_network(r["prefix"], strict=False))
        r["asn"] = norm_asn(r["asn"])
        if not (r["prefix"] or r["asn"]):
            raise ValueError(f"{path}: row for {r['org_id']} has neither prefix nor asn")
        if r["prefix"]:
            r["confidence"] = r["confidence"] if r["confidence"] in CONF_RANK else "high"
        else:
            r["confidence"] = min_conf(r["confidence"] if r["confidence"] in CONF_RANK else "medium",
                                       "medium")
    return rows


def load_domains(path):
    """domains.csv -> rows with lower-cased, dot-stripped domains."""
    rows = read_csv(path, DOM_COLS)
    for r in rows:
        r["domain"] = domain_key(r["domain"])
        r["confidence"] = r["confidence"] or "high"
    return [r for r in rows if r["domain"]]


def split_multi(text, sep):
    return [p.strip() for p in (text or "").split(sep) if p.strip()]


def norm_asn(asn):
    """'2055', 'as2055', 'AS2055 ' -> 'AS2055'; empty/NA -> ''."""
    a = (asn or "").strip().upper()
    if a.startswith("AS"):
        a = a[2:]
    return f"AS{int(a)}" if a.isdigit() else ""


# --- domain matching ---------------------------------------------------------

def domain_key(name):
    """Canonical DNS name: lower-case, no trailing dot, no leading wildcard."""
    n = (name or "").strip().lower().rstrip(".")
    if n.startswith("*."):
        n = n[2:]
    return n


def under_domain(name, root):
    """True if `name` IS `root` or sits under it at a LABEL boundary:
    'a.nola.gov' and 'nola.gov' match 'nola.gov'; 'evilnola.gov' does not."""
    n, r = domain_key(name), domain_key(root)
    return bool(r) and (n == r or n.endswith("." + r))


class DomainTable:
    """Suffix-match table: the longest registered domain that `name` falls
    under wins (so 'ololrmc.com' beats a hypothetical 'com' entry, and a
    sub-org's 'x.la.gov' beats 'la.gov'). A domain added twice keeps its FIRST
    value (add() returns False on the duplicate) — precedence is row order."""

    def __init__(self):
        self._rows = {}

    def add(self, domain, value):
        """-> True if inserted, False if the domain was already present (kept)."""
        d = domain_key(domain)
        if not d or d in self._rows:
            return False
        self._rows[d] = value
        return True

    def get(self, domain):
        return self._rows.get(domain_key(domain))

    def __len__(self):
        return len(self._rows)

    def lookup(self, name):
        """-> (matched_domain, value) or None. Walks the name's own suffixes so
        cost is O(labels), not O(table)."""
        n = domain_key(name)
        labels = n.split(".")
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in self._rows:
                return cand, self._rows[cand]
        return None


# --- longest-prefix matching -------------------------------------------------

class PrefixTable:
    """Longest-prefix match over CIDRs. Prefixes are bucketed by (family, length)
    into dicts keyed by the network's integer value, so a lookup is at most one
    dict probe per distinct prefix length present — microseconds, no tree.
    A prefix added twice keeps its FIRST value (add() returns False on the
    duplicate) — precedence is row order (OTS rows are added first)."""

    def __init__(self):
        self._buckets = {}   # (version, plen) -> {net_int: (prefix_str, value)}
        self._lengths = {4: [], 6: []}

    def add(self, prefix, value):
        """-> True if inserted, False if that exact prefix was already present (kept)."""
        net = ipaddress.ip_network(prefix, strict=False)
        key = (net.version, net.prefixlen)
        if key not in self._buckets:
            self._buckets[key] = {}
            self._lengths[net.version] = sorted(self._lengths[net.version] + [net.prefixlen],
                                                reverse=True)
        bucket = self._buckets[key]
        if int(net.network_address) in bucket:
            return False
        bucket[int(net.network_address)] = (str(net), value)   # str(net) keeps the family's notation
        return True

    def get(self, prefix):
        """Value stored for exactly this prefix, or None."""
        net = ipaddress.ip_network(prefix, strict=False)
        hit = self._buckets.get((net.version, net.prefixlen), {}).get(int(net.network_address))
        return hit[1] if hit else None

    def __len__(self):
        return sum(len(b) for b in self._buckets.values())

    def lookup(self, ip):
        """-> (prefix_str, value) of the most specific containing prefix, or None.
        The prefix string is the stored network in its own family's notation
        ('2001:db8::/32', never an integer re-rendered as IPv4). Unparseable
        input -> None (never raises: rDNS names get passed in)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        bits = addr.max_prefixlen
        n = int(addr)
        for plen in self._lengths[addr.version]:
            net_int = (n >> (bits - plen)) << (bits - plen)
            hit = self._buckets[(addr.version, plen)].get(net_int)
            if hit is not None:
                return hit
        return None


# --- the Attributor ----------------------------------------------------------

def _read_parquet(con, path):
    """Parquet -> list of dicts (empty list if the file is absent)."""
    if not os.path.isfile(path):
        return []
    rel = con.execute(f"SELECT * FROM read_parquet('{path}')")
    cols = [d[0] for d in rel.description]
    return [dict(zip(cols, row)) for row in rel.fetchall()]


class Attributor:
    """In-memory owner lookups over store/registry/*.parquet.

    load(store_dir=None): read registry_orgs / registry_networks / registry_domains /
    ip_attribution (any may be missing -> empty). Returns self.
    lookup(ip) -> dict | None ; lookup_domain(name) -> org dict | None.
    """

    def __init__(self):
        self.orgs = {}                 # org_id -> org row
        self.networks = PrefixTable()  # prefix -> network row
        self.domains = DomainTable()   # domain -> domain row
        self.attribution = {}          # ip -> ip_attribution row
        self.store_dir = None

    def load(self, store_dir=None):
        import duckdb
        self.store_dir = store_dir or REGISTRY_STORE
        con = duckdb.connect()
        try:
            for o in _read_parquet(con, os.path.join(self.store_dir, "registry_orgs.parquet")):
                self.orgs[o["org_id"]] = o
            for n in _read_parquet(con, os.path.join(self.store_dir, "registry_networks.parquet")):
                if n.get("prefix"):
                    self.networks.add(n["prefix"], n)
            for d in _read_parquet(con, os.path.join(self.store_dir, "registry_domains.parquet")):
                self.domains.add(d["domain"], d)
            for a in _read_parquet(con, os.path.join(self.store_dir, "ip_attribution.parquet")):
                self.attribution[a["ip"]] = a
        finally:
            con.close()
        return self

    def org(self, org_id):
        return self.orgs.get(org_id)

    def _network_hit(self, ip):
        hit = self.networks.lookup(ip)
        if not hit:
            return None
        prefix, row = hit
        org = self.orgs.get(row.get("org_id") or "", {})
        src = (row.get("source") or "")
        return {
            "org_id": row.get("org_id") or "",
            "org_name": org.get("name", ""),
            "sector": org.get("sector", ""),
            "jurisdiction": org.get("jurisdiction", ""),
            "method": "ots_cidr" if src.startswith("ots") else "registry_network",
            "confidence": row.get("confidence") or "high",
            "evidence": f"prefix {prefix} ({src})" + (f" agency={row['agency']}" if row.get("agency") else ""),
            "as_of": str(row.get("as_of") or ""),
        }

    def lookup(self, ip):
        """Owner of one IP: live longest-prefix match on registry_networks first
        (curated/OTS CIDRs are the strongest evidence and may be newer than the
        last build), then the precomputed ip_attribution row. None if unknown.
        A precomputed row with no org_id (e.g. a lone cymru_asn observation) is
        still returned — its evidence tells the analyst which network it is on."""
        hit = self._network_hit(ip)
        if hit:
            return hit
        row = self.attribution.get(ip)
        if row is None:
            return None
        return {k: ("" if row.get(k) is None else str(row.get(k))) for k in ATTR_COLS if k != "ip"}

    def lookup_domain(self, name):
        """Org that owns a DNS name (suffix match on registry_domains, label
        boundary, longest domain wins) -> org row + 'domain' + 'confidence', or None."""
        hit = self.domains.lookup(name)
        if not hit:
            return None
        domain, row = hit
        org = self.orgs.get(row.get("org_id") or "")
        if org is None:
            return None
        out = dict(org)
        out["domain"] = domain
        out["confidence"] = row.get("confidence") or "high"
        return out


if __name__ == "__main__":
    # Spot-check: registry.py <ip-or-name> [...]
    import sys
    att = Attributor().load()
    print(f"registry: {len(att.orgs)} orgs, {len(att.networks)} prefixes, "
          f"{len(att.domains)} domains, {len(att.attribution):,} attributed IPs")
    for q in sys.argv[1:]:
        r = att.lookup(q) if q[:1].isdigit() or ":" in q else att.lookup_domain(q)
        print(f"  {q:40s} -> {r}")
