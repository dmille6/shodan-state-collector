"""Tests for the Phase-2 leads table, notification packets and Shadowserver ingest.

A fabricated store (observations + vulns tables with the store's derived views,
ioc_ips / ioc_cidrs / ioc_matches like the integrator's), a published registry
generation (store/registry/CURRENT -> gen dir with orgs / networks / domains /
ip_attribution incl. `conflict`), a tripwire ledger and a Shadowserver parquet
exercise: evidence rules, CVE / report-class scoped identity, shared appliance
definitions, eligibility (status preserved), registry generation read +
unavailable vs explicit-unattributed, conflict -> review, service binding
accept/refuse, ownership reconciliation on every lead, migration marker + legacy
mapping, snapshot/pointer durability, remediation only on 'gone', reopen only on
a newer scan, rebuild recovery, ranking, digest, packet content / escaping /
status filtering / single-org / appendix authorization from the current registry /
host-level freshness, Shadowserver classes, validation + quarantine, lock, exit
codes, IPv6 canonicalisation, HMAC2.

Run:  venv/bin/python -m pytest tests/test_leads_packets.py -q
"""
import gzip
import json
import os
import sys
from datetime import date, datetime

import pytest

duckdb = pytest.importorskip("duckdb")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import build_store as bs             # noqa: E402
import leads as L                    # noqa: E402
import make_packet as MP             # noqa: E402
import ingest_shadowserver as SS     # noqa: E402

TODAY = date(2026, 9, 15)
NEWEST = date(2026, 9, 14)
OBS_COLS = ["observation_id", "date", "ip", "port", "transport", "asn", "org", "isp", "product", "version", "cpe23", "service",
            "info", "city", "region_code", "hostnames", "domains", "tags", "banner_ts", "hash", "tier", "tier_reason",
            "http_title", "http_host", "http_server", "cert_cn", "cert_org", "cert_issuer", "cert_sans", "cert_expired",
            "cert_expires", "cert_sha256", "jarm"]
OBS_TYPES = {"date": "DATE", "port": "INTEGER", "banner_ts": "TIMESTAMP", "cert_expired": "BOOLEAN"}
VIEWS = [
    """CREATE OR REPLACE VIEW latest_observed AS
       SELECT * EXCLUDE (rn) FROM (SELECT *, row_number() OVER (PARTITION BY ip, port, transport
              ORDER BY date DESC, banner_ts DESC NULLS LAST, observation_id DESC) AS rn FROM observations) WHERE rn = 1""",
    """CREATE OR REPLACE VIEW exposure_status AS
       SELECT *, date_diff('day', date, (SELECT max(date) FROM observations)) AS days_since_seen,
              CASE WHEN date_diff('day', date, (SELECT max(date) FROM observations)) <= 14 THEN 'active'
                   WHEN date_diff('day', date, (SELECT max(date) FROM observations)) <= 45 THEN 'stale'
                   ELSE 'gone' END AS status FROM latest_observed""",
    """CREATE OR REPLACE VIEW current_state AS
       SELECT * EXCLUDE (days_since_seen, status) FROM exposure_status WHERE status = 'active'""",
    """CREATE OR REPLACE VIEW lifecycle AS
       SELECT ip, port, transport, min(date) AS first_seen, max(date) AS last_seen, count(DISTINCT date) AS days_observed,
              date_diff('day', min(date), max(date)) + 1 AS span_days FROM observations GROUP BY ip, port, transport""",
    """CREATE OR REPLACE VIEW ioc_matches AS
       WITH cs AS (SELECT *, CAST(split_part(ip, '.', 1) AS UBIGINT) * 16777216 + CAST(split_part(ip, '.', 2) AS UBIGINT) * 65536
                   + CAST(split_part(ip, '.', 3) AS UBIGINT) * 256 + CAST(split_part(ip, '.', 4) AS UBIGINT) AS ip_int FROM current_state)
       SELECT cs.* EXCLUDE (ip_int), i.sources AS ioc_sources, NULL AS ioc_cidr FROM cs JOIN ioc_ips i ON i.ip = cs.ip
       UNION ALL
       SELECT cs.* EXCLUDE (ip_int), c.sources, c.cidr FROM cs JOIN ioc_cidrs c ON cs.ip_int BETWEEN c.lo AND c.hi""",
]


def obs(ip, port, tier, org="Test University", d=NEWEST, transport="tcp", ts=None, **kw):
    row = {c: None for c in OBS_COLS}
    row.update({"observation_id": f"{ip}-{port}-{d}", "date": d, "ip": ip, "port": port, "transport": transport, "org": org,
                "tier": tier, "product": "nginx", "service": "http", "banner_ts": ts or datetime(d.year, d.month, d.day, 3, 0, 0),
                "hash": "1", "tags": "", "hostnames": "", "city": "Baton Rouge"})
    row.update(kw)
    return row


def vuln(o, cve, verified=False, in_kev=True, epss=0.5, cvss=9.8):
    return {"observation_id": o["observation_id"], "date": o["date"], "ip": o["ip"], "port": o["port"],
            "transport": o["transport"], "cve": cve, "cvss": cvss, "in_kev": in_kev, "epss": epss, "verified": verified}


def add_obs(con, rows):
    if rows:
        con.executemany(f"INSERT INTO observations VALUES ({', '.join('?' * len(OBS_COLS))})", [[r[c] for c in OBS_COLS] for r in rows])


def add_vulns(con, rows):
    cols = ["observation_id", "date", "ip", "port", "transport", "cve", "cvss", "in_kev", "epss", "verified"]
    if rows:
        con.executemany(f"INSERT INTO vulns VALUES ({', '.join('?' * len(cols))})", [[r[c] for c in cols] for r in rows])


def ss_ev(rtype, ts, ip, port, proto="tcp", tag=None, sev="high"):
    return {"report_type": rtype, "timestamp": ts, "ip": ip, "port": port, "protocol": proto, "asn": "64512", "geo": "US",
            "tag": tag, "severity": sev, "detail": "{}", "ingested_on": TODAY}


def ip_int(ip):
    a, b, c, d = (int(x) for x in ip.split("."))
    return a * 16777216 + b * 65536 + c * 256 + d


ORGS = [["ORG-TU", "Test University", "education", "state", "", "testu.edu", "direct", "", "hand", "2026-09-15"],
        ["ORG-CT", "City of Testville", "government", "municipal", "", "testville.la.gov", "direct", "", "hand", "2026-09-15"],
        ["ORG-PJ", "Testville Police Jury", "government", "parish", "", "", "direct", "", "hand", "2026-09-15"],
        ["ORG-DW", "Delta Widgets Inc", "small_business", "private", "", "", "direct", "", "hand", "2026-09-15"],
        ["ORG-OTHER", "Other College", "education", "state", "", "", "direct", "", "hand", "2026-09-15"]]
NETWORKS = [["10.0.0.0/31", "", "ORG-TU", "curated", "high", "2026-09-15"], ["10.0.0.2/32", "", "ORG-TU", "curated", "high", "2026-09-15"]]
DOMAINS = [["testville.la.gov", "ORG-CT", "hand", "high", "2026-09-15"], ["testu.edu", "ORG-TU", "hand", "high", "2026-09-15"]]
ATTR = [  # ip, org_id, org_name, sector, jurisdiction, method, confidence, evidence, as_of, conflict
    ["10.0.0.6", "ORG-CT", "City of Testville", "government", "municipal", "domain_dns", "high", "vpn.testville.la.gov", "2026-09-15", ""],
    ["10.0.0.15", "ORG-CT", "City of Testville", "government", "municipal", "domain_dns", "high", "mail", "2026-09-15", ""],
    ["10.0.0.16", "ORG-CT", "City of Testville", "government", "municipal", "domain_dns", "high", "x", "2026-09-15", ""],
    ["10.0.0.31", "ORG-CT", "City of Testville", "government", "municipal", "domain_dns", "medium", "x", "2026-09-15", "rdns=la-ct;cert=la-pj"],
    ["10.0.0.30", "ORG-PJ", "Testville Police Jury", "government", "parish", "registry_asn", "medium", "AS1", "2026-09-15", ""],
    ["10.0.0.9", "", "", "", "", "arin_rdap", "low", "no registry org", "2026-09-15", ""],
]


def write_registry(reg_dir, attr=ATTR, networks=NETWORKS, domains=DOMAINS, orgs=ORGS, gen="gen-test"):
    """A published generation: <reg_dir>/<gen>/*.parquet + CURRENT pointer."""
    d = os.path.join(reg_dir, gen)
    os.makedirs(d, exist_ok=True)
    con = duckdb.connect()
    spec = {"registry_orgs.parquet": (["org_id", "name", "sector", "jurisdiction", "aliases", "domains", "contact_route", "notes",
                                       "source", "as_of"], orgs),
            "registry_networks.parquet": (["prefix", "asn", "org_id", "source", "confidence", "as_of"], networks),
            "registry_domains.parquet": (["domain", "org_id", "source", "confidence", "as_of"], domains),
            "ip_attribution.parquet": (["ip", "org_id", "org_name", "sector", "jurisdiction", "method", "confidence", "evidence",
                                        "as_of", "conflict"], attr)}
    for name, (cols, rows) in spec.items():
        con.execute("CREATE OR REPLACE TABLE t (" + ", ".join(f"{c} VARCHAR" for c in cols) + ")")
        if rows:
            con.executemany(f"INSERT INTO t VALUES ({', '.join('?' * len(cols))})", rows)
        con.execute(f"COPY t TO '{os.path.join(d, name)}' (FORMAT PARQUET)")
    con.close()
    with open(os.path.join(reg_dir, "CURRENT"), "w") as fh:
        fh.write(gen + "\n")


@pytest.fixture
def world(tmp_path):
    store = str(tmp_path / "store.duckdb")
    con = duckdb.connect(store)
    con.execute("CREATE TABLE observations (" + ", ".join(f"{c} {OBS_TYPES.get(c, 'VARCHAR')}" for c in OBS_COLS) + ")")
    con.execute("CREATE TABLE vulns (observation_id VARCHAR, date DATE, ip VARCHAR, port INTEGER, transport VARCHAR, cve VARCHAR, "
                "cvss DOUBLE, in_kev BOOLEAN, epss DOUBLE, verified BOOLEAN)")
    con.execute("CREATE TABLE ioc_ips (ip VARCHAR, sources VARCHAR)")
    con.execute("CREATE TABLE ioc_cidrs (cidr VARCHAR, lo UBIGINT, hi UBIGINT, sources VARCHAR)")
    a = obs("10.0.0.1", 445, "education", product="Samba")
    a2 = obs("10.0.0.1", 80, "education", product="nginx")
    b = obs("10.0.0.2", 443, "education", product="Apache httpd", version="2.4.49")
    c = obs("10.0.0.3", 443, "small_business", org="Bob's Bait", product="Apache httpd")
    d = obs("10.0.0.4", 502, "critical_infrastructure", org="Bayou Water", service="modbus", product=None)
    d2 = obs("10.0.0.5", 47808, "small_business", org="Acme Controls", service="auto", product=None)
    e = obs("10.0.0.6", 443, "government", org="City of Testville", product="FortiGate", http_title="FortiGate SSL-VPN",
            hostnames="vpn.testville.la.gov")                                                       # bound by hostname
    e2 = obs("10.0.0.6", 22, "government", org="City of Testville", product="OpenSSH")
    e3 = obs("10.0.0.6", 8080, "government", org="City of Testville", product="FortiGate")         # no name: unbound
    f = obs("10.0.0.7", 443, "small_business", org="Bob's Bait", product="FortiGate")
    g = obs("10.0.0.8", 8080, "residential", org="Cox Communications")
    h = obs("10.0.0.9", 9200, "small_business", org="Delta Widgets", product="Elasticsearch")
    i = obs("10.0.0.11", 80, "small_business", org="Delta Widgets")
    i2 = obs("10.0.0.11", 443, "small_business", org="Delta Widgets")
    j = obs("10.0.0.13", 22, "unclassified", org="Some Carrier", product="OpenSSH")
    k = obs("10.0.0.14", 502, "honeypot", org="?", service="modbus", tags="honeypot")
    sh = obs("10.0.0.15", 443, "government", org="City of Testville", product="Microsoft IIS", http_title="Outlook Web App",
             cpe23="cpe:2.3:a:microsoft:exchange_server", cert_cn="mail.testville.la.gov")          # bound by cert name
    inj = obs("10.0.0.16", 8443, "government", org="City of Testville", cert_org="City of Testville",   # bound by cert_org
              product="Evil | **bold** [link](http://x) `code`\n# heading <b>", http_title="FortiGate | *x*\r\n# h",
              hostnames="a`b|c")
    cf = obs("10.0.0.31", 443, "government", org="City of Testville", product="FortiGate", hostnames="pj.testville.la.gov")
    old = obs("10.0.0.2", 443, "education", d=date(2026, 6, 29))
    add_obs(con, [a, a2, b, c, d, d2, e, e2, e3, f, g, h, i, i2, j, k, sh, inj, cf, old])
    add_vulns(con, [vuln(a, "CVE-2020-0796", verified=True, epss=0.9), vuln(a, "CVE-2017-0144", verified=True, epss=0.95),
                    vuln(b, "CVE-2021-41773", epss=0.97), vuln(b, "CVE-2021-42013", epss=0.6), vuln(b, "CVE-2000-0001", in_kev=False),
                    vuln(c, "CVE-2021-41773"), vuln(g, "CVE-2020-0796", verified=True)])
    con.execute("INSERT INTO ioc_ips VALUES ('10.0.0.8', 'spamhaus_drop'), ('192.0.2.1', 'x')")
    con.execute("INSERT INTO ioc_cidrs VALUES ('10.0.0.12/30', ?, ?, 'spamhaus_drop')", [ip_int("10.0.0.12"), ip_int("10.0.0.15")])
    for v in VIEWS:
        con.execute(v)
    con.close()
    reg = str(tmp_path / "registry")
    write_registry(reg)
    ssp = str(tmp_path / "ss" / "events.parquet")
    SS.append_parquet([ss_ev("sinkhole_http_drone", datetime(2026, 9, 12, 4, 5, 6), "10.0.0.11", 51234, tag="avalanche-andromeda"),
                       ss_ev("scan_ssl", datetime(2026, 9, 12, 5, 0, 0), "10.0.0.11", 443, sev="low"),
                       ss_ev("sinkhole_http_drone", datetime(2026, 8, 1, 4, 5, 6), "10.0.0.13", 22, tag="old"),
                       ss_ev("sinkhole_http_drone", datetime(2026, 9, 13, 1, 0, 0), "10.0.0.30", 40000, tag="qakbot")], ssp)
    hits = tmp_path / "hits"
    hits.mkdir()
    ledger = {"hosts": {"10.0.0.9": {"first_seen": "2026-09-01", "last_seen": "2026-09-10", "selectors": ["tag:compromised"],
                                     "last_banner_ts": "2026-09-11T00:00:00"},
                        "10.0.0.10": {"first_seen": "2026-07-01", "last_seen": "2026-07-01", "selectors": ["tag:c2"]},
                        "10.0.0.20": {"first_seen": "2026-09-12", "last_seen": "2026-09-13", "selectors": ["tag:c2"],
                                      "last_banner_ts": "2026-09-13T02:00:00"}}, "_meta": {}}
    (hits / "seen_ledger.json").write_text(json.dumps(ledger))
    with gzip.open(hits / "louisiana-compromise-2026-09-10.json.gz", "wt") as fh:
        fh.write(json.dumps({"ip_str": "10.0.0.9", "port": 9200, "transport": "tcp", "tags": ["compromised", "database"],
                             "_compromise_selector": "tag:compromised", "timestamp": "2026-09-09T05:00:00"}) + "\n")
    ioc = tmp_path / "ioc_ips.json"
    ioc.write_text(json.dumps({"10.0.0.13": ["feodo"], "_cidrs": {"10.0.0.0/8": ["x"]}, "_meta": {"as_of": "x"}}))
    return {"store": store, "ldir": str(tmp_path / "leads"), "hits": hits, "reg": reg, "tmp": tmp_path,
            "paths": {"ledger_path": str(hits / "seen_ledger.json"), "hits_dir": str(hits), "ioc_path": str(ioc),
                      "registry_dir": reg, "ss_parquet": ssp}}


def ctx(w, write=True):
    return L.open_ctx(w["store"], w["ldir"], write=write)


def refresh(w, today=TODAY, **over):
    c = ctx(w)
    try:
        return L.refresh(c, today, **dict(w["paths"], **over))
    finally:
        c.close()


def rows(w, sql="SELECT * FROM leads", params=None):
    c = ctx(w, write=False)
    try:
        return L.fetch_dicts(c.con, sql, params)
    finally:
        c.close()


def by_id(w):
    return {r["lead_id"]: r for r in rows(w)}


def by_type(w):
    out = {}
    for r in rows(w):
        out.setdefault(r["evidence_type"], []).append(r)
    return out


def setst(w, lid, status=None, **kw):
    c = ctx(w)
    try:
        L.set_status(c, lid, status, today=kw.pop("today", TODAY), **kw)
    finally:
        c.close()


def add_store(w, obs_rows=(), vuln_rows=()):
    con = duckdb.connect(w["store"])
    add_obs(con, list(obs_rows))
    add_vulns(con, list(vuln_rows))
    con.close()


def time_shift(w, d):
    add_store(w, [obs("10.0.0.99", 80, "small_business", org="Newcomer", d=d)])


def packet(w, today=TODAY, **kw):
    c = ctx(w, write=False)
    try:
        return MP.build_markdown(MP.gather(c, today, registry_dir=w["reg"], **kw))
    finally:
        c.close()


def events(w, lid):
    return [e["event"] for e in rows(w, "SELECT event FROM lead_events WHERE lead_id = ? ORDER BY ts", [lid])]


def clear(w, *lids):
    for lid in lids:
        setst(w, lid, review_cleared=True, analyst="jd")


A_ID = L.lead_id("10.0.0.1", 445, "tcp", "kev_verified", "CVE-2020-0796")
A2_ID = L.lead_id("10.0.0.1", 445, "tcp", "kev_verified", "CVE-2017-0144")
B1_ID = L.lead_id("10.0.0.2", 443, "tcp", "kev_inferred", "CVE-2021-41773")
B2_ID = L.lead_id("10.0.0.2", 443, "tcp", "kev_inferred", "CVE-2021-42013")
ICS_ID = L.lead_id("10.0.0.4", 502, "tcp", "ics")
CT_ID = L.lead_id("10.0.0.9", 9200, "tcp", "compromise_tag")
CT20_ID = L.lead_id("10.0.0.20", 0, "host", "compromise_tag")
IOC_ID = L.lead_id("10.0.0.13", 0, "host", "ioc_match")
E_ID = L.lead_id("10.0.0.6", 443, "tcp", "appliance")
E3_ID = L.lead_id("10.0.0.6", 8080, "tcp", "appliance")
CF_ID = L.lead_id("10.0.0.31", 443, "tcp", "appliance")
SSC_ID = L.lead_id("10.0.0.11", 0, "host", "shadowserver", "compromise:sinkhole_http_drone")
SSE_ID = L.lead_id("10.0.0.11", 443, "tcp", "shadowserver", "exposure:scan_ssl")
SS30_ID = L.lead_id("10.0.0.30", 0, "host", "shadowserver", "compromise:x")


# --- identity / definitions ----------------------------------------------------------

def test_lead_id_scoping_and_ipv6_canonical():
    import hashlib
    assert L.lead_id("1.2.3.4", 443, "tcp", "kev_inferred", "CVE-1") == hashlib.sha1(b"1.2.3.4|443|tcp|kev_inferred|CVE-1").hexdigest()[:16]
    assert L.lead_id("1.2.3.4", 443, "tcp", "ics", "anything") == hashlib.sha1(b"1.2.3.4|443|tcp|ics").hexdigest()[:16]
    assert L.lead_id("1.2.3.4", 0, "host", "shadowserver", "compromise:a,b") == hashlib.sha1(b"1.2.3.4|0|host|shadowserver|compromise").hexdigest()[:16]
    assert L.lead_id("1.2.3.4", 0, "host", "shadowserver", "compromise:a") != L.lead_id("1.2.3.4", 0, "host", "shadowserver", "exposure:a")
    assert L.canon_ip("2001:0db8:0000::0001") == "2001:db8::1" and L.canon_ip("010.0.0.1") in ("10.0.0.1", "010.0.0.1")
    assert L.lead_id("2001:0DB8::1", 22, "tcp", "ics") == L.lead_id("2001:db8::1", 22, "tcp", "ics")


def test_appliance_definitions_shared_with_build_store():
    assert L.APPLIANCE_PATTERNS is bs.APPLIANCE_PATTERNS
    assert L.appliance_match({"product": "FortiGate", "cpe23": "", "http_title": ""})[0].startswith("Fortinet")
    assert L.appliance_match({"product": "showa", "cpe23": "", "http_title": ""}) is None


def test_transport_and_render_helpers():
    assert L.norm_transport("TCP") == "tcp" and L.norm_transport("x<y|z") == "other" and L.norm_transport("") == "tcp"
    assert MP.tp("sctp") == "other" and MP.ipc("1.2.3.4") == "1.2.3.4" and "\\|" in MP.ipc("1.2|3")
    assert MP.num("12|x") == "12\\|x" and MP.lid("z|z") == "z\\|z" and MP.status_word("weird|x") == "weird\\|x"


# --- generation + attribution ----------------------------------------------------------

def test_generation_rules_and_attribution(world):
    refresh(world)
    by = by_type(world)
    kv = {r["lead_id"]: r for r in by["kev_verified"]}
    assert set(kv) == {A_ID, A2_ID}
    a = kv[A_ID]
    assert (a["org_id"], a["org_name"], a["sector"], a["attr_method"], a["attr_confidence"], a["needs_attribution_review"]) == \
        ("ORG-TU", "Test University", "education", "registry_network", "high", False)
    assert a["org_at_first_seen"] == "Test University [ORG-TU]" and a["attr_conflict"] == ""
    assert a["last_scan_ts"] == datetime(2026, 9, 14, 3, 0, 0)
    assert {r["lead_id"] for r in by["kev_inferred"]} == {B1_ID, B2_ID}
    assert sorted(r["ip"] for r in by["ics"]) == ["10.0.0.4", "10.0.0.5"]
    app = {r["lead_id"]: r for r in by["appliance"]}
    assert sorted(r["ip"] for r in app.values()) == ["10.0.0.15", "10.0.0.16", "10.0.0.31", "10.0.0.6", "10.0.0.6"]
    # service binding: hostname / cert name / cert_org bind; a nameless service on the same ip does not
    assert app[E_ID]["org_id"] == "ORG-CT" and app[E_ID]["attr_method"] == "domain_dns" and not app[E_ID]["needs_attribution_review"]
    sh = next(r for r in app.values() if r["ip"] == "10.0.0.15")
    inj = next(r for r in app.values() if r["ip"] == "10.0.0.16")
    assert sh["org_id"] == "ORG-CT" and inj["org_id"] == "ORG-CT" and not inj["needs_attribution_review"]
    assert (app[E3_ID]["org_id"], app[E3_ID]["org_name"], app[E3_ID]["attr_method"], app[E3_ID]["attr_confidence"],
            app[E3_ID]["needs_attribution_review"]) == (None, "City of Testville", "unbound(domain_dns)", "low", True)
    # registry conflict carried and flagged
    assert app[CF_ID]["attr_conflict"] == "rdns=la-ct;cert=la-pj" and app[CF_ID]["needs_attribution_review"] and app[CF_ID]["org_id"] == "ORG-CT"
    ct = {r["lead_id"]: r for r in by["compromise_tag"]}
    assert set(ct) == {CT_ID, CT20_ID}
    assert ct[CT_ID]["last_scan_ts"] == datetime(2026, 9, 9, 5, 0, 0)          # per-service banner from the hit archive
    assert ct[CT20_ID]["last_scan_ts"] == datetime(2026, 9, 13, 2, 0, 0)       # host-level: ledger last_banner_ts
    assert ct[CT_ID]["last_event"] == date(2026, 9, 10) and ct[CT20_ID]["last_event"] == date(2026, 9, 13)
    # explicit unattributed registry row: label, low, review
    assert (ct[CT_ID]["org_id"], ct[CT_ID]["org_name"], ct[CT_ID]["attr_method"], ct[CT_ID]["attr_confidence"],
            ct[CT_ID]["needs_attribution_review"]) == (None, "Delta Widgets", "arin_rdap", "low", True)
    assert ct[CT20_ID]["org_name"] == L.UNATTRIBUTED and ct[CT20_ID]["attr_confidence"] == "none" and not ct[CT20_ID]["needs_attribution_review"]
    ss = {r["lead_id"]: r for r in by["shadowserver"]}
    assert set(ss) == {SSC_ID, SSE_ID, SS30_ID}
    assert ss[SSC_ID]["evidence_key"].startswith("compromise:") and ss[SSC_ID]["last_event"] == date(2026, 9, 12)
    # host-level evidence on a non-ownership attribution keeps the org but needs review
    assert ss[SS30_ID]["org_id"] == "ORG-PJ" and ss[SS30_ID]["attr_method"] == "registry_asn" and ss[SS30_ID]["needs_attribution_review"]
    assert ss[SS30_ID]["tier"] == "government"
    io = {r["ip"]: r for r in by["ioc_match"]}
    assert set(io) == {"10.0.0.13", "10.0.0.15"} and "CIDR range(s) 10.0.0.12/30" in io["10.0.0.13"]["evidence"]
    ips = {r["ip"] for rs in by.values() for r in rs}
    assert not ips & {"10.0.0.8", "10.0.0.14", "10.0.0.10", "192.0.2.1", "10.0.0.3", "10.0.0.7", "_cidrs"}


def test_registry_generation_pointer_is_used_not_flat_file(world):
    # a stale flat file at the registry root must be ignored in favour of CURRENT
    con = duckdb.connect()
    con.execute("CREATE TABLE t (ip VARCHAR, org_id VARCHAR, org_name VARCHAR, sector VARCHAR, jurisdiction VARCHAR, method VARCHAR, "
                "confidence VARCHAR, evidence VARCHAR, as_of VARCHAR)")
    con.execute("INSERT INTO t VALUES ('10.0.0.6', 'ORG-STALE', 'Stale Org', 'government', 'x', 'registry_network', 'high', 'x', '2026-01-01')")
    con.execute(f"COPY t TO '{os.path.join(world['reg'], 'ip_attribution.parquet')}' (FORMAT PARQUET)")
    con.close()
    refresh(world)
    assert by_id(world)[E_ID]["org_id"] == "ORG-CT"


def test_registry_unavailable_keeps_previous_attribution(world, tmp_path):
    refresh(world)
    before = by_id(world)
    empty = str(tmp_path / "noreg")
    os.makedirs(empty)
    counts, _ = refresh(world, date(2026, 9, 16), registry_dir=empty)
    after = by_id(world)
    assert counts["owner_changed"] == 0
    for lid in (A_ID, E_ID, E3_ID, CT_ID, SS30_ID):
        assert (after[lid]["org_id"], after[lid]["org_name"], after[lid]["attr_method"], after[lid]["attr_confidence"],
                after[lid]["needs_attribution_review"]) == \
            (before[lid]["org_id"], before[lid]["org_name"], before[lid]["attr_method"], before[lid]["attr_confidence"],
             before[lid]["needs_attribution_review"])
    # a brand-new lead under an unavailable registry: label + review
    o = obs("10.0.0.40", 443, "government", org="New Town", product="FortiGate", d=date(2026, 9, 16))
    add_store(world, [o])
    refresh(world, date(2026, 9, 17), registry_dir=empty)
    r = by_id(world)[L.lead_id("10.0.0.40", 443, "tcp", "appliance")]
    assert r["org_name"] == "New Town" and r["attr_method"] == "shodan_org" and r["needs_attribution_review"]


def test_explicit_unattributed_row_replaces_store_ownership(world):
    refresh(world)
    c = ctx(world)
    c.con.execute("UPDATE leads SET org_id = 'ORG-OLD', org_name = 'Old Owner', attr_method = 'store', attr_confidence = 'medium' "
                  "WHERE lead_id = ?", [CT_ID])
    c.close()
    counts, _ = refresh(world, date(2026, 9, 16))
    r = by_id(world)[CT_ID]
    assert counts["owner_changed"] >= 1 and r["org_id"] is None and r["org_name"] == "Delta Widgets" and r["attr_method"] == "arin_rdap"
    assert "ORG-OLD -> (none)" in r["notes"] and r["needs_attribution_review"]


def test_ownership_reconciled_for_no_candidate_lead_and_empty_to_org(world):
    refresh(world)
    setst(world, B2_ID, "queued", analyst="jd")
    time_shift(world, date(2026, 10, 4))                     # B2's service goes stale: no candidate today
    nets = NETWORKS[:1] + [["10.0.0.2/32", "", "ORG-OTHER", "curated", "high", "2026-10-05"]]
    write_registry(world["reg"], networks=nets)
    counts, _ = refresh(world, date(2026, 10, 5))
    r = by_id(world)[B2_ID]
    assert r["org_id"] == "ORG-OTHER" and r["status"] == "new" and r["prior_status"] == "queued" and r["needs_attribution_review"]
    assert r["analyst"] is None and "ORG-TU -> ORG-OTHER" in r["notes"] and "owner_changed" in events(world, B2_ID)
    # empty -> org is an ownership change too (CT lead had no org_id)
    clear(world, CT_ID)
    write_registry(world["reg"], networks=nets + [["10.0.0.9/32", "", "ORG-DW", "curated", "high", "2026-10-05"]])
    counts, _ = refresh(world, date(2026, 10, 6))
    r = by_id(world)[CT_ID]
    assert r["org_id"] == "ORG-DW" and r["org_name"] == "Delta Widgets Inc" and r["needs_attribution_review"]
    assert "(none) -> ORG-DW" in r["notes"] and r["attr_method"] == "registry_network"
    assert r["org_at_first_seen"] == "Delta Widgets"


def test_attribution_confidence_drop_closes_episode(world):
    refresh(world)
    setst(world, E_ID, "notified", via="direct")
    write_registry(world["reg"], attr=[a for a in ATTR if a[0] != "10.0.0.6"])       # 10.0.0.6 now unknown -> label
    counts, _ = refresh(world, date(2026, 9, 17))
    r = by_id(world)[E_ID]
    assert r["status"] == "new" and r["prior_status"] == "notified" and r["needs_attribution_review"] and r["notified_on"] is None
    assert r["attr_confidence"] == "low" and r["org_id"] is None


def test_conflict_refused_by_packets_until_cleared(world):
    refresh(world)
    with pytest.raises(SystemExit):
        packet(world, ip="10.0.0.31")
    clear(world, CF_ID)
    md = packet(world, ip="10.0.0.31")
    assert "10.0.0.31" in md
    refresh(world, date(2026, 9, 16))                              # unchanged conflict does not re-flag
    assert not by_id(world)[CF_ID]["needs_attribution_review"]
    write_registry(world["reg"], attr=[a if a[0] != "10.0.0.31" else a[:9] + ["rdns=la-ct;cert=la-zz"] for a in ATTR])
    refresh(world, date(2026, 9, 17))                              # a NEW conflict does
    assert by_id(world)[CF_ID]["needs_attribution_review"] and by_id(world)[CF_ID]["attr_conflict"] == "rdns=la-ct;cert=la-zz"


# --- eligibility -------------------------------------------------------------------

def test_residential_is_never_a_lead(world):
    _, excluded = refresh(world)
    assert excluded["residential"] >= 1 and excluded["honeypot"] >= 1
    assert rows(world, "SELECT count(*) AS n FROM leads WHERE tier IN ('residential', 'honeypot')")[0]["n"] == 0


def test_ineligibility_keeps_analyst_status_and_hides(world):
    refresh(world)
    setst(world, ICS_ID, "false_positive", analyst="jd", note="bait shop")
    add_store(world, [obs("10.0.0.4", 502, "residential", org="Bayou Water", service="modbus", product=None, d=date(2026, 9, 15))])
    counts, _ = refresh(world, date(2026, 9, 16))
    r = by_id(world)[ICS_ID]
    assert counts["ineligible"] == 1 and r["status"] == "false_positive" and r["eligible"] is False and r["prior_status"] == "false_positive"
    c = ctx(world, write=False)
    assert ICS_ID not in {x["lead_id"] for x in L.ranked_leads(c)} and ICS_ID in {x["lead_id"] for x in L.ranked_leads(c, include_ineligible=True)}
    c.close()
    with pytest.raises(SystemExit):
        packet(world, ip="10.0.0.4", include_closed=True)
    add_store(world, [obs("10.0.0.4", 502, "critical_infrastructure", org="Bayou Water", service="modbus", product=None, d=date(2026, 9, 17))])
    counts, _ = refresh(world, date(2026, 9, 18))
    r = by_id(world)[ICS_ID]
    assert counts["eligible_again"] == 1 and r["eligible"] is True and r["status"] == "false_positive"


# --- lifecycle ---------------------------------------------------------------------

def test_refresh_is_idempotent(world):
    c1, _ = refresh(world)
    n1 = len(rows(world))
    c2, _ = refresh(world, date(2026, 9, 16))
    all_rows = rows(world)
    assert c1["inserted"] == n1 and c2["inserted"] == 0 and c2["owner_changed"] == 0 and c2["review_flagged"] == 0
    assert len(all_rows) == n1 == len({r["lead_id"] for r in all_rows})
    assert {r["last_evaluated"] for r in all_rows} == {date(2026, 9, 16)} and max(r["last_seen"] for r in all_rows) == NEWEST


def test_set_mirror_crash_rolls_back_and_pointer_only_after_commit(world, monkeypatch):
    refresh(world)
    ptr_before = open(os.path.join(world["ldir"], "CURRENT")).read().strip()
    setst(world, A_ID, "notified", via="MS-ISAC", analyst="jd", note="sent")
    r = by_id(world)[A_ID]
    assert r["status"] == "notified" and r["notified_on"] == TODAY and r["prior_status"] == "new"
    ptr = open(os.path.join(world["ldir"], "CURRENT")).read().strip()
    snap = os.path.join(world["ldir"], "snapshots", ptr)
    assert ptr != ptr_before and sorted(os.listdir(snap)) == ["lead_events.parquet", "leads.parquet", "migrations.parquet"]
    monkeypatch.setattr(L, "write_snapshot", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(SystemExit):
        setst(world, A_ID, "acknowledged")
    monkeypatch.undo()
    assert by_id(world)[A_ID]["status"] == "notified" and open(os.path.join(world["ldir"], "CURRENT")).read().strip() == ptr
    real_commit = duckdb.DuckDBPyConnection.commit
    monkeypatch.setattr(duckdb.DuckDBPyConnection, "commit", lambda self: (_ for _ in ()).throw(RuntimeError("commit failed")))
    with pytest.raises(SystemExit):
        setst(world, A_ID, "acknowledged")
    monkeypatch.setattr(duckdb.DuckDBPyConnection, "commit", real_commit)
    assert by_id(world)[A_ID]["status"] == "notified" and open(os.path.join(world["ldir"], "CURRENT")).read().strip() == ptr
    for i in range(7):
        setst(world, A_ID, note=f"n{i}")
    gens = sorted(os.listdir(os.path.join(world["ldir"], "snapshots")))
    assert len(gens) == L.KEEP_SNAPSHOTS and open(os.path.join(world["ldir"], "CURRENT")).read().strip() == gens[-1]


def test_cve_scoped_suppression(world):
    refresh(world)
    setst(world, B1_ID, "false_positive")
    add_store(world, [], [vuln(obs("10.0.0.2", 443, "education"), "CVE-2024-99999", epss=0.4)])
    refresh(world, date(2026, 9, 16))
    r = by_id(world)
    assert r[B1_ID]["status"] == "false_positive" and r[B2_ID]["status"] == "new"
    assert r[L.lead_id("10.0.0.2", 443, "tcp", "kev_inferred", "CVE-2024-99999")]["status"] == "new"


def test_remediation_only_when_service_is_gone(world):
    refresh(world)
    setst(world, A_ID, "notified", via="direct")
    clear(world, IOC_ID)
    setst(world, IOC_ID, "notified", via="direct")
    time_shift(world, date(2026, 10, 4))
    counts, _ = refresh(world, date(2026, 10, 5))
    assert counts["remediated"] == 0 and by_id(world)[A_ID]["status"] == "notified"
    time_shift(world, date(2026, 11, 15))
    counts, _ = refresh(world, date(2026, 11, 16))
    r = by_id(world)
    assert counts["remediated"] == 2 and r[A_ID]["status"] == "remediated" and r[IOC_ID]["status"] == "remediated"
    assert r[A_ID]["prior_status"] == "notified" and r[A2_ID]["status"] == "new"


def test_host_level_needs_every_service_gone(world):
    refresh(world)
    setst(world, IOC_ID, "notified")
    add_store(world, [obs("10.0.0.13", 80, "unclassified", org="Some Carrier", d=date(2026, 11, 15))])
    counts, _ = refresh(world, date(2026, 11, 16))
    assert counts["remediated"] == 0 and by_id(world)[IOC_ID]["status"] == "notified"


def test_reopen_only_on_newer_scan_not_recollected_banner(world):
    refresh(world)
    setst(world, A_ID, "notified", via="MS-ISAC")
    time_shift(world, date(2026, 11, 15))
    assert refresh(world, date(2026, 11, 16))[0]["remediated"] == 1
    o = obs("10.0.0.1", 445, "education", product="Samba", d=date(2026, 11, 16), ts=datetime(2026, 9, 14, 3, 0, 0))
    add_store(world, [o], [vuln(o, "CVE-2020-0796", verified=True)])
    counts, _ = refresh(world, date(2026, 11, 17))
    r = by_id(world)[A_ID]
    assert counts["reopened"] == 0 and r["status"] == "remediated" and r["last_scan_ts"] == datetime(2026, 9, 14, 3, 0, 0)
    o = obs("10.0.0.1", 445, "education", product="Samba", d=date(2026, 11, 17), ts=datetime(2026, 11, 17, 1, 0, 0))
    add_store(world, [o], [vuln(o, "CVE-2020-0796", verified=True)])
    counts, _ = refresh(world, date(2026, 11, 18))
    r = by_id(world)[A_ID]
    assert counts["reopened"] == 1 and r["status"] == "new" and r["prior_status"] == "remediated" and r["notified_on"] is None
    assert "notified 2026-09-15 via MS-ISAC" in r["notes"] and "reopened" in events(world, A_ID)


def test_compromise_reopen_uses_service_banner_not_ledger_touch(world, monkeypatch):
    refresh(world)
    clear(world, CT_ID)
    setst(world, CT_ID, "notified")
    time_shift(world, date(2026, 11, 15))
    refresh(world, date(2026, 11, 16))
    assert by_id(world)[CT_ID]["status"] == "remediated"
    monkeypatch.setattr(L, "COMPROMISE_WINDOW_DAYS", 365)
    led = json.loads((world["hits"] / "seen_ledger.json").read_text())
    led["hosts"]["10.0.0.9"]["last_seen"] = "2026-11-17"
    led["hosts"]["10.0.0.9"]["last_banner_ts"] = "2026-11-17T09:00:00"        # ledger banner moved, service banner did not
    (world["hits"] / "seen_ledger.json").write_text(json.dumps(led))
    counts, _ = refresh(world, date(2026, 11, 18))
    assert counts["reopened"] == 0 and by_id(world)[CT_ID]["status"] == "remediated"
    with gzip.open(world["hits"] / "louisiana-compromise-2026-11-18.json.gz", "wt") as fh:      # a newer SERVICE banner
        fh.write(json.dumps({"ip_str": "10.0.0.9", "port": 9200, "transport": "tcp", "tags": ["compromised"],
                             "_compromise_selector": "tag:compromised", "timestamp": "2026-11-18T05:00:00"}) + "\n")
    counts, _ = refresh(world, date(2026, 11, 19))
    assert counts["reopened"] == 1 and by_id(world)[CT_ID]["status"] == "new"


def test_legacy_migration_marker_and_mapping(world):
    old_a = L.lead_id("10.0.0.1", 445, "tcp", "kev_verified")                 # names ONE of the two CVEs
    old_b = L.lead_id("10.0.0.2", 443, "tcp", "kev_inferred")                 # names both
    old_z = L.lead_id("10.0.0.50", 443, "tcp", "kev_inferred")                # zero targets
    s = duckdb.connect(world["store"])
    s.execute("CREATE TABLE leads (lead_id VARCHAR, ip VARCHAR, port INTEGER, transport VARCHAR, org_id VARCHAR, org_name VARCHAR, "
              "tier VARCHAR, sector VARCHAR, evidence_type VARCHAR, evidence VARCHAR, confidence VARCHAR, first_seen DATE, last_seen DATE, "
              "status VARCHAR, notified_via VARCHAR, notified_on DATE, analyst VARCHAR, notes VARCHAR, updated_at TIMESTAMP)")
    s.executemany("INSERT INTO leads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
        [old_a, "10.0.0.1", 445, "tcp", None, "Test University", "education", "education", "kev_verified",
         "KEV CVE(s) VERIFIED by Shodan: CVE-2020-0796", "high", date(2026, 9, 1), date(2026, 9, 10), "notified", "MS-ISAC",
         date(2026, 9, 2), "jd", "old note", datetime(2026, 9, 10)],
        [old_b, "10.0.0.2", 443, "tcp", None, "Test University", "education", "education", "kev_inferred",
         "KEV inferred: CVE-2021-41773, CVE-2021-42013", "medium", date(2026, 9, 1), date(2026, 9, 10), "disputed", None, None, "jd",
         "", datetime(2026, 9, 10)],
        [old_z, "10.0.0.50", 443, "tcp", None, "Gone Corp", "education", "education", "kev_inferred", "KEV inferred: CVE-2020-1111",
         "medium", date(2026, 9, 1), date(2026, 9, 10), "queued", None, None, "jd", "", datetime(2026, 9, 10)],
        [ICS_ID, "10.0.0.4", 502, "tcp", None, "Bayou Water", "critical_infrastructure", "critical_infrastructure", "ics", "ICS", "medium",
         date(2026, 9, 1), date(2026, 9, 10), "remediated", "direct", date(2026, 9, 3), "jd", "", datetime(2026, 9, 10)],
    ])
    s.close()
    counts, _ = refresh(world)
    r = by_id(world)
    assert rows(world, "SELECT name FROM migrations ORDER BY name") == [{"name": "legacy_import_v1"}, {"name": "shadowserver_class_id_v1"}]
    # exact-CVE mapping: A mapped (notified carried), A2 not named -> new + review, legacy row kept + flagged
    assert r[A_ID]["status"] == "notified" and r[A_ID]["notified_via"] == "MS-ISAC" and r[A_ID]["first_seen"] == date(2026, 9, 1)
    assert r[A2_ID]["status"] == "new" and r[A2_ID]["needs_attribution_review"] and "did not name this CVE" in r[A2_ID]["notes"]
    assert old_a in r and r[old_a]["status"] == "notified" and r[old_a]["needs_attribution_review"] and "legacy lead kept" in r[old_a]["notes"]
    # both named -> both mapped (disputed carried), legacy row gone
    assert r[B1_ID]["status"] == "disputed" and r[B2_ID]["status"] == "disputed" and r[B1_ID]["needs_attribution_review"]   # multi-CVE
    assert old_b not in r and counts["migrated"] == 1
    # zero targets: kept, status preserved, flagged
    assert r[old_z]["status"] == "queued" and r[old_z]["needs_attribution_review"] and "no per-CVE lead" in r[old_z]["notes"]
    # a remediated legacy lead whose service is observed again by a newer scan reopens (its history intact)
    assert r[ICS_ID]["status"] == "new" and r[ICS_ID]["prior_status"] == "remediated" and r[ICS_ID]["notified_via"] is None
    assert "imported_legacy" in events(world, ICS_ID) and "reopened" in events(world, ICS_ID)
    # marker prevents re-import; second refresh is stable
    s = duckdb.connect(world["store"])
    s.execute("DROP TABLE leads")
    s.close()
    refresh(world, date(2026, 9, 16))
    assert by_id(world)[A_ID]["status"] == "notified" and by_id(world)[old_z]["status"] == "queued"


def test_shadowserver_ids_migrated_in_place(world):
    refresh(world)
    setst(world, SSC_ID, "queued", analyst="jd")
    old = L.lead_id("10.0.0.11", 0, "host", "shadowserver")                    # pre-class scheme
    c = ctx(world)
    c.con.execute("UPDATE leads SET lead_id = ? WHERE lead_id = ?", [old, SSC_ID])
    c.con.execute("UPDATE lead_events SET lead_id = ? WHERE lead_id = ?", [old, SSC_ID])
    c.con.execute("DELETE FROM migrations WHERE name = 'shadowserver_class_id_v1'")
    c.close()
    counts, _ = refresh(world, date(2026, 9, 16))
    r = by_id(world)
    assert old not in r and r[SSC_ID]["status"] == "queued" and r[SSC_ID]["analyst"] == "jd" and counts["inserted"] == 0
    assert "id_migrated" in events(world, SSC_ID) and "status" in events(world, SSC_ID)


def test_rebuild_recovery_for_leads(world):
    refresh(world)
    setst(world, A_ID, "acknowledged")
    s = duckdb.connect(world["store"])
    s.execute("DROP TABLE leads")
    s.close()
    refresh(world, date(2026, 9, 16))
    s = duckdb.connect(world["store"], read_only=True)
    assert s.execute("SELECT status FROM leads WHERE lead_id = ?", [A_ID]).fetchone() == ("acknowledged",)
    s.close()
    os.remove(os.path.join(world["ldir"], "leads.duckdb"))
    c = ctx(world)
    assert L.ensure_leads_db(c) == "restored"
    assert L.fetch_dicts(c.con, "SELECT status FROM leads WHERE lead_id = ?", [A_ID])[0]["status"] == "acknowledged"
    assert c.con.execute("SELECT count(*) FROM migrations").fetchone()[0] == 2
    c.close()


# --- ranking / list / digest -------------------------------------------------------

def test_ranking_order_and_filters(world):
    refresh(world)
    c = ctx(world, write=False)
    order = [r["evidence_type"] for r in L.ranked_leads(c)]
    seen = [t for i, t in enumerate(order) if t not in order[:i]]
    assert seen == ["kev_verified", "compromise_tag", "shadowserver", "ics", "appliance", "kev_inferred", "ioc_match"]
    top = L.ranked_leads(c, limit=2)
    assert [t["evidence_key"] for t in top] == ["CVE-2017-0144", "CVE-2020-0796"] and top[0]["epss"] == pytest.approx(0.95)
    assert len(L.ranked_leads(c, org="ORG-CT")) == 5 and len(L.ranked_leads(c, org="city of testville")) == 6
    md = L.digest(c, TODAY)
    assert "| education |" in md and "high=4" in md and "needs review" in md and "-1d" not in md
    c.close()


# --- packets -----------------------------------------------------------------------

def test_packet_sections_and_wording(world):
    refresh(world)
    md = packet(world, org="Test University")
    for section in ("## 1. Summary", "## 2. What we observed", "## 3. What this is not", "## 4. Recommended actions",
                    "## 5. How to verify", "## 6. Contact and handling", "## Reviewer sign-off", "## Appendix A"):
        assert section in md, section
    assert "**Status:** DRAFT" in md and "Priority:** HIGH" in md and "currently active (last observed 2026-09-14)" in md
    assert "registry method `registry_network`" in md and "confidence **high**" in md
    clear(world, ICS_ID)
    md_ics = packet(world, org="Bayou Water")
    assert "reachability alone is a serious exposure that must be verified" in md_ics and "reachability is control" not in md_ics
    assert "Shodan org field 'Bayou Water' only" in md_ics


def test_packet_refuses_label_only_leads_until_cleared(world):
    refresh(world)
    with pytest.raises(SystemExit):
        packet(world, org="Bayou Water")
    with pytest.raises(SystemExit):
        packet(world, ip="10.0.0.30")                              # host-level on non-ownership attribution
    # an analyst's clearance sticks across refreshes while the attribution is unchanged
    clear(world, ICS_ID)
    counts, _ = refresh(world, date(2026, 9, 16))
    assert counts["review_flagged"] == 0 and not by_id(world)[ICS_ID]["needs_attribution_review"]
    assert "Bayou Water" in packet(world, date(2026, 9, 16), org="Bayou Water")
    clear(world, CT_ID)                                            # explicit registry row without an org: label wording
    assert "network-operator label, not an ownership record (registry `arin_rdap`: no organisation recorded)" in \
        packet(world, date(2026, 9, 16), ip="10.0.0.9")


def test_packet_appendix_authorized_by_current_registry_only(world):
    refresh(world)
    app = packet(world, org="Test University").split("## Appendix A")[1]
    assert "| `10.0.0.1` | 80/tcp |" in app and "| `10.0.0.1` | 445/tcp |" in app and "omitted" not in app
    app2 = packet(world, org="City of Testville").split("## Appendix A")[1]
    assert "| `10.0.0.6` | 443/tcp |" in app2 and "22/tcp" not in app2 and "8080/tcp" not in app2
    assert "omitted: shared/unresolved ownership" in app2
    # the registry changes (10.0.0.1 no longer a curated network) — lead rows still say registry_network/high,
    # but authorization comes from the CURRENT registry: the extra service disappears without a refresh
    write_registry(world["reg"], networks=NETWORKS[1:], attr=ATTR + [["10.0.0.1", "ORG-TU", "Test University", "education", "state",
                                                                      "domain_dns", "high", "x", "2026-09-16", ""]])
    app3 = packet(world, org="Test University").split("## Appendix A")[1]
    assert "80/tcp" not in app3 and "445/tcp" in app3 and "omitted" in app3
    # a registry conflict on the address also withdraws the privilege
    write_registry(world["reg"], attr=ATTR + [["10.0.0.1", "ORG-TU", "Test University", "education", "state", "registry_network",
                                               "high", "x", "2026-09-16", "rdns=x"]], networks=NETWORKS[1:])
    assert "80/tcp" not in packet(world, org="Test University").split("## Appendix A")[1]


def test_packet_flags_attribution_conflict_between_lead_rows(world):
    refresh(world)
    c = ctx(world)
    c.con.execute("UPDATE leads SET org_id = 'ORG-ZZ', org_name = 'Zed Corp', last_evaluated = DATE '2026-09-10' WHERE lead_id = ?", [A2_ID])
    c.close()
    md = packet(world, org="Test University")
    assert "Attribution conflict" in md and "80/tcp" not in md.split("## Appendix A")[1]


def test_packet_shadowserver_classes_priority_and_host_freshness(world):
    refresh(world)
    clear(world, SSC_ID, SSE_ID, CT_ID)
    md = packet(world, org="Delta Widgets")
    assert "**REQUIRED**" in md and "Possible infection — Shadowserver sinkhole" in md and "| 443/tcp |" in md and "| — |" in md
    assert "host-level evidence — last event 2026-09-12 (3 d ago)" in md and "51234" not in md.split("### Finding detail")[0]
    # 40 days later with no newer event: host-level leads are historical, never "still observed"
    setst(world, SSC_ID, "notified", via="direct")
    md2 = packet(world, date(2026, 10, 25), org="Delta Widgets")
    assert "no newer event — last event 2026-09-12 (43 d ago)" in md2 and "still observed" not in md2
    assert "### No longer observed — historical" in md2 and "| H1 |" in md2
    setst(world, SSC_ID, "false_positive")
    setst(world, CT_ID, "false_positive")
    md3 = packet(world, org="Delta Widgets")
    assert "Priority:** MEDIUM" in md3 and "Second reviewer (recommended)" in md3


def test_packet_status_filtering_and_exposure_state(world):
    refresh(world)
    setst(world, A_ID, "notified", via="MS-ISAC")
    setst(world, A2_ID, "false_positive")
    setst(world, B1_ID, "suppressed")
    md = packet(world, org="Test University")
    assert "previously notified on 2026-09-15" in md and "— still observed" in md and "1 still observed" in md and "CVE-2021-41773" not in md
    md2 = packet(world, org="Test University", include_closed=True)
    assert "CVE-2017-0144" in md2 and "closed; included on request" in md2
    time_shift(world, date(2026, 11, 15))
    md3 = packet(world, date(2026, 11, 16), org="Test University")
    assert "### No longer observed — historical" in md3 and "| H1 |" in md3 and "no longer observed — last observed 2026-09-14" in md3


def test_packet_refuses_multi_org_residential_now_and_unattributed(world, monkeypatch):
    refresh(world)
    c = ctx(world, write=False)
    real = L.ranked_leads
    two = [dict(r) for r in real(c, org="ORG-TU")[:1]] + [dict(r) for r in real(c, org="ORG-CT")[:1]]
    monkeypatch.setattr(L, "ranked_leads", lambda *a, **k: two)
    with pytest.raises(SystemExit) as ex:
        MP.select_leads(c, org="anything")
    assert "Test University" in str(ex.value) and "City of Testville" in str(ex.value)
    monkeypatch.undo()
    with pytest.raises(SystemExit):
        MP.select_leads(c, org="unattributed")
    c.close()
    add_store(world, [obs("10.0.0.6", 443, "residential", org="Cox", product="FortiGate", d=date(2026, 9, 15))])
    with pytest.raises(SystemExit):
        packet(world, ip="10.0.0.6")
    md = packet(world, ip="10.0.0.20")
    assert "unattributed — no registry attribution" in md and "confidence **none**" in md


def test_packet_escapes_banner_text(world):
    refresh(world)
    md = packet(world, org="City of Testville")
    assert "**bold**" not in md and "[link](http://x)" not in md and "`code`" not in md
    assert "\\| \\*\\*bold\\*\\*" in md and "\\[link\\]" in md and "a'b\\|c" in md
    assert not any(line.startswith("# heading") for line in md.splitlines())
    table = md.split("## 2. What we observed")[1].split("\nScan age = ")[0]
    assert len([ln for ln in table.splitlines() if ln.startswith("| ")]) == 1 + 3


def test_packet_main_writes_file_and_pdf(world, tmp_path):
    refresh(world)
    out = tmp_path / "packets"
    rc = MP.main(["--ip", "10.0.0.6", "--db", world["store"], "--leads-dir", world["ldir"], "--registry-dir", world["reg"],
                  "--out-dir", str(out), "--date", "2026-09-15"] + (["--pdf"] if pytest.importorskip("reportlab") else []))
    assert rc == 0
    files = sorted(os.listdir(out))
    assert files == ["City_of_Testville_2026-09-15.md", "City_of_Testville_2026-09-15.pdf"]


# --- shadowserver ------------------------------------------------------------------

CSV = ('"timestamp","ip","protocol","port","hostname","tag","asn","geo","region","city","naics","sector","infection","src_port","dst_ip"\n'
       '"2026-09-14 03:12:44","10.0.0.11","tcp","51234","host.example.net","avalanche-andromeda","64512","US","LOUISIANA","BATON ROUGE","0","","andromeda","51234","192.0.2.9"\n'
       '"2026-09-14 03:12:44","10.0.0.11","udp","51234","host.example.net","avalanche-andromeda","64512","US","LOUISIANA","BATON ROUGE","0","","andromeda","51234","192.0.2.9"\n'
       '"2026-09-14T03:13:01-05:00","2001:0DB8:0000::0001","sctp","","","","64512","US","LOUISIANA","LAFAYETTE","","","","",""\n'
       '"2026-09-14 03:14:00","","tcp","80","","","","","","","","","","",""\n'
       '"2027-01-01 00:00:00","10.0.0.13","tcp","80","","","","","","","","","","",""\n'
       '"2026-09-14 03:15:00","10.0.0.14","tcp","80","","","","","","","","","","","","SURPLUS"\n'
       '"not a date","10.0.0.15","tcp","80","","","","","","","","","","",""\n'
       '"2026-09-14 03:16:00","10.0.0.999","tcp","80","","","","","","","","","","",""\n'
       '"2026-09-14 03:17:00","10.0.0.16","tcp","70000","","","","","","","","","","",""\n'
       '"2026-09-14 03:18:00","10.0.0.17","t<p","80","","","","","","","","","","",""\n')


def test_classify_report_types():
    for t in ("sinkhole_http_drone", "microsoft_sinkhole", "spam", "compromised_website", "malware_url", "botnet_drone", "cc_ip"):
        assert SS.classify_report(t) == "compromise", t
    for t in ("scan_ssl", "vulnerable_exchange", "exposed_ipp", "ics", "open_elasticsearch", "accessible_rdp", "blocklist", "unknown_thing"):
        assert SS.classify_report(t) == "exposure", t


def test_parse_report_validation_quarantine_and_ipv6(tmp_path):
    p = tmp_path / "2026-09-14-sinkhole_http_drone-louisiana.csv"
    p.write_text(CSV)
    sha, events, bad = SS.parse_report(str(p), today=TODAY)
    assert len(events) == 3 and events[1]["protocol"] == "udp"
    assert events[2]["ip"] == "2001:db8::1" and events[2]["protocol"] == "other" and events[2]["timestamp"] == datetime(2026, 9, 14, 8, 13, 1)
    assert sorted(r for r, _ in bad) == ["future-dated", "invalid ip", "invalid protocol", "missing ip", "port out of range",
                                         "surplus fields", "unparseable timestamp"]


def test_ingest_lock_identity_dedupe_recovery_and_exit_codes(tmp_path):
    store = str(tmp_path / "s.duckdb")
    inc, proc, quar = tmp_path / "incoming", tmp_path / "processed", tmp_path / "quarantine"
    pq, man = str(tmp_path / "ss" / "events.parquet"), str(tmp_path / "ss" / "manifest.json")
    inc.mkdir()
    (inc / "2026-09-14-sinkhole_http_drone-louisiana.csv").write_text(CSV)
    kw = dict(processed_dir=str(proc), quarantine_dir=str(quar), parquet=pq, manifest_path=man)
    argv = ["ingest", "--incoming", str(inc), "--processed", str(proc), "--quarantine", str(quar), "--parquet", pq, "--manifest", man]
    lock = SS.acquire_lock(pq)
    assert SS.ingest_dir(None, str(inc), today=TODAY, **kw) is None and os.listdir(inc) and not os.path.exists(man)
    assert SS.main(argv + ["--db", store]) == 3                                         # lock held: exit 3
    lock.close()
    assert SS.main(argv + ["--db", str(tmp_path / "nodir" / "x.duckdb")]) == 4          # store not writable: degraded
    assert os.listdir(inc) and os.path.exists(pq) and os.path.exists(man)               # parquet/manifest durable, input kept
    assert SS.main(argv + ["--db", store]) == 0                                          # retry: published + moved
    assert os.listdir(inc) == [] and len(os.listdir(proc)) == 1
    con = duckdb.connect(store)
    assert con.execute("SELECT count(*) FROM shadowserver_events").fetchone()[0] == 3
    assert con.execute("SELECT ip FROM shadowserver_events WHERE protocol = 'other'").fetchone() == ("2001:db8::1",)
    m = json.load(open(man))
    ident, entry = next(iter(m["files"].items()))
    assert ident.endswith(":sinkhole_http_drone") and entry["rows_loaded"] == 3 and entry["rows_quarantined"] == 7
    (inc / "2026-09-14-scan_ssl-louisiana.csv").write_text(CSV)                         # same bytes, other type = new identity
    assert SS.ingest_dir(con, str(inc), today=TODAY, **kw) == {"loaded": 3}
    (inc / "2026-09-15-sinkhole_http_drone-louisiana.csv").write_text(CSV.splitlines()[0] + "\n" + CSV.splitlines()[1] + "\n")
    assert SS.ingest_dir(con, str(inc), today=TODAY, **kw) == {"empty": 1}              # event-level dedupe
    con.execute("DROP TABLE shadowserver_events")
    assert SS.restore_table(con, pq) and con.execute("SELECT count(*) FROM shadowserver_events").fetchone()[0] == 6
    con.close()


def test_hmac2_known_vector():
    assert SS.hmac2("key", "The quick brown fox jumps over the lazy dog") == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"


def test_fetch_soft_fails_without_keys(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSERVER_API_KEY", raising=False)
    monkeypatch.delenv("SHADOWSERVER_SECRET", raising=False)
    monkeypatch.setattr(SS, "ENV_PATH", str(tmp_path / "no.env"))
    assert SS.fetch("2026-09-14", incoming=str(tmp_path / "inc")) == 0
    monkeypatch.setenv("SHADOWSERVER_API_KEY", "k")
    monkeypatch.setenv("SHADOWSERVER_SECRET", "s")
    monkeypatch.setattr(SS, "api_call", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    assert SS.fetch("2026-09-14", incoming=str(tmp_path / "inc")) == 0
