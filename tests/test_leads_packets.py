"""Tests for the Phase-2 leads table, notification packets and Shadowserver ingest.

A tiny fabricated store (observations + vulns TABLES with the same derived views
build_store.py defines, plus ioc_ips / ioc_cidrs / ioc_matches like the integrator's)
+ a registry parquet + tripwire ledger + Shadowserver parquet exercise: every
evidence rule, CVE-scoped identity, shared appliance definitions, per-host
eligibility (status preserved), owner-change episodes + review flag, legacy
migration, idempotent refresh, snapshot/pointer durability, remediation only on
'gone', reopen only on a newer SCAN, rebuild recovery, ranking, digest, packet
content / escaping / status filtering / single-org / cross-tenant appendix /
current-tier recheck, Shadowserver classes, validation + quarantine, lock,
idempotent ingest, HMAC2.

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
OBS_COLS = ["observation_id", "date", "ip", "port", "transport", "asn", "org", "isp", "product", "version",
            "cpe23", "service", "info", "city", "region_code", "hostnames", "domains", "tags", "banner_ts",
            "hash", "tier", "tier_reason", "http_title", "http_host", "http_server", "cert_cn", "cert_org",
            "cert_issuer", "cert_sans", "cert_expired", "cert_expires", "cert_sha256", "jarm"]
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
       SELECT ip, port, transport, min(date) AS first_seen, max(date) AS last_seen,
              count(DISTINCT date) AS days_observed, date_diff('day', min(date), max(date)) + 1 AS span_days
       FROM observations GROUP BY ip, port, transport""",
    """CREATE OR REPLACE VIEW ioc_matches AS
       WITH cs AS (SELECT *, CAST(split_part(ip, '.', 1) AS UBIGINT) * 16777216 + CAST(split_part(ip, '.', 2) AS UBIGINT) * 65536
                   + CAST(split_part(ip, '.', 3) AS UBIGINT) * 256 + CAST(split_part(ip, '.', 4) AS UBIGINT) AS ip_int FROM current_state)
       SELECT cs.* EXCLUDE (ip_int), i.sources AS ioc_sources, NULL AS ioc_cidr FROM cs JOIN ioc_ips i ON i.ip = cs.ip
       UNION ALL
       SELECT cs.* EXCLUDE (ip_int), c.sources, c.cidr FROM cs JOIN ioc_cidrs c ON cs.ip_int BETWEEN c.lo AND c.hi""",
]


def obs(ip, port, tier, org="Test University", d=NEWEST, transport="tcp", ts=None, **kw):
    row = {c: None for c in OBS_COLS}
    row.update({"observation_id": f"{ip}-{port}-{d}", "date": d, "ip": ip, "port": port, "transport": transport,
                "org": org, "tier": tier, "product": "nginx", "service": "http",
                "banner_ts": ts or datetime(d.year, d.month, d.day, 3, 0, 0), "hash": "1", "tags": "", "hostnames": "",
                "city": "Baton Rouge"})
    row.update(kw)
    return row


def vuln(o, cve, verified=False, in_kev=True, epss=0.5, cvss=9.8):
    return {"observation_id": o["observation_id"], "date": o["date"], "ip": o["ip"], "port": o["port"],
            "transport": o["transport"], "cve": cve, "cvss": cvss, "in_kev": in_kev, "epss": epss, "verified": verified}


def add_obs(con, rows):
    if rows:
        con.executemany(f"INSERT INTO observations VALUES ({', '.join('?' * len(OBS_COLS))})",
                        [[r[c] for c in OBS_COLS] for r in rows])


def add_vulns(con, rows):
    cols = ["observation_id", "date", "ip", "port", "transport", "cve", "cvss", "in_kev", "epss", "verified"]
    if rows:
        con.executemany(f"INSERT INTO vulns VALUES ({', '.join('?' * len(cols))})", [[r[c] for c in cols] for r in rows])


def ss_ev(rtype, ts, ip, port, proto="tcp", tag=None, sev="high"):
    return {"report_type": rtype, "timestamp": ts, "ip": ip, "port": port, "protocol": proto, "asn": "64512",
            "geo": "US", "tag": tag, "severity": sev, "detail": "{}", "ingested_on": TODAY}


def ip_int(ip):
    a, b, c, d = (int(x) for x in ip.split("."))
    return a * 16777216 + b * 65536 + c * 256 + d


def write_registry(path, rows):
    r = duckdb.connect()
    r.execute("CREATE TABLE a (ip VARCHAR, org_id VARCHAR, org_name VARCHAR, sector VARCHAR, jurisdiction VARCHAR, "
              "method VARCHAR, confidence VARCHAR, evidence VARCHAR, as_of VARCHAR)")
    r.executemany("INSERT INTO a VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    r.execute(f"COPY a TO '{path}' (FORMAT PARQUET)")
    r.close()


REGISTRY = [
    ["10.0.0.1", "ORG-TU", "Test University", "education", "state", "registry_network", "high", "10.0.0.0/29", "2026-09-15"],
    ["10.0.0.2", "ORG-TU", "Test University", "education", "state", "registry_network", "high", "10.0.0.0/29", "2026-09-15"],
    ["10.0.0.6", "ORG-CT", "City of Testville", "government", "municipal", "domain_dns", "high", "testville.la.gov", "2026-09-15"],
    ["10.0.0.15", "ORG-CT", "City of Testville", "government", "municipal", "domain_dns", "high", "x", "2026-09-15"],
    ["10.0.0.16", "ORG-CT", "City of Testville", "government", "municipal", "domain_dns", "high", "x", "2026-09-15"],
    ["10.0.0.30", "ORG-PJ", "Testville Police Jury", "government", "parish", "registry_asn", "medium", "AS1", "2026-09-15"],
    ["10.0.0.9", "", "", "", "", "arin_rdap", "low", "no registry org", "2026-09-15"],
]


@pytest.fixture
def world(tmp_path):
    store = str(tmp_path / "store.duckdb")
    con = duckdb.connect(store)
    con.execute("CREATE TABLE observations (" + ", ".join(f"{c} {OBS_TYPES.get(c, 'VARCHAR')}" for c in OBS_COLS) + ")")
    con.execute("CREATE TABLE vulns (observation_id VARCHAR, date DATE, ip VARCHAR, port INTEGER, transport VARCHAR, "
                "cve VARCHAR, cvss DOUBLE, in_kev BOOLEAN, epss DOUBLE, verified BOOLEAN)")
    con.execute("CREATE TABLE ioc_ips (ip VARCHAR, sources VARCHAR)")
    con.execute("CREATE TABLE ioc_cidrs (cidr VARCHAR, lo UBIGINT, hi UBIGINT, sources VARCHAR)")
    a = obs("10.0.0.1", 445, "education", product="Samba")
    a2 = obs("10.0.0.1", 80, "education", product="nginx")                                    # extra service, whole-address org
    b = obs("10.0.0.2", 443, "education", product="Apache httpd", version="2.4.49")
    c = obs("10.0.0.3", 443, "small_business", org="Bob's Bait", product="Apache httpd")
    d = obs("10.0.0.4", 502, "critical_infrastructure", org="Bayou Water", service="modbus", product=None)
    d2 = obs("10.0.0.5", 47808, "small_business", org="Acme Controls", service="auto", product=None)
    e = obs("10.0.0.6", 443, "government", org="City of Testville", product="FortiGate", http_title="FortiGate SSL-VPN")
    e2 = obs("10.0.0.6", 22, "government", org="City of Testville", product="OpenSSH")      # extra service, NOT whole-address
    f = obs("10.0.0.7", 443, "small_business", org="Bob's Bait", product="FortiGate")
    g = obs("10.0.0.8", 8080, "residential", org="Cox Communications")
    h = obs("10.0.0.9", 9200, "small_business", org="Delta Widgets", product="Elasticsearch")
    i = obs("10.0.0.11", 80, "small_business", org="Delta Widgets")
    i2 = obs("10.0.0.11", 443, "small_business", org="Delta Widgets")
    j = obs("10.0.0.13", 22, "unclassified", org="Some Carrier", product="OpenSSH")
    k = obs("10.0.0.14", 502, "honeypot", org="?", service="modbus", tags="honeypot")
    sh = obs("10.0.0.15", 443, "government", org="City of Testville", product="Microsoft IIS",
             http_title="Outlook Web App", cpe23="cpe:2.3:a:microsoft:exchange_server")
    inj = obs("10.0.0.16", 8443, "government", org="City of Testville",
              product="Evil | **bold** [link](http://x) `code`\n# heading <b>", http_title="FortiGate | *x*\r\n# h",
              hostnames="a`b|c")
    old = obs("10.0.0.2", 443, "education", d=date(2026, 6, 29))
    add_obs(con, [a, a2, b, c, d, d2, e, e2, f, g, h, i, i2, j, k, sh, inj, old])
    add_vulns(con, [vuln(a, "CVE-2020-0796", verified=True, epss=0.9), vuln(a, "CVE-2017-0144", verified=True, epss=0.95),
                    vuln(b, "CVE-2021-41773", epss=0.97), vuln(b, "CVE-2021-42013", epss=0.6),
                    vuln(b, "CVE-2000-0001", in_kev=False), vuln(c, "CVE-2021-41773"), vuln(g, "CVE-2020-0796", verified=True)])
    con.execute("INSERT INTO ioc_ips VALUES ('10.0.0.8', 'spamhaus_drop'), ('192.0.2.1', 'x')")
    con.execute("INSERT INTO ioc_cidrs VALUES ('10.0.0.12/30', ?, ?, 'spamhaus_drop')", [ip_int("10.0.0.12"), ip_int("10.0.0.15")])
    for v in VIEWS:
        con.execute(v)
    con.close()
    reg = str(tmp_path / "ip_attribution.parquet")
    write_registry(reg, REGISTRY)
    ssp = str(tmp_path / "ss" / "events.parquet")
    SS.append_parquet([ss_ev("sinkhole_http_drone", datetime(2026, 9, 12, 4, 5, 6), "10.0.0.11", 51234, tag="avalanche-andromeda"),
                       ss_ev("scan_ssl", datetime(2026, 9, 12, 5, 0, 0), "10.0.0.11", 443, sev="low"),
                       ss_ev("sinkhole_http_drone", datetime(2026, 8, 1, 4, 5, 6), "10.0.0.13", 22, tag="old"),
                       ss_ev("sinkhole_http_drone", datetime(2026, 9, 13, 1, 0, 0), "10.0.0.30", 40000, tag="qakbot")], ssp)
    hits = tmp_path / "hits"
    hits.mkdir()
    ledger = {"hosts": {"10.0.0.9": {"first_seen": "2026-09-01", "last_seen": "2026-09-10", "selectors": ["tag:compromised"],
                                     "last_banner_ts": "2026-09-09T05:00:00"},
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
                      "attribution_parquet": reg, "ss_parquet": ssp}}


def ctx(w, write=True):
    return L.open_ctx(w["store"], w["ldir"], write=write)


def refresh(w, today=TODAY):
    c = ctx(w)
    try:
        return L.refresh(c, today, **w["paths"])
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
        return MP.build_markdown(MP.gather(c, today, **kw))
    finally:
        c.close()


def events(w, lid):
    return [e["event"] for e in rows(w, "SELECT event FROM lead_events WHERE lead_id = ? ORDER BY ts", [lid])]


A_ID = L.lead_id("10.0.0.1", 445, "tcp", "kev_verified", "CVE-2020-0796")
A2_ID = L.lead_id("10.0.0.1", 445, "tcp", "kev_verified", "CVE-2017-0144")
B1_ID = L.lead_id("10.0.0.2", 443, "tcp", "kev_inferred", "CVE-2021-41773")
B2_ID = L.lead_id("10.0.0.2", 443, "tcp", "kev_inferred", "CVE-2021-42013")
ICS_ID = L.lead_id("10.0.0.4", 502, "tcp", "ics")
CT_ID = L.lead_id("10.0.0.9", 9200, "tcp", "compromise_tag")
IOC_ID = L.lead_id("10.0.0.13", 0, "host", "ioc_match")
E_ID = L.lead_id("10.0.0.6", 443, "tcp", "appliance")


# --- identity / definitions --------------------------------------------------------

def test_lead_id_cve_scoped_only_for_kev_types():
    import hashlib
    assert L.lead_id("1.2.3.4", 443, "tcp", "kev_inferred", "CVE-1") == hashlib.sha1(b"1.2.3.4|443|tcp|kev_inferred|CVE-1").hexdigest()[:16]
    assert L.lead_id("1.2.3.4", 443, "tcp", "kev_inferred", "CVE-1") != L.lead_id("1.2.3.4", 443, "tcp", "kev_inferred", "CVE-2")
    assert L.lead_id("1.2.3.4", 443, "tcp", "ics", "anything") == hashlib.sha1(b"1.2.3.4|443|tcp|ics").hexdigest()[:16]


def test_appliance_definitions_shared_with_build_store():
    assert L.APPLIANCE_PATTERNS is bs.APPLIANCE_PATTERNS
    assert L.appliance_match({"product": "FortiGate", "cpe23": "", "http_title": ""})[0].startswith("Fortinet")
    assert L.appliance_match({"product": "", "cpe23": "", "http_title": "Outlook Web App"})[0].startswith("Microsoft Exchange")
    assert L.appliance_match({"product": "showa", "cpe23": "", "http_title": ""}) is None


def test_transport_normalised_everywhere():
    assert L.norm_transport("TCP") == "tcp" and L.norm_transport("x<y|z") == "other" and L.norm_transport("") == "tcp"
    assert MP.tp("sctp") == "other" and MP.ipc("1.2.3.4") == "1.2.3.4" and "\\|" in MP.ipc("1.2|3")
    assert MP.num("12|x") == "12\\|x" and MP.num("7") == "7" and MP.lid("z|z") == "z\\|z" and MP.lid("a" * 16) == "a" * 16 and MP.status_word("weird|x") == "weird\\|x"


# --- generation --------------------------------------------------------------------

def test_generation_rules_per_evidence_type(world):
    refresh(world)
    by = by_type(world)
    kv = {r["lead_id"]: r for r in by["kev_verified"]}
    assert set(kv) == {A_ID, A2_ID} and all(r["confidence"] == "high" and r["status"] == "new" for r in kv.values())
    assert (kv[A_ID]["org_id"], kv[A_ID]["org_name"], kv[A_ID]["sector"], kv[A_ID]["attr_method"], kv[A_ID]["attr_confidence"]) == \
        ("ORG-TU", "Test University", "education", "registry_network", "high")
    assert kv[A_ID]["eligible"] is True and "host tier education" in kv[A_ID]["eligibility_reason"]
    assert kv[A_ID]["last_scan_ts"] == datetime(2026, 9, 14, 3, 0, 0) and kv[A_ID]["last_seen"] == NEWEST
    assert set(r["lead_id"] for r in by["kev_inferred"]) == {B1_ID, B2_ID}
    assert sorted((r["ip"], r["port"]) for r in by["ics"]) == [("10.0.0.4", 502), ("10.0.0.5", 47808)]
    assert sorted(r["ip"] for r in by["appliance"]) == ["10.0.0.15", "10.0.0.16", "10.0.0.6"]
    ct = {r["ip"]: r for r in by["compromise_tag"]}
    assert set(ct) == {"10.0.0.9", "10.0.0.20"}
    assert ct["10.0.0.9"]["last_scan_ts"] == datetime(2026, 9, 9, 5, 0, 0)            # ledger last_banner_ts
    assert ct["10.0.0.20"]["org_name"] == L.UNATTRIBUTED and ct["10.0.0.20"]["attr_confidence"] == "none"
    assert ct["10.0.0.9"]["attr_method"] == "shodan_org" and ct["10.0.0.9"]["org_name"] == "Delta Widgets"
    ss = {(r["ip"], r["port"], r["transport"]): r for r in by["shadowserver"]}
    assert set(ss) == {("10.0.0.11", 0, "host"), ("10.0.0.11", 443, "tcp"), ("10.0.0.30", 0, "host")}
    assert ss[("10.0.0.11", 0, "host")]["evidence_key"].startswith("compromise:") and ss[("10.0.0.11", 443, "tcp")]["confidence"] == "medium"
    assert ss[("10.0.0.30", 0, "host")]["tier"] == "government" and ss[("10.0.0.30", 0, "host")]["org_name"] == "Testville Police Jury"
    io = {r["ip"]: r for r in by["ioc_match"]}
    assert set(io) == {"10.0.0.13", "10.0.0.15"}                     # CIDR hits from the ioc_matches view; 10.0.0.8 residential
    assert "CIDR range(s) 10.0.0.12/30" in io["10.0.0.13"]["evidence"] and io["10.0.0.13"]["port"] == 0
    ips = {r["ip"] for rs in by.values() for r in rs}
    assert not ips & {"10.0.0.8", "10.0.0.14", "10.0.0.10", "192.0.2.1", "10.0.0.3", "10.0.0.7", "10.0.0.0/8", "_cidrs"}


def test_ioc_fallback_ignores_meta_keys(world):
    s = duckdb.connect(world["store"])
    s.execute("DROP VIEW ioc_matches")
    s.close()
    refresh(world)
    io = [r["ip"] for r in by_type(world)["ioc_match"]]
    assert io == ["10.0.0.13"]


def test_shadowserver_read_from_parquet_not_store_table(world):
    s = duckdb.connect(world["store"])
    s.execute(SS.EVENTS_DDL)
    s.execute("INSERT INTO shadowserver_events VALUES ('scan_ssl', '2026-09-13 01:00:00', '10.0.0.6', 443, 'tcp', NULL, NULL, NULL, 'low', '{}', ?)", [TODAY])
    s.close()
    refresh(world)
    assert "10.0.0.6" not in {r["ip"] for r in by_type(world)["shadowserver"]}


# --- eligibility -------------------------------------------------------------------

def test_residential_is_never_a_lead(world):
    _, excluded = refresh(world)
    assert excluded["residential"] >= 1 and excluded["honeypot"] >= 1
    assert rows(world, "SELECT count(*) AS n FROM leads WHERE tier IN ('residential', 'honeypot')")[0]["n"] == 0


def test_ineligibility_keeps_analyst_status_and_hides(world):
    refresh(world)
    setst(world, ICS_ID, "false_positive", analyst="jd", note="it's a bait shop")
    add_store(world, [obs("10.0.0.4", 502, "residential", org="Bayou Water", service="modbus", product=None, d=date(2026, 9, 15))])
    counts, _ = refresh(world, date(2026, 9, 16))
    r = by_id(world)[ICS_ID]
    assert counts["ineligible"] == 1 and r["status"] == "false_positive" and r["eligible"] is False
    assert r["prior_status"] == "false_positive" and "residential" in r["eligibility_reason"] and r["analyst"] == "jd"
    c = ctx(world, write=False)
    assert ICS_ID not in {x["lead_id"] for x in L.ranked_leads(c)}
    assert ICS_ID in {x["lead_id"] for x in L.ranked_leads(c, include_ineligible=True)}
    assert "Bayou Water" not in L.digest(c, date(2026, 9, 16))
    c.close()
    with pytest.raises(SystemExit):
        packet(world, ip="10.0.0.4", include_closed=True)
    add_store(world, [obs("10.0.0.4", 502, "critical_infrastructure", org="Bayou Water", service="modbus", product=None, d=date(2026, 9, 17))])
    counts, _ = refresh(world, date(2026, 9, 18))
    r = by_id(world)[ICS_ID]
    assert counts["eligible_again"] == 1 and r["eligible"] is True and r["status"] == "false_positive"
    assert events(world, ICS_ID)[-2:] == ["ineligible", "eligible_again"]


# --- lifecycle ---------------------------------------------------------------------

def test_refresh_is_idempotent_and_separates_last_seen_from_last_evaluated(world):
    c1, _ = refresh(world)
    n1 = len(rows(world))
    c2, _ = refresh(world, date(2026, 9, 16))
    all_rows = rows(world)
    assert c1["inserted"] == n1 and c2["inserted"] == 0 and len(all_rows) == n1 == len({r["lead_id"] for r in all_rows})
    assert {r["first_seen"] for r in all_rows} == {TODAY} and {r["last_evaluated"] for r in all_rows} == {date(2026, 9, 16)}
    assert max(r["last_seen"] for r in all_rows) == NEWEST


def test_primary_key_enforced(world):
    refresh(world)
    c = ctx(world)
    with pytest.raises(duckdb.Error):
        c.con.execute("INSERT INTO leads (lead_id, ip) VALUES (?, '1.1.1.1')", [A_ID])
    c.close()


def test_set_mirror_crash_rolls_back_and_pointer_only_after_commit(world, monkeypatch):
    refresh(world)
    ptr_before = open(os.path.join(world["ldir"], "CURRENT")).read().strip()
    setst(world, A_ID, "notified", via="MS-ISAC", analyst="jd", note="sent")
    r = by_id(world)[A_ID]
    assert r["status"] == "notified" and r["notified_via"] == "MS-ISAC" and r["notified_on"] == TODAY and r["prior_status"] == "new"
    ptr = open(os.path.join(world["ldir"], "CURRENT")).read().strip()
    snap = os.path.join(world["ldir"], "snapshots", ptr)
    assert ptr != ptr_before and sorted(os.listdir(snap)) == ["lead_events.parquet", "leads.parquet"]
    assert duckdb.connect().execute(f"SELECT status FROM read_parquet('{snap}/leads.parquet') WHERE lead_id = ?", [A_ID]).fetchone() == ("notified",)
    # snapshot write fails -> rolled back, pointer untouched, no stray generation
    monkeypatch.setattr(L, "write_snapshot", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(SystemExit):
        setst(world, A_ID, "acknowledged")
    monkeypatch.undo()
    assert by_id(world)[A_ID]["status"] == "notified"
    assert open(os.path.join(world["ldir"], "CURRENT")).read().strip() == ptr
    # commit fails after the snapshot -> snapshot discarded, pointer untouched
    real_commit = duckdb.DuckDBPyConnection.commit
    monkeypatch.setattr(duckdb.DuckDBPyConnection, "commit", lambda self: (_ for _ in ()).throw(RuntimeError("commit failed")))
    with pytest.raises(SystemExit):
        setst(world, A_ID, "acknowledged")
    monkeypatch.setattr(duckdb.DuckDBPyConnection, "commit", real_commit)
    assert by_id(world)[A_ID]["status"] == "notified"
    assert open(os.path.join(world["ldir"], "CURRENT")).read().strip() == ptr
    gens = os.listdir(os.path.join(world["ldir"], "snapshots"))
    assert ptr in gens and all(os.path.exists(os.path.join(world["ldir"], "snapshots", g, "leads.parquet")) for g in gens)
    # pruning keeps the newest 5
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
    setst(world, IOC_ID, "notified", via="direct")
    time_shift(world, date(2026, 10, 4))                       # stale, not gone
    counts, _ = refresh(world, date(2026, 10, 5))
    assert counts["remediated"] == 0 and by_id(world)[A_ID]["status"] == "notified"
    time_shift(world, date(2026, 11, 15))                      # gone
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
    counts, _ = refresh(world, date(2026, 11, 16))
    assert counts["remediated"] == 1
    # the SAME cached banner re-collected on a later day: not a newer scan -> stays remediated
    o = obs("10.0.0.1", 445, "education", product="Samba", d=date(2026, 11, 16), ts=datetime(2026, 9, 14, 3, 0, 0))
    add_store(world, [o], [vuln(o, "CVE-2020-0796", verified=True)])
    counts, _ = refresh(world, date(2026, 11, 17))
    r = by_id(world)[A_ID]
    assert counts["reopened"] == 0 and r["status"] == "remediated" and r["last_scan_ts"] == datetime(2026, 9, 14, 3, 0, 0)
    # a genuinely newer scan reopens a NEW episode
    o = obs("10.0.0.1", 445, "education", product="Samba", d=date(2026, 11, 17), ts=datetime(2026, 11, 17, 1, 0, 0))
    add_store(world, [o], [vuln(o, "CVE-2020-0796", verified=True)])
    counts, _ = refresh(world, date(2026, 11, 18))
    r = by_id(world)[A_ID]
    assert counts["reopened"] == 1 and r["status"] == "new" and r["prior_status"] == "remediated"
    assert r["notified_on"] is None and r["notified_via"] is None and r["last_scan_ts"] == datetime(2026, 11, 17, 1, 0, 0)
    assert "notified 2026-09-15 via MS-ISAC" in r["notes"] and "reopened" in events(world, A_ID)


def test_compromise_reopen_uses_ledger_banner_ts(world, monkeypatch):
    refresh(world)
    setst(world, CT_ID, "notified")
    time_shift(world, date(2026, 11, 15))
    refresh(world, date(2026, 11, 16))
    assert by_id(world)[CT_ID]["status"] == "remediated"
    monkeypatch.setattr(L, "COMPROMISE_WINDOW_DAYS", 365)
    led = json.loads((world["hits"] / "seen_ledger.json").read_text())
    led["hosts"]["10.0.0.9"]["last_seen"] = "2026-11-17"                # ledger touched, banner unchanged
    (world["hits"] / "seen_ledger.json").write_text(json.dumps(led))
    counts, _ = refresh(world, date(2026, 11, 18))
    assert counts["reopened"] == 0 and by_id(world)[CT_ID]["status"] == "remediated"
    led["hosts"]["10.0.0.9"]["last_banner_ts"] = "2026-11-17T09:00:00"
    (world["hits"] / "seen_ledger.json").write_text(json.dumps(led))
    counts, _ = refresh(world, date(2026, 11, 19))
    assert counts["reopened"] == 1 and by_id(world)[CT_ID]["status"] == "new"


def test_owner_change_closes_episode_and_flags_review(world):
    refresh(world)
    setst(world, A_ID, "notified", via="MS-ISAC", analyst="jd")
    reg = [r if r[0] != "10.0.0.1" else ["10.0.0.1", "ORG-OTHER", "Other College", "education", "state", "registry_network",
                                         "high", "moved", "2026-09-16"] for r in REGISTRY]
    write_registry(world["reg"], reg)
    counts, _ = refresh(world, date(2026, 9, 16))
    r = by_id(world)[A_ID]
    assert counts["owner_changed"] == 2                                   # both CVE leads on 10.0.0.1
    assert r["status"] == "new" and r["prior_status"] == "notified" and r["needs_attribution_review"] is True
    assert r["notified_on"] is None and r["notified_via"] is None and r["analyst"] is None
    assert r["org_id"] == "ORG-OTHER" and "ORG-TU -> ORG-OTHER" in r["notes"] and "notified 2026-09-15 via MS-ISAC" in r["notes"]
    ev = rows(world, "SELECT detail FROM lead_events WHERE lead_id = ? AND event = 'owner_changed'", [A_ID])
    assert json.loads(ev[0]["detail"])["old_org_id"] == "ORG-TU" and json.loads(ev[0]["detail"])["notified_via"] == "MS-ISAC"
    with pytest.raises(SystemExit):
        packet(world, date(2026, 9, 16), org="Other College")
    setst(world, A_ID, review_cleared=True, analyst="jd")
    assert by_id(world)[A_ID]["needs_attribution_review"] is False
    setst(world, A2_ID, review_cleared=True)
    assert "Other College" in packet(world, date(2026, 9, 16), org="Other College")
    # attribution confidence DROP also closes the episode
    setst(world, E_ID, "notified", via="direct")
    reg = [r for r in reg if r[0] != "10.0.0.6"]
    write_registry(world["reg"], reg)                                     # 10.0.0.6 falls back to shodan_org/low
    counts, _ = refresh(world, date(2026, 9, 17))
    r = by_id(world)[E_ID]
    assert r["status"] == "new" and r["needs_attribution_review"] and r["attr_confidence"] == "low" and r["notified_on"] is None


def test_legacy_migration_maps_old_kev_ids(world):
    old_a = L.lead_id("10.0.0.1", 445, "tcp", "kev_verified")               # legacy: no CVE in the hash
    old_b = L.lead_id("10.0.0.2", 443, "tcp", "kev_inferred")
    s = duckdb.connect(world["store"])
    s.execute("CREATE TABLE leads (lead_id VARCHAR, ip VARCHAR, port INTEGER, transport VARCHAR, org_id VARCHAR, org_name VARCHAR, "
              "tier VARCHAR, sector VARCHAR, evidence_type VARCHAR, evidence VARCHAR, confidence VARCHAR, first_seen DATE, "
              "last_seen DATE, status VARCHAR, notified_via VARCHAR, notified_on DATE, analyst VARCHAR, notes VARCHAR, updated_at TIMESTAMP)")
    s.executemany("INSERT INTO leads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
        [old_a, "10.0.0.1", 445, "tcp", None, "Test University", "education", "education", "kev_verified",
         "KEV CVE(s) VERIFIED by Shodan: CVE-2017-0144, CVE-2020-0796", "high", date(2026, 9, 1), date(2026, 9, 10),
         "notified", "MS-ISAC", date(2026, 9, 2), "jd", "old note", datetime(2026, 9, 10)],
        [old_b, "10.0.0.2", 443, "tcp", None, "Test University", "education", "education", "kev_inferred",
         "KEV CVE(s) inferred: CVE-2021-41773", "medium", date(2026, 9, 1), date(2026, 9, 10),
         "suppressed", None, None, "jd", "", datetime(2026, 9, 10)],
        [ICS_ID, "10.0.0.4", 502, "tcp", None, "Bayou Water", "critical_infrastructure", "critical_infrastructure", "ics",
         "ICS", "medium", date(2026, 9, 1), date(2026, 9, 10), "acknowledged", "direct", date(2026, 9, 3), "jd", "", datetime(2026, 9, 10)],
    ])
    s.close()
    counts, _ = refresh(world)
    r = by_id(world)
    assert counts["migrated"] == 2 and old_a not in r and old_b not in r
    for lid in (A_ID, A2_ID):
        assert r[lid]["status"] == "notified" and r[lid]["notified_via"] == "MS-ISAC" and r[lid]["notified_on"] == date(2026, 9, 2)
        assert r[lid]["needs_attribution_review"] is True and r[lid]["first_seen"] == date(2026, 9, 1)
        assert "migrated from legacy lead " + old_a in r[lid]["notes"] and "old note" in r[lid]["notes"]
        assert "migrated_from" in events(world, lid)
    assert r[B1_ID]["status"] == "suppressed" and r[B1_ID]["needs_attribution_review"] is False
    assert r[B2_ID]["status"] == "suppressed"                              # every per-CVE lead of that service
    assert r[ICS_ID]["status"] == "acknowledged" and "imported_legacy" in events(world, ICS_ID)
    assert "migrated_legacy_id" in events(world, old_a)
    refresh(world, date(2026, 9, 16))                                      # idempotent afterwards
    assert by_id(world)[A_ID]["status"] == "notified"


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
    assert L.fetch_dicts(c.con, "SELECT status, eligible FROM leads WHERE lead_id = ?", [A_ID])[0] == {"status": "acknowledged", "eligible": True}
    assert c.con.execute("SELECT count(*) FROM lead_events").fetchone()[0] > 0
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
    ss = L.ranked_leads(c, evidence="shadowserver")
    assert ss[0]["severity"] == "high" and ss[-1]["severity"] == "low"
    assert len(L.ranked_leads(c, org="ORG-CT")) == 4 and len(L.ranked_leads(c, statuses=("queued",))) == 0
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
    assert "**Status:** DRAFT" in md and "Second reviewer (recommended)" in md and "Priority:** HIGH" in md
    assert "have not accessed, scanned, or interacted" in md and "currently active (last observed 2026-09-14)" in md
    assert "registry method `registry_network`" in md and "confidence **high**" in md
    md_ics = packet(world, org="Bayou Water")
    assert "reachability alone is a serious exposure that must be verified" in md_ics and "reachability is control" not in md_ics
    assert "Shodan org field 'Bayou Water' only" in md_ics


def test_packet_appendix_cross_tenant_safety(world):
    refresh(world)
    app = packet(world, org="Test University").split("## Appendix A")[1]
    assert "| `10.0.0.1` | 80/tcp |" in app and "| `10.0.0.1` | 445/tcp |" in app          # whole-address ownership
    assert "omitted" not in app
    app2 = packet(world, org="City of Testville").split("## Appendix A")[1]
    assert "| `10.0.0.6` | 443/tcp |" in app2 and "22/tcp" not in app2                        # domain-attributed: leads only
    assert "Other services on 3 address(es) omitted: shared/unresolved ownership" in app2
    assert "`10.0.0.1` " not in app2


def test_packet_flags_attribution_conflict(world):
    refresh(world)
    c = ctx(world)
    c.con.execute("UPDATE leads SET org_id = 'ORG-ZZ', org_name = 'Zed Corp', last_evaluated = DATE '2026-09-10' WHERE lead_id = ?", [A2_ID])
    c.close()
    md = packet(world, org="Test University")
    assert "Attribution conflict" in md and "10.0.0.1" in md.split("**Attribution conflict**")[1].split("\n")[0]
    app = md.split("## Appendix A")[1]
    assert "80/tcp" not in app                                             # conflict removes whole-address privilege


def test_packet_shadowserver_classes_and_priority(world):
    refresh(world)
    md = packet(world, org="Delta Widgets")
    assert "**REQUIRED**" in md and "Possible infection — Shadowserver sinkhole" in md
    assert "Exposed or vulnerable service — Shadowserver scan report" in md and "| 443/tcp |" in md and "| — |" in md
    assert "51234" not in md.split("### Finding detail")[0]
    setst(world, L.lead_id("10.0.0.11", 0, "host", "shadowserver"), "false_positive")
    setst(world, CT_ID, "false_positive")
    md2 = packet(world, org="Delta Widgets")
    assert "Priority:** MEDIUM" in md2 and "Second reviewer (recommended)" in md2 and "Possible infection" not in md2


def test_packet_status_filtering_and_exposure_state(world):
    refresh(world)
    setst(world, A_ID, "notified", via="MS-ISAC")
    setst(world, A2_ID, "false_positive")
    setst(world, B1_ID, "suppressed")
    md = packet(world, org="Test University")
    assert "previously notified on 2026-09-15" in md and "— still observed" in md
    assert "CVE-2017-0144" not in md.split("### Finding detail")[1].split("## 3.")[0] and "CVE-2021-41773" not in md
    md2 = packet(world, org="Test University", include_closed=True)
    assert "CVE-2017-0144" in md2 and "closed; included on request" in md2
    # a new lead whose service is gone is listed as historical, not as a current finding
    time_shift(world, date(2026, 11, 15))                       # B2 (new) and A (notified) are now gone
    md3 = packet(world, date(2026, 11, 16), org="Test University")
    assert "### No longer observed — historical" in md3 and "| H1 |" in md3
    assert "no longer observed — last observed 2026-09-14" in md3 and "last observed 2026-09-14" in md3.split("Previously notified")[1].split("\n")[0]


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
    # host is residential NOW in the store (no refresh yet): refused on the packet side
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
    assert len([ln for ln in table.splitlines() if ln.startswith("| ")]) == 1 + 4


def test_packet_main_writes_file_and_pdf(world, tmp_path):
    refresh(world)
    out = tmp_path / "packets"
    rc = MP.main(["--ip", "10.0.0.6", "--db", world["store"], "--leads-dir", world["ldir"], "--out-dir", str(out),
                  "--date", "2026-09-15"] + (["--pdf"] if pytest.importorskip("reportlab") else []))
    assert rc == 0
    files = sorted(os.listdir(out))
    assert files == ["City_of_Testville_2026-09-15.md", "City_of_Testville_2026-09-15.pdf"]
    assert "10.0.0.6" in (out / files[0]).read_text() and (out / files[1]).stat().st_size > 1000


# --- shadowserver ------------------------------------------------------------------

CSV = ('"timestamp","ip","protocol","port","hostname","tag","asn","geo","region","city","naics","sector","infection","src_port","dst_ip"\n'
       '"2026-09-14 03:12:44","10.0.0.11","tcp","51234","host.example.net","avalanche-andromeda","64512","US","LOUISIANA","BATON ROUGE","0","","andromeda","51234","192.0.2.9"\n'
       '"2026-09-14 03:12:44","10.0.0.11","udp","51234","host.example.net","avalanche-andromeda","64512","US","LOUISIANA","BATON ROUGE","0","","andromeda","51234","192.0.2.9"\n'
       '"2026-09-14T03:13:01-05:00","10.0.0.12","sctp","","","","64512","US","LOUISIANA","LAFAYETTE","","","","",""\n'
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


def test_parse_report_validation_and_quarantine(tmp_path):
    p = tmp_path / "2026-09-14-sinkhole_http_drone-louisiana.csv"
    p.write_text(CSV)
    sha, events, bad = SS.parse_report(str(p), today=TODAY)
    assert len(events) == 3
    assert events[0]["timestamp"] == datetime(2026, 9, 14, 3, 12, 44) and events[1]["protocol"] == "udp"
    assert events[2]["timestamp"] == datetime(2026, 9, 14, 8, 13, 1) and events[2]["protocol"] == "other"
    assert json.loads(events[2]["detail"])["protocol_raw"] == "sctp"
    assert sorted(r for r, _ in bad) == ["future-dated", "invalid ip", "invalid protocol", "missing ip", "port out of range",
                                         "surplus fields", "unparseable timestamp"]
    assert SS.parse_ts("2026-09-14T03:12:44Z") == datetime(2026, 9, 14, 3, 12, 44)


def test_ingest_lock_identity_dedupe_and_recovery(tmp_path):
    store = str(tmp_path / "s.duckdb")
    inc, proc, quar = tmp_path / "incoming", tmp_path / "processed", tmp_path / "quarantine"
    pq, man = str(tmp_path / "ss" / "events.parquet"), str(tmp_path / "ss" / "manifest.json")
    inc.mkdir()
    (inc / "2026-09-14-sinkhole_http_drone-louisiana.csv").write_text(CSV)
    kw = dict(processed_dir=str(proc), quarantine_dir=str(quar), parquet=pq, manifest_path=man)
    # a concurrent ingester holds the lock: exit cleanly, nothing touched
    lock = SS.acquire_lock(pq)
    assert lock is not None
    assert SS.ingest_dir(None, str(inc), today=TODAY, **kw) is None and os.listdir(inc) and not os.path.exists(man)
    lock.close()
    assert SS.ingest_dir(None, str(inc), today=TODAY, dry_run=True, **kw) == {"loaded": 3}
    assert not os.path.exists(pq) and os.listdir(inc)
    # publication failure keeps the input in incoming/ (parquet + manifest already durable)
    class Broken:
        def execute(self, *a, **k):
            raise duckdb.Error("locked")
    assert SS.ingest_dir(Broken(), str(inc), today=TODAY, **kw) == {"unpublished": 1}
    assert os.listdir(inc) and os.path.exists(pq) and os.path.exists(man)
    con = duckdb.connect(store)
    assert SS.ingest_dir(con, str(inc), today=TODAY, **kw) == {"duplicate": 1}          # retried: now published + moved
    assert os.listdir(inc) == [] and len(os.listdir(proc)) == 1
    assert con.execute("SELECT count(*) FROM shadowserver_events").fetchone()[0] == 3    # tcp + udp kept apart
    m = json.load(open(man))
    ident, entry = next(iter(m["files"].items()))
    assert ident.endswith(":sinkhole_http_drone") and entry["report_type"] == "sinkhole_http_drone"
    assert entry["rows_loaded"] == 3 and entry["rows_quarantined"] == 7
    assert (quar / "2026-09-14-sinkhole_http_drone-louisiana.csv.quarantine.csv").read_text().count("\n") == 8
    # same bytes under a different report type = a different file; same rows = deduped events
    (inc / "2026-09-14-scan_ssl-louisiana.csv").write_text(CSV)
    tot = SS.ingest_dir(con, str(inc), today=TODAY, **kw)
    assert tot == {"loaded": 3} and con.execute("SELECT count(*) FROM shadowserver_events").fetchone()[0] == 6
    (inc / "copy (1).csv").write_text(CSV)                                              # type 'copy (1)' -> new identity, rows dedupe? no: type differs
    (inc / "2026-09-15-sinkhole_http_drone-louisiana.csv").write_text(CSV.splitlines()[0] + "\n" + CSV.splitlines()[1] + "\n")
    tot = SS.ingest_dir(con, str(inc), today=TODAY, **kw)
    assert tot.get("empty") == 1                                                          # overlapping rows: event-level dedupe
    con.execute("DROP TABLE shadowserver_events")
    assert SS.restore_table(con, pq)
    n = con.execute("SELECT count(*) FROM shadowserver_events").fetchone()[0]
    assert n == duckdb.connect().execute(f"SELECT count(*) FROM read_parquet('{pq}')").fetchone()[0]
    assert [r[0] for r in con.execute("SELECT column_name FROM information_schema.columns WHERE table_name='shadowserver_events' "
                                      "ORDER BY ordinal_position").fetchall()] == SS.EVENT_COLUMNS
    con.close()


def test_hmac2_known_vector():
    assert SS.hmac2("key", "The quick brown fox jumps over the lazy dog") == \
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"


def test_fetch_soft_fails_without_keys(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWSERVER_API_KEY", raising=False)
    monkeypatch.delenv("SHADOWSERVER_SECRET", raising=False)
    monkeypatch.setattr(SS, "ENV_PATH", str(tmp_path / "no.env"))
    assert SS.fetch("2026-09-14", incoming=str(tmp_path / "inc")) == 0
    monkeypatch.setenv("SHADOWSERVER_API_KEY", "k")
    monkeypatch.setenv("SHADOWSERVER_SECRET", "s")
    monkeypatch.setattr(SS, "api_call", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    assert SS.fetch("2026-09-14", incoming=str(tmp_path / "inc")) == 0
