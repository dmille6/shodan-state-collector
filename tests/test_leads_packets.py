"""Tests for the Phase-2 leads table, notification packets and Shadowserver ingest.

A tiny fabricated store (observations + vulns TABLES with the same derived views
build_store.py defines) + a registry parquet + tripwire ledger + IOC list +
Shadowserver events exercise: every evidence rule, CVE-scoped identity, shared
appliance definitions, per-host eligibility and auto-suppression, idempotent
refresh, analyst-status durability (mirror crash), remediation only on 'gone',
reopen only on a newer observation, rebuild recovery for leads and Shadowserver
events, ranking, digest, packet content/escaping/status filtering/single-org,
Shadowserver report classes, quarantine, timestamps, idempotent ingest, HMAC2.

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
]


def obs(ip, port, tier, org="Test University", d=NEWEST, transport="tcp", **kw):
    row = {c: None for c in OBS_COLS}
    row.update({"observation_id": f"{ip}-{port}-{d}", "date": d, "ip": ip, "port": port, "transport": transport,
                "org": org, "tier": tier, "product": "nginx", "service": "http",
                "banner_ts": datetime(d.year, d.month, d.day, 3, 0, 0), "hash": "1", "tags": "", "hostnames": "",
                "city": "Baton Rouge"})
    row.update(kw)
    return row


def vuln(o, cve, verified=False, in_kev=True, epss=0.5, cvss=9.8):
    return {"observation_id": o["observation_id"], "date": o["date"], "ip": o["ip"], "port": o["port"],
            "transport": o["transport"], "cve": cve, "cvss": cvss, "in_kev": in_kev, "epss": epss,
            "verified": verified}


def add_obs(con, rows):
    if rows:
        con.executemany(f"INSERT INTO observations VALUES ({', '.join('?' * len(OBS_COLS))})",
                        [[r[c] for c in OBS_COLS] for r in rows])


def add_vulns(con, rows):
    cols = ["observation_id", "date", "ip", "port", "transport", "cve", "cvss", "in_kev", "epss", "verified"]
    if rows:
        con.executemany(f"INSERT INTO vulns VALUES ({', '.join('?' * len(cols))})", [[r[c] for c in cols] for r in rows])


def ss_event(rtype, ts, ip, port, proto="tcp", tag=None, sev="high"):
    return [rtype, ts, ip, port, proto, "64512", "US", tag, sev, json.dumps({"_class": SS.classify_report(rtype)}), TODAY]


@pytest.fixture
def world(tmp_path):
    store = str(tmp_path / "store.duckdb")
    con = duckdb.connect(store)
    con.execute("CREATE TABLE observations (" + ", ".join(f"{c} {OBS_TYPES.get(c, 'VARCHAR')}" for c in OBS_COLS) + ")")
    con.execute("CREATE TABLE vulns (observation_id VARCHAR, date DATE, ip VARCHAR, port INTEGER, transport VARCHAR, "
                "cve VARCHAR, cvss DOUBLE, in_kev BOOLEAN, epss DOUBLE, verified BOOLEAN)")
    a = obs("10.0.0.1", 445, "education", product="Samba")                                   # kev_verified x2 CVEs
    b = obs("10.0.0.2", 443, "education", product="Apache httpd", version="2.4.49")          # kev_inferred x2 CVEs
    c = obs("10.0.0.3", 443, "small_business", org="Bob's Bait", product="Apache httpd")     # non-priority: excluded
    d = obs("10.0.0.4", 502, "critical_infrastructure", org="Bayou Water", service="modbus", product=None)
    d2 = obs("10.0.0.5", 47808, "small_business", org="Acme Controls", service="auto", product=None)
    e = obs("10.0.0.6", 443, "government", org="City of Testville", product="FortiGate", http_title="FortiGate SSL-VPN")
    f = obs("10.0.0.7", 443, "small_business", org="Bob's Bait", product="FortiGate")        # non-priority
    g = obs("10.0.0.8", 8080, "residential", org="Cox Communications")                       # never
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
    add_obs(con, [a, b, c, d, d2, e, f, g, h, i, i2, j, k, sh, inj, old])
    add_vulns(con, [vuln(a, "CVE-2020-0796", verified=True, epss=0.9), vuln(a, "CVE-2017-0144", verified=True, epss=0.95),
                    vuln(b, "CVE-2021-41773", epss=0.97), vuln(b, "CVE-2021-42013", epss=0.6),
                    vuln(b, "CVE-2000-0001", in_kev=False), vuln(c, "CVE-2021-41773"),
                    vuln(g, "CVE-2020-0796", verified=True)])
    for v in VIEWS:
        con.execute(v)
    con.execute(SS.EVENTS_DDL)
    con.executemany("INSERT INTO shadowserver_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
        ss_event("sinkhole_http_drone", datetime(2026, 9, 12, 4, 5, 6), "10.0.0.11", 51234, tag="avalanche-andromeda"),
        ss_event("scan_ssl", datetime(2026, 9, 12, 5, 0, 0), "10.0.0.11", 443, sev="low"),
        ss_event("sinkhole_http_drone", datetime(2026, 8, 1, 4, 5, 6), "10.0.0.13", 22, tag="old"),
        ss_event("sinkhole_http_drone", datetime(2026, 9, 13, 1, 0, 0), "10.0.0.30", 40000, tag="qakbot"),  # registry-only host
    ])
    con.close()
    # registry attribution parquet
    reg = str(tmp_path / "ip_attribution.parquet")
    r = duckdb.connect()
    r.execute("CREATE TABLE a (ip VARCHAR, org_id VARCHAR, org_name VARCHAR, sector VARCHAR, jurisdiction VARCHAR, "
              "method VARCHAR, confidence VARCHAR, evidence VARCHAR, as_of VARCHAR)")
    r.executemany("INSERT INTO a VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [
        ["10.0.0.1", "ORG-TU", "Test University", "education", "state", "registry_network", "high", "10.0.0.0/29", "2026-09-15"],
        ["10.0.0.2", "ORG-TU", "Test University", "education", "state", "registry_network", "high", "10.0.0.0/29", "2026-09-15"],
        ["10.0.0.6", "ORG-CT", "City of Testville", "government", "municipal", "domain_dns", "high", "testville.la.gov", "2026-09-15"],
        ["10.0.0.15", "ORG-CT", "City of Testville", "government", "municipal", "domain_dns", "high", "x", "2026-09-15"],
        ["10.0.0.16", "ORG-CT", "City of Testville", "government", "municipal", "domain_dns", "high", "x", "2026-09-15"],
        ["10.0.0.30", "ORG-PJ", "Testville Police Jury", "government", "parish", "registry_asn", "medium", "AS1", "2026-09-15"],
        ["10.0.0.9", "", "", "", "", "arin_rdap", "low", "no registry org", "2026-09-15"],
    ])
    r.execute(f"COPY a TO '{reg}' (FORMAT PARQUET)")
    r.close()
    hits = tmp_path / "hits"
    hits.mkdir()
    ledger = {"hosts": {"10.0.0.9": {"first_seen": "2026-09-01", "last_seen": "2026-09-10", "selectors": ["tag:compromised"],
                                     "last_banner_ts": "2026-09-09T05:00:00"},
                        "10.0.0.10": {"first_seen": "2026-07-01", "last_seen": "2026-07-01", "selectors": ["tag:c2"]},
                        "10.0.0.20": {"first_seen": "2026-09-12", "last_seen": "2026-09-13", "selectors": ["tag:c2"]}},
              "_meta": {}}
    (hits / "seen_ledger.json").write_text(json.dumps(ledger))
    with gzip.open(hits / "louisiana-compromise-2026-09-10.json.gz", "wt") as fh:
        fh.write(json.dumps({"ip_str": "10.0.0.9", "port": 9200, "transport": "tcp", "tags": ["compromised", "database"],
                             "_compromise_selector": "tag:compromised", "timestamp": "2026-09-09T05:00:00"}) + "\n")
    ioc = tmp_path / "ioc_ips.json"
    ioc.write_text(json.dumps({"10.0.0.13": ["feodo"], "10.0.0.8": ["spamhaus_drop"], "192.0.2.1": ["x"]}))
    return {"store": store, "ldb": str(tmp_path / "leads" / "leads.duckdb"),
            "parquet": str(tmp_path / "leads" / "leads.parquet"), "events": str(tmp_path / "leads" / "lead_events.parquet"),
            "paths": {"ledger_path": str(hits / "seen_ledger.json"), "hits_dir": str(hits), "ioc_path": str(ioc),
                      "attribution_parquet": reg, "ss_parquet": str(tmp_path / "no_ss.parquet")},
            "tmp": tmp_path, "hits": hits}


def ctx(w, write=True):
    return L.open_ctx(w["store"], w["ldb"], write=write)


def refresh(w, today=TODAY):
    c = ctx(w)
    try:
        return L.refresh(c, today, parquet=w["parquet"], events_parquet=w["events"], **w["paths"])
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


def setst(w, lid, status, **kw):
    c = ctx(w)
    try:
        L.set_status(c, lid, status, today=kw.pop("today", TODAY), parquet=w["parquet"], events_parquet=w["events"], **kw)
    finally:
        c.close()


def add_store(w, obs_rows=(), vuln_rows=()):
    con = duckdb.connect(w["store"])
    add_obs(con, list(obs_rows))
    add_vulns(con, list(vuln_rows))
    con.close()


def time_shift(w, d):
    """A new day `d` in the store makes every older observation stale/gone."""
    add_store(w, [obs("10.0.0.99", 80, "small_business", org="Newcomer", d=d)])


def packet(w, today=TODAY, **kw):
    c = ctx(w, write=False)
    try:
        return MP.build_markdown(MP.gather(c, today, **kw))
    finally:
        c.close()


A_ID = L.lead_id("10.0.0.1", 445, "tcp", "kev_verified", "CVE-2020-0796")
A2_ID = L.lead_id("10.0.0.1", 445, "tcp", "kev_verified", "CVE-2017-0144")
B1_ID = L.lead_id("10.0.0.2", 443, "tcp", "kev_inferred", "CVE-2021-41773")
B2_ID = L.lead_id("10.0.0.2", 443, "tcp", "kev_inferred", "CVE-2021-42013")
ICS_ID = L.lead_id("10.0.0.4", 502, "tcp", "ics")
CT_ID = L.lead_id("10.0.0.9", 9200, "tcp", "compromise_tag")
IOC_ID = L.lead_id("10.0.0.13", 0, "host", "ioc_match")


# --- identity / definitions --------------------------------------------------------

def test_lead_id_cve_scoped_only_for_kev_types():
    import hashlib
    assert L.lead_id("1.2.3.4", 443, "tcp", "kev_inferred", "CVE-1") == \
        hashlib.sha1(b"1.2.3.4|443|tcp|kev_inferred|CVE-1").hexdigest()[:16]
    assert L.lead_id("1.2.3.4", 443, "tcp", "kev_inferred", "CVE-1") != L.lead_id("1.2.3.4", 443, "tcp", "kev_inferred", "CVE-2")
    assert L.lead_id("1.2.3.4", 443, "tcp", "ics", "anything") == hashlib.sha1(b"1.2.3.4|443|tcp|ics").hexdigest()[:16]


def test_appliance_definitions_shared_with_build_store():
    assert L.APPLIANCE_PATTERNS is bs.APPLIANCE_PATTERNS
    assert L.appliance_match({"product": "FortiGate", "cpe23": "", "http_title": ""})[0].startswith("Fortinet")
    assert L.appliance_match({"product": "", "cpe23": "", "http_title": "Outlook Web App"})[0].startswith("Microsoft Exchange")
    assert L.appliance_match({"product": "showa", "cpe23": "", "http_title": ""}) is None


# --- generation --------------------------------------------------------------------

def test_generation_rules_per_evidence_type(world):
    refresh(world)
    by = by_type(world)
    kv = {r["lead_id"]: r for r in by["kev_verified"]}
    assert set(kv) == {A_ID, A2_ID} and all(r["confidence"] == "high" and r["status"] == "new" for r in kv.values())
    assert kv[A_ID]["evidence_key"] == "CVE-2020-0796" and "VERIFIED" in kv[A_ID]["evidence"]
    assert (kv[A_ID]["org_id"], kv[A_ID]["org_name"], kv[A_ID]["sector"], kv[A_ID]["attr_method"],
            kv[A_ID]["attr_confidence"]) == ("ORG-TU", "Test University", "education", "registry_network", "high")
    ki = {r["lead_id"]: r for r in by["kev_inferred"]}
    assert set(ki) == {B1_ID, B2_ID}                                   # per CVE; 10.0.0.3 non-priority excluded
    assert all(r["confidence"] == "medium" for r in ki.values())
    assert sorted((r["ip"], r["port"]) for r in by["ics"]) == [("10.0.0.4", 502), ("10.0.0.5", 47808)]
    assert sorted(r["ip"] for r in by["appliance"]) == ["10.0.0.15", "10.0.0.16", "10.0.0.6"]   # priority tiers only
    ct = by["compromise_tag"]
    assert {(r["ip"], r["port"], r["transport"]) for r in ct} == {("10.0.0.9", 9200, "tcp"), ("10.0.0.20", 0, "host")}
    unk = next(r for r in ct if r["ip"] == "10.0.0.20")
    assert unk["org_name"] == L.UNATTRIBUTED and unk["attr_confidence"] == "none" and unk["tier"] == "unclassified"
    d9 = next(r for r in ct if r["ip"] == "10.0.0.9")
    assert d9["org_name"] == "Delta Widgets" and d9["attr_method"] == "shodan_org" and d9["attr_confidence"] == "low"
    ss = {(r["ip"], r["port"], r["transport"]): r for r in by["shadowserver"]}
    assert set(ss) == {("10.0.0.11", 0, "host"), ("10.0.0.11", 443, "tcp"), ("10.0.0.30", 0, "host")}
    assert ss[("10.0.0.11", 0, "host")]["confidence"] == "high" and ss[("10.0.0.11", 0, "host")]["evidence_key"].startswith("compromise:")
    assert "COMPROMISE" in ss[("10.0.0.11", 0, "host")]["evidence"] and "sinkhole_http_drone" in ss[("10.0.0.11", 0, "host")]["evidence"]
    assert ss[("10.0.0.11", 443, "tcp")]["confidence"] == "medium" and ss[("10.0.0.11", 443, "tcp")]["evidence_key"] == "exposure:scan_ssl"
    assert ss[("10.0.0.30", 0, "host")]["tier"] == "government" and ss[("10.0.0.30", 0, "host")]["org_name"] == "Testville Police Jury"
    io = by["ioc_match"]
    assert [(r["ip"], r["port"], r["transport"]) for r in io] == [("10.0.0.13", 0, "host")]
    ips = {r["ip"] for rs in by.values() for r in rs}
    assert not ips & {"10.0.0.8", "10.0.0.14", "10.0.0.10", "192.0.2.1", "10.0.0.3", "10.0.0.7"}
    assert all(r["first_seen"] == TODAY and r["last_evaluated"] == TODAY for rs in by.values() for r in rs)
    assert kv[A_ID]["last_seen"] == NEWEST and d9["last_seen"] == date(2026, 9, 10)


def test_residential_is_never_a_lead(world):
    _, excluded = refresh(world)
    assert excluded["residential"] >= 1 and excluded["honeypot"] >= 1
    assert rows(world, "SELECT count(*) AS n FROM leads WHERE tier IN ('residential', 'honeypot')")[0]["n"] == 0


def test_host_turning_residential_auto_suppresses_and_reinstates(world):
    refresh(world)
    setst(world, ICS_ID, "notified", via="direct", analyst="jd")
    add_store(world, [obs("10.0.0.4", 502, "residential", org="Bayou Water", service="modbus", product=None, d=date(2026, 9, 15))])
    counts, _ = refresh(world, date(2026, 9, 16))
    r = by_id(world)[ICS_ID]
    assert counts["auto_suppressed"] == 1 and r["status"] == "suppressed" and r["tier"] == "residential"
    assert "host now residential" in r["notes"] and r["analyst"] == "jd" and r["notified_via"] == "direct"
    assert "new -> notified" in r["notes"]                               # history preserved
    add_store(world, [obs("10.0.0.4", 502, "critical_infrastructure", org="Bayou Water", service="modbus", product=None, d=date(2026, 9, 17))])
    counts, _ = refresh(world, date(2026, 9, 18))
    r = by_id(world)[ICS_ID]
    assert counts["reinstated"] == 1 and r["status"] == "new" and "reinstated" in r["notes"]


# --- lifecycle ---------------------------------------------------------------------

def test_refresh_is_idempotent_and_separates_last_seen_from_last_evaluated(world):
    c1, _ = refresh(world)
    n1 = len(rows(world))
    c2, _ = refresh(world, date(2026, 9, 16))
    all_rows = rows(world)
    assert c1["inserted"] == n1 and c2["inserted"] == 0 and len(all_rows) == n1
    assert len({r["lead_id"] for r in all_rows}) == n1
    assert {r["first_seen"] for r in all_rows} == {TODAY}
    assert {r["last_evaluated"] for r in all_rows} == {date(2026, 9, 16)}
    assert max(r["last_seen"] for r in all_rows) == NEWEST                  # no newer observation: last_seen unchanged


def test_primary_key_enforced(world):
    refresh(world)
    c = ctx(world)
    try:
        with pytest.raises(duckdb.Error):
            c.con.execute("INSERT INTO leads (lead_id, ip) VALUES (?, '1.1.1.1')", [A_ID])
    finally:
        c.close()


def test_set_preserves_and_mirror_crash_rolls_back(world, monkeypatch):
    refresh(world)
    setst(world, A_ID, "notified", via="MS-ISAC", analyst="jd", note="sent")
    r = by_id(world)[A_ID]
    assert r["status"] == "notified" and r["notified_via"] == "MS-ISAC" and r["notified_on"] == TODAY
    assert "new -> notified via MS-ISAC by jd: sent" in r["notes"]
    mirror = duckdb.connect().execute(f"SELECT status FROM read_parquet('{world['parquet']}') WHERE lead_id = ?", [A_ID]).fetchone()
    assert mirror == ("notified",)
    ev = rows(world, "SELECT event FROM lead_events WHERE lead_id = ? ORDER BY ts", [A_ID])
    assert [e["event"] for e in ev] == ["created", "status"]
    # crash while writing the mirror -> nothing saved
    monkeypatch.setattr(L, "mirror_leads", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(SystemExit):
        setst(world, A_ID, "acknowledged")
    monkeypatch.undo()
    r = by_id(world)[A_ID]
    assert r["status"] == "notified" and "acknowledged" not in (r["notes"] or "")
    assert [e["event"] for e in rows(world, "SELECT event FROM lead_events WHERE lead_id = ?", [A_ID])] == ["created", "status"]
    # analyst status survives refresh
    counts, _ = refresh(world, date(2026, 9, 16))
    assert counts["preserved"] >= 1 and by_id(world)[A_ID]["status"] == "notified"


def test_cve_scoped_suppression(world):
    refresh(world)
    setst(world, B1_ID, "false_positive")
    add_store(world, [], [vuln(obs("10.0.0.2", 443, "education"), "CVE-2024-99999", epss=0.4)])
    refresh(world, date(2026, 9, 16))
    r = by_id(world)
    assert r[B1_ID]["status"] == "false_positive" and r[B2_ID]["status"] == "new"
    new_id = L.lead_id("10.0.0.2", 443, "tcp", "kev_inferred", "CVE-2024-99999")
    assert r[new_id]["status"] == "new"


def test_remediation_only_when_service_is_gone(world):
    refresh(world)
    setst(world, A_ID, "notified", via="direct")
    setst(world, IOC_ID, "notified", via="direct")
    time_shift(world, date(2026, 10, 4))                       # 09-14 is 20 d old: stale, not gone
    counts, _ = refresh(world, date(2026, 10, 5))
    assert counts["remediated"] == 0
    assert by_id(world)[A_ID]["status"] == "notified" and by_id(world)[IOC_ID]["status"] == "notified"
    time_shift(world, date(2026, 11, 15))                      # 62 d: gone
    counts, _ = refresh(world, date(2026, 11, 16))
    r = by_id(world)
    assert counts["remediated"] == 2 and r[A_ID]["status"] == "remediated" and r[IOC_ID]["status"] == "remediated"
    assert "remediated: service gone" in r[A_ID]["notes"]
    assert r[A2_ID]["status"] == "new"                            # only notified/acknowledged remediate


def test_host_level_needs_every_service_gone(world):
    refresh(world)
    setst(world, IOC_ID, "notified")
    add_store(world, [obs("10.0.0.13", 80, "unclassified", org="Some Carrier", d=date(2026, 11, 15))])   # one fresh service
    counts, _ = refresh(world, date(2026, 11, 16))
    assert counts["remediated"] == 0 and by_id(world)[IOC_ID]["status"] == "notified"


def test_reopen_only_on_newer_observation(world, monkeypatch):
    refresh(world)
    setst(world, CT_ID, "notified", via="MS-ISAC")
    time_shift(world, date(2026, 11, 15))                      # 9200 gone; ledger 09-10 outside the 30-d window
    counts, _ = refresh(world, date(2026, 11, 16))
    assert counts["remediated"] == 1 and by_id(world)[CT_ID]["status"] == "remediated"
    # the same cached evidence re-enters the window: unchanged obs date -> stays remediated
    monkeypatch.setattr(L, "COMPROMISE_WINDOW_DAYS", 365)
    counts, _ = refresh(world, date(2026, 11, 17))
    r = by_id(world)[CT_ID]
    assert counts["reopened"] == 0 and r["status"] == "remediated" and r["last_seen"] == date(2026, 9, 10)
    # a NEWER flag reopens as a new episode: notified_on cleared, history kept
    led = json.loads((world["hits"] / "seen_ledger.json").read_text())
    led["hosts"]["10.0.0.9"]["last_seen"] = "2026-11-17"
    (world["hits"] / "seen_ledger.json").write_text(json.dumps(led))
    counts, _ = refresh(world, date(2026, 11, 18))
    r = by_id(world)[CT_ID]
    assert counts["reopened"] == 1 and r["status"] == "new" and r["notified_on"] is None and r["notified_via"] is None
    assert r["last_seen"] == date(2026, 11, 17) and r["first_seen"] == TODAY
    assert "reopened" in r["notes"] and "notified 2026-09-15 via MS-ISAC" in r["notes"]
    assert "reopened" in [e["event"] for e in rows(world, "SELECT event FROM lead_events WHERE lead_id = ?", [CT_ID])]


def test_rebuild_recovery_for_leads(world):
    refresh(world)
    setst(world, A_ID, "acknowledged")
    # 1) the store is rebuilt: its leads COPY vanishes -> republished from the authoritative DB
    s = duckdb.connect(world["store"])
    s.execute("DROP TABLE leads")
    s.close()
    refresh(world, date(2026, 9, 16))
    s = duckdb.connect(world["store"], read_only=True)
    assert s.execute("SELECT status FROM leads WHERE lead_id = ?", [A_ID]).fetchone() == ("acknowledged",)
    s.close()
    # 2) the authoritative file itself is lost -> restored from the parquet mirror
    os.remove(world["ldb"])
    c = ctx(world)
    try:
        assert L.ensure_leads_db(c, world["parquet"], world["events"]) == "restored"
        assert L.fetch_dicts(c.con, "SELECT status FROM leads WHERE lead_id = ?", [A_ID])[0]["status"] == "acknowledged"
        assert c.con.execute("SELECT count(*) FROM lead_events").fetchone()[0] > 0
    finally:
        c.close()


# --- ranking / list / digest -------------------------------------------------------

def test_ranking_order_and_filters(world):
    refresh(world)
    c = ctx(world, write=False)
    try:
        order = [r["evidence_type"] for r in L.ranked_leads(c)]
        seen = [t for i, t in enumerate(order) if t not in order[:i]]
        assert seen == ["kev_verified", "compromise_tag", "shadowserver", "ics", "appliance", "kev_inferred", "ioc_match"]
        assert order == sorted(order, key=lambda t: L.EVIDENCE_RANK[t])
        top = L.ranked_leads(c, limit=2)
        assert [t["evidence_key"] for t in top] == ["CVE-2017-0144", "CVE-2020-0796"]      # EPSS 0.95 then 0.90
        assert top[0]["epss"] == pytest.approx(0.95)
        ss = [r for r in L.ranked_leads(c, evidence="shadowserver")]
        assert ss[0]["severity"] == "high" and ss[-1]["severity"] == "low"                  # compromise before exposure
        assert len(L.ranked_leads(c, org="ORG-CT")) == 3 and len(L.ranked_leads(c, org="city of testville")) == 3
        assert len(L.ranked_leads(c, statuses=("queued",))) == 0
    finally:
        c.close()


def test_digest_markdown_shows_attribution(world):
    refresh(world)
    c = ctx(world, write=False)
    try:
        md = L.digest(c, TODAY)
        assert "| education |" in md and "high=4" in md and "days-to-disappear" in md
        assert "still-open lead age: n=" in md and "-1d" not in md and "## By evidence type" in md
        assert "week ending" in L.digest(c, date(2026, 9, 30), weekly=True)
    finally:
        c.close()


# --- packets -----------------------------------------------------------------------

def test_packet_sections_and_wording(world):
    refresh(world)
    md = packet(world, org="Test University")
    for section in ("## 1. Summary", "## 2. What we observed", "## 3. What this is not", "## 4. Recommended actions",
                    "## 5. How to verify", "## 6. Contact and handling", "## Reviewer sign-off", "## Appendix A"):
        assert section in md, section
    assert "**Status:** DRAFT" in md and "TLP" in md and "Second reviewer (recommended)" in md
    assert "have not accessed, scanned, or interacted" in md and "Priority:** HIGH" in md
    assert "`10.0.0.1`" in md and "445/tcp" in md and "CVE-2020-0796" in md and "CVE-2017-0144" in md
    assert "registry method `registry_network`" in md and "confidence **high**" in md
    # only the lead's own CVE in each CVE finding
    f1 = md.split("#### Finding 1")[1].split("#### Finding 2")[0]
    assert f1.count("CISA KEV;") == 1
    # ICS wording
    md_ics = packet(world, org="Bayou Water")
    assert "reachability alone is a serious exposure that must be verified" in md_ics and "reachability is control" not in md_ics
    assert "Shodan org field 'Bayou Water' only" in md_ics and "confidence **low**" in md_ics


def test_packet_shadowserver_classes_and_priority(world):
    refresh(world)
    md = packet(world, org="Delta Widgets")
    assert "**REQUIRED**" in md and "Possible infection — Shadowserver sinkhole" in md
    assert "Exposed or vulnerable service — Shadowserver scan report" in md
    assert "| 443/tcp |" in md and "| — |" in md                        # exposure names the port; compromise is host-level
    assert "51234" not in md.split("## 3.")[0].split("### Finding detail")[0]   # source port never an exposed port
    assert "Priority:** HIGH" in md
    # exposure-only packet: medium, second reviewer only recommended
    setst(world, L.lead_id("10.0.0.11", 0, "host", "shadowserver"), "false_positive")
    setst(world, CT_ID, "false_positive")
    md2 = packet(world, org="Delta Widgets")
    assert "Priority:** MEDIUM" in md2 and "Second reviewer (recommended)" in md2 and "Possible infection" not in md2


def test_packet_status_filtering(world):
    refresh(world)
    setst(world, A_ID, "notified", via="MS-ISAC")
    setst(world, A2_ID, "false_positive")
    setst(world, B1_ID, "suppressed")
    md = packet(world, org="Test University")
    assert "previously notified on 2026-09-15" in md and "CVE-2020-0796" in md
    assert "CVE-2017-0144" not in md.split("### Finding detail")[1].split("## 3.")[0]
    assert "CVE-2021-41773" not in md
    md2 = packet(world, org="Test University", include_closed=True)
    assert "CVE-2017-0144" in md2 and "CVE-2021-41773" in md2 and "closed; included on request" in md2
    for lid in (B2_ID, A_ID):
        setst(world, lid, "remediated")
    with pytest.raises(SystemExit):
        packet(world, org="Test University")


def test_packet_refuses_multi_org_residential_and_unattributed(world, monkeypatch):
    refresh(world)
    c = ctx(world, write=False)
    try:
        real = L.ranked_leads
        two = [dict(r) for r in real(c, org="ORG-TU")[:1]] + [dict(r) for r in real(c, org="ORG-CT")[:1]]
        monkeypatch.setattr(L, "ranked_leads", lambda *a, **k: two)
        with pytest.raises(SystemExit) as ex:
            MP.select_leads(c, org="anything")
        assert "Test University" in str(ex.value) and "City of Testville" in str(ex.value)
        monkeypatch.undo()
        with pytest.raises(SystemExit):
            MP.select_leads(c, org="unattributed")
    finally:
        c.close()
    # a lead whose host is residential is refused even if the table says so
    c = ctx(world)
    c.con.execute("UPDATE leads SET tier = 'residential' WHERE lead_id = ?", [ICS_ID])
    c.close()
    with pytest.raises(SystemExit):
        packet(world, ip="10.0.0.4")
    # unattributed host: stated as such, never promoted
    md = packet(world, ip="10.0.0.20")
    assert "unattributed — no registry attribution" in md and "confidence **none**" in md


def test_packet_escapes_banner_text(world):
    refresh(world)
    md = packet(world, org="City of Testville")
    assert "**bold**" not in md and "[link](http://x)" not in md and "`code`" not in md
    assert "\\| \\*\\*bold\\*\\*" in md and "\\[link\\]" in md
    assert not any(line.startswith("# heading") for line in md.splitlines())
    table = md.split("## 2. What we observed")[1].split("\nScan age = ")[0]
    body = [ln for ln in table.splitlines() if ln.startswith("| ")]
    assert len(body) == 1 + 3                                   # header + one row per lead, nothing split by newlines
    assert "a'b\\|c" in md


def test_packet_appendix_only_active_same_org(world):
    refresh(world)
    add_store(world, [obs("10.0.0.6", 22, "government", org="City of Testville", product="OpenSSH", d=date(2026, 6, 1))])
    md = packet(world, org="City of Testville")
    app = md.split("## Appendix A")[1]
    assert "| `10.0.0.6` | 443/tcp |" in app and "22/tcp" not in app          # stale service excluded
    assert "`10.0.0.1`" not in app                                               # other org's hosts excluded


def test_packet_main_writes_file_and_pdf(world, tmp_path):
    refresh(world)
    out = tmp_path / "packets"
    rc = MP.main(["--ip", "10.0.0.6", "--db", world["store"], "--leads-db", world["ldb"], "--out-dir", str(out),
                  "--date", "2026-09-15"] + (["--pdf"] if pytest.importorskip("reportlab") else []))
    assert rc == 0
    files = sorted(os.listdir(out))
    assert files == ["City_of_Testville_2026-09-15.md", "City_of_Testville_2026-09-15.pdf"]
    assert "10.0.0.6" in (out / files[0]).read_text() and (out / files[1]).stat().st_size > 1000


# --- shadowserver ------------------------------------------------------------------

CSV = ('"timestamp","ip","protocol","port","hostname","tag","asn","geo","region","city","naics","sector","infection","src_port","dst_ip"\n'
       '"2026-09-14 03:12:44","10.0.0.11","tcp","51234","host.example.net","avalanche-andromeda","64512","US","LOUISIANA","BATON ROUGE","0","","andromeda","51234","192.0.2.9"\n'
       '"2026-09-14T03:13:01-05:00","10.0.0.12","udp","","","","64512","US","LOUISIANA","LAFAYETTE","","","","",""\n'
       '"2026-09-14 03:14:00","","tcp","80","","","","","","","","","","",""\n'
       '"2027-01-01 00:00:00","10.0.0.13","tcp","80","","","","","","","","","","",""\n'
       '"2026-09-14 03:15:00","10.0.0.14","tcp","80","","","","","","","","","","","","SURPLUS"\n'
       '"not a date","10.0.0.15","tcp","80","","","","","","","","","","",""\n')


def test_classify_report_types():
    for t in ("sinkhole_http_drone", "microsoft_sinkhole", "spam", "compromised_website", "malware_url", "botnet_drone", "cc_ip"):
        assert SS.classify_report(t) == "compromise", t
    for t in ("scan_ssl", "vulnerable_exchange", "exposed_ipp", "ics", "open_elasticsearch", "accessible_rdp", "blocklist", "unknown_thing"):
        assert SS.classify_report(t) == "exposure", t


def test_parse_report_quarantine_and_timestamps(tmp_path):
    p = tmp_path / "2026-09-14-sinkhole_http_drone-louisiana.csv"
    p.write_text(CSV)
    sha, events, bad = SS.parse_report(str(p), today=TODAY)
    assert len(sha) == 64 and len(events) == 2
    assert events[0]["timestamp"] == datetime(2026, 9, 14, 3, 12, 44) and events[0]["port"] == 51234
    assert events[1]["timestamp"] == datetime(2026, 9, 14, 8, 13, 1)          # -05:00 offset -> UTC
    assert sorted(r for r, _ in bad) == ["future-dated", "missing ip", "surplus fields", "unparseable timestamp"]
    d = json.loads(events[0]["detail"])
    assert d["_class"] == "compromise" and d["_file_sha"] == sha and d["hostname"] == "host.example.net"
    assert SS.parse_ts("2026-09-14T03:12:44Z") == datetime(2026, 9, 14, 3, 12, 44)
    assert SS.parse_filename("2026-09-14-scan_ssl-united_states-geo.csv") == ("2026-09-14", "scan_ssl", "united_states-geo")


def test_ingest_idempotent_transactional_and_rebuild_recovery(tmp_path):
    store = str(tmp_path / "s.duckdb")
    inc, proc, quar = tmp_path / "incoming", tmp_path / "processed", tmp_path / "quarantine"
    pq, man = str(tmp_path / "ss" / "events.parquet"), str(tmp_path / "ss" / "manifest.json")
    inc.mkdir()
    (inc / "2026-09-14-sinkhole_http_drone-louisiana.csv").write_text(CSV)
    kw = dict(processed_dir=str(proc), quarantine_dir=str(quar), parquet=pq, manifest_path=man)
    assert SS.ingest_dir(None, str(inc), today=TODAY, dry_run=True, **kw) == {"loaded": 2}
    assert not os.path.exists(pq) and not os.path.exists(man) and os.listdir(inc)
    con = duckdb.connect(store)
    assert SS.ingest_dir(con, str(inc), today=TODAY, **kw) == {"loaded": 2}
    assert os.listdir(inc) == [] and len(os.listdir(proc)) == 1
    assert (quar / "2026-09-14-sinkhole_http_drone-louisiana.csv.quarantine.csv").read_text().count("\n") == 5
    assert con.execute("SELECT count(*) FROM shadowserver_events").fetchone()[0] == 2
    m = json.load(open(man))
    entry = list(m["files"].values())[0]
    assert entry["report_type"] == "sinkhole_http_drone" and entry["rows_loaded"] == 2 and entry["rows_quarantined"] == 4
    # same bytes, new name -> duplicate by sha; overlapping rows in a different file -> event-level dedupe
    (inc / "copy (1).csv").write_text(CSV)
    (inc / "2026-09-15-sinkhole_http_drone-louisiana.csv").write_text(CSV.splitlines()[0] + "\n" + CSV.splitlines()[1] + "\n"
        + '"2026-09-15 01:00:00","10.0.0.11","tcp","51235","","avalanche-andromeda","64512","US","","","","","","",""\n')
    tot = SS.ingest_dir(con, str(inc), today=TODAY, **kw)
    assert tot == {"duplicate": 1, "loaded": 1}
    assert con.execute("SELECT count(*) FROM shadowserver_events").fetchone()[0] == 3
    assert duckdb.connect().execute(f"SELECT count(*) FROM read_parquet('{pq}')").fetchone()[0] == 3
    # store rebuilt: table gone -> restored exactly from the parquet
    con.execute("DROP TABLE shadowserver_events")
    assert SS.restore_table(con, pq)
    got = con.execute("SELECT report_type, ip, port, tag FROM shadowserver_events ORDER BY timestamp, port").fetchall()
    assert got == [("sinkhole_http_drone", "10.0.0.11", 51234, "avalanche-andromeda"), ("sinkhole_http_drone", "10.0.0.12", None, None),
                   ("sinkhole_http_drone", "10.0.0.11", 51235, "avalanche-andromeda")]
    cols = [r[0] for r in con.execute("SELECT column_name FROM information_schema.columns WHERE table_name='shadowserver_events' "
                                      "ORDER BY ordinal_position").fetchall()]
    assert cols == SS.EVENT_COLUMNS
    con.close()


def test_leads_read_shadowserver_parquet_when_table_is_gone(world, tmp_path):
    pq = str(tmp_path / "ss" / "events.parquet")
    SS.append_parquet([{"report_type": "scan_ssl", "timestamp": datetime(2026, 9, 13, 1, 0), "ip": "10.0.0.6", "port": 443,
                        "protocol": "tcp", "asn": None, "geo": None, "tag": None, "severity": "low", "detail": "{}",
                        "ingested_on": TODAY}], pq)
    s = duckdb.connect(world["store"])
    s.execute("DROP TABLE shadowserver_events")
    s.close()
    world["paths"]["ss_parquet"] = pq
    refresh(world)
    ss = by_type(world)["shadowserver"]
    assert [(r["ip"], r["port"]) for r in ss] == [("10.0.0.6", 443)]


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
