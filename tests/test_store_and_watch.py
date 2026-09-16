"""Tests for the Phase-1 store/collector/tripwire changes:
observation identity, certificate + HTTP projection, the verified flag,
freshness views, collector dedup, and tripwire failure semantics.

Run:  venv/bin/python -m pytest tests/ -q
"""
import gzip
import json
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import build_store as bs          # noqa: E402
import shodan_collect as sc       # noqa: E402
import compromise_watch as cw     # noqa: E402


def banner(ip="203.0.113.10", port=443, transport="tcp", sid="rec-1", ts="2026-09-01T01:02:03",
           h=12345, org="Cox Communications", hostnames=(), domains=(), tags=(), vulns=None,
           cert=None, http=None, region="LA"):
    b = {"ip_str": ip, "port": port, "transport": transport, "timestamp": ts, "hash": h,
         "org": org, "hostnames": list(hostnames), "domains": list(domains), "tags": list(tags),
         "location": {"country_code": "US", "region_code": region, "city": "Baton Rouge"},
         "_shodan": {"id": sid, "module": "https"}, "vulns": vulns or {}}
    if cert:
        b["ssl"] = {"jarm": "29d29d", "cert": cert}
    if http:
        b["http"] = http
    return b


HOSPITAL_CERT = {
    "subject": {"CN": "vpn.ololrmc.com", "O": "Our Lady of the Lake Regional Medical Center"},
    "issuer": {"CN": "DigiCert TLS RSA SHA256 2020 CA1"},
    "expired": False, "expires": "20270101000000Z",
    "fingerprint": {"sha256": "ab" * 32},
    "extensions": [{"name": "subjectAltName", "data": "DNS:vpn.ololrmc.com, DNS:*.ololrmc.com, DNS:portal.ololrmc.com"}],
}


# --- observation identity ---------------------------------------------------

def test_observation_id_prefers_shodan_record_id():
    assert bs.observation_id(banner(sid="abc")) == "abc"
    b = banner(sid=None); del b["_shodan"]["id"]
    a = bs.observation_id(b)
    b2 = banner(sid=None, ip="203.0.113.11"); del b2["_shodan"]["id"]
    assert a and a != bs.observation_id(b2)


def test_collector_keeps_identical_banner_on_two_hosts_and_drops_page_repeats():
    seen = set()
    out = []
    class Out:
        def write(self, line): out.append(json.loads(line))
    same_hash = 999
    matches = [banner(ip="203.0.113.1", sid="r1", h=same_hash),
               banner(ip="203.0.113.2", sid="r2", h=same_hash),      # different host, same banner
               banner(ip="203.0.113.1", sid="r1", h=same_hash)]      # page repeat of r1
    w, d = sc._write_matches(matches, Out(), seen, lambda b: True)
    assert w == 2 and d == 0 and {o["ip_str"] for o in out} == {"203.0.113.1", "203.0.113.2"}
    # fallback key when there is no record id
    b3 = banner(ip="203.0.113.3", h=same_hash); del b3["_shodan"]["id"]
    b4 = dict(b3, timestamp="2026-09-01T09:00:00")
    assert sc.observation_key(b3) != sc.observation_key(b4)


# --- certificate / http projection -------------------------------------------

def test_cert_fields_and_identity_names():
    b = banner(cert=HOSPITAL_CERT, http={"title": "Portal", "host": "portal.ololrmc.com", "server": "nginx"})
    cf = bs.cert_fields(b)
    assert cf["cert_cn"] == "vpn.ololrmc.com" and cf["cert_org"].startswith("Our Lady")
    assert cf["cert_sans"] == "*.ololrmc.com,portal.ololrmc.com,vpn.ololrmc.com"
    assert cf["cert_expired"] is False and cf["cert_sha256"] == "ab" * 32 and cf["jarm"] == "29d29d"
    assert bs.identity_names(b) == {"vpn.ololrmc.com", "ololrmc.com", "portal.ololrmc.com"}
    assert bs.cert_fields(banner())["cert_cn"] is None
    assert bs.identity_names(banner(http={"host": "203.0.113.10:8443"})) == set()


def run_build_day(banners):
    d = tempfile.mkdtemp()
    gz = os.path.join(d, "louisiana-events-2026-09-01.json.gz")
    with gzip.open(gz, "wt") as f:
        for b in banners:
            f.write(json.dumps(b) + "\n")
    of = open(os.path.join(d, "obs.ndjson"), "w")
    vf = open(os.path.join(d, "vuln.ndjson"), "w")
    kev = {"CVE-2024-38475"}
    date, n_obs, n_vuln, n_drop = bs.build_day(gz, kev, {"CVE-2024-38475": 0.9}, of, vf, lambda r: True)
    of.close(); vf.close()
    obs = [json.loads(l) for l in open(of.name)]
    vul = [json.loads(l) for l in open(vf.name)]
    return date, obs, vul


def test_build_day_projects_identity_cert_verified_and_tiers_by_cert():
    b = banner(cert=HOSPITAL_CERT, http={"title": "Portal", "host": "portal.ololrmc.com", "server": "nginx"},
               vulns={"CVE-2024-38475": {"verified": True, "cvss": 9.8},
                      "CVE-2021-40438": {"verified": False, "cvss": 9.0}})
    date, obs, vul = run_build_day([b])
    assert date == "2026-09-01" and len(obs) == 1 and len(vul) == 2
    o = obs[0]
    assert o["observation_id"] == "rec-1" and o["cert_cn"] == "vpn.ololrmc.com"
    assert o["http_title"] == "Portal" and o["http_host"] == "portal.ololrmc.com"
    # a hospital certificate on Cox space attributes the hospital
    assert o["tier"] == "critical_infrastructure"
    by_cve = {v["cve"]: v for v in vul}
    assert by_cve["CVE-2024-38475"]["verified"] is True and by_cve["CVE-2024-38475"]["in_kev"] is True
    assert by_cve["CVE-2021-40438"]["verified"] is False
    assert all(v["observation_id"] == "rec-1" and v["transport"] == "tcp" for v in vul)


def test_build_day_two_hosts_same_banner_both_projected():
    a = banner(ip="203.0.113.1", sid="r1", h=7)
    b = banner(ip="203.0.113.2", sid="r2", h=7)
    _, obs, _ = run_build_day([a, b])
    assert {o["ip"] for o in obs} == {"203.0.113.1", "203.0.113.2"}


# --- freshness views ----------------------------------------------------------

def test_freshness_views_split_active_stale_gone():
    duckdb = pytest.importorskip("duckdb")
    d = tempfile.mkdtemp()
    bs.STORE = d; bs.OBS_DIR = os.path.join(d, "observations"); bs.VULN_DIR = os.path.join(d, "vulns")
    con = duckdb.connect(os.path.join(d, "t.duckdb"))
    rows = [("2026-09-14", "10.0.0.1", "active"), ("2026-08-20", "10.0.0.2", "stale"),
            ("2026-06-01", "10.0.0.3", "gone"), ("2026-09-01", "10.0.0.1", "older-row-of-active")]
    for date, ip, _ in rows:
        of = open(os.path.join(d, f"{date}.ndjson"), "w")
        of.write(json.dumps({"observation_id": f"{ip}-{date}", "date": date, "ip": ip, "port": 443,
                             "transport": "tcp", "asn": "AS1", "org": "x", "isp": "x", "product": None,
                             "version": None, "cpe23": "", "service": "https", "info": None, "city": None,
                             "region_code": "LA", "hostnames": "", "domains": "", "tags": "",
                             "banner_ts": f"{date}T00:00:00", "hash": "1", "tier": "small_business",
                             "http_title": None, "http_host": None, "http_server": None, "cert_cn": None,
                             "cert_org": None, "cert_issuer": None, "cert_sans": "", "cert_expired": None,
                             "cert_expires": None, "cert_sha256": None, "jarm": None}) + "\n")
        of.close()
        bs.copy_to_partition(con, of.name, 1, bs.OBS_DIR, date, bs.OBS_SELECT)
        vf = open(os.path.join(d, f"{date}.v.ndjson"), "w")
        vf.write(json.dumps({"observation_id": f"{ip}-{date}", "date": date, "ip": ip, "port": 443, "transport": "tcp",
                             "cve": "CVE-2020-0001", "cvss": 5.0, "in_kev": False, "epss": 0.1, "verified": False}) + "\n")
        vf.close()
        bs.copy_to_partition(con, vf.name, 1, bs.VULN_DIR, date, bs.VULN_SELECT)
    bs.refresh_views(con)
    status = dict(con.execute("select ip, status from exposure_status order by ip").fetchall())
    assert status == {"10.0.0.1": "active", "10.0.0.2": "stale", "10.0.0.3": "gone"}
    cur = con.execute("select ip, observation_id from current_state").fetchall()
    assert cur == [("10.0.0.1", "10.0.0.1-2026-09-14")]          # latest row wins, one per ip:port:transport
    assert con.execute("select count(*) from latest_observed").fetchone()[0] == 3
    joined = con.execute("select count(*) from current_state cs join vulns v on v.observation_id = cs.observation_id").fetchone()[0]
    assert joined == 1


# --- tripwire failure semantics -------------------------------------------------

def hit(ip, sel="tag:c2"):
    return {"ip": ip, "selectors": {sel}, "banners": [{"timestamp": "2026-09-01T00:00:00"}]}


def test_reconcile_new_ongoing_cleared():
    ledger = {"hosts": {"1.1.1.1": {"first_seen": "2026-08-01"}}, "_meta": {"last_run_active": ["1.1.1.1"]}}
    new, ongoing, cleared, recurred = cw.reconcile({"2.2.2.2": hit("2.2.2.2")}, ledger, "2026-09-01")
    assert new == ["2.2.2.2"] and ongoing == [] and cleared == ["1.1.1.1"] and recurred == []
    assert ledger["_meta"]["last_run_active"] == ["2.2.2.2"]


def test_reconcile_provider_failure_does_not_clear():
    ledger = {"hosts": {"1.1.1.1": {"first_seen": "2026-08-01"}}, "_meta": {"last_run_active": ["1.1.1.1"]}}
    new, ongoing, cleared, recurred = cw.reconcile({}, ledger, "2026-09-01", failed=["tag:c2"])
    assert cleared == [] and ledger["_meta"]["last_run_active"] == ["1.1.1.1"]
    assert ledger["_meta"]["last_run_incomplete"]["failed"] == ["tag:c2"]


def test_reconcile_recurred_host_is_alarming_again():
    ledger = {"hosts": {"1.1.1.1": {"first_seen": "2026-07-01", "last_seen": "2026-07-10"}},
              "_meta": {"last_run_active": []}}          # it had cleared
    new, ongoing, cleared, recurred = cw.reconcile({"1.1.1.1": hit("1.1.1.1")}, ledger, "2026-09-01")
    assert recurred == ["1.1.1.1"] and new == [] and ongoing == []
    assert ledger["hosts"]["1.1.1.1"]["first_seen"] == "2026-07-01"     # history preserved
