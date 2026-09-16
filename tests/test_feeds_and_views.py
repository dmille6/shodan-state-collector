"""Tests for the Phase-2 integrator pieces: exploit/IOC feed parsers, has_exploit,
registry-driven tiering in build_store, and the appliance / ioc views."""
import json
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import refresh_reference as rr     # noqa: E402
import build_store as bs           # noqa: E402
from tests.test_store_and_watch import banner, run_build_day   # noqa: E402


def test_feed_parsers():
    msf = json.dumps({"exploit/x": {"references": ["CVE-2021-1234", "URL-http://x"]},
                      "aux/y": {"references": ["cve-2019-0708"]}}).encode()
    assert rr.parse_metasploit(msf) == {"CVE-2021-1234": {"metasploit"}, "CVE-2019-0708": {"metasploit"}}
    nuc = b'{"ID":"CVE-2000-0114","Info":{"Name":"x"}}\n{"ID":"not-a-cve"}\n'
    assert rr.parse_nuclei(nuc) == {"CVE-2000-0114": {"nuclei"}}
    assert rr.parse_ip_lines(b"# c\n1.2.3.4\n5.6.7.8 # x\nnot an ip\n", "feodo") == {"1.2.3.4": {"feodo"}, "5.6.7.8": {"feodo"}}
    assert rr.parse_cidr_lines(b"; hdr\n1.2.3.0/24 ; SBL1\n", "spamhaus_drop") == {"1.2.3.0/24": {"spamhaus_drop"}}
    tf = b'# hdr\n"2026-09-01 00:00:00", "1", "9.9.9.9:443", "ip:port", "botnet_cc"\n'
    assert rr.parse_threatfox(tf) == {"9.9.9.9": {"threatfox"}}
    assert rr.parse_urlhaus(b"http://1.1.1.1:8080/bin.sh\nhttp://evil.example/x\nhttp://1.2.3.4.example.org/x\n") == {"1.1.1.1": {"urlhaus"}}


def test_has_exploit_projected():
    b = banner(vulns={"CVE-2024-38475": {"verified": False, "cvss": 9.8}, "CVE-2000-0001": {"cvss": 5}})
    d = tempfile.mkdtemp()
    gz = os.path.join(d, "louisiana-events-2026-09-01.json.gz")
    import gzip
    with gzip.open(gz, "wt") as f:
        f.write(json.dumps(b) + "\n")
    of, vf = open(os.path.join(d, "o"), "w"), open(os.path.join(d, "v"), "w")
    bs.build_day(gz, {"CVE-2024-38475"}, {}, of, vf, lambda r: True, exploits={"CVE-2024-38475": ["nuclei"]})
    of.close(); vf.close()
    vul = {json.loads(l)["cve"]: json.loads(l) for l in open(vf.name)}
    assert vul["CVE-2024-38475"]["has_exploit"] is True and vul["CVE-2000-0001"]["has_exploit"] is False


class FakeAttributor:
    def __init__(self, table): self.table = table
    def lookup(self, ip): return self.table.get(ip)


def test_registry_high_confidence_overrides_keyword_tier():
    attr = FakeAttributor({"203.0.113.10": {"org_id": "la-ots", "org_name": "Office of Technology Services",
                                            "sector": "government", "method": "ots_cidr", "confidence": "high"}})
    b = banner(org="Cox Communications", hostnames=["wsip-1-2-3-4.br.br.cox.net"], domains=["cox.net"])
    d = tempfile.mkdtemp(); gz = os.path.join(d, "louisiana-events-2026-09-01.json.gz")
    import gzip
    with gzip.open(gz, "wt") as f:
        f.write(json.dumps(b) + "\n")
    of, vf = open(os.path.join(d, "o"), "w"), open(os.path.join(d, "v"), "w")
    bs.build_day(gz, set(), {}, of, vf, lambda r: True, attributor=attr)
    of.close(); vf.close()
    o = json.loads(open(of.name).readline())
    assert o["tier"] == "government" and o["tier_reason"].startswith("registry: Office of Technology Services")
    assert o["attr_org_id"] == "la-ots" and o["attr_confidence"] == "high"
    # low confidence is recorded but does not override
    attr2 = FakeAttributor({"203.0.113.10": {"org_id": "", "org_name": "COX-AS", "sector": "", "method": "cymru_asn", "confidence": "low"}})
    of, vf = open(os.path.join(d, "o2"), "w"), open(os.path.join(d, "v2"), "w")
    bs.build_day(gz, set(), {}, of, vf, lambda r: True, attributor=attr2)
    of.close(); vf.close()
    o = json.loads(open(of.name).readline())
    assert o["tier"] == "residential" and o["attr_method"] == "cymru_asn"


def test_appliance_and_ioc_views():
    duckdb = pytest.importorskip("duckdb")
    d = tempfile.mkdtemp()
    bs.STORE = d; bs.OBS_DIR = os.path.join(d, "observations"); bs.VULN_DIR = os.path.join(d, "vulns")
    con = duckdb.connect(os.path.join(d, "t.duckdb"))
    base = {"date": "2026-09-14", "transport": "tcp", "asn": "AS1", "org": "x", "isp": "x", "version": None,
            "cpe23": "", "service": "https", "info": None, "city": None, "region_code": "LA", "hostnames": "",
            "domains": "", "tags": "", "banner_ts": None, "hash": "1", "tier": "government", "tier_reason": "r",
            "attr_org_id": None, "attr_org_name": None, "attr_method": None, "attr_confidence": None,
            "http_host": None, "http_server": None, "cert_cn": None, "cert_org": None, "cert_issuer": None,
            "cert_sans": "", "cert_expired": None, "cert_expires": None, "cert_sha256": None, "jarm": None}
    rows = [dict(base, observation_id="a", ip="10.0.0.1", port=443, product="FortiGate", http_title=None),
            dict(base, observation_id="b", ip="10.0.0.2", port=443, product=None, http_title="Citrix Gateway"),
            dict(base, observation_id="c", ip="10.0.0.3", port=80, product="Apache httpd", http_title="Fortitude Bank")]
    of = open(os.path.join(d, "o.ndjson"), "w")
    for r in rows:
        of.write(json.dumps(r) + "\n")
    of.close()
    bs.copy_to_partition(con, of.name, 3, bs.OBS_DIR, "2026-09-14", bs.OBS_SELECT)
    ioc_path = os.path.join(d, "ioc_ips.json")
    json.dump({"10.0.0.3": ["cins"], "_cidrs": {}, "_meta": {}}, open(ioc_path, "w"))
    real = bs.tr.load_json
    bs.tr.load_json = lambda p, default: json.load(open(ioc_path)) if p.endswith("ioc_ips.json") else default
    try:
        bs.refresh_views(con)
    finally:
        bs.tr.load_json = real
    appl = dict(con.execute("select ip, appliance from appliance_exposure order by ip").fetchall())
    assert appl == {"10.0.0.1": "Fortinet FortiGate/FortiOS", "10.0.0.2": "Citrix NetScaler/Gateway"}   # 'Fortitude' is not FortiGate
    assert con.execute("select ip, ioc_sources from ioc_matches").fetchall() == [("10.0.0.3", "cins")]



def test_real_attributor_prefix_changes_stored_tier():
    """Integration: the real registry.Attributor, a curated /24, and build_day."""
    registry = pytest.importorskip("registry")
    a = registry.Attributor()
    a.orgs["la-ots"] = {"org_id": "la-ots", "name": "Louisiana Office of Technology Services",
                        "sector": "government", "jurisdiction": "state"}
    a.networks.add("203.0.113.0/24", {"org_id": "la-ots", "source": "curated", "confidence": "high"})
    b = banner(org="Cox Communications", hostnames=["wsip-1-2-3-4.br.br.cox.net"], domains=["cox.net"])
    d = tempfile.mkdtemp(); gz = os.path.join(d, "louisiana-events-2026-09-01.json.gz")
    import gzip
    with gzip.open(gz, "wt") as f:
        f.write(json.dumps(b) + "\n")
    of, vf = open(os.path.join(d, "o"), "w"), open(os.path.join(d, "v"), "w")
    bs.build_day(gz, set(), {}, of, vf, lambda r: True, attributor=a)
    of.close(); vf.close()
    o = json.loads(open(of.name).readline())
    assert o["tier"] == "government" and o["attr_method"] == "registry_network"
    assert "Office of Technology Services" in o["tier_reason"] and "keyword said residential" in o["tier_reason"]


def test_domain_or_cert_attribution_never_sets_the_tier():
    for method in ("domain_dns", "cert", "registry_asn", "roster_name", "arin_rdap"):
        a = {"org_id": "la-ochsner", "org_name": "Ochsner", "sector": "healthcare",
             "method": method, "confidence": "high", "evidence": "x"}
        assert bs.registry_tier(a) is None, method
    assert bs.registry_tier({"org_id": "x", "sector": "government", "method": "ots_cidr",
                             "confidence": "high", "evidence": "prefix 10.0.0.0/8 (ots)"}) == "government"
    assert bs.registry_tier({"org_id": "x", "sector": "government", "method": "registry_network",
                             "confidence": "high", "evidence": "prefix; also matches la-y"}) is None
    assert bs.registry_tier({"org_id": "x", "sector": "government", "method": "ots_cidr",
                             "confidence": "medium", "evidence": "p"}) is None


def test_load_attributor_reports_failure_loudly(monkeypatch, capsys):
    import types, sys as _sys
    fake = types.ModuleType("registry")
    class Broken:
        def load(self, *a, **k): raise RuntimeError("boom")
    fake.Attributor = Broken
    monkeypatch.setitem(_sys.modules, "registry", fake)
    assert bs.load_attributor() is None
    assert "FAILED to load" in capsys.readouterr().err


def test_feed_refresh_keeps_previous_entries_when_a_source_fails(tmp_path, monkeypatch):
    rr.REF = str(tmp_path)
    path = tmp_path / "exploits.json"
    json.dump({"CVE-2020-0001": ["metasploit"], "CVE-2020-0002": ["nuclei"], "_meta": {}}, open(path, "w"))
    def fake_fetch(url, timeout=60):
        if "metasploit" in url:
            raise OSError("down")
        return b'{"ID":"CVE-2021-0003"}\n'
    monkeypatch.setattr(rr, "fetch", fake_fetch)
    rr.refresh_exploits()
    out = json.load(open(path))
    assert out["CVE-2020-0001"] == ["metasploit"]          # kept from the previous generation
    assert "CVE-2020-0002" not in out                       # nuclei refreshed successfully: gone
    assert out["CVE-2021-0003"] == ["nuclei"] and out["_meta"]["sources"]["metasploit"]["stale"] is True
    monkeypatch.setattr(rr, "fetch", lambda url, timeout=60: (_ for _ in ()).throw(OSError("all down")))
    rr.refresh_exploits()
    assert json.load(open(path)) == out                    # every source failed: file untouched
