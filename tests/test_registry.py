"""Tests for the Phase-2 owner registry: CSV loading, longest-prefix and
label-boundary domain matching, the Cymru / RDAP parsers, attribution
precedence, the OTS drop-in and the Attributor over real parquet files.
No network: every external call is a canned string / dict.

Run:  venv/bin/python -m pytest tests/test_registry.py -q
"""
import json
import os
import sys
from datetime import date

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import registry as rg              # noqa: E402
import build_registry as br        # noqa: E402

TODAY = date(2026, 9, 15)
AS_OF = "2026-09-15"

ORGS_CSV = """org_id,name,sector,jurisdiction,aliases,domains,contact_route,notes,source,as_of
la-nola,City of New Orleans,government,municipal,City of New Orleans;NOLA,nola.gov,MS-ISAC,,curated,2026-09-15
la-lsu,Louisiana State University,education,state,LSU,lsu.edu;lsuagcenter.com,direct,,curated,2026-09-15
la-ochsner,Ochsner Health,healthcare,private,Ochsner;Ochsner Clinic Foundation,ochsner.org,Health-ISAC,,curated,2026-09-15
la-ots,Louisiana Office of Technology Services,government,state,OTS;State of Louisiana,la.gov,OTS/ESF-17,,curated,2026-09-15
la-dow,Dow Louisiana Operations,critical_infrastructure,private,Dow;Dow Chemical,dow.com,direct,,curated,2026-09-15
"""
NETWORKS_CSV = """prefix,asn,org_id,source,confidence,as_of
10.0.0.0/16,AS2055,la-lsu,curated,high,2026-09-15
10.0.5.0/24,,la-nola,curated,high,2026-09-15
,AS63103,la-ochsner,curated,medium,2026-09-15
"""
DOMAINS_CSV = """domain,org_id,source,confidence,as_of
nola.gov,la-nola,curated,high,2026-09-15
lsu.edu,la-lsu,curated,high,2026-09-15
"""


@pytest.fixture
def ref_dir(tmp_path):
    d = tmp_path / "registry"
    d.mkdir()
    (d / "orgs.csv").write_text(ORGS_CSV)
    (d / "networks.csv").write_text(NETWORKS_CSV)
    (d / "domains.csv").write_text(DOMAINS_CSV)
    return str(d)


# --- CSV loading -------------------------------------------------------------

def test_load_registry_csvs_merges_org_domains_and_validates(ref_dir):
    orgs, nets, doms = br.load_registry_csvs(ref_dir)
    assert [o["org_id"] for o in orgs] == ["la-nola", "la-lsu", "la-ochsner", "la-ots", "la-dow"]
    # domains.csv had 2 rows; orgs.csv contributes the rest (dedup on nola.gov / lsu.edu)
    by_dom = {d["domain"]: d for d in doms}
    assert set(by_dom) == {"nola.gov", "lsu.edu", "lsuagcenter.com", "ochsner.org", "la.gov", "dow.com"}
    assert by_dom["lsuagcenter.com"]["source"] == "orgs.csv"
    assert by_dom["nola.gov"]["source"] == "curated"
    # networks: prefixes normalised, ASN normalised, ASN-only rows allowed
    assert nets[0]["prefix"] == "10.0.0.0/16" and nets[0]["asn"] == "AS2055"
    assert nets[2]["prefix"] == "" and nets[2]["asn"] == "AS63103"


def test_csv_validation_rejects_bad_rows(tmp_path):
    p = tmp_path / "orgs.csv"
    p.write_text(ORGS_CSV.replace("healthcare", "hospitalz"))
    with pytest.raises(ValueError, match="unknown sector"):
        rg.load_orgs(str(p))
    p.write_text("org_id,name\nx,y\n")
    with pytest.raises(ValueError, match="missing column"):
        rg.load_orgs(str(p))
    n = tmp_path / "networks.csv"
    n.write_text("prefix,asn,org_id,source,confidence,as_of\n,,la-lsu,curated,high,2026-09-15\n")
    with pytest.raises(ValueError, match="neither prefix nor asn"):
        rg.load_networks(str(n))


def test_unknown_org_id_in_networks_is_rejected(ref_dir):
    with open(os.path.join(ref_dir, "networks.csv"), "a") as fh:
        fh.write("10.9.0.0/24,,la-nobody,curated,high,2026-09-15\n")
    with pytest.raises(ValueError, match="unknown org_id"):
        br.load_registry_csvs(ref_dir)


def test_norm_asn():
    assert rg.norm_asn("2055") == "AS2055"
    assert rg.norm_asn(" as2055 ") == "AS2055"
    assert rg.norm_asn("NA") == "" and rg.norm_asn(None) == ""


# --- longest-prefix matching -------------------------------------------------

def test_longest_prefix_wins_over_covering_16():
    t = rg.PrefixTable()
    t.add("10.0.0.0/16", "wide")
    t.add("10.0.5.0/24", "narrow")
    assert t.lookup("10.0.5.7") == ("10.0.5.0/24", "narrow")
    assert t.lookup("10.0.6.7") == ("10.0.0.0/16", "wide")
    assert t.lookup("10.1.0.1") is None
    assert t.lookup("not-an-ip") is None


def test_prefix_table_handles_ipv6_and_non_network_form():
    t = rg.PrefixTable()
    t.add("2001:db8::/32", "v6")
    t.add("192.0.2.77/24", "v4")           # host bits set; normalised to /24 network
    assert t.lookup("2001:db8:1::1") == ("2001:db8::/32", "v6")
    assert t.lookup("192.0.2.1") == ("192.0.2.0/24", "v4")
    assert t.lookup("2001:db9::1") is None


# --- domain matching ---------------------------------------------------------

def test_under_domain_respects_label_boundary():
    assert rg.under_domain("nola.gov", "nola.gov")
    assert rg.under_domain("vpn.nola.gov.", "nola.gov")
    assert rg.under_domain("*.nola.gov", "nola.gov")
    assert not rg.under_domain("evilnola.gov", "nola.gov")
    assert not rg.under_domain("nola.gov.evil.com", "nola.gov")


def test_domain_table_longest_suffix_and_boundary():
    t = rg.DomainTable()
    t.add("la.gov", "ots")
    t.add("dotd.la.gov", "dotd")
    t.add("nola.gov", "nola")
    assert t.lookup("www.dotd.la.gov") == ("dotd.la.gov", "dotd")
    assert t.lookup("ldh.la.gov") == ("la.gov", "ots")
    assert t.lookup("EvilNola.gov") is None
    assert t.lookup("mail.nola.gov") == ("nola.gov", "nola")


# --- Cymru parser ------------------------------------------------------------

CYMRU_REPLY = """Bulk mode; whois.cymru.com [2026-09-16 02:08:59 +0000]
10349   | 129.81.233.231   | 129.81.233.0/24     | US | arin     | 1987-10-11 | TULANE - Tulane University, US
2055    | 130.39.1.1       | 130.39.0.0/16       | US | arin     | 1988-05-09 | LSU - Louisiana State University, US
NA      | 10.255.255.1     | NA                  | NA | NA       | NA         | NA
2055 32440 | 198.51.100.9  | 198.51.100.0/24     | US | arin     | 2001-01-01 | MULTI - two origins, US
Error: no entries found
"""


def test_parse_cymru_verbose_reply():
    got = br.parse_cymru(CYMRU_REPLY)
    assert got["130.39.1.1"] == {"asn": "AS2055", "prefix": "130.39.0.0/16", "cc": "US",
                                 "registry": "arin", "allocated": "1988-05-09",
                                 "as_name": "LSU - Louisiana State University, US"}
    assert got["129.81.233.231"]["asn"] == "AS10349"
    assert got["10.255.255.1"] == {"asn": "", "prefix": "", "cc": "", "registry": "",
                                   "allocated": "", "as_name": ""}
    assert got["198.51.100.9"]["asn"] == "AS2055"            # first origin kept
    assert len(got) == 4


def test_fill_cymru_batches_caches_and_survives_a_failed_batch(tmp_path, monkeypatch):
    monkeypatch.setattr(br, "CYMRU_BATCH", 2)
    calls = []

    def fake_query(ips):
        calls.append(list(ips))
        if "10.0.0.3" in ips:
            raise OSError("connection refused")
        return "\n".join(f"2055 | {ip} | 10.0.0.0/8 | US | arin | 2000-01-01 | LSU, US" for ip in ips)

    cache = br.JsonCache(str(tmp_path / "cymru.json"), 30)
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
    got = br.fill_cymru(cache, ips, TODAY, network=True, query=fake_query)
    assert calls == [["10.0.0.1", "10.0.0.2"], ["10.0.0.3", "10.0.0.4"], ["10.0.0.5"]]
    assert set(got) == {"10.0.0.1", "10.0.0.2", "10.0.0.5"}          # failed batch skipped
    saved = json.load(open(tmp_path / "cymru.json"))
    assert saved["as_of"] == AS_OF and saved["entries"]["10.0.0.1"]["as_of"] == AS_OF
    # second run: cache hit, no query at all; --skip-network never calls either
    calls.clear()
    again = br.fill_cymru(br.JsonCache(str(tmp_path / "cymru.json"), 30), ["10.0.0.1"], TODAY, query=fake_query)
    assert calls == [] and again["10.0.0.1"]["asn"] == "AS2055"
    assert br.fill_cymru(cache, ["10.0.0.3"], TODAY, network=False, query=fake_query) == {}
    assert calls == []


def test_json_cache_expires_old_entries(tmp_path):
    cache = br.JsonCache(str(tmp_path / "c.json"), 30)
    cache.put("k", {"v": 1}, date(2026, 1, 1))
    assert cache.fresh("k", date(2026, 1, 20)) == {"v": 1, "as_of": "2026-01-01"}
    assert cache.fresh("k", date(2026, 3, 1)) is None
    assert cache.fresh("k", date(2026, 1, 20), ttl_days=3) is None


# --- RDAP parser -------------------------------------------------------------

RDAP_DOC = {
    "handle": "AS10349", "name": "TULANE", "startAutnum": 10349,
    "entities": [
        {"handle": "TD138-ARIN", "roles": ["technical"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Tim Deeves"], ["kind", {}, "text", "individual"]]]},
        {"handle": "TULANE-Z", "roles": ["registrant"],
         "vcardArray": ["vcard", [["fn", {}, "text", "Tulane University"], ["kind", {}, "text", "org"]]]},
    ],
}


def test_parse_rdap_autnum_prefers_registrant_never_a_contact():
    assert br.parse_rdap_autnum(RDAP_DOC) == {"handle": "AS10349", "name": "TULANE",
                                              "org_handle": "TULANE-Z", "org_name": "Tulane University"}
    no_reg = {"handle": "AS1", "name": "X", "entities": [
        {"handle": "P1", "roles": ["technical"], "vcardArray": ["vcard", [["fn", {}, "text", "A Person"], ["kind", {}, "text", "individual"]]]},
        {"handle": "O1", "roles": ["administrative"], "vcardArray": ["vcard", [["fn", {}, "text", "Some Org"], ["kind", {}, "text", "org"]]]}]}
    # an administrative 'org' entity is a contact, not the owner: ignored
    assert br.parse_rdap_autnum(no_reg) == {"handle": "AS1", "name": "X", "org_handle": "", "org_name": ""}
    assert br.parse_rdap_autnum({})["org_name"] == ""


def test_fill_rdap_rate_limits_caches_and_fails_soft(tmp_path):
    slept, fetched = [], []

    def fake_fetch(asn):
        fetched.append(asn)
        if asn == "AS666":
            raise OSError("503")
        return RDAP_DOC

    cache = br.JsonCache(str(tmp_path / "rdap.json"), 90)
    got = br.fill_rdap(cache, ["AS10349", "AS666", "AS10349"], TODAY, fetch=fake_fetch, sleep=slept.append)
    assert fetched == ["AS10349", "AS666"] and slept == [br.RDAP_SLEEP]
    assert got == {"AS10349": dict(br.parse_rdap_autnum(RDAP_DOC), as_of=AS_OF)}
    assert "error" in json.load(open(tmp_path / "rdap.json"))["entries"]["AS666"]
    # the error entry is honoured for a few days, then retried
    fetched.clear()
    br.fill_rdap(cache, ["AS666"], date(2026, 9, 16), fetch=fake_fetch, sleep=slept.append)
    assert fetched == []
    br.fill_rdap(cache, ["AS666"], date(2026, 9, 30), fetch=fake_fetch, sleep=slept.append)
    assert fetched == ["AS666"]


# --- org-name matching -------------------------------------------------------

def test_match_org_name_is_equality_only_and_ignores_carriers(ref_dir):
    orgs, _, _ = br.load_registry_csvs(ref_dir)
    assert br.match_org_name("OCHSNER CLINIC FOUNDATION", orgs) == "la-ochsner"
    assert br.match_org_name("The Dow Chemical Company", orgs) == "la-dow"     # suffix/'the' ignored
    assert br.match_org_name("Dow", orgs) == "la-dow"
    assert br.match_org_name("Dow Jones & Company, Inc.", orgs) is None
    assert br.match_org_name("Ochsner Clinic Foundation - Jefferson", orgs) is None   # no containment
    assert br.match_org_name("State of Louisiana", orgs) == "la-ots"
    assert br.match_org_name("State of Louisiana Supreme Court", orgs) is None
    assert br.match_org_name("Level 3 Parent, LLC", orgs) is None
    assert br.match_org_name("", orgs) is None
    # a carrier alias can never attribute: LUS Fiber's space holds subscribers
    orgs.append({"org_id": "la-lus", "name": "Lafayette Utilities System", "aliases": "LUS Fiber"})
    assert br.is_carrier_name("LUS Fiber") and br.is_carrier_name("Cox Communications Inc.")
    assert not br.is_carrier_name("Lafayette Utilities System")
    assert br.match_org_name("LUS Fiber", orgs) is None
    assert br.match_org_name("Lafayette Utilities System", orgs) == "la-lus"


# --- attribution precedence --------------------------------------------------

def make_ctx(ref_dir, cymru=None, rdap=None, ots=()):
    orgs, nets, doms = br.load_registry_csvs(ref_dir)
    return br.build_context(orgs, list(ots) + nets, doms, cymru or {}, rdap or {}, AS_OF)


def host(**kw):
    h = {"asn": "", "org": "", "tier": "government", "hostnames": [], "cert_names": []}
    h.update(kw)
    return h


def test_attribution_precedence(ref_dir):
    cymru = {"10.0.5.1": {"asn": "AS7018", "as_name": "ATT-INTERNET4, US", "prefix": "10.0.0.0/8"},
             "10.0.9.1": {"asn": "AS7018", "as_name": "ATT-INTERNET4, US", "prefix": "10.0.0.0/8"},
             "198.51.100.1": {"asn": "AS63103", "as_name": "OCF-AS, US", "prefix": "198.51.100.0/24"},
             "198.51.100.2": {"asn": "AS10349", "as_name": "TULANE, US", "prefix": "198.51.100.0/24"},
             "198.51.100.3": {"asn": "AS20355", "as_name": "DP-BTR, US", "prefix": "198.51.100.0/24"},
             "198.51.100.4": {"asn": "AS7018", "as_name": "ATT-INTERNET4, US", "prefix": "198.51.100.0/24"}}
    rdap = {"AS10349": {"name": "TULANE", "org_handle": "TULANE-Z", "org_name": "Tulane University"},
            "AS20355": {"name": "DP-BTR", "org_handle": "DOL-40", "org_name": "DartPoints Operating Company, LLC"},
            "AS63103": {"name": "OCF-AS", "org_handle": "OCHSNE", "org_name": "Ochsner Clinic Foundation"}}
    ots = [{"prefix": "10.0.5.0/25", "asn": "", "org_id": "la-ots", "source": "ots_cidrs",
            "confidence": "high", "as_of": AS_OF, "agency": "LDH", "contact": "soc@example"}]
    ctx = make_ctx(ref_dir, cymru, rdap, ots)
    orgs = {o["org_id"]: o for o in br.load_registry_csvs(ref_dir)[0]}
    orgs["la-tulane"] = {"org_id": "la-tulane", "name": "Tulane University", "sector": "education",
                         "jurisdiction": "private", "aliases": "Tulane"}
    ctx["orgs"] = orgs
    ctx["names"] = br.NameIndex(list(orgs.values()))

    # 1. OTS CIDR (/25) beats the curated /24 and /16 and any rDNS
    r = br.attribute_ip("10.0.5.1", host(hostnames=["www.lsu.edu"]), ctx)
    assert (r["method"], r["org_id"]) == ("ots_cidr", "la-ots")
    assert "agency=LDH" in r["evidence"] and r["org_name"] == "Louisiana Office of Technology Services"
    # ... but a hostname of ANOTHER org on that address is a conflict: flagged, capped at medium
    assert (r["confidence"], r["conflict"]) == ("medium", "prefix=la-ots;rdns=la-lsu")
    r = br.attribute_ip("10.0.5.2", host(), ctx)
    assert (r["confidence"], r["conflict"]) == ("high", "")
    # 2. curated /24 beats /16 (longest prefix) and beats rDNS
    r = br.attribute_ip("10.0.5.200", host(hostnames=["www.lsu.edu"]), ctx)
    assert (r["method"], r["org_id"], r["evidence"]) == ("registry_network", "la-nola", "prefix 10.0.5.0/24 (curated)")
    assert (r["confidence"], r["conflict"]) == ("medium", "prefix=la-nola;rdns=la-lsu")
    r = br.attribute_ip("10.0.9.1", host(), ctx)
    assert (r["method"], r["org_id"], r["confidence"]) == ("registry_network", "la-lsu", "high")
    # 3. rDNS under a registry domain beats cert and ASN; label boundary holds
    r = br.attribute_ip("198.51.100.1", host(hostnames=["vpn.nola.gov"], cert_names=["x.ochsner.org"]), ctx)
    assert (r["method"], r["org_id"], r["evidence"]) == ("domain_dns", "la-nola", "rDNS vpn.nola.gov under nola.gov")
    # rDNS and certificate disagree -> structured conflict, medium
    assert (r["confidence"], r["conflict"]) == ("medium", "rdns=la-nola;cert=la-ochsner")
    r = br.attribute_ip("198.51.100.1", host(hostnames=["vpn.nola.gov"], cert_names=["x.nola.gov"]), ctx)
    assert (r["confidence"], r["conflict"]) == ("high", "")
    # two orgs' names on one IP: the org with more names wins, but only at MEDIUM,
    # and the competitor is named in both evidence and conflict
    r = br.attribute_ip("198.51.100.1", host(hostnames=["a.nola.gov", "b.nola.gov", "x.ochsner.org"]), ctx)
    assert (r["org_id"], r["confidence"], r["conflict"]) == ("la-nola", "medium", "rdns=la-nola,la-ochsner")
    assert r["evidence"] == "rDNS a.nola.gov under nola.gov; SHARED IP: names of la-ochsner also present"
    r = br.attribute_ip("198.51.100.1", host(hostnames=["evilnola.gov"], cert_names=["x.ochsner.org"]), ctx)
    assert (r["method"], r["org_id"]) == ("cert", "la-ochsner")
    # 4. registry ASN row (medium) when no name evidence
    r = br.attribute_ip("198.51.100.1", host(), ctx)
    assert (r["method"], r["confidence"], r["org_id"]) == ("registry_asn", "medium", "la-ochsner")
    assert r["evidence"].startswith("AS63103 OCF-AS, US prefix 198.51.100.0/24 (Cymru)")
    # 5. RDAP registrant matching an alias -> medium; not matching -> low, org empty
    r = br.attribute_ip("198.51.100.2", host(), ctx)
    assert (r["method"], r["confidence"], r["org_id"], r["sector"]) == ("arin_rdap", "medium", "la-tulane", "education")
    r = br.attribute_ip("198.51.100.3", host(), ctx)
    assert (r["method"], r["confidence"], r["org_id"]) == ("arin_rdap", "low", "")
    assert "DartPoints" in r["evidence"]
    # 6. only the Cymru origin -> low, org empty
    r = br.attribute_ip("198.51.100.4", host(), ctx)
    assert (r["method"], r["confidence"], r["org_id"]) == ("cymru_asn", "low", "")
    assert r["evidence"] == "AS7018 ATT-INTERNET4, US prefix 198.51.100.0/24"
    # 7. Cymru unavailable: fall back to Shodan's ASN, then to nothing
    r = br.attribute_ip("203.0.113.9", host(asn="AS7018", org="AT&T Enterprises, LLC"), ctx)
    assert (r["method"], r["confidence"]) == ("shodan_asn", "low")
    r = br.attribute_ip("203.0.113.10", host(), ctx)
    assert (r["method"], r["confidence"], r["org_id"]) == ("none", "low", "")
    assert set(r) == set(rg.ATTR_COLS)


def test_ots_drop_in_maps_agency_or_defaults_to_ots(ref_dir, tmp_path):
    orgs, _, _ = br.load_registry_csvs(ref_dir)
    p = tmp_path / "ots_cidrs.csv"
    p.write_text("prefix,agency,contact\n10.20.0.0/22,City of New Orleans,noc@example\n"
                 "10.21.0.7/24,Office of Motor Vehicles,\nnot-a-prefix,X,\n")
    rows = br.load_ots_cidrs(str(p), orgs, AS_OF)
    assert [(r["prefix"], r["org_id"], r["source"], r["confidence"]) for r in rows] == [
        ("10.20.0.0/22", "la-nola", "ots_cidrs", "high"),
        ("10.21.0.0/24", "la-ots", "ots_cidrs", "high")]
    assert rows[1]["agency"] == "Office of Motor Vehicles"
    assert br.load_ots_cidrs(str(tmp_path / "absent.csv"), orgs, AS_OF) == []


# --- Attributor over real parquet -------------------------------------------

def test_attributor_end_to_end(ref_dir, tmp_path):
    import duckdb
    orgs, nets, doms = br.load_registry_csvs(ref_dir)
    ctx = br.build_context(orgs, nets, doms, {"203.0.113.5": {"asn": "AS7018", "as_name": "ATT", "prefix": "203.0.113.0/24"}}, {}, AS_OF)
    attribution = [br.attribute_ip("203.0.113.5", host(), ctx),
                   br.attribute_ip("203.0.113.6", host(hostnames=["a.lsu.edu"]), ctx)]
    out = str(tmp_path / "registry")
    con = duckdb.connect()
    br.write_parquet(con, orgs, rg.ORG_COLS, os.path.join(out, "registry_orgs.parquet"))
    br.write_parquet(con, nets, rg.NET_COLS + ["agency", "contact"], os.path.join(out, "registry_networks.parquet"))
    br.write_parquet(con, doms, rg.DOM_COLS, os.path.join(out, "registry_domains.parquet"))
    br.write_parquet(con, attribution, rg.ATTR_COLS, os.path.join(out, "ip_attribution.parquet"))
    br.write_parquet(con, [], rg.ATTR_COLS, os.path.join(out, "empty.parquet"))
    assert con.execute(f"SELECT count(*) FROM read_parquet('{out}/empty.parquet')").fetchone()[0] == 0
    con.close()

    att = rg.Attributor().load(out)
    assert len(att.orgs) == 5 and len(att.networks) == 2 and len(att.domains) == 6
    # live prefix match (not in ip_attribution at all)
    r = att.lookup("10.0.5.9")
    assert (r["org_id"], r["org_name"], r["method"], r["confidence"]) == ("la-nola", "City of New Orleans", "registry_network", "high")
    assert r["sector"] == "government" and r["as_of"] == AS_OF
    # precomputed rows
    assert att.lookup("203.0.113.6")["org_id"] == "la-lsu" and att.lookup("203.0.113.6")["method"] == "domain_dns"
    low = att.lookup("203.0.113.5")
    assert low["org_id"] == "" and low["method"] == "cymru_asn" and low["confidence"] == "low"
    assert att.lookup("203.0.113.7") is None
    assert att.lookup("garbage") is None
    # domains: suffix + label boundary, longest wins, returns the org row
    d = att.lookup_domain("Mail.NOLA.gov.")
    assert d["org_id"] == "la-nola" and d["domain"] == "nola.gov" and d["contact_route"] == "MS-ISAC"
    assert att.lookup_domain("evilnola.gov") is None
    assert att.lookup_domain("ldh.la.gov")["org_id"] == "la-ots"


# --- review items: shared IPs, shared networks, row confidence -----------------

def test_name_evidence_on_shared_network_is_medium(ref_dir):
    cymru = {"198.51.100.9": {"asn": "AS22773", "as_name": "ASN-CXA-ALL-CCI-22773-RDC - Cox Communications Inc., US",
                              "prefix": "198.51.100.0/24"},
             "198.51.100.8": {"asn": "AS16509", "as_name": "AMAZON-02 - Amazon.com, Inc., US", "prefix": "198.51.100.0/24"}}
    ctx = make_ctx(ref_dir, cymru)
    r = br.attribute_ip("198.51.100.9", host(hostnames=["vpn.nola.gov"]), ctx)
    assert (r["method"], r["confidence"], r["org_id"]) == ("domain_dns", "medium", "la-nola")
    assert "on shared/carrier network 'ASN-CXA-ALL-CCI-22773-RDC - Cox Communications Inc., US'" in r["evidence"]
    r = br.attribute_ip("198.51.100.8", host(cert_names=["www.lsu.edu"]), ctx)
    assert (r["method"], r["confidence"]) == ("cert", "medium")
    # Cymru unavailable: Shodan's org names the network and is judged the same way
    r = br.attribute_ip("203.0.113.1", host(org="Cox Communications", hostnames=["vpn.nola.gov"]), ctx)
    assert r["confidence"] == "medium"
    # a non-carrier network keeps high
    r = br.attribute_ip("203.0.113.2", host(org="City of New Orleans", hostnames=["vpn.nola.gov"]), ctx)
    assert r["confidence"] == "high"


def test_domain_row_confidence_caps_name_evidence(ref_dir):
    with open(os.path.join(ref_dir, "domains.csv"), "a") as fh:
        fh.write("brla.gov,la-nola,guess,medium,2026-09-15\nweird.example,la-lsu,guess,low,2026-09-15\n")
    ctx = make_ctx(ref_dir)
    assert br.attribute_ip("203.0.113.3", host(hostnames=["x.brla.gov"]), ctx)["confidence"] == "medium"
    assert br.attribute_ip("203.0.113.4", host(hostnames=["x.weird.example"]), ctx)["confidence"] == "low"
    assert br.attribute_ip("203.0.113.5", host(hostnames=["x.nola.gov"]), ctx)["confidence"] == "high"


def test_asn_only_rows_are_capped_at_medium_and_carrier_rows_skipped(ref_dir, capsys):
    with open(os.path.join(ref_dir, "networks.csv"), "a") as fh:
        fh.write(",AS100,la-lsu,curated,,2026-09-15\n"          # blank confidence
                 ",AS101,la-lsu,curated,high,2026-09-15\n"      # claims high
                 "10.7.0.0/24,,la-lsu,curated,,2026-09-15\n"    # prefix row, blank -> high
                 ",AS102,la-cox,curated,high,2026-09-15\n")     # carrier org
    with open(os.path.join(ref_dir, "orgs.csv"), "a") as fh:
        fh.write("la-cox,Cox Communications Inc.,telecom,private,Cox,cox.net,ISP abuse-c,,curated,2026-09-15\n")
    orgs, nets, _ = br.load_registry_csvs(ref_dir)
    by_key = {(n["prefix"], n["asn"]): n["confidence"] for n in nets}
    assert by_key[("", "AS100")] == "medium" and by_key[("", "AS101")] == "medium"
    assert by_key[("10.7.0.0/24", "")] == "high"
    assert ("", "AS102") not in by_key
    assert "ASN-only row AS102 for carrier org la-cox skipped" in capsys.readouterr().out
    ctx = br.build_context(orgs, nets, [], {"203.0.113.6": {"asn": "AS101", "as_name": "X", "prefix": ""}}, {}, AS_OF)
    assert br.attribute_ip("203.0.113.6", host(), ctx)["confidence"] == "medium"


def test_ots_row_wins_equal_prefix_and_conflicts_are_logged(ref_dir, capsys):
    orgs, nets, doms = br.load_registry_csvs(ref_dir)
    ots = [{"prefix": "10.0.5.0/24", "asn": "", "org_id": "la-ots", "source": "ots_cidrs",
            "confidence": "high", "as_of": AS_OF, "agency": "LDH", "contact": ""}]
    ctx = br.build_context(orgs, ots + nets, doms + [{"domain": "nola.gov", "org_id": "la-lsu",
                                                      "source": "dup", "confidence": "high", "as_of": AS_OF}],
                           {}, {}, AS_OF)
    r = br.attribute_ip("10.0.5.1", host(), ctx)
    assert (r["method"], r["org_id"]) == ("ots_cidr", "la-ots")
    out = capsys.readouterr().out
    assert "prefix 10.0.5.0/24 also listed for la-nola (curated); keeping la-ots (ots_cidrs)" in out
    assert "domains: nola.gov also listed for la-lsu; keeping la-nola" in out
    assert ctx["domains"].lookup("x.nola.gov")[1]["org_id"] == "la-nola"


def test_prefix_table_keeps_first_and_formats_ipv6():
    t = rg.PrefixTable()
    assert t.add("2001:db8:1::/48", "first") is True
    assert t.add("2001:db8:1::/48", "second") is False
    assert t.lookup("2001:db8:1::9") == ("2001:db8:1::/48", "first")
    assert t.get("2001:db8:1::/48") == "first"
    t.add("10.0.0.0/8", "v4")
    assert t.lookup("10.9.9.9") == ("10.0.0.0/8", "v4")


def test_norm_org_name_and_ambiguous_keys(capsys):
    n = br.norm_org_name
    assert n("Acme, L.L.C.") == n("Acme LLC") == n("ACME Inc") == "acme"
    assert n("Acme Holdings Co., Inc.") == "acme holdings"
    assert n("The University of the South") == "university of the south"      # only a LEADING 'the'
    assert n("Baton Rouge Water Company") == "baton rouge water"
    orgs = [{"org_id": "a", "name": "Acme LLC", "aliases": ""},
            {"org_id": "b", "name": "Acme Inc", "aliases": "Acme Widgets"},
            {"org_id": "c", "name": "Zeta Corp", "aliases": ""}]
    idx = br.NameIndex(orgs)
    assert idx.ambiguous == {"acme"}
    assert "name 'acme' is claimed by more than one org" in capsys.readouterr().out
    assert idx.match("ACME, Inc.") is None and br.match_org_name("Acme", orgs) is None
    assert idx.match("Acme Widgets") == "b" and idx.match("zeta corporation") == "c"


def test_roster_ambiguous_keys_never_match(tmp_path, capsys):
    d = tmp_path / "rosters"
    d.mkdir()
    (d / "healthcare.csv").write_text("name,sector,subsector,city,parish,domain,website,source,as_of\n"
                                      "Acme Clinic LLC,healthcare,clinic,,,,,NPPES,2026-09-15\n"
                                      "Acme Clinic Inc,healthcare,clinic,,,,,NPPES,2026-09-15\n"
                                      "Bayou Hospital,healthcare,hospital,,,,,NPPES,2026-09-15\n"
                                      "Bayou Hospital,healthcare,hospital,,,,,NPPES,2026-09-15\n")
    (d / "education.csv").write_text("name,sector,subsector,city,parish,domain,website,source,as_of\n"
                                     "Bayou Hospital,education,school,,,,,NCES,2026-09-15\n")
    idx = br.load_rosters(str(d))
    assert set(idx) == set()                      # both keys ambiguous
    assert "2 name(s) normalise to a key shared by different rows" in capsys.readouterr().out
    (d / "education.csv").write_text("name,sector,subsector,city,parish,domain,website,source,as_of\n")
    idx = br.load_rosters(str(d))
    assert set(idx) == {"bayou hospital"}         # identical repeat rows are fine


def test_cymru_candidates_exclude_residential(ref_dir, tmp_path, monkeypatch):
    hosts = {"10.0.0.1": host(tier="residential"), "10.0.0.2": host(tier="small_business"),
             "10.0.0.3": host(tier="residential"), "10.0.0.4": host(tier="government")}
    assert br.cymru_candidates(hosts) == ["10.0.0.2", "10.0.0.4"]
    # and main() really passes only those to fill_cymru
    sent = []
    monkeypatch.setattr(br, "read_hosts", lambda db, limit=None: hosts)
    monkeypatch.setattr(br, "fill_cymru", lambda cache, ips, today, network=True, **kw: sent.append(list(ips)) or {})
    monkeypatch.setattr(br, "fill_rdap", lambda cache, asns, today, network=True, **kw: {})
    real_load = br.load_registry_csvs
    monkeypatch.setattr(br, "load_registry_csvs", lambda: real_load(ref_dir))
    monkeypatch.setattr(br, "load_rosters", lambda: {})
    monkeypatch.setattr(br, "CYMRU_CACHE", str(tmp_path / "c.json"))
    monkeypatch.setattr(br, "RDAP_CACHE", str(tmp_path / "r.json"))
    monkeypatch.setattr(sys, "argv", ["build_registry.py", "--dry-run", "--skip-network", "--out", str(tmp_path / "out")])
    assert br.main() == 0
    assert sent == [["10.0.0.2", "10.0.0.4"]]


def test_unreadable_store_keeps_previous_attribution(ref_dir, tmp_path, monkeypatch):
    import duckdb
    out = tmp_path / "out"
    out.mkdir()
    con = duckdb.connect()
    prev = [{"ip": "203.0.113.9", "org_id": "la-lsu", "org_name": "Louisiana State University",
             "sector": "education", "jurisdiction": "state", "method": "domain_dns",
             "confidence": "high", "evidence": "old", "as_of": "2026-09-01"}]
    br.write_parquet(con, prev, rg.ATTR_COLS, str(out / "ip_attribution.parquet"))
    con.close()
    monkeypatch.setattr(br, "read_hosts", lambda db, limit=None: None)          # store unreadable
    real_load = br.load_registry_csvs
    monkeypatch.setattr(br, "load_registry_csvs", lambda: real_load(ref_dir))
    monkeypatch.setattr(br, "load_rosters", lambda: {})
    monkeypatch.setattr(br, "CYMRU_CACHE", str(tmp_path / "c.json"))
    monkeypatch.setattr(br, "RDAP_CACHE", str(tmp_path / "r.json"))
    monkeypatch.setattr(sys, "argv", ["build_registry.py", "--skip-network", "--out", str(out)])
    assert br.main() == 0
    att = rg.Attributor().load(str(out))
    assert att.lookup("203.0.113.9")["evidence"] == "old"          # previous rows carried forward
    assert len(att.orgs) == 5                                      # registry tables still refreshed
    assert att.generation != str(out) and os.path.basename(att.generation).startswith("gen-")
    assert not [p for p in os.listdir(out) if p.endswith(".tmp")]


def test_write_generation_is_all_or_nothing(tmp_path, monkeypatch):
    from datetime import datetime as dt
    out = tmp_path / "registry"
    orgs = [{"org_id": "x", "name": "X"}]
    gen1 = br.write_generation(str(out), {"registry_orgs.parquet": (orgs, rg.ORG_COLS),
                                          "ip_attribution.parquet": ([], rg.ATTR_COLS)},
                               now=dt(2026, 9, 15, 1, 0, 0))
    assert open(out / "CURRENT").read().strip() == "gen-20260915T010000"
    real = br.write_parquet
    calls = []

    def flaky(con, rows, cols, path, stage=None):
        calls.append(path)
        if len(calls) == 2:
            raise RuntimeError("disk full")
        real(con, rows, cols, path, stage=stage)

    monkeypatch.setattr(br, "write_parquet", flaky)
    with pytest.raises(RuntimeError):
        br.write_generation(str(out), {"registry_orgs.parquet": ([], rg.ORG_COLS),
                                       "ip_attribution.parquet": ([], rg.ATTR_COLS)},
                            now=dt(2026, 9, 15, 2, 0, 0))
    assert open(out / "CURRENT").read().strip() == "gen-20260915T010000"     # pointer untouched
    assert sorted(d for d in os.listdir(out) if d.startswith("gen-")) == ["gen-20260915T010000"]
    assert rg.resolve_generation(str(out)) == gen1


# --- second review pass: conflicts, generations, stale evidence, newest tier ----

def test_duplicate_domain_conflict_is_flagged(ref_dir):
    orgs, nets, doms = br.load_registry_csvs(ref_dir)
    dup = {"domain": "nola.gov", "org_id": "la-lsu", "source": "dup", "confidence": "high", "as_of": AS_OF}
    ctx = br.build_context(orgs, nets, doms + [dup], {}, {}, AS_OF)
    r = br.attribute_ip("203.0.113.20", host(hostnames=["www.nola.gov"]), ctx)
    assert (r["org_id"], r["confidence"], r["conflict"]) == ("la-nola", "medium", "duplicate domain nola.gov: la-nola vs la-lsu")
    ots = [{"prefix": "10.0.5.0/24", "asn": "", "org_id": "la-ots", "source": "ots_cidrs",
            "confidence": "high", "as_of": AS_OF, "agency": "", "contact": ""}]
    ctx = br.build_context(orgs, ots + nets, doms, {}, {}, AS_OF)
    r = br.attribute_ip("10.0.5.7", host(), ctx)
    assert (r["method"], r["org_id"], r["confidence"]) == ("ots_cidr", "la-ots", "medium")
    assert r["conflict"] == "duplicate prefix 10.0.5.0/24: la-ots vs la-nola"
    # a MORE SPECIFIC curated prefix still wins by longest-prefix, without conflict
    ctx = br.build_context(orgs, [{"prefix": "10.0.0.0/8", "asn": "", "org_id": "la-ots", "source": "ots_cidrs",
                                   "confidence": "high", "as_of": AS_OF}] + nets, doms, {}, {}, AS_OF)
    r = br.attribute_ip("10.0.5.7", host(), ctx)
    assert (r["method"], r["org_id"], r["confidence"], r["conflict"]) == ("registry_network", "la-nola", "high", "")


def test_generation_pointer_load_fallback_and_pruning(tmp_path, capsys):
    from datetime import datetime as dt
    out = tmp_path / "registry"
    orgs = [{"org_id": "la-x", "name": "X Org", "sector": "government", "jurisdiction": "state"}]
    attr = [{"ip": "203.0.113.1", "org_id": "la-x", "org_name": "X Org", "sector": "government",
             "jurisdiction": "state", "method": "domain_dns", "confidence": "high", "evidence": "e",
             "as_of": "2026-09-10", "conflict": ""}]
    for i in range(4):
        br.write_generation(str(out), {"registry_orgs.parquet": (orgs, rg.ORG_COLS),
                                       "ip_attribution.parquet": (attr, rg.ATTR_COLS)},
                            now=dt(2026, 9, 15, 0, 0, i))
    gens = sorted(d for d in os.listdir(out) if d.startswith("gen-"))
    assert gens == ["gen-20260915T000001", "gen-20260915T000002", "gen-20260915T000003"]   # last 3 kept
    att = rg.Attributor().load(str(out))
    assert os.path.basename(att.generation) == "gen-20260915T000003"
    assert att.lookup("203.0.113.1")["org_id"] == "la-x" and att.attribution_as_of == "2026-09-10"
    out_txt = capsys.readouterr().out
    assert "registry_networks.parquet missing — loaded empty" in out_txt and "loaded 1 orgs" in out_txt
    # pointer to a vanished generation -> flat-file fallback (compatibility)
    (out / "CURRENT").write_text("gen-doesnotexist\n")
    import duckdb
    con = duckdb.connect()
    br.write_parquet(con, attr[:1], rg.ATTR_COLS, str(out / "ip_attribution.parquet"))
    con.close()
    att = rg.Attributor().load(str(out))
    assert att.generation == str(out) and att.lookup("203.0.113.1")["method"] == "domain_dns"
    assert att.lookup("203.0.113.1")["conflict"] == ""
    (out / "CURRENT").unlink()
    assert rg.resolve_generation(str(out)) == str(out)


def test_stale_cymru_record_kept_when_network_fails(ref_dir, tmp_path):
    cache = br.JsonCache(str(tmp_path / "cymru.json"), 30)
    cache.put("198.51.100.1", {"asn": "AS63103", "as_name": "OCF-AS, US", "prefix": "198.51.100.0/24"},
              date(2026, 1, 1))                                     # long expired
    status = {}

    def down(ips):
        raise OSError("network unreachable")

    got = br.fill_cymru(cache, ["198.51.100.1"], TODAY, network=True, query=down, status=status)
    assert status == {"attempted": 1, "failed": 1}
    assert got["198.51.100.1"]["asn"] == "AS63103" and got["198.51.100.1"]["stale"] is True
    assert got["198.51.100.1"]["stale_as_of"] == "2026-01-01"
    ctx = make_ctx(ref_dir, got)
    r = br.attribute_ip("198.51.100.1", host(), ctx)
    assert (r["method"], r["org_id"], r["confidence"]) == ("registry_asn", "la-ochsner", "medium")
    assert "(stale as_of 2026-01-01)" in r["evidence"]
    # fresher data replaces the stale record
    fresh = lambda ips: "\n".join(f"2055 | {ip} | 10.0.0.0/8 | US | arin | 2000-01-01 | LSU, US" for ip in ips)
    got = br.fill_cymru(cache, ["198.51.100.1"], TODAY, network=True, query=fresh, status=status)
    assert got["198.51.100.1"]["asn"] == "AS2055" and "stale" not in got["198.51.100.1"]
    # RDAP: the last good record survives an outage, marked stale
    rc = br.JsonCache(str(tmp_path / "rdap.json"), 90)
    rc.put("AS10349", br.parse_rdap_autnum(RDAP_DOC), date(2026, 1, 1))
    got = br.fill_rdap(rc, ["AS10349"], TODAY, fetch=lambda a: (_ for _ in ()).throw(OSError("503")),
                       sleep=lambda s: None, status=status)
    assert got["AS10349"]["org_name"] == "Tulane University" and got["AS10349"]["stale"] is True
    assert rc.get("AS10349")["prev"]["org_name"] == "Tulane University"


def test_keep_stronger_previous_rows_on_outage():
    new = [{"ip": "1.1.1.1", "org_id": "", "confidence": "low", "evidence": "AS1", "method": "shodan_asn",
            "org_name": "", "sector": "", "jurisdiction": "", "as_of": AS_OF, "conflict": ""},
           {"ip": "1.1.1.2", "org_id": "la-x", "confidence": "high", "evidence": "prefix", "method": "registry_network",
            "org_name": "X", "sector": "", "jurisdiction": "", "as_of": AS_OF, "conflict": ""}]
    prev = {"1.1.1.1": {"ip": "1.1.1.1", "org_id": "la-y", "confidence": "medium", "evidence": "rdap",
                        "method": "arin_rdap", "org_name": "Y", "sector": "", "jurisdiction": "",
                        "as_of": "2026-09-10", "conflict": None},
            "1.1.1.2": {"ip": "1.1.1.2", "org_id": "", "confidence": "low", "evidence": "x",
                        "method": "cymru_asn", "as_of": "2026-09-10"}}
    assert br.keep_stronger_previous(new, prev, "Cymru down") == 1
    assert new[0]["org_id"] == "la-y" and new[0]["confidence"] == "medium" and new[0]["conflict"] == ""
    assert new[0]["evidence"] == "rdap (kept from previous build as_of 2026-09-10: Cymru down)"
    assert new[1]["org_id"] == "la-x"                       # the stronger new row is kept


def test_read_hosts_uses_newest_observation_for_tier(tmp_path):
    import duckdb
    store = tmp_path / "store"
    con = duckdb.connect()
    rows = [("2026-09-01", "203.0.113.5", 80, "tcp", "2026-09-01 01:00:00", "obs-a", "AS22773", "Cox Communications",
             "residential", "old.example.net", "", "", "", ""),
            ("2026-09-02", "203.0.113.5", 443, "tcp", "2026-09-02 01:00:00", "obs-b", "AS2055", "Louisiana State University",
             "education", "www.lsu.edu", "", "www.lsu.edu", "www.lsu.edu", "Louisiana State University")]
    for r in rows:
        part = store / "observations" / f"date={r[0]}"
        part.mkdir(parents=True)
        con.execute("CREATE OR REPLACE TABLE t (date DATE, ip VARCHAR, port INTEGER, transport VARCHAR, "
                    "banner_ts TIMESTAMP, observation_id VARCHAR, asn VARCHAR, org VARCHAR, tier VARCHAR, "
                    "hostnames VARCHAR, tags VARCHAR, cert_sans VARCHAR, cert_cn VARCHAR, cert_org VARCHAR)")
        con.execute("INSERT INTO t VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", list(r))
        con.execute(f"COPY t TO '{part / 'data.parquet'}' (FORMAT PARQUET)")
    con.close()
    hosts = br.read_hosts(str(store / "exposure.duckdb"))         # no db file -> partition fallback
    h = hosts["203.0.113.5"]
    assert (h["tier"], h["asn"], h["org"]) == ("education", "AS2055", "Louisiana State University")
    assert h["hostnames"] == ["old.example.net", "www.lsu.edu"]     # names unioned over all ports
    assert h["cert_names"] == ["www.lsu.edu"] and h["cert_orgs"] == ["Louisiana State University"]
    assert br.cymru_candidates(hosts) == ["203.0.113.5"]           # newest tier is not residential
    assert br.read_hosts(str(tmp_path / "nowhere" / "exposure.duckdb")) is None


def test_attributor_is_fast_enough(ref_dir, tmp_path):
    import time
    t = rg.PrefixTable()
    for i in range(2000):
        t.add(f"10.{i // 256}.{i % 256}.0/24", i)
    t.add("10.0.0.0/8", "wide")
    ips = [f"10.{i % 200}.{(i * 7) % 256}.{i % 250}" for i in range(100_000)]
    start = time.perf_counter()
    hits = sum(1 for ip in ips if t.lookup(ip))
    assert hits == len(ips)
    assert time.perf_counter() - start < 5.0          # ~0.5s typical


def test_roster_attribution_matches_exact_normalised_names(tmp_path):
    import csv as _csv
    import build_registry as br
    p = tmp_path / "healthcare.csv"
    with open(p, "w", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=["name", "sector", "subsector", "city", "parish", "domain", "website", "source", "as_of"])
        w.writeheader()
        w.writerow({"name": "Willis-Knighton Medical Center", "sector": "healthcare", "subsector": "hospital", "source": "https://npi", "as_of": "2026-09-15"})
        w.writerow({"name": "Cox Communications", "sector": "healthcare", "subsector": "hospital", "source": "x", "as_of": "2026-09-15"})   # carrier: ignored
    rosters = br.load_rosters(str(tmp_path))
    assert len(rosters) == 1
    host = {"org": "Cox Communications", "cert_orgs": ["WILLIS-KNIGHTON MEDICAL CENTER"], "hostnames": [], "cert_names": []}
    row = br.roster_attribution("10.0.0.1", host, rosters, "2026-09-15")
    assert row and row["method"] == "roster_name" and row["confidence"] == "medium" and row["sector"] == "healthcare"
    host2 = {"org": "Willis-Knighton Medical Center", "cert_orgs": [], "hostnames": [], "cert_names": []}
    assert br.roster_attribution("10.0.0.2", host2, rosters, "2026-09-15")["confidence"] == "low"
    host3 = {"org": "Willis Knighton Med", "cert_orgs": ["Some Other Clinic"], "hostnames": [], "cert_names": []}
    assert br.roster_attribution("10.0.0.3", host3, rosters, "2026-09-15") is None
