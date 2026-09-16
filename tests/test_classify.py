"""Regression tests for triage_report.classify().

Every "misfire" case below is a REAL host shape measured in the live store on
2026-09-15 (org / hostnames / domains / ports / tags as Shodan reported them),
reduced to the fields that drove the wrong answer. Keep it that way: when the
classifier gets something wrong in production, add the host here first.

Run:  venv/bin/python -m pytest tests/ -q
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from triage_report import classify, kw_in, gov_domain_kind, TIERS  # noqa: E402


def host(org=None, hostnames=(), domains=(), ports=(80,), tags=()):
    return {"org": org, "hostnames": list(hostnames), "domains": list(domains),
            "ports": set(ports), "tags": set(tags)}


def tier(**kw):
    return classify(host(**kw))[0]


# --- whole-word keyword matching --------------------------------------------

@pytest.mark.parametrize("kw,text,expected", [
    ("lsu", "dslsubs15-117.eatel.net", False),        # REV subscriber, was 'education'
    ("lsu", "lsu.edu", True),
    ("lsu", "mail-lsu-01.example.net", True),
    ("isd", "mddevops01.morrisdickson.com", False),   # Morris & Dickson, was 'education'
    ("allen", "allentown-cable.example.net", False),
    ("allen", "allen.k12.la.us", True),
    ("rev", "department of revenue", False),          # 'rev' ISP must not swallow Revenue
    ("rev", "rev", True),
    ("court", "courtyard-marriott.example.com", False),
    ("city of", "city of baton rouge", True),
])
def test_kw_in_is_whole_word(kw, text, expected):
    assert kw_in(kw, text) is expected


# --- domain authority --------------------------------------------------------

@pytest.mark.parametrize("domain,kind", [
    ("la.gov", "la"), ("adminlaw.la.gov", "la"), ("goea.state.la.us", "la"),
    ("louisiana.gov", "la"), ("lafayettela.gov", "la"), ("nola.gov", "la"),
    ("ci.westmonroe.la.us", "la"), ("lib.la.us", "la"),
    ("bossier.k12.la.us", None),               # K-12 is education, not government
    ("pa.gov", "other_state"), ("tx.gov", "other_state"), ("state.tx.us", "other_state"),
    ("nasa.gov", "gov"), ("ligo.org", None), ("cox.net", None),
])
def test_gov_domain_kind(domain, kind):
    assert gov_domain_kind(domain) == kind


# --- measured misfires: government tier ---------------------------------------

def test_cameron_communications_subscriber_is_not_government():
    # 931 hosts; 'cameron' parish substring in the ISP name put them in government
    assert tier(org="Cameron Communications, LLC", hostnames=["adsl-2773.camtel.net"],
                domains=["camtel.net"], ports=[80, 137]) == "residential"


def test_cameron_telephone_is_not_government():
    assert tier(org="Cameron Telephone", ports=[161]) == "residential"


def test_allens_communications_subscriber_is_not_government():
    # 872 hosts; 'allen'
    assert tier(org="Allens Communications", hostnames=["ip-199-68-58-070.atvci.net"],
                domains=["atvci.net"], ports=[161]) == "residential"
    assert tier(org="Allens Communications", ports=[161]) == "residential"


def test_pennsylvania_is_out_of_state_gov():
    # 296 hosts on pa.gov landed in the Louisiana government tier
    assert tier(org="Commonwealth of PA - OA / Integrated Network Management Services",
                hostnames=["dlissologin.pa.gov"], domains=["pa.gov"], ports=[80, 443]) == "out_of_state_gov"


def test_parish_broadband_is_not_government():
    assert tier(org="Parish Broadband", ports=[8291]) == "residential"


def test_acadiana_wireless_is_not_government():
    # 'acadia' parish substring inside ACADIANA
    assert tier(org="ACADIANA WIRELESS LLC", ports=[123, 161, 1701, 8291]) == "residential"


def test_pavlov_media_client_named_after_city_is_not_government():
    # hostname carries 'lafayette.la.us' as a label, but the domain is pavlovmedia.net
    assert tier(org="PAVLOV MEDIA INC",
                hostnames=["host-211-46.lalacap.lafayette.la.us.clients.pavlovmedia.net"],
                domains=["pavlovmedia.net"], ports=[9302]) == "residential"


def test_ligo_is_not_government():
    # 'livingston' parish word in the org; it is a Caltech research facility
    assert tier(org="LIGO Livingston Observatory", hostnames=["lloepics.ligo-la.caltech.edu"],
                domains=["caltech.edu"], ports=[22, 443]) == "education"


def test_parish_name_needs_a_civic_noun():
    assert tier(org="Jefferson Financial Credit Union", ports=[443]) == "small_business"
    assert tier(org="Jefferson Parish Police Jury", ports=[443]) == "government"
    assert tier(org="Livingston Parish Sheriff", ports=[443]) == "government"
    assert tier(org="Orleans Coffee Company", ports=[443]) == "small_business"


# --- measured misfires: education tier ---------------------------------------

def test_rev_subscriber_hostname_containing_lsu_is_residential():
    # 356 REV hosts; 'lsu' matched inside 'dslsubs'
    assert tier(org="REV", hostnames=["dslsubs15-117.eatel.net"], domains=["eatel.net"],
                ports=[8443]) == "residential"


def test_morris_dickson_is_not_education():
    # 42 hosts; 'isd' matched inside 'morrisdickson'
    assert tier(org="Whole Sale", hostnames=["sales.morrisdickson.com"],
                domains=["morrisdickson.com"], ports=[80, 443]) == "small_business"


def test_loyola_edu_domain_beats_orleans_parish_name():
    # 138 hosts; 'orleans' in "New Orleans" ran before the .edu check
    assert tier(org="Loyola University New Orleans", hostnames=["gold.loyno.edu"],
                domains=["loyno.edu"], ports=[80, 443]) == "education"


def test_ul_lafayette_is_education_even_without_a_domain():
    assert tier(org="University of Louisiana at Lafayette", ports=[22, 123, 161]) == "education"
    assert tier(org="University of Louisiana at Lafayette", hostnames=["209.33.venyu.com"],
                domains=["venyu.com"], ports=[161]) == "education"


def test_k12_domain_on_carrier_space_is_education():
    # allen.k12.la.us on Conterra used to be 'government' via parish 'allen'
    assert tier(org="Conterra", hostnames=["allen.k12.la.us", "mail.apsb.us"],
                domains=["allen.k12.la.us", "apsb.us"], ports=[443]) == "education"
    assert tier(org="Optimum", hostnames=["ns.bossier.k12.la.us"],
                domains=["bossier.k12.la.us"], ports=[500]) == "education"


# --- genuine positives must keep working --------------------------------------

def test_la_gov_domains_are_government_regardless_of_carrier():
    assert tier(org="Cox Communications Inc.", hostnames=["adminlaw.la.gov"],
                domains=["cox.net", "la.gov"], ports=[443]) == "government"
    assert tier(org="SKYRIDER COMMUNICATIONS LLC", hostnames=["westmonroe.la.gov"],
                domains=["la.gov"], ports=[443]) == "government"
    assert tier(org="LUS Fiber", hostnames=["mail2.lafayettela.gov"],
                domains=["lafayettela.gov"], ports=[443]) == "government"


def test_state_ots_is_government():
    assert tier(org="State of Louisiana Office of Technology Services",
                hostnames=["epsm.goea.la.gov"], domains=["la.gov"], ports=[443]) == "government"
    assert tier(org="State of Louisiana Office of Technology Services", ports=[443]) == "government"


def test_department_of_revenue_is_government_not_rev_isp():
    assert tier(org="Louisiana Department of Revenue", ports=[443]) == "government"


def test_police_jury_and_school_board():
    assert tier(org="Bossier Parish Police Jury", ports=[443]) == "government"
    assert tier(org="Jefferson Parish School Board", ports=[443]) == "education"


def test_healthcare_is_critical_infrastructure():
    assert tier(org="Ochsner Clinic Foundation", ports=[443]) == "critical_infrastructure"
    assert tier(org="Our Lady of the Lake Hospital", ports=[443]) == "critical_infrastructure"
    assert tier(org="Acadian Ambulance Service, Inc.", ports=[443]) == "critical_infrastructure"


def test_universities_are_education():
    for org in ("Louisiana State University", "Tulane University", "Louisiana Tech University",
                "Southern University", "McNeese State University"):
        assert tier(org=org, ports=[443]) == "education", org


def test_oil_and_gas_keywords_are_critical_infrastructure():
    assert tier(org="Placid Refining Company", ports=[443]) == "critical_infrastructure"
    assert tier(org="Gulf South Pipeline", ports=[443]) == "critical_infrastructure"


def test_ics_port_on_carrier_space_is_critical_infrastructure():
    assert tier(org="Verizon Business", hostnames=["managedrtu.com"], domains=["managedrtu.com"],
                ports=[443, 502, 8080], tags=["ics"]) == "critical_infrastructure"


# --- honeypots and scanners ---------------------------------------------------

def test_honeypot_tag_disqualifies_even_with_ics_port():
    assert tier(org="Optimum", ports=[21, 22, 23, 104, 143, 502],
                tags=["eol-product", "honeypot", "ics"]) == "honeypot"


def test_megaport_host_is_not_critical_infrastructure():
    # a customer domain keeps it as a reviewable business lead, flagged — never ICS
    t, reason = classify(host(org="Cox Communications Inc.", hostnames=["swiftly.lubawc.com"],
                              domains=["cox.net", "lubawc.com"], ports=list(range(1, 200)) + [502]))
    assert t == "small_business" and "mega-port" in reason
    assert tier(org="Cox Communications Inc.", hostnames=["wsip-70-169-64-243.br.br.cox.net"],
                domains=["cox.net"], ports=range(1, 200)) == "honeypot"


def test_loni_honeypot_with_example_com():
    assert tier(org="Louisiana Board of Regents/Louisiana Optical Network Initiative (LONI)",
                hostnames=["example.com"], domains=["example.com"], ports=[21, 22, 25, 80, 104],
                tags=["database", "eol-product", "honeypot"]) == "honeypot"


# --- contract --------------------------------------------------------------

def test_every_tier_returned_is_declared():
    samples = [host(org="x"), host(), host(org="Cox Communications", ports=[502]),
               host(org="Cox Communications", hostnames=["a.b"], tags=["honeypot"]),
               host(domains=["pa.gov"]), host(domains=["la.gov"]), host(domains=["x.edu"])]
    for h in samples:
        t, reason = classify(h)
        assert t in TIERS, t
        assert reason


def test_missing_optional_fields_do_not_crash():
    assert classify({"org": None, "hostnames": [], "domains": [], "ports": set()})[0] == "unclassified"
    assert classify({"org": "Foo Inc", "hostnames": [], "domains": [], "ports": set()})[0] == "small_business"


# --- compound sector words in hostnames ---------------------------------------

def test_sector_word_as_tail_of_compound_hostname_counts():
    assert tier(org="Conterra", hostnames=["vpn.lcmchealth.org"], domains=["lcmchealth.org"],
                ports=[443]) == "critical_infrastructure"
    assert tier(org="AT&T Enterprises, LLC", hostnames=["mail.franklinmedical.com"],
                domains=["franklinmedical.com"], ports=[443]) == "critical_infrastructure"


def test_false_compounds_do_not_count():
    assert tier(org="AT&T Enterprises, LLC", hostnames=["www.lahospitalitygroup.com"],
                domains=["lahospitalitygroup.com"], ports=[443]) == "small_business"
    assert tier(org="GTT", hostnames=["empower-portal.example.com"], domains=["example.com"],
                ports=[443]) == "small_business"
    assert tier(org="Pennington Biomedical Research Center", hostnames=["x.pbrc.edu"],
                domains=["pbrc.edu"], ports=[443]) == "education"
    assert tier(org="Synergy Bank", ports=[443]) == "small_business"


def test_short_sector_words_stay_whole_word():
    assert tier(org="Las Vegas Sands", ports=[443]) == "small_business"      # 'gas'
    assert tier(org="Clearwater Marine", ports=[443]) == "small_business"    # 'water'
    assert tier(org="Boiler Room Bar", ports=[443]) == "small_business"      # 'oil'
    assert tier(org="ONEAL GAS", ports=[443]) == "critical_infrastructure"


def test_helpers_used_by_build_store_still_exist():
    import triage_report
    assert callable(triage_report.load_json)
    assert triage_report.load_json("/nonexistent/x.json", {"d": 1}) == {"d": 1}


# --- second-pass cases (from the Codex review) --------------------------------

def test_domain_authority_edge_cases():
    assert gov_domain_kind("agency.pa.gov") == "other_state"      # 3-label other-state
    assert gov_domain_kind("la.gov.") == "la"                      # trailing root dot
    assert gov_domain_kind("k12.la.us") is None                    # exact K-12 root
    assert gov_domain_kind("vpn.ebrso.org") == "la"                # under an allowlisted locality domain
    assert gov_domain_kind("lafayette.la.us.clients.pavlovmedia.net") is None   # embedded, not a suffix
    assert tier(org="Cox Communications", hostnames=["vpn.ebrso.org"], ports=[443]) == "government"


def test_other_state_domain_is_out_of_scope_before_sector():
    # health.pa.gov is Pennsylvania's problem, not critical infrastructure in Louisiana
    assert tier(org="Commonwealth of PA - OA", hostnames=["health.pa.gov"], domains=["pa.gov"],
                ports=[443]) == "out_of_state_gov"


def test_conflicting_louisiana_org_with_other_state_domain_stays_in_scope():
    assert tier(org="Louisiana Department of Revenue", domains=["pa.gov"], ports=[443]) == "government"


def test_hyphenated_phrase_and_compound_sheriff():
    assert tier(org="Cox Communications", hostnames=["vpn.city-of-example.example"],
                ports=[443]) == "government"
    assert tier(org="Jefferson Parish School-Board", ports=[443]) == "education"


def test_plurals_and_isd():
    assert tier(org="Regional Hospitals", ports=[443]) == "critical_infrastructure"
    assert tier(org="Example ISD", ports=[443]) == "education"


def test_bare_parish_word_is_not_government():
    assert tier(org="Parish Brewing Company", ports=[443]) == "small_business"
    assert tier(org="Example Parish School", ports=[443]) == "education"
    assert tier(org="Jefferson Parish", ports=[443]) == "government"
    assert tier(org="St. Tammany Parish Government", ports=[443]) == "government"


def test_civic_noun_must_be_near_the_parish_name():
    # 'library' in an unrelated hostname must not turn "Jefferson Design" into government
    assert tier(org="Jefferson Design", hostnames=["library.example.net"], domains=["example.net"],
                ports=[443]) == "small_business"
    assert tier(org="Cox Communications", hostnames=["vpn.caddo-sheriff.example"],
                ports=[443]) == "government"


def test_customer_identity_beside_carrier_rdns_is_business():
    assert tier(org="Cox Communications", hostnames=["host-42.example.net", "vpn.acme.example"],
                domains=["acme.example"], ports=[443]) == "small_business"
    assert tier(org="Conterra", hostnames=["vpn.acmefiber.example"], domains=["acmefiber.example"],
                ports=[443]) == "small_business"
    assert tier(org="Cox Communications Inc.", hostnames=["wsip-70-169-64-243.br.br.cox.net"],
                domains=["cox.net"], ports=[443]) == "residential"


def test_business_carrier_without_identity_is_unclassified_not_residential():
    assert tier(org="AT&T Enterprises, LLC", ports=[443]) == "unclassified"
    assert tier(org="Nexus Medical", ports=[443]) == "critical_infrastructure"


def test_stoplist_cannot_manufacture_a_boundary():
    assert tier(org="Conterra", domains=["energysynergy.example"], ports=[443]) == "small_business"
    assert tier(org="Conterra", domains=["lcmc2health.example"], ports=[443]) == "critical_infrastructure"


def test_megaport_with_authoritative_louisiana_domain_keeps_sector():
    assert tier(org="Jefferson Parish Police Jury", domains=["jeffparish.net"],
                ports=range(10000, 10101)) == "government"
    assert tier(org="Cox Communications", ports=range(10000, 10101)) == "honeypot"
    assert tier(org="Cox Communications", ports=range(10000, 10100)) != "honeypot"   # exactly 100 is not >100


def test_ics_port_on_megaport_host_is_not_critical_infrastructure():
    assert tier(org="Optimum", ports=list(range(10000, 10101)) + [502]) == "honeypot"


# --- third-pass cases (from the second Codex review) ---------------------------

def test_k12_identity_beats_other_state_name_on_same_ip():
    assert tier(org="Conterra", hostnames=["mail.allen.k12.la.us", "legacy.agency.tx.gov"],
                ports=[443]) == "education"


def test_megaport_host_with_sector_identity_keeps_its_tier_with_a_flag():
    t, reason = classify(host(org="Ochsner Clinic Foundation", ports=list(range(10000, 10101)) + [443]))
    assert t == "critical_infrastructure" and "mega-port" in reason
    t, reason = classify(host(org="City of Ruston", ports=range(10000, 10101)))
    assert t == "government" and "mega-port" in reason
    assert tier(org="Cox Communications", ports=range(10000, 10101)) == "honeypot"


def test_customer_domain_beside_carrier_rdns_is_business():
    assert tier(org="Cox Communications", hostnames=["wsip-70-169-64-243.br.br.cox.net"],
                domains=["cox.net", "bayou-accounting.example"], ports=[3389]) == "small_business"
    assert tier(org="Cox Communications", hostnames=["wsip-70-169-64-243.br.br.cox.net"],
                domains=["cox.net"], ports=[3389]) == "residential"


def test_parish_civic_pairing_cannot_span_two_names():
    assert tier(org="Cox Communications", hostnames=["vpn.jefferson.design", "library.vendor.example"],
                domains=["jefferson.design", "vendor.example"], ports=[443]) == "small_business"
    assert tier(org="Cox Communications", hostnames=["www.city.example", "of.other.example"],
                ports=[443]) == "small_business"


def test_multiword_parish_names_with_hostname_separators():
    assert tier(org="Cox Communications", hostnames=["vpn.east-baton-rouge-parish.example"],
                ports=[443]) == "government"
    assert tier(org="Cox Communications", hostnames=["gis.st-tammany-parish.example"],
                ports=[443]) == "government"
    assert tier(org="St. Tammany Parish Government", ports=[443]) == "government"


# --- fourth-pass cases (from the third Codex review) --------------------------

def test_megaport_business_stays_a_reviewable_lead():
    t, reason = classify(host(org="Whole Sale", hostnames=["sales.morrisdickson.com"],
                              domains=["morrisdickson.com"], ports=range(10000, 10101)))
    assert t == "small_business" and "mega-port" in reason


def test_k12_hostname_beats_its_la_us_parent_domain():
    assert tier(org="Conterra", hostnames=["mail.allen.k12.la.us"], domains=["la.us"],
                ports=[443]) == "education"


def test_static_hostname_under_customer_domain_is_business():
    assert tier(org="Cox Communications", hostnames=["static.morrisdickson.com"],
                domains=["morrisdickson.com"], ports=[3389]) == "small_business"
    assert tier(org="Cox Communications", hostnames=["wsip-1-2-3-4.br.br.cox.net"],
                domains=["cox.net"], ports=[3389]) == "residential"
    assert tier(org="Cox Communications", hostnames=["evilcox.net"], domains=["evilcox.net"],
                ports=[3389]) == "small_business"      # suffix must respect label boundary


def test_only_louisiana_edu_overrides_an_out_of_state_name():
    assert tier(org="Commonwealth of PA", hostnames=["health.pa.gov", "shared.example.edu"],
                ports=[443]) == "out_of_state_gov"
    assert tier(org="Conterra", hostnames=["legacy.agency.tx.gov", "vpn.lsu.edu"],
                ports=[443]) == "education"


def test_report_keeps_the_review_flag_visible(tmp_path):
    import gzip, json, subprocess, sys, os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    gz = tmp_path / "louisiana-events-2026-01-01.json.gz"
    with gzip.open(gz, "wt") as f:
        for port in list(range(10000, 10101)) + [3389]:
            f.write(json.dumps({"ip_str": "203.0.113.5", "port": port, "org": "Ochsner Clinic Foundation",
                                "hostnames": [], "domains": [], "tags": [], "vulns": {}}) + "\n")
        f.write(json.dumps({"ip_str": "203.0.113.6", "port": 443, "org": "City of Ruston",
                            "hostnames": [], "domains": [], "tags": [], "vulns": {}}) + "\n")
    out = tmp_path / "report.md"
    r = subprocess.run([sys.executable, os.path.join(root, "triage_report.py"), str(gz), "--out", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    text = out.read_text()
    assert "mega-port" in text and "203.0.113.5" in text and "⚠" in text
    assert "| government | 1 |" in text


# --- fifth-pass cases (from the fourth Codex review) --------------------------

def test_carrier_rdns_label_does_not_set_sector_or_government():
    assert tier(org="Cox Communications", hostnames=["cpe-health.cox.net"], domains=["cox.net"],
                ports=[443]) == "residential"
    assert tier(org="Cox Communications", hostnames=["cpe-police.cox.net"], domains=["cox.net"],
                ports=[443]) == "residential"


def test_mixed_jurisdiction_is_flagged_and_foreign_names_do_not_set_sector():
    t, reason = classify(host(org="Conterra", hostnames=["vpn.lsu.edu", "health.pa.gov"], ports=[443]))
    assert t == "education" and "mixed jurisdiction" in reason and "health.pa.gov" in reason


def test_zero_score_flagged_host_appears_in_review_queue(tmp_path):
    import gzip, json, subprocess, sys, os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    gz = tmp_path / "louisiana-events-2026-01-01.json.gz"
    with gzip.open(gz, "wt") as f:
        for port in list(range(10000, 10101)) + [443]:      # no CVEs, no admin/db ports: score 0
            f.write(json.dumps({"ip_str": "203.0.113.7", "port": port, "org": "Ochsner Clinic Foundation",
                                "hostnames": [], "domains": [], "tags": [], "vulns": {}}) + "\n")
    out = tmp_path / "report.md"
    r = subprocess.run([sys.executable, os.path.join(root, "triage_report.py"), str(gz), "--out", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    text = out.read_text()
    assert "Review queue" in text and "203.0.113.7" in text and "mega-port" in text


def test_out_of_state_government_org_without_a_gov_domain():
    assert tier(org="Commonwealth of PA - OA / Integrated Network Management Services",
                ports=[443]) == "out_of_state_gov"
    assert tier(org="State of Texas Department of Information Resources", ports=[443]) == "out_of_state_gov"
    assert tier(org="State of Louisiana Office of Technology Services", ports=[443]) == "government"
    assert tier(org="Commonwealth of PA", hostnames=["gis.la.gov"], ports=[443]) == "government"


def test_certificate_organisation_is_trusted_identity():
    h = host(org="Cox Communications", hostnames=["wsip-1-2-3-4.br.br.cox.net"], domains=["cox.net"], ports=[443])
    h["cert_orgs"] = {"Our Lady of the Lake Regional Medical Center"}
    assert classify(h)[0] == "critical_infrastructure"
    h["cert_orgs"] = {"Jefferson Parish Sheriff's Office"}
    assert classify(h)[0] == "government"
    h["cert_orgs"] = {"Acme Widgets LLC"}
    assert classify(h)[0] == "small_business"
