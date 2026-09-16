"""Tests for refresh_rosters.py and discover_domains.py. No network: every
parser runs on canned payloads, HTTP is faked, and the resolver uses a fake
getaddrinfo.

Run:  venv/bin/python -m pytest tests/test_rosters_discovery.py -q
"""
import csv
import datetime as dt
import io
import json
import os
import socket
import stat
import sys
import threading
import urllib.error
import urllib.parse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import refresh_rosters as rr  # noqa: E402
import discover_domains as dd  # noqa: E402


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    d = tmp_path / "cache"
    monkeypatch.setattr(rr, "CACHE_DIR", str(d))
    monkeypatch.setattr(rr.time, "sleep", lambda *_: None)
    return d


def write_roster_file(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rr.COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in rr.COLUMNS})


# --- roster CSV writer / keep-previous / carry-over / manifest ------------------------------

def test_write_roster_columns_dedupe_and_sort(tmp_path):
    rows = [rr.row("Zeta Water", "water", "community", "Houma", "Terrebonne Parish", source="u"),
            rr.row("Alpha Water", "water", "community", "Crowley", "Acadia", source="u"),
            rr.row("ALPHA WATER", "water", "community", "CROWLEY", "Acadia", source="u")]  # dup
    out = rr.write_roster("water", rows, roster_dir=str(tmp_path))
    assert [r["name"] for r in out] == ["Alpha Water", "Zeta Water"]
    with open(tmp_path / "water.csv", newline="") as f:
        rd = csv.DictReader(f)
        assert rd.fieldnames == rr.COLUMNS
        data = list(rd)
    assert data[1]["parish"] == "Terrebonne"          # "Parish" suffix stripped
    assert data[0]["as_of"] == rr.TODAY and data[0]["source"] == "u"
    assert not os.path.exists(tmp_path / "water.csv.tmp")   # atomic rename left no temp


def test_write_roster_dry_run_writes_nothing(tmp_path):
    rr.write_roster("water", [rr.row("X", "water", "community", source="u")], dry_run=True,
                    roster_dir=str(tmp_path))
    assert not os.path.exists(tmp_path / "water.csv")


def test_fetch_failure_keeps_previous_file(tmp_path, monkeypatch, capsys):
    prev = [rr.row("Old Water Co", "water", "community", "Crowley", "Acadia", source=rr.SDWIS_URL, as_of="2026-01-05")]
    write_roster_file(tmp_path / "water.csv", prev)
    before = open(tmp_path / "water.csv").read()
    monkeypatch.setitem(rr.FETCHERS, "water",
                        lambda: ([], [rr.report(rr.SDWIS_URL, rr.SDWIS_URL, 0, False, "", "unreachable")]))
    rows, entry = rr.run_sector("water", roster_dir=str(tmp_path))
    assert open(tmp_path / "water.csv").read() == before
    assert [r["name"] for r in rows] == ["Old Water Co"]
    assert entry["kept_previous"] is True and entry["complete"] is False and entry["rows"] == 1
    assert "kept previous, 1 rows, as_of 2026-01-05" in capsys.readouterr().out


def test_fetch_crash_keeps_previous_file(tmp_path, monkeypatch):
    write_roster_file(tmp_path / "water.csv", [rr.row("Old", "water", "community", source="u", as_of="2026-01-01")])

    def boom():
        raise RuntimeError("kaboom")
    monkeypatch.setitem(rr.FETCHERS, "water", boom)
    rows, entry = rr.run_sector("water", roster_dir=str(tmp_path))
    assert rows[0]["name"] == "Old" and entry["kept_previous"]


def test_partial_fetch_carries_over_failed_source_rows(tmp_path, monkeypatch, capsys):
    eia_old = rr.row("Entergy Louisiana LLC", "energy", "electric_utility", "Baton Rouge",
                     source=rr.EIA860_PREFIX + "archive/xls/eia8602023.zip", as_of="2026-01-05")
    bsee_old = rr.row("Gone Offshore Inc", "energy", "offshore_operator", "Houma", source=rr.BSEE_URL, as_of="2026-01-05")
    write_roster_file(tmp_path / "energy.csv", [eia_old, bsee_old])
    bsee_new = rr.row("New Offshore LLC", "energy", "offshore_operator", "Lafayette", source=rr.BSEE_URL)
    monkeypatch.setitem(rr.FETCHERS, "energy", lambda: (
        [bsee_new], [rr.report(rr.EIA860_URL, rr.EIA860_PREFIX, 0, False, "", "unreachable"),
                     rr.report(rr.BSEE_URL, rr.BSEE_URL, 1, True, "2026-09-01")]))
    rows, entry = rr.run_sector("energy", roster_dir=str(tmp_path))
    names = {r["name"]: r for r in rows}
    assert "Entergy Louisiana LLC" in names and names["Entergy Louisiana LLC"]["as_of"] == "2026-01-05"
    assert "New Offshore LLC" in names
    assert "Gone Offshore Inc" not in names          # its source was complete: refreshed, not carried
    assert entry["complete"] is False and entry["kept_previous"] is False
    assert "carrying over 1 previous rows" in capsys.readouterr().out


def test_manifest_written_and_merged(tmp_path):
    path = str(tmp_path / "manifest.json")
    rr.write_manifest({"water": {"rows": 3, "complete": True, "sources": [
        rr.report(rr.SDWIS_URL, rr.SDWIS_URL, 3, True, "Mon, 01 Sep 2026 00:00:00 GMT")]}}, path=path)
    rr.write_manifest({"energy": {"rows": 1, "complete": False, "sources": []}}, path=path)
    m = json.load(open(path))
    assert set(m) == {"water", "energy"}
    src = m["water"]["sources"][0]
    assert {"source", "fetched_at", "rows", "complete", "dataset_version"} <= set(src)
    assert src["dataset_version"].startswith("Mon, 01 Sep 2026")
    rr.write_manifest({"water": {}}, dry_run=True, path=path)
    assert json.load(open(path))["water"]["rows"] == 3


def test_manual_dropin_loaded(tmp_path, monkeypatch):
    monkeypatch.setattr(rr, "MANUAL_DIR", str(tmp_path))
    with open(tmp_path / "energy.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rr.COLUMNS)
        w.writeheader()
        w.writerow({"name": "Acme Gas Operator", "subsector": "operator", "city": "Lafayette"})
        w.writerow({"name": "", "subsector": "operator"})  # blank name ignored
    rows = rr.load_manual("energy")
    assert len(rows) == 1
    assert rows[0]["sector"] == "energy" and rows[0]["source"].startswith("manual:")
    assert rr.load_manual("water") == []


# --- deadlines, HTTP backoff, cache privacy ---------------------------------------------------

def test_deadline_child_never_outlives_parent():
    parent = rr.Deadline(10)
    child = parent.child(100)
    assert child.remaining() <= parent.remaining() + 0.01
    assert rr.Deadline().remaining() == float("inf")
    assert rr.Deadline(0).expired()
    assert rr.Deadline(1).clip(30) <= 1.0


class FakeResp:
    def __init__(self, body, headers=None):
        self.body, self.headers = body, headers or {}

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, headers=None):
    h = email_headers(headers or {})
    return urllib.error.HTTPError("http://x", code, "err", h, io.BytesIO(b""))


def email_headers(d):
    import email.message
    m = email.message.Message()
    for k, v in d.items():
        m[k] = v
    return m


def test_http_get_backs_off_on_429_with_retry_after(monkeypatch, cache_dir):
    calls, sleeps = [], []
    monkeypatch.setattr(rr.time, "sleep", sleeps.append)

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        if len(calls) == 1:
            raise http_error(429, {"Retry-After": "3"})
        if len(calls) == 2:
            raise http_error(503)
        return FakeResp(b"ok", {"Last-Modified": "Mon, 01 Sep 2026 00:00:00 GMT"})
    monkeypatch.setattr(rr.urllib.request, "urlopen", fake_urlopen)
    rr.set_deadline(rr.Deadline())
    data, headers = rr.http_get("https://npiregistry.cms.hhs.gov/api/?x=1", 30)
    assert data == b"ok" and headers["Last-Modified"].startswith("Mon")
    assert sleeps == [3.0, 4.0]          # Retry-After honoured, then exponential 2**(attempt+1)


def test_http_get_gives_up_after_retries_and_not_on_404(monkeypatch, cache_dir):
    sleeps = []
    monkeypatch.setattr(rr.time, "sleep", sleeps.append)
    n = [0]

    def always_429(req, timeout=None):
        n[0] += 1
        raise http_error(429)
    monkeypatch.setattr(rr.urllib.request, "urlopen", always_429)
    assert rr.http_get("https://x/", 30) == (None, None)
    assert n[0] == rr.FETCH_RETRIES and len(sleeps) == rr.FETCH_RETRIES - 1

    def not_found(req, timeout=None):
        raise http_error(404)
    sleeps.clear()
    monkeypatch.setattr(rr.urllib.request, "urlopen", not_found)
    assert rr.http_get("https://x/", 30) == (None, None) and sleeps == []


def test_http_get_respects_deadline(monkeypatch, cache_dir):
    monkeypatch.setattr(rr.urllib.request, "urlopen", lambda *a, **k: pytest.fail("must not fetch"))
    rr.set_deadline(rr.Deadline(0))
    try:
        assert rr.http_get("https://x/", 30) == (None, None)
    finally:
        rr.set_deadline(rr.Deadline())


def test_retry_after_parsing():
    assert rr.retry_after_seconds("7", 0) == 7.0
    assert rr.retry_after_seconds(None, 0) == 2.0 and rr.retry_after_seconds("", 2) == 8.0
    assert rr.retry_after_seconds("junk", 0) == 2.0
    assert rr.retry_after_seconds("100000", 0) == 120.0
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=30)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert 25 <= rr.retry_after_seconds(future, 0) <= 31


def test_fetch_caches_body_and_meta(monkeypatch, cache_dir):
    monkeypatch.setattr(rr.urllib.request, "urlopen",
                        lambda req, timeout=None: FakeResp(b"a,b\n1,2\n", {"Last-Modified": "Tue, 02 Sep 2026 00:00:00 GMT"}))
    assert rr.fetch("https://x/f.csv", cache_name="f.csv") == "a,b\n1,2\n"
    monkeypatch.setattr(rr.urllib.request, "urlopen", lambda *a, **k: pytest.fail("should hit cache"))
    assert rr.fetch("https://x/f.csv", cache_name="f.csv") == "a,b\n1,2\n"
    assert rr.dataset_version("f.csv") == "Tue, 02 Sep 2026 00:00:00 GMT"
    assert rr.dataset_version("missing.csv", 2023) == "2023"
    assert stat.S_IMODE(os.stat(cache_dir).st_mode) == 0o700


def test_nppes_slim_drops_personal_contact_fields():
    raw = {"result_count": 1, "results": [{
        "number": "1", "basic": {"organization_name": "X HOSPITAL", "authorized_official_first_name": "JANE",
                                 "authorized_official_last_name": "DOE", "authorized_official_telephone_number": "5551234"},
        "addresses": [{"address_purpose": "LOCATION", "address_1": "1 MAIN ST", "city": "HOUMA", "state": "LA",
                       "postal_code": "70360", "telephone_number": "5559999", "fax_number": "5558888"}],
        "taxonomies": [{"code": "282N00000X", "desc": "General Acute Care Hospital", "primary": True, "license": "L1"}]}]}
    slim = json.dumps(rr.nppes_slim(raw))
    for secret in ("JANE", "DOE", "5551234", "5559999", "5558888", "1 MAIN ST", "L1"):
        assert secret not in slim
    obj = json.loads(slim)
    assert obj["results"][0]["basic"] == {"organization_name": "X HOSPITAL"}
    assert obj["results"][0]["addresses"][0]["city"] == "HOUMA"
    assert rr.parse_nppes_page(obj, "General Acute Care Hospital", "hospital")[0]["name"] == "X Hospital"


# --- SDWIS ----------------------------------------------------------------------------------------

SDWIS_CSV = """pwsid,pws_name,pws_activity_code,pws_type_code,population_served_count,city_name,state_code
LA1001001,CITY OF CROWLEY WATER SYSTEM,A,CWS,13000,CROWLEY,LA
LA1001002,ACADIA PARISH WATERWORKS DIST 1,A,CWS,2500,RAYNE,LA
LA1001003,OLD MILL CAMPGROUND,A,TNCWS,50,CHURCH POINT,LA
LA1001004,ROLLING HILLS SCHOOL,A,NTNCWS,400,EUNICE,LA
LA1001005,DEFUNCT WATER CO,I,CWS,900,CROWLEY,LA
"""
SDWIS_GEO = """pwsid,area_type_code,county_served
LA1001001,CN,Acadia Parish
LA1001004,CN,St. Landry Parish
"""


def test_parse_sdwis_filters_and_parish():
    rows = rr.parse_sdwis(SDWIS_CSV, SDWIS_GEO)
    names = {r["name"]: r for r in rows}
    assert set(names) == {"City of Crowley Water System", "Acadia Parish Waterworks Dist 1",
                          "Rolling Hills School"}
    assert names["City of Crowley Water System"]["parish"] == "Acadia"
    assert names["City of Crowley Water System"]["subsector"] == "community"
    assert names["Rolling Hills School"]["subsector"] == "non_community"
    assert names["Rolling Hills School"]["parish"] == "St. Landry"
    assert names["Acadia Parish Waterworks Dist 1"]["parish"] == ""     # no geo row
    assert all(r["sector"] == "water" and r["source"] == rr.SDWIS_URL for r in rows)


def test_parse_sdwis_without_geo():
    rows = rr.parse_sdwis(SDWIS_CSV, None)
    assert len(rows) == 3 and all(r["parish"] == "" for r in rows)


# --- NPPES -----------------------------------------------------------------------------------------

def nppes_result(name, city, descs, number="1"):
    return {"number": number, "basic": {"organization_name": name},
            "addresses": [{"address_purpose": "MAILING", "city": "DALLAS", "state": "TX"},
                          {"address_purpose": "LOCATION", "city": city, "state": "LA"}],
            "taxonomies": [{"desc": d, "primary": i == 0} for i, d in enumerate(descs)]}


NPPES_PAGE = {"result_count": 4, "results": [
    nppes_result("OUR LADY OF THE LAKE REGIONAL MEDICAL CENTER", "BATON ROUGE", ["General Acute Care Hospital"]),
    nppes_result("HOSPITALITY STAFFING LLC", "METAIRIE", ["Clinic/Center, Multi-Specialty"]),   # fuzzy hit
    nppes_result("ACADIAN AMBULANCE SERVICE INC", "LAFAYETTE", ["Ambulance, Land Transport", "Hospital"]),
    nppes_result("999999", "METAIRIE", ["General Acute Care Hospital"]),   # registry junk
]}


def test_parse_nppes_page_whole_word_filter_and_location():
    rows = rr.parse_nppes_page(NPPES_PAGE, "Hospital", "hospital")
    names = [r["name"] for r in rows]
    assert "Our Lady of the Lake Regional Medical Center" in names
    assert "Acadian Ambulance Service Inc" in names
    assert not any("Hospitality" in n for n in names)   # 'hospital' must not match 'hospitality'
    assert "999999" not in names and len(rows) == 2
    r = rows[0]
    assert r["city"] == "Baton Rouge" and r["sector"] == "healthcare" and r["subsector"] == "hospital"
    assert r["source"].startswith(rr.NPPES_URL) and "number=" in r["source"]


def test_parse_nppes_page_errors_and_empty():
    assert rr.parse_nppes_page({"Errors": [{"description": "x"}]}, "Hospital", "hospital") == []
    assert rr.parse_nppes_page({"results": []}, "Hospital", "hospital") == []
    assert rr.parse_nppes_page(None, "Hospital", "hospital") == []


def qs(url):
    return {k: v[0] for k, v in urllib.parse.parse_qs(url.split("?", 1)[1]).items()}


def test_nppes_pages_error_payload_is_error_not_complete(cache_dir):
    def api_error(url, timeout=30):
        return json.dumps({"Errors": [{"description": "No taxonomy codes found", "number": "14"}]})
    rows, status = rr.nppes_pages("Bogus", "clinic", None, [10], api_error)
    assert rows == [] and status == "error"
    assert not os.path.exists(cache_dir) or not os.listdir(cache_dir)   # errors never cached

    def http_fail(url, timeout=30):
        return None
    assert rr.nppes_pages("Bogus", "clinic", None, [10], http_fail)[1] == "error"
    assert rr.nppes_pages("Bogus", "clinic", None, [10], http_fail, rr.Deadline(0))[1] == "deadline"
    assert rr.nppes_pages("Bogus", "clinic", None, [0], http_fail)[1] == "budget"


def test_nppes_pages_caches_slim_pages(cache_dir):
    calls = []

    def one_page(url, timeout=30):
        calls.append(url)
        return json.dumps({"results": [nppes_result("X HOSPITAL", "HOUMA", ["General Acute Care Hospital"])]})
    rows, status = rr.nppes_pages("General Acute Care Hospital", "hospital", None, [10], one_page)
    assert status == "complete" and rows[0]["name"] == "X Hospital"
    rows2, status2 = rr.nppes_pages("General Acute Care Hospital", "hospital", None, [10], one_page)
    assert len(calls) == 1 and rows2 == rows and status2 == "complete"   # served from cache
    assert stat.S_IMODE(os.stat(cache_dir).st_mode) == 0o700


def test_fetch_healthcare_pages_partitions_and_dedupes(monkeypatch, cache_dir):
    """Fake API: 'Hospital' has one short page; 'Clinic/Center' fills every
    page up to the ceiling so it must be partitioned by ZIP prefix. The same
    org seen as clinic and hospital keeps the hospital subsector."""
    monkeypatch.setattr(rr, "NPPES_TAXONOMIES", [("Clinic/Center", "clinic"), ("Hospital", "hospital")])
    monkeypatch.setattr(rr, "LA_ZIP_PREFIXES", ["700*", "701*"])
    calls = []

    def fake_fetch(url, timeout=30):
        calls.append(url)
        q = qs(url)
        term, skip, postal = q["taxonomy_description"], int(q["skip"]), q.get("postal_code")
        if term.startswith("Hospital"):
            return json.dumps({"results": [nppes_result("BIG HOSPITAL", "MONROE", ["General Acute Care Hospital"])]})
        if postal is None:   # unpartitioned clinic query is always full
            return json.dumps({"results": [nppes_result(f"C{skip}", "X", ["Clinic/Center"])] * rr.NPPES_PAGE})
        if skip == 0:
            return json.dumps({"results": [nppes_result(f"CLINIC {postal}", "MONROE", ["Clinic/Center"]),
                                           nppes_result("BIG HOSPITAL", "MONROE", ["Clinic/Center, Multi-Specialty"])]})
        return json.dumps({"results": []})

    rows, reports = rr.fetch_healthcare(max_requests=100, fetch_fn=fake_fetch)
    by = {r["name"]: r for r in rows}
    assert by["Big Hospital"]["subsector"] == "hospital"
    assert {"Clinic 700*", "Clinic 701*"} <= set(by)
    unpart = [u for u in calls if "Clinic" in u and "postal_code" not in u]
    assert len(unpart) == rr.NPPES_MAX_SKIP // rr.NPPES_PAGE + 1   # skip 0..1000
    assert any("postal_code=700" in u for u in calls)
    assert reports[0]["complete"] is True and reports[0]["rows"] == len(rows)


def test_fetch_healthcare_keeps_statewide_rows_when_zip_fallback_fails(monkeypatch, cache_dir):
    monkeypatch.setattr(rr, "NPPES_TAXONOMIES", [("Clinic/Center", "clinic")])
    monkeypatch.setattr(rr, "LA_ZIP_PREFIXES", ["700*"])

    def fake_fetch(url, timeout=30):
        q = qs(url)
        if q.get("postal_code"):
            return None                      # ZIP partition unreachable
        return json.dumps({"results": [nppes_result(f"CLINIC {q['skip']} {i}", "X", ["Clinic/Center"])
                                       for i in range(rr.NPPES_PAGE)]})
    rows, reports = rr.fetch_healthcare(max_requests=100, fetch_fn=fake_fetch)
    assert len(rows) == rr.NPPES_PAGE * (rr.NPPES_MAX_SKIP // rr.NPPES_PAGE + 1)   # statewide pages kept
    assert reports[0]["complete"] is False and "700*: error" in reports[0]["note"]


def test_fetch_healthcare_budget_stops(monkeypatch, cache_dir):
    n = [0]

    def fake_fetch(url, timeout=30):
        n[0] += 1
        return json.dumps({"results": [nppes_result("A", "B", ["General Acute Care Hospital"])] * rr.NPPES_PAGE})

    rows, reports = rr.fetch_healthcare(max_requests=3, fetch_fn=fake_fetch)
    assert n[0] == 3 and reports[0]["complete"] is False


def test_fetch_healthcare_stops_at_deadline(monkeypatch, cache_dir):
    called = []
    rows, reports = rr.fetch_healthcare(max_requests=10, fetch_fn=lambda u, timeout=30: called.append(u),
                                        deadline=rr.Deadline(0))
    assert called == [] and rows == [] and reports[0]["complete"] is False


# --- education (pagination) / energy / government parsers ---------------------------------------

def test_fetch_pages_follows_next_and_caches_only_complete(cache_dir):
    calls = []

    def pages(url, timeout=120):
        calls.append(url)
        if "page=2" in url:
            return json.dumps({"count": 3, "next": None, "results": [{"id": 3}]})
        return json.dumps({"count": 3, "next": url + "&page=2", "results": [{"id": 1}, {"id": 2}]})
    results, complete = rr.fetch_pages("https://api/x/?fips=22", "x.json", pages)
    assert [r["id"] for r in results] == [1, 2, 3] and complete and len(calls) == 2
    results, complete = rr.fetch_pages("https://api/x/?fips=22", "x.json", pages)
    assert len(calls) == 2 and len(results) == 3           # cached

    def flaky(url, timeout=120):
        if "page=2" in url:
            return None
        return json.dumps({"next": url + "&page=2", "results": [{"id": 1}]})
    results, complete = rr.fetch_pages("https://api/y/?fips=22", "y.json", flaky)
    assert [r["id"] for r in results] == [1] and complete is False
    assert not os.path.exists(cache_dir / "y.json")          # partial never cached
    results, complete = rr.fetch_pages("https://api/z/?fips=22", "z.json",
                                       lambda u, timeout=120: json.dumps({"next": u + "&p", "results": [{"id": 0}]}),
                                       max_pages=3)
    assert len(results) == 3 and complete is False


def test_fetch_education_paginates_and_reports(monkeypatch, cache_dir):
    monkeypatch.setattr(rr, "CCD_YEARS", [2023])
    monkeypatch.setattr(rr, "IPEDS_YEARS", [2023])
    monkeypatch.setattr(rr, "LA_EDU_DOMAINS", {"nicholls.edu", "lsu.edu"})

    def api(url, timeout=120):
        if "ccd" in url:
            if "page=2" in url:
                return json.dumps({"next": None, "results": [
                    {"school_name": "Rayne High", "lea_name": "Acadia Parish", "leaid": "2200030",
                     "city_location": "Rayne", "county_code": "22001", "school_status": 1}]})
            return json.dumps({"next": url + "&page=2", "results": [
                {"school_name": "Crowley High", "lea_name": "Acadia Parish", "leaid": "2200030",
                 "city_location": "Crowley", "county_code": "22001", "school_status": 1}]})
        return json.dumps({"next": None, "results": [
            {"inst_name": "Nicholls State University", "city": "Thibodaux", "county_name": "Lafourche Parish",
             "url_school": "www.nicholls.edu/", "currently_active_ipeds": 1}]})
    rows, reports = rr.fetch_education(fetch_fn=api)
    subs = sorted((r["subsector"], r["name"]) for r in rows)
    assert subs == [("higher_ed", "Nicholls State University"), ("higher_ed_domain", "lsu.edu"),
                    ("k12_district", "Acadia Parish"), ("k12_school", "Crowley High"), ("k12_school", "Rayne High")]
    ccd, ipeds, edu = reports
    assert ccd["complete"] and ccd["dataset_version"] == "2023" and ccd["rows"] == 3
    assert ccd["prefix"] == rr.URBAN_PREFIX + "schools/ccd/directory"
    assert ipeds["complete"] and edu["rows"] == 1


def test_parse_ccd_schools_and_districts():
    obj = {"results": [
        {"school_name": "Crowley High School", "lea_name": "Acadia Parish", "leaid": "2200030",
         "city_location": "Crowley", "county_code": "22001", "school_status": 1},
        {"school_name": "Rayne High School", "lea_name": "Acadia Parish", "leaid": "2200030",
         "city_location": "Rayne", "county_code": "22001", "school_status": 1},
        {"school_name": "Closed School", "lea_name": "Acadia Parish", "leaid": "2200030",
         "city_location": "Rayne", "county_code": "22001", "school_status": 2},
    ]}
    rows = rr.parse_ccd(obj, "u")
    subs = [(r["subsector"], r["name"], r["parish"]) for r in rows]
    assert subs == [("k12_district", "Acadia Parish", "Acadia"),
                    ("k12_school", "Crowley High School", "Acadia"),
                    ("k12_school", "Rayne High School", "Acadia")]


def test_parse_ipeds_domain_from_url():
    obj = {"results": [{"inst_name": "Nicholls State University", "city": "Thibodaux",
                        "county_name": "Lafourche Parish", "url_school": "www.nicholls.edu/",
                        "currently_active_ipeds": 1},
                       {"inst_name": "Gone College", "city": "X", "county_name": "Y",
                        "url_school": "", "currently_active_ipeds": 0}]}
    rows = rr.parse_ipeds(obj, "u")
    assert len(rows) == 1
    assert rows[0]["domain"] == "nicholls.edu" and rows[0]["website"] == "https://www.nicholls.edu/"
    assert rows[0]["parish"] == "Lafourche"


def test_parse_bsee_companies_filters_la_active_dedupes():
    text = ('"01816","19930622","Aegis Energy, Inc.","AEGIS ENERGY INC","","","G","","","","","","",'
            '"113 Heymann Blvd.","Building 7","Lafayette","LA","70503",""\r\n'
            '"01816","19930622","Aegis Energy, Inc.","AEGIS ENERGY INC","","","G","","","","","","",'
            '"115 Heymann Blvd.","","Lafayette","LA","70503",""\r\n'
            '"03267","20121107","145 OG HOLDINGS, LLC","145 OG","","P","G","Y","A","","","","",'
            '"4514 Cole Ave.","Suite 600","Dallas","TX","75205","United States"\r\n'
            '"00830","19831114","Old Co","OLD CO","19990101","","G","","","","","","",'
            '"1 Main","","Houma","LA","70360",""\r\n')
    rows = rr.parse_bsee_companies(text)
    assert [(r["name"], r["city"], r["subsector"]) for r in rows] == [("Aegis Energy, Inc.", "Lafayette", "offshore_operator")]


def test_parse_eia_sheet_utility_and_plant():
    util = [["2023 Form EIA-860 Data"],
            ["Utility ID", "Utility Name", "Street Address", "City", "State", "Zip"],
            ["1", "Entergy Louisiana LLC", "446 N Blvd", "Baton Rouge", "LA", "70802"],
            ["2", "Someone Else", "x", "Decatur", "IL", "62525"]]
    rows = rr.parse_eia_sheet(util, "utility", "u")
    assert [(r["name"], r["subsector"], r["city"]) for r in rows] == [("Entergy Louisiana LLC", "electric_utility", "Baton Rouge")]
    plant = [["hdr"], ["Utility ID", "Utility Name", "Plant Code", "Plant Name", "City", "State", "County"],
             ["1", "Entergy Louisiana LLC", "9", "Waterford 3", "Killona", "LA", "St. Charles"]]
    rows = rr.parse_eia_sheet(plant, "plant", "u")
    assert rows[0]["name"] == "Waterford 3" and rows[0]["parish"] == "St. Charles"
    assert rr.parse_eia_sheet([["no", "header"]], "utility", "u") == []


def test_parse_gazetteer_municipalities():
    text = ("USPS\tGEOID\tANSICODE\tNAME\tLSAD\tFUNCSTAT\tALAND\n"
            "LA\t2200100\t1\tAbbeville city\t25\tA\t1\n"
            "LA\t2200240\t2\tAbita Springs town\t43\tA\t1\n"
            "LA\t2200300\t3\tAcme village\t47\tA\t1\n"
            "LA\t2200400\t4\tBayou Cane CDP\t57\tS\t1\n"
            "LA\t2205000\t5\tBaton Rouge city\t25\tA\t1\n")
    rows = rr.parse_gazetteer(text, "u")
    assert [r["name"] for r in rows] == ["City of Abbeville", "Town of Abita Springs", "Village of Acme",
                                         "City of Baton Rouge / Parish of East Baton Rouge"]
    assert rows[0]["subsector"] == "municipal_city" and rows[0]["city"] == "Abbeville"


def test_parishes_are_64_with_fips():
    assert len(rr.PARISHES) == 64 and len({p for p, _ in rr.PARISHES}) == 64
    assert rr.PARISH_BY_FIPS["22071"] == "Orleans" and rr.PARISH_BY_FIPS["22033"] == "East Baton Rouge"
    rows = rr.parish_rows("u")
    assert rows[0]["name"] == "Acadia Parish Government" and rows[0]["city"] == "Crowley"
    assert all(r["subsector"] == "parish" for r in rows)


# --- crt.sh parser and query ---------------------------------------------------------------------

CRT = [
    {"common_name": "*.beau.k12.la.us", "name_value": "*.beau.k12.la.us\nbeau.k12.la.us\nCES.beau.k12.la.us."},
    {"common_name": "beau.k12.la.us", "name_value": "beau.k12.la.us\nces.beau.k12.la.us"},   # dupes
    {"common_name": "mail.example.com", "name_value": "mail.example.com\nwww.stpsb.k12.la.us"},  # off-seed
    {"common_name": "*.wild.k12.la.us", "name_value": "*.*.wild.k12.la.us\nadmin@x.k12.la.us\n10.0.0.1"},
    {"common_name": None, "name_value": None},
]


def test_parse_crtsh_strips_wildcards_dedupes_and_scopes():
    names = dd.parse_crtsh(CRT, "k12.la.us")
    assert names == ["beau.k12.la.us", "ces.beau.k12.la.us", "wild.k12.la.us", "www.stpsb.k12.la.us"]


def test_normalize_name_edge_cases():
    assert dd.normalize_name("*.X.LA.GOV.") == "x.la.gov"
    assert dd.normalize_name("foo.*.la.gov") is None
    assert dd.normalize_name("1.2.3.4") is None
    assert dd.normalize_name("me@la.gov") is None
    assert dd.normalize_name("bad host.la.gov") is None
    assert dd.normalize_name("") is None


@pytest.mark.parametrize("name,seed,expected", [
    ("ces.beau.k12.la.us", "k12.la.us", "beau.k12.la.us"),
    ("beau.k12.la.us", "k12.la.us", "beau.k12.la.us"),
    ("www.ldh.la.gov", "la.gov", "ldh.la.gov"),
    ("la.gov", "la.gov", "la.gov"),
    ("mail.cs.lsu.edu", "lsu.edu", "lsu.edu"),
    ("lsu.edu", "lsu.edu", "lsu.edu"),
    ("www.stpl.lib.la.us", "la.us", "stpl.lib.la.us"),
    ("www.brla.gov", "brla.gov", "brla.gov"),
])
def test_registered_domain(name, seed, expected):
    assert dd.registered_domain(name, seed) == expected


def test_crtsh_query_one_attempt_per_mode_then_fails(monkeypatch):
    monkeypatch.setattr(dd.time, "sleep", lambda *_: None)
    seen = []

    def flaky(url, timeout=60):
        seen.append((url, timeout))
        if "exclude=expired" in url:
            return [{"name_value": "a.la.gov", "common_name": "a.la.gov"}]
        raise TimeoutError("timed out")

    entries, mode = dd.crtsh_query("la.gov", fetch_fn=flaky)
    assert mode == "wildcard_unexpired" and len(entries) == 1
    assert seen[0][0].startswith("https://crt.sh/?q=%25.la.gov") and seen[0][1] == 60
    assert seen[1][1] == 30

    seen.clear()

    def dead(url, timeout=60):
        seen.append(url)
        raise OSError("down")
    assert dd.crtsh_query("la.gov", fetch_fn=dead) == ([], "failed")
    assert len(seen) == len(dd.CRTSH_MODES)          # exactly one attempt per mode, no retries
    assert seen[-1].startswith("https://crt.sh/?q=la.gov")


def test_crtsh_query_respects_deadline(monkeypatch):
    monkeypatch.setattr(dd.time, "sleep", lambda *_: None)
    calls = []

    def slow_fail(url, timeout=60):
        calls.append(timeout)
        raise TimeoutError()
    assert dd.crtsh_query("la.gov", fetch_fn=slow_fail, deadline=dd.Deadline(0)) == ([], "failed")
    assert calls == []                                # no attempt with no time left
    dd.crtsh_query("la.gov", fetch_fn=slow_fail, deadline=dd.Deadline(20))
    assert calls and all(t <= 20 for t in calls)      # timeouts clipped to the deadline


def test_cache_roundtrip_and_expiry(tmp_path, monkeypatch):
    monkeypatch.setattr(dd, "CACHE_DIR", str(tmp_path))
    dd.save_cache("la.gov", [{"name_value": "x.la.gov"}], "wildcard")
    obj = dd.load_cache("la.gov")
    assert obj and obj["count"] == 1 and obj["mode"] == "wildcard" and "fetched_at" in obj
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=8)
    assert dd.load_cache("la.gov", now=later) is None
    assert dd.load_cache("nope.gov") is None


# --- resolver ----------------------------------------------------------------------------------------

def fake_getaddrinfo(name, port, family=0, type=0, proto=0, flags=0):
    table = {"a.la.gov": ["192.0.2.1", "192.0.2.1", "2001:db8::1"], "b.la.gov": ["192.0.2.2"]}
    if name not in table:
        raise socket.gaierror(-2, "Name or service not known")
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in table[name]]


def test_resolve_one_dedupes_and_handles_failure():
    assert dd.resolve_one("a.la.gov", getaddrinfo=fake_getaddrinfo) == ["192.0.2.1", "2001:db8::1"]
    assert dd.resolve_one("zzz.la.gov", getaddrinfo=fake_getaddrinfo) == []


def test_resolve_names_concurrent_cap():
    resolved, unresolved, pending = dd.resolve_names(["a.la.gov", "b.la.gov", "zzz.la.gov", "a.la.gov"],
                                                     workers=2, timeout=2, getaddrinfo=fake_getaddrinfo)
    assert resolved == {"a.la.gov": ["192.0.2.1", "2001:db8::1"], "b.la.gov": ["192.0.2.2"]}
    assert unresolved == {"zzz.la.gov"} and pending == set()
    assert dd.resolve_names([], getaddrinfo=fake_getaddrinfo) == ({}, set(), set())


def test_resolve_names_deadline_stops_and_reports_pending():
    release = threading.Event()

    def slow(name, *a, **k):
        if name.startswith("hung"):
            release.wait(5)           # simulates a lame delegation that never answers
            raise socket.gaierror(-3, "timeout")
        return fake_getaddrinfo(name, *a, **k)

    t0 = dd.time.monotonic()
    resolved, unresolved, pending = dd.resolve_names(
        ["hung1.la.gov", "hung2.la.gov", "a.la.gov", "zzz.la.gov"], workers=4, timeout=0.2, getaddrinfo=slow)
    assert dd.time.monotonic() - t0 < 3
    assert resolved == {"a.la.gov": ["192.0.2.1", "2001:db8::1"]}
    assert unresolved == {"zzz.la.gov"} and pending == {"hung1.la.gov", "hung2.la.gov"}
    release.set()


def test_resolve_names_job_deadline_clips_budget():
    release = threading.Event()

    def hang(name, *a, **k):
        release.wait(5)
        raise socket.gaierror(-3, "timeout")
    t0 = dd.time.monotonic()
    resolved, unresolved, pending = dd.resolve_names(["h.la.gov"], workers=1, timeout=60,
                                                     getaddrinfo=hang, deadline=dd.Deadline(0.3))
    assert dd.time.monotonic() - t0 < 2 and pending == {"h.la.gov"}
    release.set()


# --- discovery merge / seeds / state --------------------------------------------------------------

def host(name, seed, ip, first="2026-01-01", last="2026-01-01"):
    return {"name": name, "seed": seed, "ip": ip, "resolved_at": first + "T00:00:00+00:00",
            "source": "crt.sh", "first_seen": first, "last_seen": last}


def test_merge_hosts_keeps_rows_for_unattempted_names_and_seeds():
    existing = [host("old.la.gov", "la.gov", "1.1.1.1"), host("x.lsu.edu", "lsu.edu", "2.2.2.2"),
                host("capped.la.gov", "la.gov", "3.3.3.3")]
    # la.gov ran: only old.la.gov was answered (resolved to a new ip); capped.la.gov hit the cap;
    # lsu.edu's crt.sh query failed -> not in results at all
    results = {"la.gov": {"resolved": {"old.la.gov": ["1.1.1.1", "9.9.9.9"]}, "unresolved": set()}}
    merged = dd.merge_hosts(existing, results, "2026-09-15", "2026-09-15T01:00:00+00:00")
    by = {(r["name"], r["ip"]): r for r in merged}
    assert set(by) == {("old.la.gov", "1.1.1.1"), ("old.la.gov", "9.9.9.9"), ("x.lsu.edu", "2.2.2.2"),
                       ("capped.la.gov", "3.3.3.3")}
    assert by[("old.la.gov", "1.1.1.1")]["first_seen"] == "2026-01-01"       # preserved
    assert by[("old.la.gov", "1.1.1.1")]["last_seen"] == "2026-09-15"
    assert by[("old.la.gov", "9.9.9.9")]["first_seen"] == "2026-09-15"
    assert by[("capped.la.gov", "3.3.3.3")]["last_seen"] == "2026-01-01"      # untouched
    assert by[("x.lsu.edu", "2.2.2.2")]["resolved_at"].startswith("2026-01-01")


def test_merge_hosts_drops_only_re_resolved_gone_rows():
    existing = [host("gone.la.gov", "la.gov", "1.1.1.1"), host("moved.la.gov", "la.gov", "2.2.2.2")]
    results = {"la.gov": {"resolved": {"moved.la.gov": ["5.5.5.5"]}, "unresolved": {"gone.la.gov"}}}
    merged = dd.merge_hosts(existing, results, "2026-09-15", "t")
    assert [(r["name"], r["ip"]) for r in merged] == [("moved.la.gov", "5.5.5.5")]


def test_merge_hosts_upgrades_legacy_rows_without_seen_columns():
    legacy = [{"name": "a.la.gov", "seed": "la.gov", "ip": "1.1.1.1", "resolved_at": "2026-03-01T00:00:00+00:00",
               "source": "crt.sh"}]
    merged = dd.merge_hosts(legacy, {}, "2026-09-15", "t")
    assert merged[0]["first_seen"] == "2026-03-01" and merged[0]["last_seen"] == "2026-03-01"


def test_merge_domains_preserves_first_seen_and_never_drops():
    existing = [{"registered_domain": "ldh.la.gov", "seed": "la.gov", "first_seen": "2026-01-01", "last_seen": "2026-01-01"},
                {"registered_domain": "old.la.gov", "seed": "la.gov", "first_seen": "2025-12-01"}]
    out = dd.merge_domains(existing, {("ldh.la.gov", "la.gov"), ("dcfs.la.gov", "la.gov")}, "2026-09-15")
    by = {r["registered_domain"]: r for r in out}
    assert by["ldh.la.gov"]["first_seen"] == "2026-01-01" and by["ldh.la.gov"]["last_seen"] == "2026-09-15"
    assert by["dcfs.la.gov"]["first_seen"] == "2026-09-15"
    assert by["old.la.gov"]["last_seen"] == "2025-12-01"          # not seen this run, still kept


def test_write_csv_and_dry_run(tmp_path):
    path = tmp_path / "hosts.csv"
    rows = [host("a.la.gov", "la.gov", "1.1.1.1")]
    dd.write_csv(str(path), dd.HOST_COLUMNS, rows, dry_run=True)
    assert not path.exists()
    dd.write_csv(str(path), dd.HOST_COLUMNS, rows)
    with open(path, newline="") as f:
        rd = csv.DictReader(f)
        assert rd.fieldnames == dd.HOST_COLUMNS and list(rd)[0]["ip"] == "1.1.1.1"
    assert not (tmp_path / "hosts.csv.tmp").exists()


def test_collect_seeds_priority_order_and_orgs_csv(tmp_path, monkeypatch):
    monkeypatch.setattr(dd, "REGISTRY_DOMAINS", str(tmp_path / "domains.csv"))
    monkeypatch.setattr(dd, "REGISTRY_ORGS", str(tmp_path / "orgs.csv"))
    monkeypatch.setattr(dd, "ROSTER_GLOB", str(tmp_path / "rosters" / "*.csv"))
    monkeypatch.setattr(dd, "LA_EDU_DOMAINS", {"lsu.edu", "regents.la.gov"})
    os.makedirs(tmp_path / "rosters")
    with open(tmp_path / "domains.csv", "w") as f:
        f.write("domain,org_id\nldh.la.gov,x\nbrla.gov,y\nnot a domain,z\n")
    with open(tmp_path / "orgs.csv", "w") as f:
        f.write("org_id,name,domains\no1,Jefferson Parish,jeffparish.net;jeffparish.gov\no2,X,\n")
    with open(tmp_path / "rosters" / "education.csv", "w") as f:
        f.write("name,domain\nNicholls,nicholls.edu\nX,\nLSU,lsu.edu\n")
    seeds = dd.collect_seeds()
    assert seeds == ["la.gov", "k12.la.us", "lsu.edu", "brla.gov", "jeffparish.net", "jeffparish.gov", "nicholls.edu"]
    # ldh.la.gov and regents.la.gov are covered by la.gov; roster lsu.edu deduped; junk dropped


def test_order_seeds_never_completed_first_then_stalest_and_skips_fresh():
    now = dt.datetime(2026, 9, 15, tzinfo=dt.timezone.utc)
    state = {"la.gov": {"completed_at": "2026-09-14T00:00:00+00:00"},      # fresh -> skipped
             "lsu.edu": {"completed_at": "2026-08-01T00:00:00+00:00"},     # stale
             "brla.gov": {"completed_at": "2026-07-01T00:00:00+00:00"},    # staler
             "bad.gov": {"completed_at": "not a date"}}
    todo, fresh = dd.order_seeds(["la.gov", "k12.la.us", "lsu.edu", "brla.gov", "bad.gov"], state, now=now)
    assert todo == ["k12.la.us", "bad.gov", "brla.gov", "lsu.edu"] and fresh == ["la.gov"]


def test_state_roundtrip(tmp_path):
    path = str(tmp_path / "state.json")
    dd.save_state({"la.gov": {"completed_at": "x", "names": 1}}, path)
    assert dd.load_state(path)["la.gov"]["names"] == 1 and not os.path.exists(path + ".tmp")
    assert dd.load_state(str(tmp_path / "missing.json")) == {}


def test_main_capped_run_keeps_previous_rows_and_is_resumable(tmp_path, monkeypatch, capsys):
    """End-to-end without network: --max-seeds 1 processes only la.gov, keeps the
    previous lsu.edu rows, and records state so the next run picks lsu.edu."""
    disc = tmp_path / "discovery"
    monkeypatch.setattr(dd, "DISC_DIR", str(disc))
    monkeypatch.setattr(dd, "CACHE_DIR", str(disc / "cache"))
    monkeypatch.setattr(dd, "HOSTS_CSV", str(disc / "discovered_hosts.csv"))
    monkeypatch.setattr(dd, "DOMAINS_CSV", str(disc / "discovered_domains.csv"))
    monkeypatch.setattr(dd, "STATE_JSON", str(disc / "state.json"))
    monkeypatch.setattr(dd, "collect_seeds", lambda: ["la.gov", "lsu.edu"])
    monkeypatch.setattr(dd, "crtsh_query", lambda seed, **k: ([{"name_value": f"a.{seed}\nb.{seed}", "common_name": ""}], "wildcard"))
    monkeypatch.setattr(dd, "resolve_names", lambda names, **k: ({"a.la.gov": ["1.1.1.1"]}, {"b.la.gov"}, set()))
    monkeypatch.setattr(dd.time, "sleep", lambda *_: None)
    os.makedirs(disc)
    dd.write_csv(dd.HOSTS_CSV, dd.HOST_COLUMNS, [host("x.lsu.edu", "lsu.edu", "2.2.2.2"), host("b.la.gov", "la.gov", "3.3.3.3")])

    assert dd.main(["--max-seeds", "1"]) == 0
    rows = dd.read_csv(dd.HOSTS_CSV)
    assert {(r["name"], r["ip"]) for r in rows} == {("a.la.gov", "1.1.1.1"), ("x.lsu.edu", "2.2.2.2")}
    state = dd.load_state()
    assert "la.gov" in state and "lsu.edu" not in state
    out = capsys.readouterr().out
    assert "1 seeds not reached this run" in out

    assert dd.main(["--max-seeds", "1"]) == 0            # resume: lsu.edu is next, la.gov is fresh
    assert "lsu.edu" in dd.load_state()
    assert "1 fresh (skipped)" in capsys.readouterr().out
