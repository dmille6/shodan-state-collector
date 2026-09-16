#!/usr/bin/env python3
"""
refresh_rosters.py — build per-sector organization rosters from PUBLIC sources.

Writes reference/rosters/<sector>.csv with the Phase 2 contract columns:
    name, sector, subsector, city, parish, domain, website, source, as_of
and a sidecar reference/rosters/manifest.json recording, per sector and per
source: fetched_at, rows, complete (bool) and dataset_version (the underlying
dataset's year / Last-Modified, not just the fetch date).

Every row carries the URL it came from (source) and the fetch date (as_of), so
downstream attribution can be evidence-graded. Nothing is fabricated, and good
data is never replaced by empty data: if a sector's sources all fail the
previous CSV is kept untouched; if one source fails or comes back partial, that
source's rows from the previous CSV are carried over (with their old as_of).
reference/rosters/manual/<sector>.csv is the documented analyst drop-in.

Sources (each in its own fetch_* function; each fails soft and logs):
    water       EPA SDWIS via Envirofacts (WATER_SYSTEM + GEOGRAPHIC_AREA for parish)
    healthcare  CMS NPPES NPI Registry API, organizational providers (NPI-2) in LA,
                partitioned by exact taxonomy description and, when a taxonomy
                exceeds the API's 1000-record skip ceiling, by 3-digit ZIP prefix
    education   NCES Common Core of Data (K-12 schools + districts) and IPEDS
                (colleges) via the Urban Institute Education Data API (paginated),
                plus the LA_EDU_DOMAINS list from triage_report
    energy      EIA-860 (utilities and plants in LA, parsed from the archive zip
                with a stdlib xlsx reader) and BSEE offshore company file
    government  the 64 parishes (hard-coded, seats included; cross-checked against
                the Census county-code file) and municipalities from the Census
                Gazetteer place file (city/town/village)

Runtime is bounded: --max-minutes (default 30) for the whole job plus a
per-sector budget (SECTOR_BUDGET_S); HTTP 429/5xx are retried with Retry-After
backoff (at most 3 attempts). Raw downloads are cached under
reference/rosters/cache/ (mode 0700); NPPES pages are reduced to the fields the
roster needs before caching so no personal contact details are kept on disk.

Usage:
    refresh_rosters.py                     # all sectors
    refresh_rosters.py --sector water --sector government
    refresh_rosters.py --dry-run           # fetch + parse, write nothing
"""
import argparse
import csv
import datetime as dt
import email.utils
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import xml.etree.ElementTree as ET

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
try:
    from triage_report import kw_in, LA_EDU_DOMAINS  # noqa: E402
except Exception:  # keep the roster builder usable even if triage_report moves
    def kw_in(kw, text):
        return re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", text) is not None
    LA_EDU_DOMAINS = set()

REF = os.path.join(SCRIPT_DIR, "reference")
ROSTER_DIR = os.path.join(REF, "rosters")
CACHE_DIR = os.path.join(ROSTER_DIR, "cache")
MANUAL_DIR = os.path.join(ROSTER_DIR, "manual")
MANIFEST = os.path.join(ROSTER_DIR, "manifest.json")

COLUMNS = ["name", "sector", "subsector", "city", "parish", "domain", "website", "source", "as_of"]
SECTORS = ["water", "healthcare", "education", "energy", "government"]
USER_AGENT = "shodan_query-rosters/1.0 (Louisiana public-sector exposure triage; contact via repo)"

DEFAULT_MAX_MINUTES = 30
# Per-sector wall-clock budgets (seconds); always clipped by the job deadline.
SECTOR_BUDGET_S = {"water": 300, "healthcare": 900, "education": 300, "energy": 600, "government": 180}
FETCH_RETRIES = 3

TODAY = dt.date.today().isoformat()

# --- Source URLs ---------------------------------------------------------------
SDWIS_URL = "https://data.epa.gov/efservice/WATER_SYSTEM/STATE_CODE/LA/CSV"
SDWIS_GEO_URL = "https://data.epa.gov/efservice/GEOGRAPHIC_AREA/PRIMACY_AGENCY_CODE/LA/CSV"
NPPES_URL = "https://npiregistry.cms.hhs.gov/api/"
CCD_URL = "https://educationdata.urban.org/api/v1/schools/ccd/directory/{year}/?fips=22"
IPEDS_URL = "https://educationdata.urban.org/api/v1/college-university/ipeds/directory/{year}/?fips=22"
EIA860_URL = "https://www.eia.gov/electricity/data/eia860/archive/xls/eia860{year}.zip"
EIA860_PREFIX = "https://www.eia.gov/electricity/data/eia860/"
BSEE_URL = "https://www.data.bsee.gov/Company/Files/compalldelimit.zip"
GAZETTEER_URL = "https://www2.census.gov/geo/docs/maps-data/data/gazetteer/{year}_Gazetteer/{year}_gaz_place_22.txt"
GAZETTEER_PREFIX = "https://www2.census.gov/geo/docs/maps-data/data/gazetteer/"
CENSUS_COUNTIES_URL = "https://www2.census.gov/geo/docs/reference/codes2020/cou/st22_la_cou2020.txt"
URBAN_PREFIX = "https://educationdata.urban.org/api/v1/"
CCD_YEARS = [2023, 2022, 2021]
IPEDS_YEARS = [2023, 2022, 2021]
EIA_YEARS = [2024, 2023, 2022]
GAZETTEER_YEARS = [2024, 2023, 2022]
MAX_API_PAGES = 50

# --- The 64 parishes and their seats (FIPS county code = odd numbers 001..127,
# alphabetical). Cross-checked at run time against the Census county file. ------
PARISHES = [
    ("Acadia", "Crowley"), ("Allen", "Oberlin"), ("Ascension", "Donaldsonville"),
    ("Assumption", "Napoleonville"), ("Avoyelles", "Marksville"), ("Beauregard", "DeRidder"),
    ("Bienville", "Arcadia"), ("Bossier", "Benton"), ("Caddo", "Shreveport"),
    ("Calcasieu", "Lake Charles"), ("Caldwell", "Columbia"), ("Cameron", "Cameron"),
    ("Catahoula", "Harrisonburg"), ("Claiborne", "Homer"), ("Concordia", "Vidalia"),
    ("De Soto", "Mansfield"), ("East Baton Rouge", "Baton Rouge"), ("East Carroll", "Lake Providence"),
    ("East Feliciana", "Clinton"), ("Evangeline", "Ville Platte"), ("Franklin", "Winnsboro"),
    ("Grant", "Colfax"), ("Iberia", "New Iberia"), ("Iberville", "Plaquemine"),
    ("Jackson", "Jonesboro"), ("Jefferson", "Gretna"), ("Jefferson Davis", "Jennings"),
    ("Lafayette", "Lafayette"), ("Lafourche", "Thibodaux"), ("LaSalle", "Jena"),
    ("Lincoln", "Ruston"), ("Livingston", "Livingston"), ("Madison", "Tallulah"),
    ("Morehouse", "Bastrop"), ("Natchitoches", "Natchitoches"), ("Orleans", "New Orleans"),
    ("Ouachita", "Monroe"), ("Plaquemines", "Pointe a la Hache"), ("Pointe Coupee", "New Roads"),
    ("Rapides", "Alexandria"), ("Red River", "Coushatta"), ("Richland", "Rayville"),
    ("Sabine", "Many"), ("St. Bernard", "Chalmette"), ("St. Charles", "Hahnville"),
    ("St. Helena", "Greensburg"), ("St. James", "Convent"), ("St. John the Baptist", "Edgard"),
    ("St. Landry", "Opelousas"), ("St. Martin", "St. Martinville"), ("St. Mary", "Franklin"),
    ("St. Tammany", "Covington"), ("Tangipahoa", "Amite"), ("Tensas", "St. Joseph"),
    ("Terrebonne", "Houma"), ("Union", "Farmerville"), ("Vermilion", "Abbeville"),
    ("Vernon", "Leesville"), ("Washington", "Franklinton"), ("Webster", "Minden"),
    ("West Baton Rouge", "Port Allen"), ("West Carroll", "Oak Grove"),
    ("West Feliciana", "St. Francisville"), ("Winn", "Winnfield"),
]
assert len(PARISHES) == 64
PARISH_BY_FIPS = {f"22{2 * i + 1:03d}": name for i, name in enumerate(n for n, _ in PARISHES)}

# --- NPPES taxonomy partitions: (search term, subsector). The API resolves
# taxonomy_description to taxonomy codes by a loose lookup ("Hospital" lands on
# "Hospitalist"), so terms are the exact NUCC descriptions; results are then
# re-filtered by a whole-word match of the term against the org's own taxonomies.
NPPES_TAXONOMIES = [
    ("General Acute Care Hospital", "hospital"),
    ("Psychiatric Hospital", "hospital"),
    ("Rehabilitation Hospital", "hospital"),
    ("Long Term Care Hospital", "hospital"),
    ("Special Hospital", "hospital"),
    ("Chronic Disease Hospital", "hospital"),
    ("Military Hospital", "hospital"),
    ("Clinic/Center", "clinic"),
    ("Federally Qualified Health Center", "clinic"),
    ("Ambulance", "ambulance"),
    ("Emergency Medical Services", "ambulance"),
    ("Skilled Nursing Facility", "nursing"),
    ("Nursing Facility/Intermediate Care Facility", "nursing"),
    ("Assisted Living Facility", "nursing"),
    ("Home Health", "home_health"),
    ("Hospice", "home_health"),
    ("Health Maintenance Organization", "health_plan"),
    ("Preferred Provider Organization", "health_plan"),
    ("Public Health or Welfare", "public_health"),
    ("Community/Behavioral Health", "behavioral_health"),
]
# Subsector precedence when an org matches several taxonomies (hospital wins).
SUBSECTOR_RANK = {"hospital": 0, "ambulance": 1, "public_health": 2, "health_plan": 3,
                  "clinic": 4, "nursing": 5, "home_health": 6, "behavioral_health": 7}
NPPES_PAGE = 200
NPPES_MAX_SKIP = 1000          # documented ceiling of the registry API
LA_ZIP_PREFIXES = [f"{z}*" for z in range(700, 715)]   # Louisiana ZIPs are 700xx-714xx


def log(msg):
    print(msg, flush=True)


def now_iso():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


# --- Deadlines -----------------------------------------------------------------------
class Deadline:
    """Monotonic wall-clock budget. child(seconds) never outlives its parent."""

    def __init__(self, seconds=None, parent=None):
        self.at = None if seconds is None else time.monotonic() + seconds
        if parent is not None and parent.at is not None:
            self.at = parent.at if self.at is None else min(self.at, parent.at)

    def remaining(self):
        return float("inf") if self.at is None else self.at - time.monotonic()

    def expired(self):
        return self.remaining() <= 0

    def clip(self, timeout):
        return timeout if self.at is None else max(1.0, min(timeout, self.remaining()))

    def child(self, seconds):
        return Deadline(seconds, parent=self)


_DEADLINE = [Deadline()]   # the deadline fetch() consults; main() swaps it per sector


def current_deadline():
    return _DEADLINE[0]


def set_deadline(d):
    _DEADLINE[0] = d


# --- Fetch helpers --------------------------------------------------------------------
def ensure_cache_dir():
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(CACHE_DIR, 0o700)
    except OSError:
        pass


def cache_read(name, max_age_days):
    """Cached bytes for `name` if younger than max_age_days, else None."""
    path = os.path.join(CACHE_DIR, name)
    if not os.path.isfile(path):
        return None
    if (time.time() - os.path.getmtime(path)) / 86400 >= max_age_days:
        return None
    with open(path, "rb") as f:
        return f.read()


def cache_write(name, data, meta=None):
    ensure_cache_dir()
    path = os.path.join(CACHE_DIR, name)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    if meta is not None:
        with open(path + ".meta.json", "w") as f:
            json.dump(meta, f)


def cache_meta(name):
    try:
        with open(os.path.join(CACHE_DIR, name + ".meta.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def retry_after_seconds(header, attempt):
    """Seconds to wait per a Retry-After header (delta or HTTP-date), else
    exponential 2,4,8. Clamped to [1, 120]."""
    wait = None
    if header:
        h = header.strip()
        if h.isdigit():
            wait = int(h)
        else:
            try:
                when = email.utils.parsedate_to_datetime(h)
                wait = (when - dt.datetime.now(dt.timezone.utc)).total_seconds()
            except (TypeError, ValueError, IndexError):
                wait = None
    if wait is None:
        wait = 2.0 ** (attempt + 1)
    return max(1.0, min(120.0, float(wait)))


def http_get(url, timeout):
    """One GET with Retry-After / exponential backoff on 429 and 5xx, bounded by
    the current deadline. Returns (bytes, headers) or (None, None)."""
    dl = current_deadline()
    for attempt in range(FETCH_RETRIES):
        if dl.expired():
            log(f"  deadline reached; skipping {url}")
            return None, None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=dl.clip(timeout)) as r:
                return r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            retryable = e.code == 429 or 500 <= e.code < 600
            wait = retry_after_seconds(e.headers.get("Retry-After") if e.headers else None, attempt)
            if retryable and attempt + 1 < FETCH_RETRIES and wait < dl.remaining():
                log(f"  HTTP {e.code} from {urllib.parse.urlsplit(url).netloc}; backing off {wait:.0f}s")
                time.sleep(wait)
                continue
            log(f"  fetch failed: {url} (HTTP {e.code})")
            return None, None
        except Exception as e:
            log(f"  fetch failed: {url} ({e})")
            return None, None
    return None, None


def fetch(url, timeout=60, cache_name=None, max_age_days=1, binary=False):
    """GET a public URL; returns text (or bytes) or None on any failure. With
    cache_name the body is cached under CACHE_DIR (plus a .meta.json with the
    server's Last-Modified) and re-used if younger than max_age_days."""
    if cache_name:
        data = cache_read(cache_name, max_age_days)
        if data is not None:
            return data if binary else data.decode("utf-8", "replace")
    data, headers = http_get(url, timeout)
    if data is None:
        return None
    if cache_name:
        cache_write(cache_name, data, {"url": url, "fetched_at": now_iso(),
                                       "last_modified": (headers or {}).get("Last-Modified", "")})
    return data if binary else data.decode("utf-8", "replace")


def dataset_version(cache_name, default=None):
    """The source's own version marker: Last-Modified when the server sends one,
    else the given default (e.g. the data year), else the fetch date."""
    meta = cache_meta(cache_name)
    if meta.get("last_modified"):
        return meta["last_modified"]
    if default:
        return str(default)
    return f"fetched {meta.get('fetched_at', TODAY)[:10]}"


def report(source, prefix, rows, complete, version, note=""):
    return {"source": source, "prefix": prefix, "fetched_at": now_iso(), "rows": rows,
            "complete": bool(complete), "dataset_version": version, "note": note}


def row(name, sector, subsector, city="", parish="", domain="", website="", source="", as_of=None):
    return {"name": clean(name), "sector": sector, "subsector": subsector, "city": clean(city),
            "parish": clean_parish(parish), "domain": clean(domain).lower(),
            "website": clean(website), "source": source, "as_of": as_of or TODAY}


def clean(s):
    return re.sub(r"\s+", " ", (s or "").strip())


def clean_parish(p):
    p = clean(p)
    return re.sub(r"\s+parish$", "", p, flags=re.I)


def titlecase(s):
    """SDWIS/NPPES shout in upper case; make all-caps names readable. Short
    entity suffixes (LLC, LP) and roman numerals stay upper; initialisms
    such as 'OLOL' are not detected and will be title-cased."""
    s = clean(s)
    if s and s == s.upper():
        s = s.title()
        s = re.sub(r"\b(Of|And|The|De|La|Du|A)\b", lambda m: m.group(0).lower(), s)
        s = re.sub(r"\b(Llc|Lp|Pc|Apmc|Ii|Iii|Iv|Wws|Ws|Wd)\b", lambda m: m.group(0).upper(), s)
        s = s[0].upper() + s[1:]
    return s


def website_to_domain(url):
    u = clean(url).lower()
    if not u:
        return ""
    u = re.sub(r"^https?://", "", u)
    u = u.split("/")[0].split(":")[0]
    u = re.sub(r"^www\.", "", u)
    return u if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", u) else ""


# --- water: EPA SDWIS ------------------------------------------------------------------
def parse_sdwis(system_csv, geo_csv=None):
    """Active Louisiana public water systems. Community systems (CWS) are the
    utilities that matter for exposure; non-transient non-community (NTNCWS,
    e.g. schools/factories on their own well) are kept; transient (TNCWS:
    campgrounds, gas stations) are dropped."""
    parish_by_pws = {}
    if geo_csv:
        for g in csv.DictReader(io.StringIO(geo_csv)):
            if g.get("county_served"):
                parish_by_pws.setdefault(g["pwsid"], g["county_served"])
    rows = []
    for r in csv.DictReader(io.StringIO(system_csv)):
        if r.get("pws_activity_code") != "A" or r.get("pws_type_code") not in ("CWS", "NTNCWS"):
            continue
        sub = "community" if r["pws_type_code"] == "CWS" else "non_community"
        rows.append(row(titlecase(r["pws_name"]), "water", sub, titlecase(r.get("city_name", "")),
                        parish_by_pws.get(r["pwsid"], ""), source=SDWIS_URL))
    return rows


def fetch_water():
    text = fetch(SDWIS_URL, timeout=120, cache_name="sdwis_water_system_la.csv")
    if not text:
        return [], [report(SDWIS_URL, SDWIS_URL, 0, False, "", "unreachable")]
    geo = fetch(SDWIS_GEO_URL, timeout=120, cache_name="sdwis_geographic_area_la.csv")
    note = ""
    if not geo:
        note = "GEOGRAPHIC_AREA unreachable; parish column empty"
        log(f"  SDWIS: {note}")
    rows = parse_sdwis(text, geo)
    log(f"  SDWIS: {len(rows)} active CWS/NTNCWS systems")
    return rows, [report(SDWIS_URL, SDWIS_URL, len(rows), bool(rows) and bool(geo),
                         dataset_version("sdwis_water_system_la.csv"), note)]


# --- healthcare: CMS NPPES ---------------------------------------------------------------
def nppes_url(term, skip, postal=None):
    q = {"version": "2.1", "enumeration_type": "NPI-2", "state": "LA",
         "taxonomy_description": term, "limit": NPPES_PAGE, "skip": skip}
    if postal:
        q["postal_code"] = postal
    return NPPES_URL + "?" + urllib.parse.urlencode(q)


def nppes_slim(page):
    """Reduce an API page to the fields the roster needs. Raw pages carry
    authorized-official names and phone numbers; those never reach disk."""
    slim = []
    for r in page.get("results", []) or []:
        slim.append({"number": r.get("number"),
                     "basic": {"organization_name": (r.get("basic") or {}).get("organization_name")},
                     "addresses": [{"address_purpose": a.get("address_purpose"), "city": a.get("city"),
                                    "state": a.get("state"), "postal_code": a.get("postal_code")}
                                   for a in r.get("addresses", []) or []],
                     "taxonomies": [{"desc": t.get("desc"), "primary": t.get("primary")}
                                    for t in r.get("taxonomies", []) or []]})
    return {"result_count": page.get("result_count", len(slim)), "results": slim}


def parse_nppes_page(page, term, subsector):
    """One API page -> roster rows for organizations whose taxonomy list
    actually contains `term` (whole-word; the API search is fuzzy)."""
    rows = []
    if not isinstance(page, dict) or page.get("Errors"):
        return rows
    for r in page.get("results", []):
        descs = [t.get("desc") or "" for t in r.get("taxonomies", [])]
        if not any(kw_in(term.lower(), d.lower()) for d in descs):
            continue
        basic = r.get("basic", {})
        name = basic.get("organization_name") or ""
        if not re.search(r"[a-z]{2}", name.lower()):   # registry junk: "999999", "1 M"
            continue
        loc = next((a for a in r.get("addresses", []) if a.get("address_purpose") == "LOCATION"),
                   None) or (r.get("addresses") or [{}])[0]
        if (loc.get("state") or "LA") != "LA":
            continue
        rows.append(row(titlecase(name), "healthcare", subsector, titlecase(loc.get("city", "")),
                        source=NPPES_URL + f"?version=2.1&enumeration_type=NPI-2&state=LA&number={r.get('number', '')}"))
    return rows


def nppes_pages(term, subsector, postal, budget, fetch_fn, deadline=None):
    """Page one (term, postal) partition. Returns (rows, status) with status in
    complete | truncated (ceiling hit, more exist) | error | budget | deadline.
    Pages are cached (slimmed) for 7 days; API error payloads are never cached."""
    deadline = deadline or current_deadline()
    rows, skip = [], 0
    while skip <= NPPES_MAX_SKIP:
        if deadline.expired():
            log("  NPPES: deadline reached")
            return rows, "deadline"
        if budget[0] <= 0:
            log("  NPPES request budget exhausted")
            return rows, "budget"
        key = "nppes_" + re.sub(r"[^a-z0-9]+", "_", f"{term}_{postal or 'all'}_{skip}".lower()) + ".json"
        cached = cache_read(key, 7)
        if cached is not None:
            page = json.loads(cached)
        else:
            budget[0] -= 1
            text = fetch_fn(nppes_url(term, skip, postal), timeout=30)
            if not text:
                return rows, "error"
            try:
                page = json.loads(text)
            except ValueError:
                return rows, "error"
            if not isinstance(page, dict) or page.get("Errors"):
                errs = page.get("Errors") if isinstance(page, dict) else page
                log(f"  NPPES '{term}' {postal or ''}: API error {json.dumps(errs)[:160]}")
                return rows, "error"
            page = nppes_slim(page)
            cache_write(key, json.dumps(page).encode())
            time.sleep(0.3)
        got = len(page.get("results", []) or [])
        rows.extend(parse_nppes_page(page, term, subsector))
        if got < NPPES_PAGE:
            return rows, "complete"
        skip += NPPES_PAGE
    return rows, "truncated"  # page at the ceiling was full -> more exist


def fetch_healthcare(max_requests=400, fetch_fn=fetch, deadline=None):
    deadline = deadline or current_deadline()
    budget = [max_requests]
    best = {}  # (name, city) -> row, keeping the highest-ranked subsector
    incomplete = []

    def keep(rows):
        for r in rows:
            k = (r["name"].lower(), r["city"].lower())
            if k not in best or SUBSECTOR_RANK[r["subsector"]] < SUBSECTOR_RANK[best[k]["subsector"]]:
                best[k] = r

    for term, subsector in NPPES_TAXONOMIES:
        if deadline.expired() or budget[0] <= 0:
            incomplete.append(f"{term}: not attempted")
            continue
        rows, status = nppes_pages(term, subsector, None, budget, fetch_fn, deadline)
        keep(rows)   # statewide rows are kept even if the ZIP fallback fails
        if status == "truncated":
            log(f"  NPPES '{term}': over the {NPPES_MAX_SKIP}-record ceiling; partitioning by ZIP prefix")
            for zp in LA_ZIP_PREFIXES:
                part, st = nppes_pages(term, subsector, zp, budget, fetch_fn, deadline)
                keep(part)
                rows.extend(part)
                if st != "complete":
                    incomplete.append(f"{term} {zp}: {st}")
                    log(f"  NPPES '{term}' {zp}: {st} (partial)")
                    if st in ("budget", "deadline"):
                        break
        elif status != "complete":
            incomplete.append(f"{term}: {status}")
        log(f"  NPPES '{term}': {len(rows)} orgs, {status} (requests left {budget[0]})")
    rows = list(best.values())
    note = "; ".join(incomplete)[:500]
    return rows, [report(NPPES_URL, NPPES_URL, len(rows), not incomplete,
                         f"live registry {TODAY}", note)]


# --- education: NCES CCD + IPEDS via Urban Institute API, LA_EDU_DOMAINS ---------------
def fetch_pages(url, cache_name, fetch_fn=fetch, max_pages=MAX_API_PAGES, max_age_days=30):
    """Follow the Urban API's `next` links. Returns (results, complete). Only a
    complete result set is cached."""
    cached = cache_read(cache_name, max_age_days)
    if cached is not None:
        try:
            return json.loads(cached).get("results", []), True
        except ValueError:
            pass
    results, nxt, pages = [], url, 0
    while nxt and pages < max_pages:
        text = fetch_fn(nxt, timeout=120)
        if not text:
            return results, False
        try:
            obj = json.loads(text)
        except ValueError:
            return results, False
        results.extend(obj.get("results", []) or [])
        nxt = obj.get("next")
        pages += 1
    complete = not nxt
    if complete and results:
        cache_write(cache_name, json.dumps({"results": results}).encode())
    elif nxt:
        log(f"  {url}: stopped after {pages} pages (max {max_pages}); partial")
    return results, complete


def parse_ccd(obj, url):
    """K-12: one row per school and one per district (LEA). Closed schools
    (school_status 2) are skipped."""
    rows, leas = [], {}
    for s in (obj or {}).get("results", []):
        if s.get("school_status") in (2, "2"):
            continue
        parish = PARISH_BY_FIPS.get(str(s.get("county_code") or ""), "")
        rows.append(row(s.get("school_name", ""), "education", "k12_school",
                        s.get("city_location") or s.get("city_mailing", ""), parish, source=url))
        lea = s.get("leaid")
        if lea and lea not in leas:
            leas[lea] = row(s.get("lea_name", ""), "education", "k12_district",
                            s.get("city_location") or s.get("city_mailing", ""), parish, source=url)
    return list(leas.values()) + rows


def parse_ipeds(obj, url):
    rows = []
    for s in (obj or {}).get("results", []):
        if str(s.get("currently_active_ipeds", "1")) == "0":
            continue
        website = clean(s.get("url_school", ""))
        rows.append(row(s.get("inst_name", ""), "education", "higher_ed", s.get("city", ""),
                        s.get("county_name", ""), website_to_domain(website),
                        ("https://" + website) if website and not website.startswith("http") else website,
                        source=url))
    return rows


def _fetch_urban(label, url_tmpl, years, cache_tmpl, parser, fetch_fn):
    for year in years:
        if current_deadline().expired():
            break
        url = url_tmpl.format(year=year)
        results, complete = fetch_pages(url, cache_tmpl.format(year=year), fetch_fn)
        if results:
            rows = parser({"results": results}, url)
            log(f"  {label} {year}: {len(rows)} rows{'' if complete else ' (partial)'}")
            return rows, report(url, URBAN_PREFIX + url_tmpl.split("/v1/")[1].split("/{")[0],
                                len(rows), complete, str(year))
    log(f"  {label}: no year reachable")
    return [], report(url_tmpl, URBAN_PREFIX + url_tmpl.split("/v1/")[1].split("/{")[0], 0, False, "",
                      "unreachable")


def fetch_education(fetch_fn=fetch):
    rows, reports = [], []
    got, rep = _fetch_urban("NCES CCD", CCD_URL, CCD_YEARS, "ccd_directory_{year}.json", parse_ccd, fetch_fn)
    rows += got
    reports.append(rep)
    got, rep = _fetch_urban("NCES IPEDS", IPEDS_URL, IPEDS_YEARS, "ipeds_directory_{year}.json", parse_ipeds, fetch_fn)
    rows += got
    reports.append(rep)
    # LA_EDU_DOMAINS is the curated higher-ed domain list already trusted by triage.
    known = {r["domain"] for r in rows if r["domain"]}
    src = "triage_report.LA_EDU_DOMAINS"
    extra = [row(d, "education", "higher_ed_domain", domain=d, source=src)
             for d in sorted(LA_EDU_DOMAINS) if d not in known]
    rows += extra
    reports.append(report(src, src, len(extra), True, "triage_report.py"))
    return rows, reports


# --- energy: EIA-860 + BSEE --------------------------------------------------------------
def read_xlsx_rows(data):
    """Minimal .xlsx reader (first worksheet) using only the stdlib; returns a
    list of lists of strings. Enough for EIA-860's flat sheets."""
    ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    x = zipfile.ZipFile(io.BytesIO(data))
    shared = []
    if "xl/sharedStrings.xml" in x.namelist():
        shared = ["".join(t.text or "" for t in si.iter(ns + "t"))
                  for si in ET.fromstring(x.read("xl/sharedStrings.xml"))]
    sheet = ET.fromstring(x.read("xl/worksheets/sheet1.xml"))
    rows = []
    for r in sheet.iter(ns + "row"):
        vals = {}
        for c in r.iter(ns + "c"):
            v = c.find(ns + "v")
            if v is None:
                continue
            val = v.text or ""
            if c.get("t") == "s":
                val = shared[int(val)]
            col, n = re.match(r"[A-Z]+", c.get("r", "A")).group(0), 0
            for ch in col:
                n = n * 26 + ord(ch) - 64
            vals[n - 1] = val
        if vals:
            rows.append([vals.get(i, "") for i in range(max(vals) + 1)])
    return rows


def parse_eia_sheet(rows, kind, url):
    """rows from read_xlsx_rows; header row is the one containing 'State'."""
    hdr_i = next((i for i, r in enumerate(rows) if "State" in r and "Utility Name" in r), None)
    if hdr_i is None:
        return []
    hdr = rows[hdr_i]
    col = {h: i for i, h in enumerate(hdr)}
    out = []
    for r in rows[hdr_i + 1:]:
        if len(r) <= col["State"] or r[col["State"]] != "LA":
            continue
        if kind == "utility":
            out.append(row(r[col["Utility Name"]], "energy", "electric_utility", r[col["City"]], source=url))
        else:
            out.append(row(r[col["Plant Name"]], "energy", "power_plant", r[col["City"]],
                           r[col["County"]] if "County" in col else "", source=url))
    return out


def fetch_eia860():
    for year in EIA_YEARS:
        if current_deadline().expired():
            break
        url = EIA860_URL.format(year=year)
        data = fetch(url, timeout=300, cache_name=f"eia860{year}.zip", max_age_days=90, binary=True)
        if not data:
            continue
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            names = z.namelist()
            util = next(n for n in names if n.startswith("1___Utility"))
            plant = next(n for n in names if n.startswith("2___Plant"))
            rows = parse_eia_sheet(read_xlsx_rows(z.read(util)), "utility", url)
            rows += parse_eia_sheet(read_xlsx_rows(z.read(plant)), "plant", url)
        except Exception as e:
            log(f"  EIA-860 {year}: parse failed ({e})")
            continue
        log(f"  EIA-860 {year}: {len(rows)} LA utilities+plants")
        return rows, report(url, EIA860_PREFIX, len(rows), bool(rows), f"EIA-860 {year}")
    log("  EIA-860: unreachable")
    return [], report(EIA860_URL, EIA860_PREFIX, 0, False, "", "unreachable")


def parse_bsee_companies(text):
    """BSEE 'compalldelimit.txt': quoted comma-delimited, 19 fields, no header.
    Observed layout: 0 company number, 1 start date, 2 name, 3 sort name,
    4 termination date, 13-18 address1, address2, city, state, zip, country.
    Keep LA-addressed companies with no termination date."""
    out, seen = [], set()
    for r in csv.reader(io.StringIO(text)):
        if len(r) < 19 or r[16] != "LA" or r[4]:
            continue
        k = (r[2].lower(), r[15].lower())
        if k in seen:
            continue
        seen.add(k)
        out.append(row(r[2], "energy", "offshore_operator", r[15], source=BSEE_URL))
    return out


def fetch_bsee():
    data = fetch(BSEE_URL, timeout=120, cache_name="bsee_compalldelimit.zip", max_age_days=30, binary=True)
    if not data:
        return [], report(BSEE_URL, BSEE_URL, 0, False, "", "unreachable")
    try:
        text = zipfile.ZipFile(io.BytesIO(data)).read("compalldelimit.txt").decode("latin-1")
    except Exception as e:
        log(f"  BSEE: bad archive ({e})")
        return [], report(BSEE_URL, BSEE_URL, 0, False, "", f"bad archive: {e}")
    rows = parse_bsee_companies(text)
    log(f"  BSEE: {len(rows)} active LA-addressed offshore companies")
    return rows, report(BSEE_URL, BSEE_URL, len(rows), bool(rows), dataset_version("bsee_compalldelimit.zip"))


def fetch_energy():
    rows, reports = [], []
    got, rep = fetch_eia860()
    rows += got
    reports.append(rep)
    got, rep = fetch_bsee()
    rows += got
    reports.append(rep)
    log("  LDNR SONRIS operator list: interactive APEX app, no public export -> manual drop-in")
    return rows, reports


# --- government: parishes + Census Gazetteer municipalities ------------------------------
def parse_gazetteer(text, url):
    """Census place gazetteer (tab-delimited). LSAD 25=city, 43=town, 47=village;
    FUNCSTAT A = active government. CDPs (57) are not governments and are dropped."""
    kinds = {"25": "city", "43": "town", "47": "village"}
    out = []
    for r in csv.DictReader(io.StringIO(text), delimiter="\t"):
        r = {k.strip(): (v or "").strip() for k, v in r.items() if k}
        if r.get("USPS") != "LA" or r.get("FUNCSTAT") != "A" or r.get("LSAD") not in kinds:
            continue
        kind = kinds[r["LSAD"]]
        base = re.sub(r"\s+(city|town|village)$", "", r["NAME"], flags=re.I)
        name = f"{kind.title()} of {base}"
        if base == "Baton Rouge":
            name = "City of Baton Rouge / Parish of East Baton Rouge"
        out.append(row(name, "government", f"municipal_{kind}", base, source=url))
    return out


def parish_rows(source):
    return [row(f"{p} Parish Government", "government", "parish", seat, p, source=source)
            for p, seat in PARISHES]


def fetch_government():
    src = CENSUS_COUNTIES_URL
    text = fetch(src, timeout=60, cache_name="census_la_counties.txt", max_age_days=90)
    note = ""
    if text:
        census = {re.sub(r"\s+Parish$", "", r["COUNTYNAME"]) for r in csv.DictReader(io.StringIO(text), delimiter="|")}
        ours = {p for p, _ in PARISHES}
        if census != ours:
            note = f"parish list mismatch vs Census: missing={sorted(census - ours)} extra={sorted(ours - census)}"
            log(f"  {note}")
    else:
        src = "hard-coded (Census county file unreachable)"
    rows = parish_rows(src)
    reports = [report(src, src, len(rows), not note, "Census 2020 county codes", note)]
    log(f"  parishes: {len(rows)}")
    for year in GAZETTEER_YEARS:
        if current_deadline().expired():
            break
        url = GAZETTEER_URL.format(year=year)
        text = fetch(url, timeout=60, cache_name=f"gazetteer_place_{year}.txt", max_age_days=90)
        if text:
            got = parse_gazetteer(text, url)
            if got:
                log(f"  Census gazetteer {year}: {len(got)} municipalities")
                rows += got
                reports.append(report(url, GAZETTEER_PREFIX, len(got), True, f"Gazetteer {year}"))
                break
    else:
        log("  Census gazetteer: unreachable (Louisiana Municipal Association has no public export)")
        reports.append(report(GAZETTEER_URL, GAZETTEER_PREFIX, 0, False, "", "unreachable"))
    return rows, reports


# --- read / write ----------------------------------------------------------------------------
def read_roster(sector, roster_dir=ROSTER_DIR):
    path = os.path.join(roster_dir, f"{sector}.csv")
    try:
        with open(path, newline="") as f:
            return [r for r in csv.DictReader(f) if (r.get("name") or "").strip()]
    except (OSError, csv.Error):
        return []


def load_manual(sector):
    """Optional analyst drop-in reference/rosters/manual/<sector>.csv (same columns)."""
    path = os.path.join(MANUAL_DIR, f"{sector}.csv")
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if not (r.get("name") or "").strip():
                continue
            out.append(row(r.get("name"), sector, r.get("subsector") or "manual", r.get("city"),
                           r.get("parish"), r.get("domain"), r.get("website"),
                           r.get("source") or f"manual:{os.path.basename(path)}", r.get("as_of") or TODAY))
    return out


def dedupe(rows):
    seen, out = set(), []
    for r in rows:
        k = (r["name"].lower(), r["subsector"], r["city"].lower())
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def write_roster(sector, rows, dry_run=False, roster_dir=ROSTER_DIR):
    """Sort, dedupe (first occurrence wins, so pass fresh rows before carried-over
    ones) and write atomically (temp file + rename)."""
    rows = dedupe(sorted(rows, key=lambda r: (r["subsector"], r["name"].lower(), r["city"].lower())))
    path = os.path.join(roster_dir, f"{sector}.csv")
    if dry_run:
        log(f"  [dry-run] would write {len(rows)} rows to {path}")
        return rows
    os.makedirs(roster_dir, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in COLUMNS})
    os.replace(tmp, path)
    log(f"  wrote {len(rows)} rows -> {path}")
    return rows


def load_manifest(path=None):
    path = path or MANIFEST
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def write_manifest(entries, dry_run=False, path=None):
    """Merge this run's sector entries into the manifest and write it atomically."""
    path = path or MANIFEST
    if dry_run:
        return
    manifest = load_manifest(path)
    manifest.update(entries)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def carry_over(prev, reports):
    """Previous rows belonging to sources that failed or came back partial this
    run. They keep their old as_of so the evidence date stays honest."""
    kept = []
    for rep in reports:
        if rep["complete"]:
            continue
        old = [r for r in prev if (r.get("source") or "").startswith(rep["prefix"])]
        if old:
            log(f"  {rep['source']}: {rep['note'] or 'incomplete'} ({rep['rows']} rows fetched); "
                f"carrying over {len(old)} previous rows (as_of {min(r['as_of'] for r in old)})")
            kept += old
    return kept


FETCHERS = {"water": fetch_water, "healthcare": fetch_healthcare, "education": fetch_education,
            "energy": fetch_energy, "government": fetch_government}


def run_sector(sector, dry_run=False, max_requests=400, job=None, roster_dir=ROSTER_DIR):
    """Fetch one sector, protect previous data, write CSV; returns (rows, manifest entry)."""
    job = job or Deadline()
    set_deadline(job.child(SECTOR_BUDGET_S.get(sector, 300)))
    prev = read_roster(sector, roster_dir)
    try:
        if sector == "healthcare":
            rows, reports = fetch_healthcare(max_requests)
        else:
            rows, reports = FETCHERS[sector]()
    except Exception as e:
        log(f"  {sector} fetch crashed: {e}")
        rows, reports = [], [report(sector, "", 0, False, "", f"crashed: {e}")]
    finally:
        set_deadline(job)
    entry = {"written_at": now_iso(), "sources": reports,
             "complete": bool(reports) and all(r["complete"] for r in reports)}
    if not rows and prev:
        as_of = max(r.get("as_of") or "" for r in prev)
        log(f"  {sector}: nothing fetched; kept previous, {len(prev)} rows, as_of {as_of}")
        entry.update({"rows": len(prev), "kept_previous": True, "complete": False})
        return prev, entry
    manual = load_manual(sector)
    if manual:
        log(f"  manual drop-in: {len(manual)} rows")
    final = write_roster(sector, rows + carry_over(prev, reports) + manual, dry_run, roster_dir)
    entry.update({"rows": len(final), "kept_previous": False})
    return final, entry


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sector", action="append", choices=SECTORS, help="limit to sector(s); default all")
    ap.add_argument("--dry-run", action="store_true", help="fetch and parse but write nothing")
    ap.add_argument("--max-requests", type=int, default=400, help="NPPES request budget (default 400)")
    ap.add_argument("--max-minutes", type=float, default=DEFAULT_MAX_MINUTES,
                    help=f"whole-job deadline in minutes (default {DEFAULT_MAX_MINUTES})")
    args = ap.parse_args(argv)
    sectors = args.sector or SECTORS
    job = Deadline(args.max_minutes * 60)
    summary, entries = {}, {}
    for sector in sectors:
        if job.expired():
            log(f"[{sector}] skipped: job deadline ({args.max_minutes} min) reached")
            continue
        log(f"[{sector}] (budget {min(SECTOR_BUDGET_S.get(sector, 300), int(job.remaining()))}s)")
        final, entry = run_sector(sector, args.dry_run, args.max_requests, job)
        entries[sector] = entry
        by_sub = {}
        for r in final:
            by_sub[r["subsector"]] = by_sub.get(r["subsector"], 0) + 1
        summary[sector] = (len(final), by_sub, entry)
    write_manifest(entries, args.dry_run)
    log("\nSummary:")
    for sector, (n, by_sub, entry) in summary.items():
        subs = ", ".join(f"{k}={v}" for k, v in sorted(by_sub.items()))
        flag = "complete" if entry["complete"] else ("kept previous" if entry.get("kept_previous") else "PARTIAL")
        log(f"  {sector:<11} {n:>6}  [{flag}]  {subs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
