#!/usr/bin/env python3
"""
triage_report.py — turn a daily Shodan archive into a sector-tiered triage brief.

Buckets EVERY unique host into a consequence-ordered tier (critical infrastructure
> government > education > small business > residential > unclassified), enriches
its CVEs with CISA KEV (known-exploited) and FIRST EPSS (exploit probability), and
ranks hosts by an actionability score. Nothing is dropped — every host is
accounted for in exactly one tier.

PASSIVE ONLY. This reads archived Shodan banners; it does not contact any host.
Findings are LEADS TO VERIFY, not confirmed vulnerabilities (Shodan maps software
versions to every CVE they *could* have — see README lesson on version inference).

Usage:
    triage_report.py daily_downloads/<file>.json.gz [--out reports/triage-<date>.md]
"""
import argparse
import gzip
import json
import os
import re
import sys
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Signals -----------------------------------------------------------------
ICS_PORTS = {502: "Modbus", 20000: "DNP3", 47808: "BACnet", 102: "S7comm",
             44818: "EtherNet/IP", 1911: "Niagara/Tridium", 2404: "IEC-104",
             789: "Red Lion", 1962: "PCWorx", 9600: "OMRON-FINS", 20547: "ProconOS"}
ADMIN_PORTS = {23: "telnet", 3389: "RDP", 5900: "VNC", 21: "FTP", 512: "rexec",
               513: "rlogin", 514: "rsh"}
DB_PORTS = {3306: "MySQL", 5432: "Postgres", 27017: "MongoDB", 6379: "Redis",
            9200: "Elasticsearch", 1433: "MSSQL", 11211: "memcached",
            5984: "CouchDB", 9042: "Cassandra"}

# A host answering on more ports than this is a honeypot, a scanner, or a
# misconfigured NAT — never a real single device. Same guard as the report's
# old honeypot filter, now applied at classification time so the store agrees.
HONEYPOT_PORT_THRESHOLD = 100

CRIT_KW = ["water", "sewer", "sewage", "wastewater", "electric", "power", "energy",
           "utility", "utilities", "co-op", "coop", "pipeline", "port of", "airport",
           "transit", "levee", "hospital", "hospitals", "health", "medical", "clinic",
           "clinics", "healthcare", "emergency", "dispatch", "scada", "treatment",
           "substation", "natural gas", "waterworks", "sewerage", "ambulance", "911",
           "refinery", "refining", "petrochemical", "offshore", "drilling", "lng",
           "oil", "gas"]
# A bare "parish" is NOT here ("Parish Brewing Company"): the parish must be
# paired with a civic noun, either by these phrases or by the PARISHES rule.
GOV_KW = ["police jury", "parish government", "parish council", "parish president",
          "parish of", "parish sheriff", "parish library", "parish assessor",
          "parish clerk", "parish jail", "parish court", "parish coroner",
          "parish fire", "parish water", "parish sewerage", "parish utilities",
          "city of", "town of", "village of", "municipal", "sheriff", "police",
          "court", "clerk of", "assessor", "registrar", "department of", "dept of",
          "governor", "legislature", "council", "district attorney", "coroner",
          "detention", "fire dept", "fire district", "state of louisiana", "office of",
          "secretary of state", "dmv", "dotd", "dhh", "levee district",
          "public library", "housing authority"]
EDU_STRONG_KW = ["school board", "board of education", "university", "college",
                 "community college", "school district"]
EDU_KW = ["school", "schools", "academy", "campus", "lsu", "tulane", "loyola", "xavier",
          "southern university", "louisiana tech", "mcneese", "nicholls", "k-12", "isd"]
# Civic nouns that must accompany a PARISH name for it to count as government.
# "Cameron Communications" and "LIGO Livingston Observatory" contain parish
# names; "Cameron Parish Police Jury" and "Livingston Parish Sheriff" are the
# government. A bare parish name is not evidence.
PARISH_CIVIC_KW = ["parish", "police jury", "pj", "government", "school board",
                   "sheriff", "assessor", "clerk", "council", "court", "courthouse",
                   "library", "911", "water", "sewerage", "fire", "jail", "detention",
                   "coroner", "registrar", "district"]
# Major consumer-broadband providers (the residential haystack)
RESI_ORG_KW = ["cox", "charter", "spectrum", "comcast", "at&t", "att internet",
               "verizon", "centurylink", "lumen", "sparklight", "cable one",
               "optimum", "suddenlink", "altice", "t-mobile", "rev", "eatel",
               "lus fiber", "volt broadband", "uniti", "catcomm", "vexus", "allo",
               # Rural Louisiana ISPs whose NAMES contain a parish name and whose
               # subscribers used to land in the government tier because of it.
               "cameron communications", "cameron telephone", "camtel",
               "allens communications", "atvci", "parish broadband",
               "acadiana wireless", "pavlov media", "conterra", "skyrider",
               "reserve telecommunications", "reserve telephone", "kaplan telephone",
               "star telephone", "delcambre telephone", "east ascension telephone",
               "hunt telecom", "vision communications", "cma communications"]
# Hostname shapes ISPs assign to subscribers. Substring on the HOSTNAME only
# (never the domain). Deliberately narrow: "fiber" and "wireless" are ordinary
# words in business names, so they are not here.
RESI_HOST_RE = ("dhcp", "dyn", "cpe.", "cpe-", "res.", "client.", "clients.", "pool",
                "broadband", "biz.rr", ".rr.com", "hsd1", "static.", "customer", "adsl",
                "dsl", "ftth", "-ip-", "ip-", "host-", "wsip-", "subs")
# Transit / CDN / cloud / hosting providers. Like the consumer ISPs above, the
# `org` field here names the NETWORK OPERATOR, not the end customer — so its text
# must NOT drive gov/edu/critical keyword matching (that mis-tiered customers,
# e.g. an "AT&T Enterprises" host landing in 'education'). Kept deliberately
# specific/multi-word to avoid substring false positives on real business names.
TRANSIT_HOST_KW = ["level 3", "level3", "cogent", "hurricane electric", "he.net",
                   "zayo", "gtt communications", "tata communications",
                   "ntt america", "windstream", "frontier communications",
                   "consolidated communications", "amazon", "aws", "google llc",
                   "google cloud", "microsoft corporation", "azure", "cloudflare",
                   "akamai", "fastly", "digitalocean", "linode", "ovh", "hetzner",
                   "vultr", "hostgator", "bluehost", "godaddy", "unified layer",
                   "namecheap", "leaseweb", "immense networks", "psychz", "quadranet",
                   "psinet", "verizon business", "at&t enterprises", "venyu"]
# Any org name that describes a bulk network rather than a specific customer.
BULK_NETWORK_KW = RESI_ORG_KW + TRANSIT_HOST_KW
PARISHES = ["acadia", "allen", "ascension", "assumption", "avoyelles", "beauregard",
            "bienville", "bossier", "caddo", "calcasieu", "caldwell", "cameron",
            "catahoula", "claiborne", "concordia", "desoto", "de soto", "east baton rouge",
            "east carroll", "east feliciana", "evangeline", "franklin", "grant",
            "iberia", "iberville", "jackson", "jefferson", "jefferson davis", "lafayette",
            "lafourche", "lasalle", "la salle", "lincoln", "livingston", "madison",
            "morehouse", "natchitoches", "orleans", "ouachita", "plaquemines",
            "pointe coupee", "rapides", "red river", "richland", "sabine", "st bernard",
            "st. bernard", "st charles", "st. charles", "st helena", "st. helena",
            "st james", "st. james", "st john", "st. john", "st landry", "st. landry",
            "st martin", "st. martin", "st mary", "st. mary", "st tammany", "st. tammany",
            "tangipahoa", "tensas", "terrebonne", "union", "vermilion", "vernon",
            "washington", "webster", "west baton rouge", "west carroll",
            "west feliciana", "winn"]
# Registered domains carriers use for subscriber rDNS. A hostname under one of
# these is the carrier's name for the line, not the customer's identity. Any
# OTHER domain beside subscriber-shaped rDNS is customer identity.
CARRIER_DOMAINS = {"cox.net", "eatel.net", "camtel.net", "atvci.net", "suddenlink.net",
                   "myvzw.com", "pavlovmedia.net", "lusfiber.net", "rr.com", "charter.com",
                   "spectrum.com", "comcast.net", "att.net", "sbcglobal.net", "bellsouth.net",
                   "centurylink.net", "qwest.net", "lumen.com", "sparklight.net", "cableone.net",
                   "optonline.net", "t-mobile.com", "tmodns.net", "xfinity.com", "verizon.net",
                   "windstream.net", "frontiernet.net", "vexus.net", "allo.net", "conterra.com",
                   "skyrider.net", "reservetele.com", "kaplantel.net", "uniti.com"}
# Louisiana higher-education domains. Only these (plus k12.la.us) count as
# Louisiana authority at the jurisdiction gate; any other .edu still tiers as
# education but cannot override an out-of-state government name on the same IP.
LA_EDU_DOMAINS = {"lsu.edu", "lsuhsc.edu", "lsus.edu", "lsua.edu", "lsue.edu", "pbrc.edu",
                  "tulane.edu", "loyno.edu", "latech.edu", "ulm.edu", "louisiana.edu",
                  "subr.edu", "sus.edu", "nsula.edu", "mcneese.edu", "nicholls.edu",
                  "selu.edu", "uno.edu", "xula.edu", "dillard.edu", "centenary.edu",
                  "gram.edu", "bpcc.edu", "dcc.edu", "delgado.edu", "lctcs.edu", "rpcc.edu",
                  "sowela.edu", "fletcher.edu", "nunez.edu", "cltcc.edu", "nltcc.edu",
                  "scl.edu", "lcu.edu", "franu.edu", "loni.org", "regents.la.gov"}
# Louisiana government domains that do not sit under la.gov / la.us.
LA_GOV_DOMAINS = {"louisiana.gov", "nola.gov", "brla.gov", "lafayettela.gov",
                  "stpgov.org", "calcasieuparish.gov", "jeffparish.gov", "jeffparish.net",
                  "ebrso.org", "jpso.com", "opcso.org", "lsp.org"}
# An org that NAMES another state's government is out of scope even when the
# banner carries no .gov domain ("Commonwealth of PA - OA / Integrated Network
# Management Services" had 130 such hosts).
OUT_OF_STATE_ORG_KW = ["commonwealth of pa", "commonwealth of pennsylvania", "commonwealth of virginia",
                       "commonwealth of kentucky", "commonwealth of massachusetts",
                       "state of texas", "state of mississippi", "state of arkansas", "state of alabama",
                       "state of florida", "state of georgia", "state of tennessee", "state of oklahoma",
                       "state of new york", "state of california", "state of ohio", "state of michigan",
                       "state of illinois", "state of missouri", "state of north carolina",
                       "state of south carolina", "state of colorado", "state of arizona",
                       "state of washington", "state of oregon", "state of nevada", "state of utah",
                       "state of new jersey", "state of maryland", "state of indiana", "state of wisconsin",
                       "state of minnesota", "state of iowa", "state of kansas", "state of nebraska",
                       "texas department of", "mississippi department of", "arkansas department of",
                       "florida department of", "georgia department of", "alabama department of"]
US_STATE_CODES = {"al", "ak", "az", "ar", "ca", "co", "ct", "de", "fl", "ga", "hi", "id",
                  "il", "in", "ia", "ks", "ky", "me", "md", "ma", "mi", "mn", "ms", "mo",
                  "mt", "ne", "nv", "nh", "nj", "nm", "ny", "nc", "nd", "oh", "ok", "or",
                  "pa", "ri", "sc", "sd", "tn", "tx", "ut", "vt", "va", "wa", "wv", "wi",
                  "wy", "dc", "pr"}

TIERS = ["critical_infrastructure", "government", "education",
         "small_business", "residential", "unclassified",
         "out_of_state_gov", "honeypot"]

def load_json(path, default):
    try:
        return json.load(open(path))
    except Exception:
        return default


_KW_RE = {}


def _kw_pattern(kw):
    """Whole-word pattern; a space in a phrase matches any run of separators,
    so 'city of' also matches 'city-of-x' and 'city_of'."""
    parts = [re.escape(p) for p in kw.split(" ")]
    return r"(?<![a-z0-9])" + r"[\s\-_.]+".join(parts) + r"(?![a-z0-9])"


def kw_in(kw, text):
    """Whole-word keyword match: 'lsu' must not match inside 'dslsubs', 'isd'
    must not match inside 'morrisdickson', 'allen' must not match 'allentown'.
    Word = run of letters/digits; punctuation and dots are boundaries, so
    'lsu.edu' and 'city-of-x' still match."""
    rx = _KW_RE.get(kw)
    if rx is None:
        rx = _KW_RE[kw] = re.compile(_kw_pattern(kw))
    return rx.search(text) is not None


def first_kw(kws, text):
    for kw in kws:
        if kw_in(kw, text):
            return kw
    return None


# Sector words that organisations glue onto their own names in hostnames and
# domains ("lcmchealth.org", "ochsnerhealth", "franklinmedical.com",
# "cleco-power"): for these, a match may be the TAIL of a longer token. The
# word must still END there — "hospitality" is not "hospital". Compounds that
# end in a sector word but mean something else are removed first.
COMPOUND_OK_KW = {"health", "hospital", "medical", "clinic", "healthcare", "electric",
                  "energy", "pipeline", "refinery", "refining", "ambulance", "utility",
                  "utilities", "petrochemical", "wastewater", "sewerage"}
COMPOUND_STOPLIST = ("synergy", "empower", "manpower", "horsepower", "willpower",
                     "hospitality", "biomedical", "healthy", "clinical")
_TAIL_RE = {}


def first_sector_kw(kws, text):
    """CRIT_KW matcher: whole-word for every keyword, plus tail-of-compound for
    the sector words above. Known false compounds are blanked with a letter
    (not a space) so the blanking can never manufacture a word boundary:
    'energysynergy' -> 'energyx', which still does not match 'energy'."""
    kw = first_kw(kws, text)
    if kw:
        return kw
    stripped = text
    for stop in COMPOUND_STOPLIST:
        stripped = stripped.replace(stop, "x")
    for kw in kws:
        if kw not in COMPOUND_OK_KW:
            continue
        rx = _TAIL_RE.get(kw)
        if rx is None:
            rx = _TAIL_RE[kw] = re.compile(re.escape(kw) + r"(?![a-z0-9])")
        if rx.search(stripped):
            return kw
    return None


def near_civic(par, text):
    """A parish name counts only with a civic noun at most one word after it
    ('Jefferson Parish', 'Jefferson Davis Parish', 'Livingston Sheriff') or in
    the phrase 'parish of <name>'. Callers pass ONE field at a time, so
    'Jefferson Design' (org) next to 'library.example.net' (hostname) cannot
    pair up across fields."""
    civic = "|".join(r"[\s\-_.]+".join(re.escape(w) for w in c.split(" ")) for c in PARISH_CIVIC_KW)
    p = r"[\s\-_.]+".join(re.escape(w) for w in par.split(" "))
    rx = re.compile(r"(?<![a-z0-9])" + p + r"(?:[\s\-_.]+[a-z0-9&]+){0,1}[\s\-_.]+(" + civic + r")(?![a-z0-9])"
                    r"|(?<![a-z0-9])parish[\s\-_.]+of[\s\-_.]+" + p + r"(?![a-z0-9])")
    m = rx.search(text)
    return (m.group(1) or "parish of") if m else None


def _is_or_under(d, root):
    return d == root or d.endswith("." + root)


def is_k12_la(d):
    return _is_or_under(d.lower().rstrip("."), "k12.la.us")


def gov_domain_kind(domain):
    """'la' for a Louisiana government domain, 'other_state' for another US
    state's public-sector namespace, 'gov' for an unclassified .gov (federal or
    an unlisted locality), None for anything else. Accepts a registered domain
    OR a full hostname (suffix match), with a trailing root dot tolerated."""
    d = domain.lower().rstrip(".")
    if is_k12_la(d):
        return None                              # K-12 is education, handled first
    if _is_or_under(d, "la.gov") or _is_or_under(d, "state.la.us"):
        return "la"
    if any(_is_or_under(d, root) for root in LA_GOV_DOMAINS):
        return "la"
    if _is_or_under(d, "la.us"):
        return "la"          # ci./co./parish./lib. localities under the state's .us
    parts = d.split(".")
    if len(parts) >= 2 and parts[-1] == "gov" and parts[-2] in US_STATE_CODES and parts[-2] != "la":
        return "other_state"                      # pa.gov, agency.pa.gov, ...
    if len(parts) >= 3 and parts[-1] == "us" and parts[-2] in US_STATE_CODES and parts[-2] != "la":
        return "other_state"                      # state.tx.us, k12.tx.us, ci.x.ms.us
    if parts[-1] == "gov":
        return "gov"
    return None


def classify(host):
    """Consequence-ordered cascade. Returns (tier, reason).

    Evidence strength, strongest first: (0) honeypot signals disqualify a host
    from every tier; (1) an ICS protocol answering is critical infrastructure;
    (2) critical-sector keywords; (3) AUTHORITATIVE DOMAINS — Louisiana .gov /
    .la.us -> government, .edu / .k12.la.us -> education, another state's .gov
    -> out_of_state_gov; (4) strong government words (sheriff, police jury, city
    of ...); (5) strong education words (university, school board ...); (6) a
    PARISH NAME, but only next to a civic noun; (7) residential / business.

    Attribution rule: the customer's OWN identity (hostnames + domains) is the
    trusted signal. The `org` field is trusted for keyword matching only when it
    is NOT a bulk network operator (consumer ISP / transit / cloud / hosting),
    because those name the carrier, not the end customer. All keyword matching
    is whole-word."""
    org_text = (host.get("org") or "").lower()
    hostnames = [h.lower().rstrip(".") for h in (host.get("hostnames") or [])]
    domains = [d.lower().rstrip(".") for d in (host.get("domains") or [])]
    ports = host.get("ports") or set()
    tags = {t.lower() for t in (host.get("tags") or [])}
    names = hostnames + domains          # authority is checked on both

    # Carrier rDNS ("cpe-health.cox.net") is the carrier's label for the line,
    # not the customer's identity: it must not feed sector or civic keywords.
    carrier_names = [h for h in hostnames
                     if any(_is_or_under(h, c) for c in CARRIER_DOMAINS)
                     and any(pat in h for pat in RESI_HOST_RE)]
    customer_names = [h for h in hostnames if h not in carrier_names]
    customer_domains = [d for d in domains if not any(_is_or_under(d, c) for c in CARRIER_DOMAINS)]
    # Names are joined with " | " — not a phrase separator — so a keyword
    # phrase ("city of") or a parish-plus-civic pairing can never be assembled
    # out of two unrelated names.
    identity_text = " | ".join(customer_names + customer_domains)

    bulk_network = first_kw(BULK_NETWORK_KW, org_text) is not None
    transit = first_kw(TRANSIT_HOST_KW, org_text) is not None
    # "AT&T Enterprises" matches the consumer 'at&t' too; a transit/business
    # carrier is NOT consumer broadband.
    consumer_isp = (first_kw(RESI_ORG_KW, org_text) is not None) and not transit
    # Keyword search space: customer identity always; org text only when the org
    # is a specific customer (not a bulk network).
    kw_text = identity_text if bulk_network else (identity_text + " | " + org_text)
    via = " (via customer domain)" if bulk_network else ""

    # 0. Shodan's honeypot tag disqualifies the host outright.
    if "honeypot" in tags:
        return "honeypot", "Shodan honeypot tag"

    # 1. Jurisdiction before sector: another state's public-sector namespace is
    #    not our constituency, whatever it serves — unless the text itself says
    #    Louisiana, which is conflicting evidence and stays in scope for review.
    kinds = {gov_domain_kind(n) for n in names} - {None}
    la_edu = any(_is_or_under(n, e) for n in names for e in LA_EDU_DOMAINS)
    authoritative_la = "la" in kinds or la_edu or any(is_k12_la(n) for n in names)
    if "other_state" in kinds and not authoritative_la and not kw_in("louisiana", kw_text):
        return "out_of_state_gov", "another state's gov domain"
    if not authoritative_la and not bulk_network and not kw_in("louisiana", kw_text):
        kw = first_kw(OUT_OF_STATE_ORG_KW, org_text)
        if kw:
            return "out_of_state_gov", f"org names another state's government ('{kw}')"
    # Mixed evidence (a Louisiana name AND another state's name on one IP) stays
    # in scope but is flagged, and the other-state names are removed from the
    # keyword evidence so Pennsylvania's "health" cannot set our sector.
    conflict = ""
    if "other_state" in kinds:
        foreign = [n for n in names if gov_domain_kind(n) == "other_state"]
        kept = [n for n in customer_names + customer_domains if n not in foreign]
        identity_text = " | ".join(kept)
        kw_text = identity_text if bulk_network else (identity_text + " | " + org_text)
        conflict = f" [mixed jurisdiction: {', '.join(foreign[:2])} — review]"

    # A host answering on >100 ports is a honeypot, scanner or NAT front — not
    # one device. It never gets an ICS-port promotion (finding 2/6), and if
    # nothing else attributes it, it is tiered 'honeypot'. But a host that
    # carries a real identity (Louisiana domain, sector or civic keyword) keeps
    # that tier with a review flag: a public NAT can front real victims.
    megaport = len(ports) > HONEYPOT_PORT_THRESHOLD
    flag = (f" [mega-port: {len(ports)} open ports — review]" if megaport else "") + conflict

    # 2. Critical infrastructure — ICS ports are a hard signal; then keywords.
    ics = [name for p, name in ICS_PORTS.items() if p in ports]
    if ics and not megaport:
        return "critical_infrastructure", f"ICS protocol exposed: {', '.join(ics)}"
    kw = first_sector_kw(CRIT_KW, kw_text)
    if kw:
        return "critical_infrastructure", f"keyword '{kw}'{via}{flag}"

    # 3. Authoritative domains beat every keyword below.
    if any(is_k12_la(n) for n in names):        # before la.us: allen.k12.la.us beats la.us
        return "education", "k12.la.us domain" + flag
    if "la" in kinds:
        return "government", "Louisiana gov domain" + flag
    if any(n.endswith(".edu") for n in names):
        return "education", "edu domain" + flag
    if "gov" in kinds:
        return "government", "gov domain (not verified as Louisiana)" + flag

    # 3. Unambiguous education institutions ("X Parish School Board" is a school
    #    board, not the parish), then government words, then other education words.
    kw = first_kw(EDU_STRONG_KW, kw_text)
    if kw:
        return "education", f"keyword '{kw}'{via}{flag}"
    kw = first_kw(GOV_KW, kw_text)
    if kw:
        return "government", f"keyword '{kw}'{via}{flag}"
    kw = first_kw(EDU_KW, kw_text)
    if kw:
        return "education", f"keyword '{kw}'{via}{flag}"

    # 5. A parish name counts only beside a civic noun ("Cameron Parish",
    #    "parish of Cameron", "Cameron Sheriff"), never on its own.
    parish_fields = customer_names + customer_domains + ([] if bulk_network else [org_text])
    for par in PARISHES:
        for field in parish_fields:
            civic = near_civic(par, field)
            if civic:
                return "government", f"parish '{par}' + '{civic}'{via}{flag}"

    # 6. Residential vs small business vs unattributable.
    #    Residential = consumer ISP AND every name is the carrier's own
    #    (subscriber-shaped rDNS under a known carrier domain), or there is no
    #    identity at all. Any customer-looking hostname, or any domain that is
    #    not a known carrier domain, is customer identity -> a business.
    # A real customer identity, or a non-bulk org name: a specific (small)
    # business — kept as a reviewable lead even on a mega-port host.
    if customer_names or customer_domains or (org_text.strip() and not bulk_network):
        return "small_business", "commercial org, not gov/edu/infra" + flag
    # 7. Nothing attributes this mega-port host: honeypot / scanner / NAT.
    if megaport:
        return "honeypot", f"{len(ports)} open ports (>{HONEYPOT_PORT_THRESHOLD}), no attributing identity"
    # 8. Consumer-broadband space with only the carrier's rDNS (or nothing): residential.
    if consumer_isp:
        return "residential", "consumer ISP / dynamic rDNS"
    # Only a bulk-network name and nothing else — we cannot attribute the customer.
    if org_text.strip():
        return "unclassified", "bulk network address space, no customer identity"
    return "unclassified", "no attribution signal"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("infile")
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=15, help="hosts to list per tier")
    args = ap.parse_args()

    kev = set(load_json(os.path.join(SCRIPT_DIR, "reference/kev.json"), {}).get("cves", []))
    epss = load_json(os.path.join(SCRIPT_DIR, "reference/epss.json"), {})

    # Aggregate banners into one record per unique IP.
    hosts = {}
    with gzip.open(args.infile, "rt") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except Exception:
                continue
            ip = r.get("ip_str")
            if not ip:
                continue
            h = hosts.setdefault(ip, {"org": None, "ports": set(), "products": set(),
                                      "hostnames": set(), "domains": set(),
                                      "cves": set(), "city": None, "tags": set()})
            h["org"] = h["org"] or r.get("org")
            h["ports"].add(r.get("port"))
            if r.get("product"):
                h["products"].add(r["product"])
            h["hostnames"].update(r.get("hostnames") or [])
            h["domains"].update(r.get("domains") or [])
            h["tags"].update(r.get("tags") or [])
            loc = r.get("location") or {}
            h["city"] = h["city"] or loc.get("city")
            for c in (r.get("vulns") or {}):
                h["cves"].add(c)

    # Normalize sets -> sorted lists for stable output.
    for h in hosts.values():
        h["hostnames"] = sorted(h["hostnames"])
        h["domains"] = sorted(h["domains"])

    # Honeypot guard now lives in classify() (tag or >100 ports -> 'honeypot'
    # tier), so the store and this report exclude the same hosts.
    tiered = defaultdict(list)
    honeypots = set()
    for ip, h in hosts.items():
        tier, reason = classify(h)
        if tier == "honeypot":
            honeypots.add(ip)
            continue
        kev_hits = sorted(h["cves"] & kev)
        max_epss = max((epss.get(c, 0.0) for c in h["cves"]), default=0.0)
        admin = sorted({ADMIN_PORTS[p] for p in h["ports"] if p in ADMIN_PORTS})
        dbs = sorted({DB_PORTS[p] for p in h["ports"] if p in DB_PORTS})
        # Same rule as classify(): a mega-port host gets no ICS evidence or score.
        ics = ([] if len(h["ports"]) > HONEYPOT_PORT_THRESHOLD
               else sorted({ICS_PORTS[p] for p in h["ports"] if p in ICS_PORTS}))
        # Actionability score: KEV dominates, then ICS, exposed admin/db, EPSS.
        score = (len(kev_hits) * 100 + len(ics) * 40 + len(admin) * 15 +
                 len(dbs) * 25 + int(max_epss * 50))
        tiered[tier].append({
            "tier": tier, "ip": ip, "org": h["org"], "city": h["city"], "score": score,
            "kev": kev_hits, "ics": ics, "admin": admin, "dbs": dbs,
            "epss": round(max_epss, 3), "n_cves": len(h["cves"]),
            "reason": reason, "products": sorted(h["products"])[:3],
        })

    lines = []
    w = lines.append
    date = os.path.basename(args.infile).replace(".json.gz", "").split("events-")[-1]
    total = sum(len(v) for v in tiered.values())
    w(f"# Louisiana exposure triage — {date}")
    w("")
    w(f"**{total:,} unique hosts** classified (+{len(honeypots)} honeypot host(s) "
      f"excluded). Findings are PASSIVE LEADS TO VERIFY, not confirmed vulnerabilities.")
    w("")
    w("## Accounting — every host bucketed (consequence order)")
    w("")
    w("| Tier | Hosts | w/ KEV CVE | w/ exposed admin | w/ ICS |")
    w("|---|--:|--:|--:|--:|")
    for t in TIERS:
        rows = tiered.get(t, [])
        w(f"| {t.replace('_',' ')} | {len(rows):,} | "
          f"{sum(1 for x in rows if x['kev']):,} | "
          f"{sum(1 for x in rows if x['admin']):,} | "
          f"{sum(1 for x in rows if x['ics']):,} |")
    w("")
    for t in TIERS:
        rows = sorted(tiered.get(t, []), key=lambda x: -x["score"])
        if not rows:
            continue
        flagged = [x for x in rows if x["score"] > 0]
        w(f"## {t.replace('_',' ').title()} — {len(rows):,} hosts "
          f"({len(flagged):,} with a risk signal)")
        w("")
        if not flagged:
            w("_No KEV/ICS/admin/db signals in this tier today._")
            w("")
            continue
        w("| score | IP | org | city | KEV | ICS | admin | DB | EPSS | reason | review |")
        w("|--:|---|---|---|---|---|---|---|--:|---|---|")
        for x in flagged[:args.top]:
            base, _, note = x['reason'].partition(" [")
            w(f"| {x['score']} | {x['ip']} | {(x['org'] or '')[:24]} | "
              f"{(x['city'] or '')[:14]} | {' '.join(x['kev'][:3]) or '—'} | "
              f"{' '.join(x['ics']) or '—'} | {' '.join(x['admin']) or '—'} | "
              f"{' '.join(x['dbs']) or '—'} | {x['epss'] or '—'} | {base[:28]} | "
              f"{('⚠ ' + note.rstrip(']')) if note else '—'} |")
        w("")

    review = [x for t in TIERS for x in tiered.get(t, []) if " [" in x["reason"]]
    if review:
        w(f"## Review queue — {len(review):,} flagged host(s), listed regardless of score")
        w("")
        w("| tier | IP | org | city | flag |")
        w("|---|---|---|---|---|")
        for x in sorted(review, key=lambda x: (TIERS.index(x["tier"]), -x["score"])):
            note = x["reason"].partition(" [")[2].rstrip("]")
            w(f"| {x['tier'].replace('_', ' ')} | {x['ip']} | {(x['org'] or '')[:24]} | "
              f"{(x['city'] or '')[:14]} | ⚠ {note} |")
        w("")

    report = "\n".join(lines)
    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        open(args.out, "w").write(report)
        print(f"Wrote {args.out}")
    else:
        print(report)


if __name__ == "__main__":
    sys.exit(main())
