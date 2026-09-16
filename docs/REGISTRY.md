# Owner registry (Phase 2)

Who owns an exposed IP? The registry answers that with **graded evidence**
(source, confidence, as_of) instead of the keyword heuristics in
`triage_report.classify()`. It is passive: nothing contacts a host.

## Files

| Path | What | Written by |
|---|---|---|
| `reference/registry/orgs.csv` | one row per organisation (hand-curated) | you |
| `reference/registry/networks.csv` | curated CIDR prefixes and ASNs -> org | you |
| `reference/registry/domains.csv` | curated DNS domains -> org | you (org rows' `domains` are merged in automatically) |
| `reference/registry/ots_cidrs.csv` | **optional** drop-in from OTS: `prefix, agency, contact` | OTS |
| `reference/registry/cymru_cache.json` | Team Cymru IP -> ASN / AS name / BGP prefix, per-entry `as_of` (30-day TTL) | `build_registry.py` |
| `reference/registry/rdap_cache.json` | ARIN RDAP autnum -> AS name + registrant org, per-entry `as_of` (90-day TTL; errors 3 days) | `build_registry.py` |
| `store/registry/registry_orgs.parquet` | orgs.csv as Parquet | `build_registry.py` |
| `store/registry/registry_networks.parquet` | OTS rows + networks.csv (`prefix, asn, org_id, source, confidence, as_of, agency, contact`) | `build_registry.py` |
| `store/registry/registry_domains.parquet` | domains.csv + org-row domains | `build_registry.py` |
| `store/registry/ip_attribution.parquet` | one row per IP in `latest_observed`: `ip, org_id, org_name, sector, jurisdiction, method, confidence, evidence, as_of` | `build_registry.py` |

Build (nightly after the store, or by hand):

```bash
venv/bin/python build_registry.py                 # full build, writes store/registry/
venv/bin/python build_registry.py --dry-run       # build in memory, write nothing
venv/bin/python build_registry.py --skip-network  # caches only: no Cymru / RDAP calls
venv/bin/python build_registry.py --limit 500     # first 500 IPs (testing)
venv/bin/python -m pytest tests/test_registry.py -q
```

Every run ends with a summary: IPs by method/confidence and the top orgs.
If `exposure.duckdb` is locked by a running `build_store.py`, the build reads
the observation partitions directly (same `latest_observed` definition).

## Using it

```python
from registry import Attributor
att = Attributor().load()                 # store/registry/*.parquet -> memory
att.lookup("130.39.1.1")
# {'org_id': 'la-lsu', 'org_name': 'Louisiana State University', 'sector': 'education',
#  'jurisdiction': 'state', 'method': 'registry_network', 'confidence': 'high',
#  'evidence': 'prefix 130.39.0.0/16 (curated (ARIN NET-130-39-0-0-1 LSU-IPV4))', 'as_of': '2026-09-15'}
att.lookup_domain("vpn.ochsner.org")      # the la-ochsner org row + 'domain': 'ochsner.org'
```

`lookup()` does a live longest-prefix match on `registry_networks` first
(OTS/curated CIDRs may be newer than the last build), then returns the
precomputed `ip_attribution` row. A row with an empty `org_id` is still
returned (its evidence names the network); an unknown IP returns `None`.
Both lookups are pure dict/int operations — ~100k calls per second-ish.

Command-line spot check: `venv/bin/python registry.py 130.39.1.1 vpn.ochsner.org`.

## Adding an organisation

1. Add a row to `orgs.csv`:
   `org_id, name, sector, jurisdiction, aliases, domains, contact_route, notes, source, as_of`
   - `org_id`: short, stable, lower-case (`la-<slug>`). Never reuse one.
   - `sector`: `critical_infrastructure|government|education|healthcare|energy|water|telecom|finance|small_business|out_of_state|other`, pipe-separate several.
   - `jurisdiction`: `state|parish|municipal|federal|private|out_of_state`.
   - `aliases`: semicolon-separated names the org appears under in ARIN registrant
     records and the OTS agency column. Matching is **equality only** after
     normalisation (case, punctuation, corporate suffixes such as Inc/LLC and a
     leading "The" are ignored) — never containment, so `St. Tammany Parish` cannot
     claim `St. Tammany Parish School Board` and `Dow` cannot claim `Dow Jones`. To
     catch a registrant, add its exact name as an alias. A carrier / consumer-ISP
     name (`triage_report.BULK_NETWORK_KW`) never matches: its space holds
     subscribers, so `LUS Fiber` is not an alias of Lafayette Utilities System.
   - `domains`: semicolon-separated registered domains the org controls. Only
     domains you are sure of — a wrong domain attributes strangers' hosts to the
     org. Do **not** list carrier/subscriber rDNS domains (`lusfiber.net`).
   - `contact_route`: `OTS/ESF-17` (state), `MS-ISAC` (local government, ports,
     airports), `Health-ISAC` (hospitals), `direct`, `ISP abuse-c`.
   - `source=curated`, `as_of=YYYY-MM-DD`.
2. Optionally add prefixes/ASNs to `networks.csv` (`prefix, asn, org_id, source, confidence, as_of`).
   A row may carry a prefix, an ASN, or both; put *why you believe it* in `source`
   (e.g. `curated (ARIN NET-130-39-0-0-1)`). ASN-only rows attribute at the row's
   confidence (use `medium`: an ASN can host tenants); prefixes default to `high`.
3. `domains.csv` is optional — every domain on the org row is merged in as
   `source=orgs.csv, confidence=high`. Use `domains.csv` when a domain needs its own
   source or confidence.
4. Rebuild: `venv/bin/python build_registry.py`. Loading fails loudly on an unknown
   `org_id`, sector or jurisdiction, or a malformed prefix.

## Dropping in the OTS list

Save the state-owned address list as `reference/registry/ots_cidrs.csv` with the
header `prefix,agency,contact` (one CIDR per row; extra columns are ignored). On
the next build each prefix becomes a `registry_networks` row with
`source=ots_cidrs, confidence=high`. The `agency` text is matched against org
names/aliases (same rule as above); when it does not match, the prefix is
attributed to **la-ots** itself and the agency and contact are kept on the row
and surface in the evidence (`prefix 10.1.2.0/24 (ots_cidrs) agency=Office of Motor Vehicles`).
Add the agency as an org (or as an alias of one) to get a precise attribution.
OTS rows outrank every other source at the same prefix.

## Methods and confidence

Precedence per IP — first hit wins (`build_registry.attribute_ip`):

| method | confidence | meaning |
|---|---|---|
| `ots_cidr` | high | IP inside a prefix from the OTS drop-in (state-owned space) |
| `registry_network` | high (row) | IP inside a curated prefix from `networks.csv`; longest prefix wins |
| `domain_dns` | high / **medium** | an rDNS hostname (Shodan `hostnames`) sits under a registry domain, label boundary (`evilnola.gov` is not `nola.gov`). Starts at the domain row's own confidence (at most high); **medium** when names of more than one registry org sit on the IP (evidence: `SHARED IP: names of la-x also present`) or when the IP is on carrier / transit / cloud / hosting space (`triage_report.BULK_NETWORK_KW`; evidence: `on shared/carrier network '…'`) — a customer name on shared hosting proves the tenant, not the address |
| `cert` | high / **medium** | a CN/SAN of a **non-self-signed** certificate sits under a registry domain; same grading as `domain_dns` |
| `registry_asn` | medium (at most) | the IP's origin ASN (Cymru, else Shodan) is an ASN-only row in `networks.csv`. ASN rows are capped at medium whatever the CSV says; an ASN row for a carrier org is skipped |
| `arin_rdap` | medium | the ARIN RDAP **registrant** (never a technical/abuse/administrative contact) of the origin ASN equals a registry org/alias |
| `arin_rdap` | low, `org_id` empty | RDAP registrant known but matches no registry org — recorded as evidence only (e.g. a carrier ASN Shodan labels with a customer's name) |
| `roster_name` | medium / low | a certificate subject O (medium) or Shodan org (low) equals a sector-roster name exactly (`reference/rosters/`) |
| `cymru_asn` | low, `org_id` empty | only the routing origin (ASN, AS name, BGP prefix) is known |
| `shodan_asn` | low, `org_id` empty | Shodan's own ASN field: residential hosts (never sent to Cymru) and any IP Cymru could not answer |
| `none` | low, `org_id` empty | no evidence at all |

RDAP is only consulted for ASNs seen on `government`, `education` or
`critical_infrastructure` hosts. All external calls are cached and fail-soft: a
feed being down lowers confidence for that run, it never aborts it.

## The `conflict` column

`ip_attribution.conflict` is `''` or a structured note, and a row with a
non-empty conflict is **capped at medium** whatever its method:

| conflict | meaning |
|---|---|
| `rdns=la-a,la-b;cert=la-c` | rDNS names and certificate names on this IP, evaluated together, point at more than one org (orgs listed best-first per source; a part is omitted when that source has no match) |
| `prefix=la-p;rdns=la-a` / `prefix=la-p;cert=la-c` | the IP is inside a registry prefix owned by `la-p` but carries names of another org (e.g. a LONI-hosted university, a Legislature host under `la.gov`) |
| `duplicate prefix P: la-a vs la-b` / `duplicate domain D: …` / `duplicate asn A: …` | the matched prefix / domain / ASN was listed for two different orgs; the first row was used, the other is recorded |

Several notes are joined with `;`. `build_store.py` refuses to set a tier
from the registry when `conflict` is non-empty; the row still names the
best-supported org so an analyst can resolve it. `registry.Attributor.lookup()`
returns the column as `conflict` (`''` for live prefix hits).

## Precedence on duplicates and ambiguous names

- **Longest prefix always wins first.** A more specific curated prefix
  (`10.0.5.0/24`, `networks.csv`) beats a wider OTS prefix (`10.0.0.0/8`)
  for an address inside both — that is the longest-prefix rule, not a conflict.
- **Equal prefixes**: the first row wins and OTS rows are loaded before
  `networks.csv`, so an OTS prefix beats a curated row for the *same* prefix.
  Equal ASN rows and equal domains likewise keep the first row (`domains.csv`
  before domains taken from `orgs.csv`). Every discarded duplicate that names a
  different org is logged (`networks: prefix … also listed for …; keeping …`)
  and, when it touches an IP, surfaces in that row's `conflict`.
- **Name normalisation** (`build_registry.norm_org_name`): lower-case;
  punctuation to spaces (`L.L.C.` and `LLC` become the same); only a *leading*
  "the" dropped; corporate suffix words (Inc, LLC, Corp, Company, Co, Ltd, …)
  dropped from the end. `Acme LLC` and `Acme Inc` therefore collide on `acme`:
  a key shared by two different registry orgs, or by two different roster rows,
  is **ambiguous** — logged once, never matched.

## What leaves the box, and what does not

- **Team Cymru** (`whois.cymru.com`, plain TCP/43, unencrypted): the list of
  **non-residential** IPs from `latest_observed`, i.e. every host whose tier is
  not `residential`. Consumer-broadband subscribers are never sent; they keep
  Shodan's ASN (`shodan_asn`). Answers are cached 30 days.
- **ARIN RDAP** (HTTPS): **ASN numbers only** (`/autnum/<n>`), and only for ASNs
  seen on government / education / critical-infrastructure hosts. No IPs, no
  names. Answers cached 90 days (errors 3 days).
- Nothing else is contacted. No host in the store is ever touched.

## Output safety: generations and the CURRENT pointer

```
store/registry/
  CURRENT                      <- one line: the live generation's directory name
  gen-20260915T222013/         <- registry_orgs / registry_networks / registry_domains / ip_attribution .parquet
  gen-20260915T210000/         <- previous (the newest 3 generations are kept)
  ...
```

Every build writes all four files into a new `gen-<timestamp>/` directory and
only then switches `CURRENT` with an atomic rename, so `registry.Attributor`
(which reads the pointer; flat files in `store/registry/` are the fallback
when there is no pointer) always sees one consistent set. A failed build
leaves the pointer untouched and removes its half-built directory.

- **Store unreadable** (not merely empty): the three registry tables are
  rebuilt and the previous generation's `ip_attribution.parquet` is **copied
  forward** unchanged; the log says `store unreadable: ip_attribution.parquet
  NOT rebuilt`.
- **Network source down**: an expired cache record is still used when it could
  not be refreshed — evidence carries `(stale as_of <date>)` — and is replaced
  only by fresher data (RDAP keeps the last *good* record beside the error).
  If Cymru or RDAP could not be reached at all, every IP whose new row would be
  weaker than its row in the previous generation keeps the previous row
  (evidence: `(kept from previous build as_of …: <reason>)`).
- `Attributor.load()` prints where it loaded from, logs every missing file
  (`… missing — loaded empty`), and exposes `attribution_as_of` (the newest
  `as_of` in `ip_attribution`) for reports to print.
