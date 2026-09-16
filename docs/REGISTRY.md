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

## Precedence on duplicates and ambiguous names

- **Equal prefix / ASN / domain listed twice**: the first row wins, and the
  conflict is logged (`networks: prefix … also listed for …; keeping …`). OTS
  rows are loaded before `networks.csv`, so an OTS prefix always beats a curated
  row for the same prefix; `domains.csv` rows beat domains taken from `orgs.csv`.
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

## Output safety

The four parquet files are written as **one generation**: each is staged as
`<name>.<pid>.tmp`, and only once all are complete are they renamed into place
back-to-back, so a reader never mixes an old `ip_attribution` with a new
`registry_orgs`. If the store cannot be read at all (not merely empty), the
three registry tables are refreshed but **`ip_attribution.parquet` is not
rewritten** — the previous file is kept and the log says
`store unreadable: ip_attribution.parquet NOT rewritten`.
