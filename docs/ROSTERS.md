# Sector rosters and domain discovery (Phase 2)

Two passive, public-source builders feed the owner registry:

| Script | Writes | Network |
|---|---|---|
| `refresh_rosters.py` | `reference/rosters/<sector>.csv`, `reference/rosters/manifest.json` | HTTPS GETs to the public feeds below; downloads cached in `reference/rosters/cache/` (mode 0700) |
| `discover_domains.py` | `reference/discovery/discovered_hosts.csv`, `discovered_domains.csv`, `state.json` | HTTPS to crt.sh (cached 7 days in `reference/discovery/cache/`) and DNS resolution only |

Neither script contacts any discovered host. Every roster row carries `source`
(the URL it came from) and `as_of` (fetch date) so attribution can be
evidence-graded. Rows are never invented, and **good data is never replaced by
empty data** (see "Failure behaviour").

Roster columns (the Phase 2 contract): `name, sector, subsector, city, parish,
domain, website, source, as_of`. `parish` is the bare parish name ("Acadia",
not "Acadia Parish"). `domain`/`website` are filled only when the source
publishes them (IPEDS does; SDWIS, NPPES, CCD, BSEE, EIA do not) — the
discovery step and the registry fill the gap.

## Runtime bounds (defaults)

| | `refresh_rosters.py` | `discover_domains.py` |
|---|---|---|
| whole job | `--max-minutes 30` | `--max-minutes 45` |
| per source / seed | sector budgets: water 300 s, healthcare 900 s, education 300 s, energy 600 s, government 180 s (always clipped by the job deadline) | crt.sh: one attempt per mode — wildcard 60 s, unexpired-only 30 s, exact 20 s, no retries; DNS: 8 s per batch of `--workers` (10) names, clipped by the job deadline |
| request caps | NPPES `--max-requests 400`; Urban API 50 pages per dataset; HTTP 429/5xx retried at most 3 times with Retry-After / 2-4-8 s backoff | `--max-seeds N` (default all), `--max-names 1000` per seed, `--sleep 2` between crt.sh calls |

When a deadline hits, the script writes what it has (merged with previous
data), logs what it skipped, and exits 0. The weekly runner should call
`discover_domains.py --max-seeds 20 --max-minutes 30` (or similar); successive
capped runs sweep the whole seed list because of the resume order below.

## Failure behaviour

`refresh_rosters.py`, per sector:
- all sources fail (nothing fetched) → the previous `<sector>.csv` is left
  untouched; log `kept previous, N rows, as_of X`; manifest `kept_previous: true`.
- one source fails or is partial (HTTP failure, API error, deadline, request
  budget, NPPES ZIP fallback failing) → the fresh rows are written **plus** the
  previous rows of the failed source (matched by `source` URL prefix), which
  keep their old `as_of`; manifest `complete: false` with a note.
- NPPES: an API error payload is an error, not an empty page; statewide rows
  already fetched are kept when the ZIP partition fails.
- Files are written to `<file>.tmp` and renamed atomically.

`discover_domains.py`:
- a failed or degraded crt.sh query, a DNS failure, the name cap or a deadline
  never drops a seed's previously discovered hosts. A host row is dropped only
  when its name was re-resolved this run and no longer resolves (or no longer
  resolves to that ip). `discovered_domains.csv` never loses rows.
- `first_seen` / `last_seen` on both files track when a row was first and last
  confirmed; `resolved_at` is the timestamp of the last successful resolution.

## Manifest — `reference/rosters/manifest.json`

One entry per sector, merged on each run:

```json
"water": {"written_at": "...", "rows": 941, "complete": true, "kept_previous": false,
          "sources": [{"source": "https://data.epa.gov/efservice/WATER_SYSTEM/STATE_CODE/LA/CSV",
                       "fetched_at": "...", "rows": 941, "complete": true,
                       "dataset_version": "<Last-Modified header, or data year>", "note": ""}]}
```

`dataset_version` is the source's own marker: the server's `Last-Modified`
when it sends one (SDWIS, BSEE), the data year for CCD/IPEDS/EIA-860/Gazetteer,
"Census 2020 county codes" for parishes, and `live registry <date>` for NPPES.

## Rosters

### water — `reference/rosters/water.csv`
- Source: EPA SDWIS via Envirofacts,
  `https://data.epa.gov/efservice/WATER_SYSTEM/STATE_CODE/LA/CSV` (system list) and
  `https://data.epa.gov/efservice/GEOGRAPHIC_AREA/PRIMACY_AGENCY_CODE/LA/CSV` (parish served).
- Kept: active systems (`pws_activity_code=A`) of type CWS (`subsector=community`)
  and NTNCWS (`subsector=non_community`, e.g. schools and plants on their own well).
  Transient systems (campgrounds, gas stations) are dropped.
- Cadence: quarterly (SDWIS is refreshed by EPA quarterly).

### healthcare — `reference/rosters/healthcare.csv`
- Source: CMS NPPES NPI Registry API v2.1, organizational providers (`enumeration_type=NPI-2`,
  `state=LA`). The API refuses a bare state query and caps `skip` at 1000, so the
  query is partitioned by `taxonomy_description` (the exact NUCC names: General
  Acute Care / Psychiatric / Rehabilitation / Long Term Care / Special / Chronic
  Disease / Military Hospital, Clinic/Center, FQHC, Ambulance, EMS, Skilled
  Nursing, Nursing Facility/ICF, Assisted Living, Home Health, Hospice, HMO, PPO,
  Public Health or Welfare, Community/Behavioral Health) and, when a taxonomy
  still exceeds the ceiling, by 3-digit ZIP prefix (`700*`..`714*`).
  The API resolves a description loosely (a bare "Hospital" lands on
  "Hospitalist"), so each result is re-filtered by a whole-word match of the
  term against the org's own taxonomy list before it is kept.
- `subsector`: hospital | clinic | ambulance | nursing | home_health | health_plan |
  public_health | behavioral_health. An org matching several keeps the highest-ranked
  (hospital first). Deduped by name+city. Pharmacies and individual practitioners
  are intentionally excluded; names without two consecutive letters ("999999") are dropped.
- Each row's `source` is the registry URL for that NPI (`...&number=<NPI>`).
- Requests: ~105 per full run (`--max-requests` caps it; default 400); 429/5xx
  are retried with Retry-After backoff. Pages are cached 7 days under
  `reference/rosters/cache/nppes_*.json` **after being reduced** to org name,
  NPI, location city/state/ZIP and taxonomy descriptions — authorized-official
  names, phone and fax numbers, and street addresses never reach disk. Error
  payloads are never cached.
- Cadence: monthly.

### education — `reference/rosters/education.csv`
- K-12: NCES Common Core of Data school directory via the Urban Institute Education
  Data API, `https://educationdata.urban.org/api/v1/schools/ccd/directory/<year>/?fips=22`
  (tries 2023, 2022, 2021; `next` links followed, up to 50 pages; only a complete
  set is cached). One row per open school (`k12_school`) and one per
  district/LEA (`k12_district`); parish from the county FIPS code.
- Higher ed: IPEDS directory via the same API,
  `https://educationdata.urban.org/api/v1/college-university/ipeds/directory/<year>/?fips=22`
  (`higher_ed`, with `website`/`domain` from IPEDS `url_school`).
- Plus `triage_report.LA_EDU_DOMAINS` as `higher_ed_domain` rows for any curated
  domain IPEDS did not already provide.
- Not used: the Louisiana Department of Education "school directory" — the data
  center at doe.louisiana.gov has no machine-readable download link, and the
  Board of Regents publishes institution lists only as web pages. If either
  publishes a CSV/XLSX, drop it in `reference/rosters/manual/education.csv`.
  K-12 district *domains* come from `discover_domains.py` on the `k12.la.us` seed
  (`discovered_domains.csv` lists every `<district>.k12.la.us`).
- Cadence: yearly (CCD/IPEDS publish annually).

### energy — `reference/rosters/energy.csv`
- EIA-860 (electric utilities and power plants), archive zip
  `https://www.eia.gov/electricity/data/eia860/archive/xls/eia860<year>.zip`
  (tries 2024, 2023, 2022; ~21 MB, cached 90 days). The `1___Utility` and
  `2___Plant` workbooks are parsed with a stdlib xlsx reader (no openpyxl on the
  server) and filtered to `State == LA`: `electric_utility` (utility city) and
  `power_plant` (plant city + parish).
- BSEE offshore companies, `https://www.data.bsee.gov/Company/Files/compalldelimit.zip`
  (Gulf of Mexico company master, no header; 19 quoted fields — name is field 3,
  termination date field 5, city/state fields 16/17). Kept: LA-addressed
  companies with no termination date (`offshore_operator`).
- LDNR SONRIS operator list: **unreachable as data** — SONRIS is an Oracle APEX
  application (`sonlite.dnr.state.la.us/ords/...`) with interactive reports only;
  there is no anonymous CSV endpoint. Export the operator report from SONRIS by
  hand and drop it in `reference/rosters/manual/energy.csv` (format below) with
  `subsector=oil_gas_operator` and `source=https://sonlite.dnr.state.la.us/...`.
- Cadence: yearly for EIA-860, quarterly for BSEE.

### government — `reference/rosters/government.csv`
- Parishes: the 64 parishes and seats are hard-coded in `refresh_rosters.PARISHES`
  (name `"<X> Parish Government"`, `subsector=parish`, `city=<seat>`), and the list
  is cross-checked at run time against the Census county-code file
  `https://www2.census.gov/geo/docs/reference/codes2020/cou/st22_la_cou2020.txt`
  (a mismatch is logged and flagged incomplete in the manifest, never silently
  fixed). That file is the `source` URL.
- Municipalities: Census Gazetteer place file
  `https://www2.census.gov/geo/docs/maps-data/data/gazetteer/<year>_Gazetteer/<year>_gaz_place_22.txt`
  (tries 2024, 2023, 2022). Active (`FUNCSTAT=A`) cities (`LSAD 25`), towns (`43`)
  and villages (`47`) become `City/Town/Village of <name>`
  (`subsector=municipal_city|municipal_town|municipal_village`); CDPs are not
  governments and are dropped. The gazetteer has no parish column, so `parish` is
  blank for municipalities.
- Louisiana Municipal Association: no public machine-readable member list; the
  Census file is the substitute.
- Cadence: yearly.

## Manual drop-ins — `reference/rosters/manual/<sector>.csv`

For any sector whose public source is missing or incomplete, an analyst can
place a CSV with the roster columns in `reference/rosters/manual/`. On every
run `refresh_rosters.py` appends those rows (after the fetched ones) and the
file survives refreshes. Rules:

- Same header as the rosters: `name,sector,subsector,city,parish,domain,website,source,as_of`.
  `name` is required; `sector` is forced to the file's sector; `subsector`
  defaults to `manual`; `source` defaults to `manual:<file>` and `as_of` to today.
  Put the real URL or document reference in `source` whenever one exists.
- Deduped against fetched rows by (name, subsector, city), case-insensitive.
- Expected drop-ins: `energy.csv` (SONRIS operators, pipeline operators,
  refineries), `education.csv` (LDOE directory if published), `government.csv`
  (sheriffs, school boards, special districts), `water.csv` (sewerage districts
  not in SDWIS).

## Domain discovery — `discover_domains.py`

Seeds, in priority order (a capped run does the important ones first):
1. `la.gov`, `k12.la.us`
2. `triage_report.LA_EDU_DOMAINS`
3. registry domains: `reference/registry/domains.csv` (`domain`) and the
   semicolon-separated `domains` column of `reference/registry/orgs.csv`
4. every `domain` in `reference/rosters/*.csv`

A seed already covered by an earlier seed (`ldh.la.gov` under `la.gov`) is skipped.

Resume order (`reference/discovery/state.json`, one entry per seed with
`completed_at`, `mode`, `names`, `resolved`, `partial`): seeds never completed
run first in priority order, then the stalest completed ones; a seed completed
within the last 7 days is skipped. `--no-resume` runs plain priority order;
`--seed X` runs exactly the seeds given.

Per seed: `https://crt.sh/?q=%25.<seed>&output=json` (cached 7 days in
`reference/discovery/cache/<seed>.json` with `fetched_at`). Exactly one attempt
per mode, in order: wildcard (60 s), wildcard with `&exclude=expired` (30 s),
exact name (20 s); a degraded mode is logged and marks the seed `partial`.
Names are lower-cased, wildcards stripped (`*.x.la.gov` -> `x.la.gov`),
emails/IPs dropped, and scoped to the seed.

`registered_domain` is the organization-level name: under a namespace suffix
(`k12.la.us`, `lib.la.us`, `la.us`, `la.gov`, ...) it is the next label
(`ces.beau.k12.la.us` -> `beau.k12.la.us`, `www.ldh.la.gov` -> `ldh.la.gov`);
otherwise the seed itself (`mail.lsu.edu` -> `lsu.edu`).

Resolution: `socket.getaddrinfo` (A/AAAA) on daemon worker threads
(`--workers`, default 10) with a hard deadline of 8 s per batch of workers,
clipped by the job deadline; lookups still pending at the deadline are reported
as unknown (previous rows kept) and the blocked threads are abandoned, never
joined. `--max-names` (default 1000) caps names per seed. DNS only — nothing
connects to the host. `--no-resolve` collects names and registered domains
without touching DNS.

Outputs:
- `discovered_hosts.csv`: `name, seed, ip, resolved_at, source=crt.sh, first_seen, last_seen`
  — one row per (name, ip); merge rules under "Failure behaviour".
- `discovered_domains.csv`: `registered_domain, seed, first_seen, last_seen`.

Cadence: weekly, after `refresh_rosters.py` so new roster domains become seeds.

## Running

```
venv/bin/python refresh_rosters.py                        # all sectors, 30-minute cap
venv/bin/python refresh_rosters.py --sector water --dry-run
venv/bin/python discover_domains.py --max-seeds 20 --max-minutes 30   # weekly runner shape
venv/bin/python discover_domains.py --seed la.gov --max-names 300
venv/bin/python discover_domains.py --no-resolve          # names only
venv/bin/python -m pytest tests/test_rosters_discovery.py -q
```
