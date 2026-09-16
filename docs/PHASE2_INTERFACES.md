# Phase 2 — shared interfaces (read before writing code)

Project: /opt/shodan_query on server 192.168.192.119 (ssh mike@..., key auth, `venv/bin/python`,
Python 3.14, duckdb 1.5, geoip2, reportlab, requests NOT installed — use urllib; pytest in venv).
Local copy of the repo for reading: this directory. Raw archives (`daily_downloads/*.json.gz`) and
the store (`store/exposure.duckdb`, views: observations, vulns, latest_observed, exposure_status,
current_state, lifecycle) live only on the server. The store may be mid-rebuild tonight after 23:30;
before that, `current_state` may hold only ~3 days — that is fine for testing.

Rules for every agent
- Create NEW files only. Do not edit build_store.py, run_nightly.sh, refresh_reference.py,
  triage_report.py, README.md, queries.sql or any test that exists — the integrator owns those.
- You may scp your new files to /opt/shodan_query and run them there with venv/bin/python for real
  testing (network access from the server works). Never touch cron, .env, daily_downloads/,
  compromise_hits/, store/exposure.duckdb (read-only queries are fine), or git.
- Every module: a docstring header, argparse CLI with --dry-run where it writes, `log()` to stdout,
  no secrets in code, graceful failure (a feed being down must not raise), and pytest tests under
  tests/ (new test files only; run `venv/bin/python -m pytest tests/<yourfile> -q` on the server).
- All keyword/identity matching must be whole-word (see triage_report.kw_in). Never dedupe by banner hash.
- Output tables are Parquet under store/registry/ or store/leads/ etc. as specified; DuckDB reads them.
- This is for a Louisiana law-enforcement cyber unit: attribution must be evidence-graded (source,
  confidence, as_of). Passive only: no scanning, no probing hosts. Resolving a DNS name is allowed.

Tables / files (column names are the contract)

reference/registry/orgs.csv  (hand-curated + generated; one row per organization)
  org_id, name, sector, jurisdiction, aliases, domains, contact_route, notes, source, as_of
  sector: one of critical_infrastructure|government|education|healthcare|energy|water|telecom|
          finance|small_business|out_of_state|other  (pipe-separate several: "healthcare|education")
  jurisdiction: state|parish|municipal|federal|private|out_of_state
  aliases/domains: semicolon-separated; contact_route: e.g. "direct", "MS-ISAC", "Health-ISAC",
  "OTS/ESF-17", "ISP abuse-c"; as_of: YYYY-MM-DD
reference/registry/networks.csv        prefix, asn, org_id, source, confidence, as_of
reference/registry/domains.csv         domain, org_id, source, confidence, as_of
reference/registry/ots_cidrs.csv       DROP-IN from OTS (state-owned): prefix, agency, contact — may be absent
reference/rosters/<sector>.csv         name, sector, subsector, city, parish, domain, website, source, as_of
store/registry/registry_orgs.parquet, registry_networks.parquet, registry_domains.parquet
store/registry/ip_attribution.parquet  ip, org_id, org_name, sector, jurisdiction, method, confidence,
                                       evidence, as_of   (one row per ip; method e.g. ots_cidr|arin_rdap|
                                       cymru_asn|domain_dns|cert|roster_name; confidence high|medium|low)
registry.py                            class Attributor: load(store_dir) ; lookup(ip) -> dict|None
                                       (longest-prefix match on registry_networks + ip_attribution)
store/exposure.duckdb  table `leads` (persisted TABLE, not a view):
  lead_id (text, stable: sha1 of ip|port|transport|evidence_type), ip, port, transport, org_id, org_name,
  tier, sector, evidence_type (kev_verified|kev_inferred|appliance|ics|compromise_tag|shadowserver|
  ioc_match|cred_leak), evidence (text), confidence (high|medium|low), first_seen, last_seen (dates),
  status (new|queued|notified|acknowledged|remediated|disputed|false_positive|suppressed),
  notified_via, notified_on, analyst, notes, updated_at
store/exposure.duckdb  table `shadowserver_events`:
  report_type, timestamp, ip, port, protocol, asn, geo, tag, severity, detail (json text), ingested_on
reference/exploits.json   {"CVE-....": ["metasploit","nuclei", ...]}      (integrator writes)
reference/ioc_ips.json    {"1.2.3.4": ["feodo","spamhaus_drop", ...]}     (integrator writes)
