# Leads, notification packets and Shadowserver — Phase 2

The store answers "what is exposed right now?" for ~30k services. Almost none of
that is a notification. This layer turns the store into a short, persisted,
evidence-graded list of **leads** — services we would actually contact an owner
about — tracks what happened to each one, and measures whether notification
leads to remediation.

Everything is **passive**. A lead is a *lead to verify*: no host is ever scanned,
probed or accessed by this pipeline, and every packet says so.

Files: `leads.py`, `make_packet.py`, `ingest_shadowserver.py`,
`tests/test_leads_packets.py`.

## Where the state lives (and what a store rebuild does to it)

`rebuild_store.sh` deletes `store/exposure.duckdb`. Anything that lives only in
that file is disposable, so:

| What | Authoritative location | Copy in `exposure.duckdb` |
|---|---|---|
| leads + event log | `store/leads/leads.duckdb` (tables `leads` — `lead_id` PRIMARY KEY — and `lead_events`); mirrored to `store/leads/leads.parquet` + `lead_events.parquet` after every commit (temp file + atomic rename) | table `leads`, re-published by every `refresh`/`set` (`CREATE OR REPLACE TABLE`) — a convenience copy |
| Shadowserver events | `store/shadowserver/events.parquet` (append + dedupe on `report_type, timestamp, ip, port, tag`) + `store/shadowserver/manifest.json` (per file: sha-256, original filename, report_type, rows loaded / duplicate / quarantined, date) | table `shadowserver_events`, re-created from the parquet by `ingest` and by `ingest_shadowserver.py restore`; `leads.py refresh` reads the parquet directly when the table is missing |

`set` writes the parquet mirror **inside** its transaction, before commit; if the
mirror write fails the status change is rolled back and reported as not saved.
`refresh` applies all its changes in one transaction, then mirrors, then publishes
the copy. If the store is locked by a rebuild the authoritative write still
happens and only the copy lags (logged). If `leads.duckdb` itself is lost,
`refresh` restores it from the parquet mirror.

## Vocabulary

| Term | Meaning |
|---|---|
| **lead** | one (ip, port, transport, evidence_type[, cve]) with a reason to notify; `lead_id = sha1("ip\|port\|transport\|evidence_type[\|cve]")[:16]` — the CVE is part of the identity for `kev_verified` / `kev_inferred`, so suppressing one inferred CVE never hides a different one |
| **host-level lead** | evidence about the address, not one service: `port 0`, `transport 'host'` — a threat-intel listing, a compromise flag whose archive carries no port, and every Shadowserver *compromise*-class event (its `port` column is the infected host's **source** port, never an exposed service) |
| **tier** | the host's consequence tier from the classifier (`critical_infrastructure`, `government`, `education`, `small_business`, `unclassified`, `out_of_state_gov`), taken from the host's **newest observation** in `latest_observed`; for a host not in the store, derived from the registry sector |
| **sector** | registry sector when the ip is attributed; else derived from the tier |
| **priority tiers** | `government`, `education`, `critical_infrastructure` — the only tiers for which weaker (inferred) evidence becomes a lead |
| **never a lead** | `residential` (a subscriber line is not an organisation we notify — aggregate statistics only) and `honeypot` (not a victim) |
| **attribution** (`org_id`, `org_name`, `attr_method`, `attr_confidence`) | carried on every lead, separate from evidence confidence: registry `ip_attribution.parquet` (method/confidence as recorded) → the store's `attr_*` columns → Shodan `org` field as method `shodan_org`, confidence `low` → `unattributed` / `none` |
| **first_seen** | the refresh date that first raised the lead |
| **last_seen** | the newest **observation** date supporting the lead (collection day, ledger `last_seen`, Shadowserver event date) |
| **last_evaluated** | the refresh date that last looked at the lead |
| **severity** | the evidence's own severity (`high`/`medium`/`low`; for Shadowserver, the report's) |
| **evidence_key** | the CVE, the appliance label, the tripwire selectors, `compromise:<types>` / `exposure:<types>` for Shadowserver, the feed names for IOC |

### Status lifecycle

```
new ──► queued ──► notified ──► acknowledged ──► remediated ──► (NEWER evidence) ──► new
  └──► disputed | false_positive | suppressed          (analyst decisions)
  any eligible ──► suppressed [auto: host now residential/honeypot] ──► new [reinstated]
```

| status | set by | meaning |
|---|---|---|
| `new` | refresh | generated, nobody has looked at it |
| `queued` | analyst | selected for a packet |
| `notified` | analyst (`set --status notified --via ...`) | packet sent; `notified_on` stamped the first time in an episode |
| `acknowledged` | analyst | the owner confirmed receipt |
| `remediated` | refresh | a `notified`/`acknowledged` lead whose **specific service** is `gone` in `exposure_status` (>45 days unseen); a host-level lead needs **every** service of the host gone. Merely absent from `current_state` (stale) is not remediated. Only those two statuses remediate |
| `disputed` | analyst | the owner says it is not theirs / not vulnerable |
| `false_positive` | analyst | we were wrong |
| `suppressed` | analyst, or refresh (auto) | do not notify. Auto-suppression happens when the host's current tier is residential/honeypot; the note says so and the lead is reinstated as `new` if the host becomes eligible again. Analyst fields and notes are never lost |

Rules `refresh` obeys: it never overwrites an analyst-set status (it advances
`last_seen`/`last_evaluated` and refreshes evidence and attribution); a
`remediated` lead is **reopened only when a newer observation** (date >
`last_seen`) shows the evidence again — unchanged cached evidence keeps it
remediated; reopening starts a **new notification episode** (`notified_on` /
`notified_via` cleared, the previous episode recorded in `notes` and
`lead_events`). Every change is appended to `notes` with its date and logged to
`lead_events(ts, lead_id, event, detail)`.

## Evidence types and confidence

| evidence_type | confidence | rule | tiers |
|---|---|---|---|
| `kev_verified` | high | a CISA-KEV CVE that Shodan itself **verified** on the host; one lead per CVE | all but never-lead |
| `compromise_tag` | high | host in `compromise_hits/seen_ledger.json` with `last_seen` in the last **30 days**; port/transport from the hit archives, else host-level | all but never-lead |
| `shadowserver` | high (compromise class) / medium (exposure class) | a `shadowserver_events` row in the last **14 days**. Compromise-class reports (sinkhole/drone/microsoft_sinkhole/spam/compromised_website/malware_url/botnet/cc …) → host-level, "possible infection" wording. Exposure-class (scan_*/vulnerable_*/exposed_*/open_*/accessible_*/ics/blocklist …) → per exposed port, "exposure to verify" wording. Unknown types are treated as exposure (the weaker claim) | all but never-lead |
| `ics` | medium | an ICS scan module, an ICS port (`triage_report.ICS_PORTS`) or Shodan's `ics` tag — never on a honeypot | all but never-lead |
| `appliance` | medium | `build_store.APPLIANCE_PATTERNS` — the **same** regex list the `appliance_exposure` view uses — over product / cpe23 / http_title | priority tiers only |
| `kev_inferred` | medium | a KEV CVE inferred from the banner version, **not** verified; one lead per CVE | priority tiers only |
| `ioc_match` | medium | ip in `reference/ioc_ips.json` and known to us (in the store or in the registry) — host-level; not re-raised while every service of the host is gone | all but never-lead |
| `cred_leak` | — | reserved; accepted by `set`, never generated | — |

Ranking (`list`, packets): `kev_verified` > `compromise_tag` > `shadowserver` >
`ics` > `appliance` > `kev_inferred` > `ioc_match`, then severity (so a
Shadowserver compromise outranks a Shadowserver exposure), then EPSS of the
lead's own CVE (or the service's worst), then tier.

## Running

```bash
cd /opt/shodan_query
venv/bin/python leads.py refresh                 # after the nightly store build; idempotent
venv/bin/python leads.py refresh --dry-run
venv/bin/python leads.py list --limit 20         # shows evidence conf AND attribution conf/method
venv/bin/python leads.py list --tier government --status new
venv/bin/python leads.py list --org "ORG-CT"     # org_id or org_name
venv/bin/python leads.py set <lead_id> --status notified --via MS-ISAC --analyst jd --note "packet LA-EXP-..."
venv/bin/python leads.py set <lead_id> --status acknowledged --note "CISO replied"
venv/bin/python leads.py digest                  # per-sector counts + attribution mix + remediation stats
venv/bin/python leads.py digest --weekly --out reports/leads_digest_$(date +%F).md
```

`refresh` prints a per tier / evidence / status summary, the attribution-confidence
mix and the excluded aggregates (residential, honeypot, non-priority inferred,
unknown IOC ips). Options `--leads-db`, `--ledger`, `--hits-dir`, `--ioc`,
`--attribution`, `--ss-parquet`, `--parquet`, `--today` exist for tests.

### The digest — measuring remediation

Per sector (residential/honeypot excluded): counts per status, the attribution
confidence mix, and three distributions — **days-to-disappear** (lead
`first_seen` → the service's last observation, for services now `gone`),
**notified-to-gone** (the same from `notified_on`), **still-open lead age**. A
service that disappears is *no longer observed*: the best passive proxy for
remediation we have, never proof of it. `--weekly` restricts the
new/notified/remediated counts to the last 7 days.

## Notification packets

```bash
venv/bin/python make_packet.py --org "ST. TAMMANY PARISH SCHOOL BOARD"   # org_name or org_id
venv/bin/python make_packet.py --org tammany                              # whole-word match, must be unique
venv/bin/python make_packet.py --ip 203.0.113.10
venv/bin/python make_packet.py --org "..." --include-closed               # + remediated/disputed/fp/suppressed
venv/bin/python make_packet.py --org "..." --pdf
venv/bin/python make_packet.py --org "..." --dry-run
```

Output: `reports/packets/<org-slug>_<date>.md` (+ `.pdf`), marked **DRAFT**
until the reviewer block is completed. Contents follow the Fletcher / Ochsner
notices: header (TLP placeholder, reference, priority); what we observed (per
lead: ip, port, service, evidence type, exact evidence, scan age, attribution
basis and confidence, status); what this is not; prioritised actions generated
from the evidence classes present (Shadowserver compromise vs exposure wording,
ICS: "protocols typically have no authentication; reachability alone is a serious
exposure that must be verified"); how to verify; contact/handling; reviewer
sign-off (second reviewer **REQUIRED** when a compromise claim is present); an
appendix of *currently active* services on the lead hosts attributed to the same
org.

Rules: only `new`/`queued` leads by default, plus `notified`/`acknowledged`
marked "previously notified on <date>"; closed statuses only with
`--include-closed`; residential/honeypot leads are refused; the selected leads
must attribute to **one** organisation or the packet is refused with the list;
attribution is stated as recorded (registry method/confidence; Shodan org shown
as a low-confidence label; otherwise "unattributed" — never promoted from a
certificate name); every banner-derived string is escaped before it enters the
markdown. Record the send with `leads.py set`.

## Shadowserver

```bash
mkdir -p reference/shadowserver/incoming
cp ~/2026-09-14-sinkhole_http_drone-louisiana.csv reference/shadowserver/incoming/
venv/bin/python ingest_shadowserver.py ingest --dry-run
venv/bin/python ingest_shadowserver.py ingest        # parquet + manifest, table re-published, file -> processed/
venv/bin/python leads.py refresh
venv/bin/python ingest_shadowserver.py restore       # after a store rebuild (optional: refresh reads the parquet)
# API, once keys exist in .env (SHADOWSERVER_API_KEY / SHADOWSERVER_SECRET):
venv/bin/python ingest_shadowserver.py fetch --date 2026-09-14 [--types sinkhole_http_drone,scan_ssl]
```

Ingest is idempotent by file sha-256 (manifest) **and** by event key; each file
is all-or-nothing (parquet temp+rename, then manifest, then table, then move).
Rows with surplus fields, a missing ip/timestamp, an unparseable timestamp or a
**future** timestamp go to `reference/shadowserver/quarantine/<file>.quarantine.csv`
with a reason; timestamps with `Z` or numeric offsets are normalised to UTC.
`severity` is Shadowserver's own column when present, else by class. Without
keys `fetch` explains and exits 0; a feed outage is logged, never raised.

### Onboarding (how the state gets reports)

Shadowserver sends free daily reports to the **owner of the address space** (or
a CSIRT that can show authority over it). For Louisiana the natural subscriber is
**OTS** (the state's IT agency and owner of the state netblocks), with the cyber
unit / fusion centre as a recipient on OTS's behalf.

1. Assemble the coverage: state-owned prefixes and ASNs from OTS (the
   `reference/registry/ots_cidrs.csv` drop-in), plus any parish/municipal space
   the unit has a written arrangement to receive reports for.
2. Apply at <https://www.shadowserver.org/what-we-do/network-reporting/get-reports/>
   with a contact at the owning organisation; Shadowserver verifies ownership
   against RIR records (or an LOA for delegated space).
3. Daily e-mail reports start; drop the CSVs into `incoming/` and `ingest`.
4. Request API access for the account; put `SHADOWSERVER_API_KEY` and
   `SHADOWSERVER_SECRET` in `.env` (never in code or git).
5. Add `fetch --date $(date -d yesterday +%F)`, `ingest` and `leads.py refresh`
   to the nightly run after the store build.

API notes (`https://transform.shadowserver.org/api2/`): every call is a POST
with a JSON body containing `apikey`; the `HMAC2` header is the hex HMAC-SHA256
of the exact body bytes keyed with the secret. `reports/list` (`date`, optional
`reports`) returns `[{id, timestamp, type, report, file, url}]`;
`reports/download` (`id`) returns the CSV. Report-type reference:
<https://www.shadowserver.org/what-we-do/network-reporting/>.
