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
| leads + event log | `store/leads/leads.duckdb` (tables `leads` — `lead_id` PRIMARY KEY — and `lead_events`) | table `leads`, re-published by every `refresh`/`set` — a convenience copy |
| lead snapshots | `store/leads/snapshots/<generation>/{leads,lead_events}.parquet`; `store/leads/CURRENT` names the generation to restore from; the newest 5 are kept | — |
| Shadowserver events | `store/shadowserver/events.parquet` + `store/shadowserver/manifest.json` | table `shadowserver_events`, re-published by every `ingest` run and by `restore`; **`leads.py` reads the parquet, never the table** |

Durability rules: `refresh` applies all changes in one transaction, then writes
a new snapshot generation (nothing existing is replaced), then publishes
`CURRENT` atomically, then re-publishes the store copy. `set` writes the
snapshot **inside** its transaction, before commit; if the snapshot fails the
change is rolled back and reported as not saved; if the commit fails the
snapshot is discarded and `CURRENT` is untouched. If `leads.duckdb` is lost,
`refresh` restores from the generation `CURRENT` names. **Migration:** the first
run on a fresh `leads.duckdb` imports a legacy `leads` table from the store
transactionally and maps old KEV lead ids (no CVE in the hash) onto the new
per-CVE leads: a legacy lead in suppressed / false_positive / notified /
acknowledged passes its status (and notification fields) to every per-CVE lead
of that service that exists at migration time, with a `migrated_from` event; if
the legacy lead covered more than one CVE the new leads are flagged
`needs_attribution_review`.

## Vocabulary

| Term | Meaning |
|---|---|
| **lead** | one (ip, port, transport, evidence_type[, cve]) with a reason to notify; `lead_id = sha1("ip\|port\|transport\|evidence_type[\|cve]")[:16]` — the CVE is part of the identity for `kev_verified` / `kev_inferred` |
| **host-level lead** | `port 0`, `transport 'host'` — a threat-intel listing, a compromise flag whose archive carries no port, every Shadowserver *compromise*-class event (its `port` column is the infected host's **source** port, never an exposed service) |
| **tier** | the host's consequence tier from its **newest observation** in `latest_observed`; for a host not in the store, derived from the registry sector |
| **eligible / eligibility_reason** | decided once per ip per refresh from that tier: `residential` and `honeypot` hosts are never notification targets. Ineligibility **never changes status** — the lead is hidden from `list`/packets/digest (`list --include-ineligible` shows it); `prior_status` records the status at the flip; when the host is eligible again the lead simply reappears with its status intact (a `false_positive` stays a `false_positive`) |
| **attribution** (`org_id`, `org_name`, `sector`, `attr_method`, `attr_confidence`) | registry `ip_attribution.parquet` as recorded → the store's `attr_*` columns → Shodan `org` as `shodan_org`/`low` → `unattributed`/`none`. Carried separately from evidence confidence |
| **owner change** | between refreshes the attributed `org_id` changes (both non-empty) **or** attribution confidence drops: the notification episode is closed (`owner_changed` event with the old org and notification history), status → `new` (`prior_status` kept), `notified_on`/`notified_via`/`analyst` cleared, `needs_attribution_review = true`. Packets refuse the lead until `set <id> --review-cleared` |
| **whole-address ownership** | `attr_method` in `ots_cidr` / `registry_network` with `high` confidence — the only case in which a packet may list *other* services on the address |
| **first_seen / last_evaluated** | refresh dates: when the lead was first raised / last looked at |
| **last_seen / last_scan_ts** | the newest **scan** supporting the lead: `banner_ts` (collection date only when `banner_ts` is null); the tripwire ledger's `last_banner_ts`; the Shadowserver event time. A re-collected cached banner is not a newer scan |
| **severity / evidence_key** | the evidence's own severity; the CVE, appliance label, tripwire selectors, `compromise:<types>` / `exposure:<types>`, IOC feeds |

### Status lifecycle

```
new ──► queued ──► notified ──► acknowledged ──► remediated ──► (NEWER SCAN) ──► new
  └──► disputed | false_positive | suppressed          (analyst decisions)
any ──► new [+ needs_attribution_review]               (owner change / attribution drop)
```

| status | set by | meaning |
|---|---|---|
| `new` | refresh | generated, nobody has looked at it |
| `queued` | analyst | selected for a packet |
| `notified` | analyst (`set --status notified --via ...`) | packet sent; `notified_on` stamped the first time in an episode |
| `acknowledged` | analyst | the owner confirmed receipt |
| `remediated` | refresh | a `notified`/`acknowledged` lead whose **specific service** is `gone` in `exposure_status` (>45 days unseen); a host-level lead needs **every** service of the host gone; stale is not remediated |
| `disputed` / `false_positive` / `suppressed` | analyst | terminal decisions, never overwritten by refresh |

`refresh` never overwrites an analyst-set status; a `remediated` lead is reopened
only by a **newer scan** (`last_scan_ts` advances) and that starts a **new
episode** (`notified_on`/`notified_via` cleared, the previous episode recorded in
`notes` and `lead_events`). Every change is appended to `notes` with its date
and logged to `lead_events(ts, lead_id, event, detail)` (`created`, `status`,
`reopened`, `remediated`, `ineligible`, `eligible_again`, `owner_changed`,
`review_cleared`, `imported_legacy`, `migrated_legacy_id`, `migrated_from`).

## Evidence types and confidence

| evidence_type | confidence | rule | tiers |
|---|---|---|---|
| `kev_verified` | high | a CISA-KEV CVE that Shodan itself **verified** on the host; one lead per CVE | all eligible |
| `compromise_tag` | high | host in `compromise_hits/seen_ledger.json` with `last_seen` in the last **30 days**; port/transport from the hit archives, else host-level; scan time = ledger `last_banner_ts` | all eligible |
| `shadowserver` | high (compromise) / medium (exposure) | an event in `store/shadowserver/events.parquet` in the last **14 days**. Compromise-class (sinkhole / drone / microsoft_sinkhole / spam / compromised_website / malware_url / botnet / cc …) → host-level, "possible infection" wording. Exposure-class (scan_* / vulnerable_* / exposed_* / open_* / accessible_* / ics / blocklist …) → per exposed port, "exposure to verify" wording. Unknown types → exposure (the weaker claim) | all eligible |
| `ics` | medium | an ICS scan module, an ICS port (`triage_report.ICS_PORTS`) or Shodan's `ics` tag — never on a honeypot | all eligible |
| `appliance` | medium | `build_store.APPLIANCE_PATTERNS` — the **same** regex list the `appliance_exposure` view uses — over product / cpe23 / http_title | priority tiers only |
| `kev_inferred` | medium | a KEV CVE inferred from the banner version, **not** verified; one lead per CVE | priority tiers only |
| `ioc_match` | medium | the host appears in the store's `ioc_matches` view — exact-ip hits **and** CIDR-range hits (Spamhaus DROP etc.); host-level, evidence names feeds and ranges. Fallback without the view: the JSON's ip keys (never `_cidrs` / `_meta`) against `current_state` | all eligible |
| `cred_leak` | — | reserved; accepted by `set`, never generated | — |

Ranking (`list`, packets): `kev_verified` > `compromise_tag` > `shadowserver` >
`ics` > `appliance` > `kev_inferred` > `ioc_match`, then severity, then EPSS of
the lead's own CVE (or the service's worst), then tier.

## Running

```bash
cd /opt/shodan_query
venv/bin/python leads.py refresh                 # after the nightly store build; idempotent
venv/bin/python leads.py refresh --dry-run
venv/bin/python leads.py list --limit 20         # flags: R = needs attribution review, X = ineligible
venv/bin/python leads.py list --tier government --status new
venv/bin/python leads.py list --org "ORG-CT" --include-ineligible
venv/bin/python leads.py set <lead_id> --status notified --via MS-ISAC --analyst jd --note "packet LA-EXP-..."
venv/bin/python leads.py set <lead_id> --status acknowledged --note "CISO replied"
venv/bin/python leads.py set <lead_id> --review-cleared --analyst jd     # after confirming a changed attribution
venv/bin/python leads.py digest                  # per-sector counts, needs-review, attribution mix, remediation stats
venv/bin/python leads.py digest --weekly --out reports/leads_digest_$(date +%F).md
```

`refresh` prints a per tier / evidence / status summary of eligible leads, the
hidden (ineligible) and needs-review counts, the attribution-confidence mix and
the excluded aggregates. Options `--leads-dir`, `--ledger`, `--hits-dir`,
`--ioc`, `--attribution`, `--ss-parquet`, `--today` exist for tests.

### The digest — measuring remediation

Per sector (ineligible leads excluded): counts per status, needs-review count,
attribution confidence mix, and three distributions — **days-to-disappear**
(lead `first_seen` → the service's last observation, for services now `gone`),
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
until the reviewer block is completed (second reviewer **REQUIRED** for a
compromise claim). Contents follow the Fletcher / Ochsner notices: header (TLP
placeholder, reference, priority); what we observed — per lead: ip, port,
service, evidence type, exact evidence, scan age, **exposure state** (currently
active / stale / no longer observed with the last-observed date), attribution
basis and confidence, status ("previously notified on <date>" for
notified/acknowledged); a "no longer observed — historical" table for new/queued
leads whose service is gone; what this is not; prioritised actions by evidence
class (Shadowserver compromise vs exposure wording; ICS: "protocols typically
have no authentication; reachability alone is a serious exposure that must be
verified"); how to verify; contact/handling; reviewer sign-off; Appendix A.

Refusals (all re-checked in `make_packet`, independently of `leads.py`):
ineligible leads; leads flagged `needs_attribution_review`; leads whose host's
**current** tier in `latest_observed` is residential/honeypot; more than one
attributed organisation among the selected leads (listed); `--org unattributed`.
Lead rows on one address are read in `last_evaluated` order and a disagreement
on the owner is reported as an **attribution conflict** (never "last row
wins"). **Cross-tenant safety:** Appendix A always lists the lead services; it
lists *other* services on an address only when that address has whole-address
ownership recorded for the recipient, otherwise it says "other services on this
address omitted: shared/unresolved ownership". Attribution is stated as recorded
(registry method/confidence; Shodan org shown as a low-confidence label; else
"unattributed" — never promoted from a certificate name). Every external string
(ip, port, transport, product, title, hostnames, org, evidence, dates, ids) is
validated or escaped at the rendering boundary. Record the send with
`leads.py set`.

## Shadowserver

```bash
mkdir -p reference/shadowserver/incoming
cp ~/2026-09-14-sinkhole_http_drone-louisiana.csv reference/shadowserver/incoming/
venv/bin/python ingest_shadowserver.py ingest --dry-run
venv/bin/python ingest_shadowserver.py ingest [--wait]   # parquet + manifest, table re-published, file -> processed/
venv/bin/python leads.py refresh
venv/bin/python ingest_shadowserver.py restore           # re-create the store table after a rebuild
# API, once keys exist in .env (SHADOWSERVER_API_KEY / SHADOWSERVER_SECRET):
venv/bin/python ingest_shadowserver.py fetch --date 2026-09-14 [--types sinkhole_http_drone,scan_ssl]
```

One `ingest` run holds `store/shadowserver/.ingest.lock` (`fcntl.flock`) from
manifest read through dedupe, parquet publish, manifest write and input move; a
second ingester exits cleanly with code 3 (or waits with `--wait`) and never
proceeds without the lock. File identity is `<sha256>:<report_type>` (report
type from the original filename, recorded in the manifest — never from the
processed name); events dedupe on `(report_type, timestamp, ip, port, protocol,
tag)`. Each file is all-or-nothing: parquet written to a pid-unique temp file
and renamed, then the manifest, then the store table is re-published; if that
publication fails the input **stays in incoming/** and is retried next run (the
table is also re-published at the end of every run). Rows with surplus fields,
a missing/invalid ip, a port outside 0–65535, a garbage protocol (known values
tcp/udp/icmp; other alphabetic names become `other` with the raw value kept in
`detail`), a missing/unparseable timestamp or a **future** timestamp go to
`reference/shadowserver/quarantine/<file>.quarantine.csv` with a reason;
timestamps with `Z` or numeric offsets are normalised to UTC.

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
