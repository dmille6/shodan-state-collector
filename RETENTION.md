# Data retention policy — DRAFT (requires records/legal sign-off)

> This is a starting-point policy for review by the agency's **records officer**
> and **legal/privacy counsel**. Bracketed `[…]` values are decisions for them,
> not defaults to adopt blindly. Do not enable automated deletion until this is
> approved.

## Data layers
| Layer | Location | Rebuildable? |
|---|---|---|
| Raw archive | `daily_downloads/*.json.gz` | No — **irreplaceable** (Shodan keeps only each host's latest banner) |
| Analytical store | `store/` (Parquet + DuckDB) | Yes — reparsed from the raw archive |
| Enrichment caches | `reference/` (KEV, EPSS) | Yes — public feeds |

## Guiding principles
1. **The raw archive is the system of record.** It cannot be re-pulled. Loss = a
   permanent hole in the longitudinal record. Protect and back it up out-of-band.
2. **Retention is not purely technical.** It is bounded by (a) the state records
   retention schedule, (b) evidence/litigation holds, and (c) privacy / data
   minimization — especially for data about private citizens.

## Proposed retention (for legal/records to confirm)

### By sector tier — differential retention
Because the collection includes **private residential hosts** (citizens' home
devices), indefinite retention of that data is a different posture than retaining
government/critical-infrastructure exposure. Recommended:

| Tier | Raw + store retention | Rationale |
|---|---|---|
| Government / critical infrastructure / education | **Indefinite** `[confirm]` | Core mission; longitudinal value for trend/dwell/remediation tracking |
| Small business | `[12–36 months]` | Useful for regional trends; less mission-critical |
| Residential | `[12–24 months, or purge-unless-case-linked]` | Privacy / data minimization for citizen devices |

Records tied to an **active investigation** are exempt from routine disposition
and preserved per evidence-hold procedures (with chain-of-custody handling),
regardless of tier.

### Storage tiering (independent of the retention *policy*)
- **Hot** (last `[12–24]` months): local disk, in the DuckDB/Parquet store, for
  fast daily analytics.
- **Cold** (older, still within retention): compressed raw `.gz` offloaded to
  `[object storage / NAS]`; re-attachable to DuckDB when history is needed.

## Privacy / civil-liberties note
This dataset maps IP addresses (including residential) over time. For a
law-enforcement unit, treat residential data with data-minimization discipline:
collect for defensive exposure monitoring, retain only as long as justified, and
gate access. Legal/privacy counsel should confirm the residential retention
window and any minimization (e.g., dropping residential rows after `[N]` months
unless linked to a case).

## Open decisions for records/legal
- [ ] Confirm applicable state records retention schedule item(s).
- [ ] Set residential / small-business retention windows.
- [ ] Approve (or reject) automated disposition after the retention window.
- [ ] Define evidence-hold carve-out and chain-of-custody handling.
- [ ] Approve cold-storage location and access controls.
