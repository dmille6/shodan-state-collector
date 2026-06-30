# Roadmap — long-term direction

This project started as a 30-day evaluation: a bash collector around the Shodan
CLI, run by cron, archiving one gzipped NDJSON file per day. That is right-sized
for an experiment. This document records where to take it **if** it graduates
from experiment to a system of record — in priority order, so the highest-value,
lowest-effort work comes first.

See also the original POC roadmap (analytical store, dashboard, CVE enrichment)
in the parent project's README; this file focuses on the **collection and
operations** layer, which that roadmap does not cover.

---

## 1. Replace the CLI with the Shodan Python library  ⭐ highest leverage

**Why:** `shodan download` is a black box that exits 0 even on a partial
download (the night-1 failure: it saved ~5% of results and reported success).
We can only detect that after the fact by counting lines and re-running the
entire query.

**What:** collect via the library's paginated cursor instead:

```python
api = shodan.Shodan(key)
for banner in api.search_cursor('state:LA country:US after:.. before:..'):
    ...
```

`search_cursor` **raises** on API errors instead of silently truncating, so you
can retry the *failed page* (cheap) rather than the whole 30k-result download
(expensive), and you know exactly how many records you pulled vs expected. Same
output format (gzipped NDJSON), same dedup — a Python collector replacing the
bash-around-CLI. This removes an entire class of silent-failure bugs.

## 2. Operational robustness

- **Date-parameterized, idempotent collector.** `--date YYYY-MM-DD` makes
  backfilling a specific day a first-class operation (we have already needed
  this twice). Skip if a day is already complete; re-pull if it is partial.
- **systemd timer instead of cron.** Gains: journald logging, `OnFailure=` hooks
  for alerting, and `Persistent=true` so a *missed* night (e.g. box rebooting at
  23:30) is caught up rather than silently skipped.
- **Dead-man's-switch.** cron/systemd can report a run that *failed*; neither
  reports a run that *never happened*. A daily healthcheck ping (healthchecks.io
  or self-hosted) that alerts on silence closes that gap — critical for an
  archive whose entire value is "no missing days."
- **Per-day manifest/index** (SQLite or JSON sidecar): record `expected_count`,
  `saved_count`, `status`, and `sha256` per day. Then "which days are missing or
  partial and need backfill?" is one query instead of eyeballing a directory.

## 3. Reproducibility — containerize

The current setup pins `setuptools<81` against the host's Python 3.14 to work
around `pkg_resources` removal. That is fragile. A Dockerfile pinning Python
3.12 + an exact `shodan==` version makes the collector run identically on any
host, survives an OS Python upgrade, and erases "works on my machine" risk. Run
it via `docker run` from the timer.

## 4. Analytical layer (from the POC roadmap)

Keep the raw `.gz` as the immutable archive; add a **DuckDB + Parquet** layer
loaded nightly (observations + vulns tables, derived current-state and
dwell-time). The current approach re-parses every file on each query and will
not scale. This unlocks trend/dwell-time/remediation analysis.

## 5. Bigger architectural question — only if this becomes load-bearing

The daily `after:/before:` delta via search-download is fine at this scale. If
continuous full-state coverage becomes important, the **supported** tools for
that are different and worth a conversation with Shodan:

- **Shodan Stream API** (`/shodan/stream`) — a real-time firehose of banners as
  they are scanned, filtered by country. No pagination, no partial-download
  problem at all. But it is a long-running **daemon**, not a cron job, and needs
  a streaming/Enterprise subscription.
- **Shodan Bulk Data / Enterprise** — sold for exactly this systematic at-scale
  archival use case.

---

## Suggested order

`1 → 2 → 3 → 4`. Items 1 and 2 are roughly a half-day each and remove ~90% of
the operational risk; 3 and 4 are for when this becomes infrastructure rather
than an experiment. Item 5 is a procurement/architecture decision, not code.
