# shodan_query

Daily collector for a US state's internet-exposed hosts, built on
[Shodan](https://www.shodan.io). Each night it pulls the day's **delta** of
host records for the configured state and archives them as one gzipped NDJSON
file per day under `daily_downloads/`.

The target state is configurable via `.env` — **default is Louisiana (`LA`)**.

> **Why archive daily?** Shodan's index keeps only each host's *latest* banner.
> Once a host is re-scanned its previous state is gone from Shodan forever. The
> daily delta is the only way to build a longitudinal record, so treat
> `daily_downloads/` as an immutable, irreplaceable system of record.

---

## How it works

Each run merges two queries and de-dupes by Shodan banner `hash`:

| Query | Purpose |
|---|---|
| `state:<CODE> country:US after:<window>` | Primary — geo-located hosts |
| `org:<name> -state:<CODE> after:<window>` | Optional — state-named orgs hosted outside the state (cloud) |

The window is `after:<yesterday> before:<tomorrow>` formatted as **DD/MM/YYYY**
(see Lessons below). Output: `daily_downloads/<name>-events-<YYYY-MM-DD>.json.gz`.

---

## Layout

```
.
├── shodan_query.sh      # the collector (portable, .env-driven)
├── .env                 # your config (gitignored — never commit)
├── .env.example         # config template (defaults to Louisiana)
├── requirements.txt     # shodan
├── daily_downloads/     # the archive (gitignored — keep private, back up)
└── venv/                # virtualenv (gitignored)
```

---

## Setup

```bash
# OS deps (Debian/Ubuntu)
sudo apt update && sudo apt install -y python3-venv

# Virtualenv + Shodan CLI
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# Shodan API key (stored at ~/.config/shodan/api_key — NOT in .env, never commit)
./venv/bin/shodan init <YOUR_API_KEY>
./venv/bin/shodan info        # confirm it works

# Config
cp .env.example .env          # then edit .env to choose the state
```

## Usage

```bash
# Run the collector manually
bash shodan_query.sh
```

To collect a different state, edit `.env` (`SHODAN_STATE_CODE`,
`SHODAN_STATE_NAME`, and the org-rescue settings). Every option is documented
inline in `.env.example`.

## Daily cron (runs as the owning user, e.g. mike)

```cron
30 23 * * * /bin/bash /opt/shodan_query/shodan_query.sh >> /opt/shodan_query/cron.log 2>&1
```

Exit codes: `0` success, `1` setup/primary-query failure, `2` zero records
collected (suspicious — investigate).

---

## ⚠️ Lessons learned (read before changing the query)

1. **Shodan `after:`/`before:` require `DD/MM/YYYY`, NOT ISO.** `after:2026-06-22`
   silently returns ~0 results with no error. Filenames stay ISO; only the query
   filter uses DD/MM/YYYY. Validate any change with
   `./venv/bin/shodan count "state:LA country:US after:<dd/mm/yyyy>"`
   (should be tens of thousands).

2. **History is unrecoverable.** Shodan holds only each host's latest banner — you
   cannot retroactively pull "what was exposed on date X." Only the forward daily
   delta builds history.

3. **The daily query is a delta, not a census.** It captures hosts re-scanned in
   the window (~4k–27k/day for LA), not all hosts in the state.

4. **`shodan count` is free** (no query-credit cost) — use it for all validation.

5. **Org-name matching is unreliable.** `org:<name>` can match firms in other
   states. The org-rescue query is most reliable for states whose name appears in
   org names (e.g. Louisiana); set `SHODAN_ORG_RESCUE=false` otherwise.

---

## Security & hygiene

This project handles a **secret** and **sensitive third-party data**:

- The API key lives at `~/.config/shodan/api_key`, outside the repo — never commit it.
- `.env` and `daily_downloads/` are gitignored — keep them out of git.
- The data lists real organizations' exposed services — **keep the repo private**
  and back the archive up out-of-band.
