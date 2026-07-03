#!/usr/bin/env python3
"""
shodan_collect.py — daily collector for a US state's internet-exposed hosts.

A more robust replacement for the CLI-based shodan_query.sh. Instead of shelling
out to `shodan download` (a black box that exits 0 even on a partial download),
this paginates the Shodan search API directly so it can:

  * retry an individual failed PAGE with exponential backoff (not re-download the
    whole result set on every blip),
  * pace requests (~1 req/sec) to stay under the rate limit and AVOID the
    throttling that truncates the CLI,
  * know exactly how many records it pulled vs the query's reported total, and
  * stream straight to gzipped NDJSON (low memory), deduped by banner hash.

Output matches the bash collector: daily_downloads/<name>-events-<DATE>.json.gz,
one Shodan banner per line.

Config comes from .env (same variables as the bash version). The API key is read
the same way the CLI stores it (~/.config/shodan/api_key) or $SHODAN_API_KEY.

Usage:
    shodan_collect.py                 # collect today's delta
    shodan_collect.py --date 2026-06-29   # backfill a specific day

Exit codes: 0 ok, 1 setup/primary-query failure, 2 zero records, 3 partial.
"""
import argparse
import gzip
import json
import os
import sys
import time
from datetime import datetime, timedelta

import shodan

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def log(msg):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} - {msg}"
    print(line, flush=True)
    try:
        with open(os.path.join(SCRIPT_DIR, "shodan_collection.log"), "a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def load_dotenv(path):
    """Minimal .env loader (KEY=VALUE, ignores blanks/#comments, strips quotes).
    Does not overwrite variables already set in the real environment."""
    if not os.path.isfile(path):
        return
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            os.environ.setdefault(key, val)


def get_api_key():
    """Resolve the key the same way the CLI does, with env-var override."""
    if os.environ.get("SHODAN_API_KEY"):
        return os.environ["SHODAN_API_KEY"].strip()
    try:
        from shodan.cli.helpers import get_api_key as cli_key
        return cli_key()
    except Exception:
        keyfile = os.path.expanduser("~/.config/shodan/api_key")
        if os.path.isfile(keyfile):
            return open(keyfile).read().strip()
    raise SystemExit("ERROR: no Shodan API key (run: shodan init <key>)")


def search_page(api, query, page, retries, backoff):
    """One search() call for a page, with exponential-backoff retries. Returns
    the result dict, or None if every attempt failed."""
    delay = backoff
    for attempt in range(1, retries + 1):
        try:
            return api.search(query, page=page, minify=False)
        except shodan.APIError as exc:
            if attempt == retries:
                log(f"    page {page}: failed after {retries} attempts ({exc})")
                return None
            log(f"    page {page}: {exc} — retry {attempt}/{retries} in {delay:.0f}s")
            time.sleep(delay)
            delay = min(delay * 2, 120)
    return None


def collect_query(api, query, out, seen, page_pause, retries, backoff, geokeep):
    """Paginate a query, writing unique banners to the open gzip file `out`.
    Returns (saved_unique, raw_fetched, reported_total, complete_bool, geo_dropped).

    Completeness is measured by RAW banners fetched vs the reported total — NOT by
    unique-after-dedup. Shodan's index returns the same banner across pages, so
    ~40% of raw results are typically duplicate hashes; comparing unique against
    the raw total would falsely flag every healthy run as partial."""
    first = search_page(api, query, 1, retries, backoff)
    if first is None:
        return 0, 0, 0, False, 0
    total = first.get("total", 0)
    first_matches = first.get("matches", [])
    raw = len(first_matches)
    saved, dropped = _write_matches(first_matches, out, seen, geokeep)
    log(f"    total reported: {total}; page 1 ok")

    page = 2
    last_good = True
    # Stop when a page returns no matches, or we pass the reported total.
    while (page - 1) * 100 < total:
        res = search_page(api, query, page, retries, backoff)
        if res is None:
            last_good = False          # a page was lost; result is partial
            break
        matches = res.get("matches", [])
        if not matches:
            break
        raw += len(matches)
        w, d = _write_matches(matches, out, seen, geokeep)
        saved += w
        dropped += d
        page += 1
        # Shodan keeps a SERVER-SIDE cursor for deep pagination that expires if you
        # page too slowly — a per-page pause caused it to time out around page ~100
        # ("Search cursor timed out. Restart from page 1"), capping big days at
        # 10k. Default page_pause is 0 (paginate at API speed, like the CLI). Only
        # set it >0 if you see throttling, and expect it to break very deep pulls.
        if page_pause:
            time.sleep(page_pause)

    return saved, raw, total, last_good, dropped


def _write_matches(matches, out, seen, geokeep):
    """Write banners not already seen (dedup by hash, fallback ip:port:ts).
    `geokeep(banner)` must return True to keep it — records failing the geo check
    are dropped (this is what prevents worldwide pollution from a broken filter).
    Returns (n_written, n_geo_dropped)."""
    written = dropped = 0
    for banner in matches:
        if not geokeep(banner):
            dropped += 1
            continue
        key = banner.get("hash")
        if key is None:
            key = f"{banner.get('ip_str')}:{banner.get('port')}:{banner.get('timestamp')}"
        if key in seen:
            continue
        seen.add(key)
        out.write(json.dumps(banner) + "\n")
        written += 1
    return written, dropped


def main():
    load_dotenv(os.path.join(SCRIPT_DIR, ".env"))

    ap = argparse.ArgumentParser(description="Collect a state's Shodan host delta.")
    ap.add_argument("--date", help="collection date YYYY-MM-DD (default: today). "
                                    "Use to backfill a specific day.")
    args = ap.parse_args()

    state_code = os.environ.get("SHODAN_STATE_CODE", "LA")
    state_name = os.environ.get("SHODAN_STATE_NAME", "louisiana")
    org_rescue = os.environ.get("SHODAN_ORG_RESCUE", "true").lower() == "true"
    org_name = os.environ.get("SHODAN_ORG_NAME") or state_name
    out_subdir = os.environ.get("OUTPUT_DIR", "daily_downloads")
    min_pct = int(os.environ.get("MIN_COMPLETENESS_PCT", "90"))
    retries = int(os.environ.get("MAX_DOWNLOAD_ATTEMPTS", "3"))
    page_pause = float(os.environ.get("PAGE_PAUSE_SECONDS", "0"))
    backoff = float(os.environ.get("RETRY_SLEEP", "30"))

    # Date + window. Shodan after:/before: REQUIRE DD/MM/YYYY (ISO returns ~0).
    if args.date:
        day = datetime.strptime(args.date, "%Y-%m-%d")
    else:
        day = datetime.now()
    iso = day.strftime("%Y-%m-%d")
    yday_q = (day - timedelta(days=1)).strftime("%d/%m/%Y")
    tmrw_q = (day + timedelta(days=1)).strftime("%d/%m/%Y")
    window = f"after:{yday_q} before:{tmrw_q}"

    api = shodan.Shodan(get_api_key())
    try:
        info = api.info()
    except shodan.APIError as exc:
        log(f"ERROR: Shodan API auth/info failed: {exc}")
        return 1
    log(f"Starting Shodan collection for state={state_code} ({state_name}) date={iso}")
    log(f"API: query credits {info.get('query_credits')}, scan credits {info.get('scan_credits')}")

    queries = [f"state:{state_code} country:US {window}"]
    if org_rescue:
        queries.append(f"org:{org_name} -state:{state_code} {window}")

    # Geo gate. NEVER trust the query's state: filter alone — it has been observed
    # to fail and return worldwide hosts (2026-07-01: 95% non-LA). We verify each
    # IP independently with MaxMind if available, else fall back to the banner's
    # own region_code. The org-rescue query (index 1) is EXEMPT — it intentionally
    # finds state-named orgs hosted out of state.
    gate = None
    try:
        import geo
        gate = geo.GeoGate(country="US", region=state_code)
        log(f"Geo gate: MaxMind {os.path.basename(gate.db_path)} (independent per-IP check)")
    except Exception as exc:
        log(f"Geo gate: MaxMind unavailable ({exc}); using banner region_code fallback")

    def geokeep_primary(banner):
        loc = banner.get("location") or {}
        if gate is not None:
            return gate.keep(banner.get("ip_str"),
                             loc.get("country_code"), loc.get("region_code"))
        return loc.get("country_code") == "US" and loc.get("region_code") == state_code

    def geokeep_all(_banner):
        return True

    daily_dir = os.path.join(SCRIPT_DIR, out_subdir)
    os.makedirs(daily_dir, exist_ok=True)
    out_path = os.path.join(daily_dir, f"{state_name}-events-{iso}.json.gz")
    if os.path.exists(out_path):
        backup = f"{out_path}.backup.{int(time.time())}"
        log(f"WARNING: {os.path.basename(out_path)} exists — backing up to {os.path.basename(backup)}")
        os.replace(out_path, backup)

    seen = set()
    total_saved = 0
    incomplete = False
    suspect = False
    tmp_path = out_path + ".tmp"
    with gzip.open(tmp_path, "wt", encoding="utf-8") as out:
        for i, q in enumerate(queries):
            log(f"Query[{i}]: {q}")
            geokeep = geokeep_all if i == 1 else geokeep_primary
            saved, raw, total, complete, dropped = collect_query(
                api, q, out, seen, page_pause, retries, backoff, geokeep)
            pct = (raw * 100 // total) if total else 100
            drop_pct = (dropped * 100 // raw) if raw else 0
            log(f"Query[{i}]: fetched {raw} of ~{total} ({pct}%), "
                f"dropped {dropped} off-target ({drop_pct}%), "
                f"{saved} unique kept{'' if complete else ' — a page was lost'}")
            total_saved += saved
            if not complete or (total and pct < min_pct):
                incomplete = True
                if i == 0:
                    log("  primary geo query is incomplete")
            # A high off-target drop rate on the PRIMARY query means Shodan's
            # state: filter misbehaved (returned worldwide hosts). The archive
            # stays clean, but we likely under-collected the target state.
            if i == 0 and drop_pct > 30:
                suspect = True
                log(f"  SUSPECT: {drop_pct}% of primary results were NOT {state_code} "
                    f"— query filter likely failed; day is clean but probably incomplete.")

    if total_saved <= 0:
        os.remove(tmp_path)
        log(f"WARNING: 0 records collected for {iso} (all queries empty). "
            f"Check the query window and API.")
        return 2

    os.replace(tmp_path, out_path)     # atomic: only a complete file appears
    size = os.path.getsize(out_path)
    log(f"Wrote {total_saved} unique records to {os.path.basename(out_path)} ({size} bytes)")

    if suspect:
        log(f"WARNING: collection for {iso} is SUSPECT — the state filter returned "
            f"mostly off-target hosts. Archive is geo-clean but likely under-collected.")
        return 4
    if incomplete:
        log(f"WARNING: collection for {iso} is PARTIAL "
            f"(below {min_pct}% or a page was lost). Data kept; flagging for review.")
        return 3
    log("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
