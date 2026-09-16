#!/usr/bin/env python3
"""
compromise_watch.py — daily compromise tripwire for the target state.

The main collector (shodan_collect.py) pulls the state's whole exposure census —
every internet-facing host, most of them merely *exposed* or *vulnerable*. This
script is the complement: it asks Shodan specifically for hosts it has flagged as
COMPROMISED / malicious, using Shodan's own threat tags and categories:

    state:<CODE> country:US tag:compromised
    state:<CODE> country:US tag:malware
    state:<CODE> country:US tag:c2
    state:<CODE> country:US tag:botnet
    state:<CODE> country:US category:malware

For Louisiana these return a near-empty set on any given day (0-2 hosts), which is
exactly the point: a tripwire that is normally silent and screams when a genuinely
bad host appears. Every hit is a confirmed Shodan threat flag, not a version-
inference lead — far higher signal than the CVE census.

Cost: each selector is sized first with a FREE `shodan count`; a paid `search`
(1 query credit/page) runs ONLY when the count is > 0, so a quiet day costs zero
query credits. Hits are archived to compromise_hits/<state>-compromise-<date>.json.gz
(full banners) and summarised to a .txt alert next to it; the run also prints a
loud ALERT block so it stands out in cron.log.

Usage:
    compromise_watch.py                  # check today
    compromise_watch.py --date 2026-07-08
    compromise_watch.py --dry-run        # counts only, spend zero credits, no archive

A persistent ledger (compromise_hits/seen_ledger.json) records every flagged host
and its first-seen date, so each run separates NEW hosts (loud alert, exit 10) from
ONGOING ones Shodan has been flagging for days (one quiet line, exit 0). Recurring
stale hits therefore no longer cause nightly alert fatigue, and a genuinely new
compromised host stands out. Hosts that stop being flagged are noted as CLEARED.

Exit codes: 0 clean or ongoing-only (nothing new), 10 NEW or RECURRED hit(s) —
investigate (takes precedence over 5), 5 provider failure with nothing new (a
count or search failed: the run is INCOMPLETE and nothing was marked cleared),
1 setup error. Incompleteness is always also written to the alert file and to
the ledger (_meta.last_run_incomplete).
"""
import argparse
import gzip
import json
import os
import sys
import time
from datetime import datetime

import shodan

# Reuse the collector's config/key plumbing (importing runs only defs — its main()
# is guarded by __main__), so the tripwire reads the same .env and API key.
from shodan_collect import load_dotenv, get_api_key

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(SCRIPT_DIR, "compromise_watch.log")
# Persistent state so the tripwire can tell a genuinely NEW compromised host from
# one Shodan has been flagging for days. Lives inside compromise_hits/ (gitignored,
# FOUO) since it records flagged IPs/first-seen dates. Rebuildable-ish, not secret.
LEDGER_PATH = os.path.join(SCRIPT_DIR, "compromise_hits", "seen_ledger.json")


def log(msg):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} - {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def build_selectors():
    """Compromise selectors from .env (overridable), scoped to the target state.
    Returns a list of (label, shodan_query) pairs."""
    tags = [t.strip() for t in os.environ.get(
        "COMPROMISE_TAGS", "compromised,malware,c2,botnet").split(",") if t.strip()]
    cats = [c.strip() for c in os.environ.get(
        "COMPROMISE_CATEGORIES", "malware").split(",") if c.strip()]
    extra = [q.strip() for q in os.environ.get(
        "COMPROMISE_EXTRA_QUERIES", "").split(";") if q.strip()]
    return tags, cats, extra


def count(api, query, retries=3, backoff=15):
    """Free result count for a query, with retry. -1 if it can't be sized."""
    delay = backoff
    for attempt in range(1, retries + 1):
        try:
            return api.count(query).get("total", 0)
        except shodan.APIError as exc:
            if attempt == retries:
                log(f"    count failed after {retries} attempts ({exc})")
                return -1
            time.sleep(min(delay, 30))
            delay *= 2
    return -1


def search_all(api, query, retries=3, backoff=15, max_pages=50):
    """Page a (small) compromise query fully. Returns (banners, complete).
    complete is False when a page failed after retries, a page came back empty
    before the reported total was reached, or the page cap was hit — in every
    such case the banners already fetched are still returned, but the caller
    must treat the selector as FAILED (nothing may be marked cleared)."""
    banners = []
    page = 1
    while True:
        if page > max_pages:
            log(f"    page cap ({max_pages}) reached — result truncated")
            return banners, False
        delay = backoff
        res = None
        for attempt in range(1, retries + 1):
            try:
                res = api.search(query, page=page, minify=False)
                break
            except shodan.APIError as exc:
                if attempt == retries:
                    log(f"    page {page}: failed after {retries} attempts ({exc})")
                    return banners, False
                time.sleep(min(delay, 30))
                delay *= 2
        matches = (res or {}).get("matches", [])
        total = (res or {}).get("total", 0)
        if not matches:
            return banners, (page - 1) * 100 >= total     # empty page early = truncated
        banners.extend(matches)
        if page * 100 >= total:
            return banners, True
        page += 1


def summarize_host(h):
    """One-line human summary of a compromised host for the alert file/log."""
    ports = ",".join(str(p) for p in sorted(h["ports"]))
    tags = ",".join(sorted(h["tags"])) or "-"
    cves = ",".join(sorted(h["vulns"])[:5]) or "-"
    host = (h["hostnames"] or [""])[0]
    return (f"{h['ip']:>39}  {(h['org'] or '?')[:28]:28}  {(h['city'] or '?')[:14]:14}  "
            f"tags[{tags}]  ports[{ports}]  matched[{','.join(sorted(h['selectors']))}]  "
            f"host[{host}]  cves[{cves}]")


def load_ledger():
    """Load the seen-host ledger; return an empty skeleton if missing/corrupt."""
    try:
        with open(LEDGER_PATH) as fh:
            data = json.load(fh)
        data.setdefault("hosts", {})
        data.setdefault("_meta", {})
        return data
    except (OSError, ValueError):
        return {"hosts": {}, "_meta": {}}


def save_ledger(ledger):
    """Atomically persist the ledger next to the hit archives."""
    os.makedirs(os.path.dirname(LEDGER_PATH), exist_ok=True)
    tmp = LEDGER_PATH + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(ledger, fh, indent=2, sort_keys=True)
    os.replace(tmp, LEDGER_PATH)


def reconcile(hosts, ledger, iso, failed=()):
    """Split this run's hits against the ledger and roll the ledger forward.
    Returns (new_ips, ongoing_ips, cleared_ips, recurred_ips), all sorted.

      new       never in the ledger
      recurred  in the ledger but NOT in the previous run's active set — it had
                cleared and is back, which is as alarming as new
      ongoing   in the previous run's active set
      cleared   in the previous active set, absent now — ONLY when no selector
                failed; a provider failure carries the active set forward
                unchanged, because "no result" is not "resolved".
    Every host seen is recorded (first_seen preserved) regardless of failures."""
    prior_hosts = ledger["hosts"]
    prev_active = set(ledger["_meta"].get("last_run_active", []))
    current_active = set(hosts)

    new_ips = sorted(ip for ip in hosts if ip not in prior_hosts)
    recurred_ips = sorted(ip for ip in hosts if ip in prior_hosts and ip not in prev_active)
    ongoing_ips = sorted(ip for ip in hosts if ip in prev_active)
    cleared_ips = [] if failed else sorted(prev_active - current_active)

    for ip, h in hosts.items():
        banner_ts = max((b.get("timestamp") or "" for b in h["banners"]), default="")
        rec = prior_hosts.get(ip) or {"first_seen": iso}
        rec["last_seen"] = iso
        rec["selectors"] = sorted(set(rec.get("selectors", [])) | set(h["selectors"]))
        if banner_ts:
            rec["last_banner_ts"] = banner_ts
        prior_hosts[ip] = rec
    if failed:
        # Keep hosts we could not re-check as active; add the ones we did see.
        ledger["_meta"]["last_run_active"] = sorted(prev_active | current_active)
        ledger["_meta"]["last_run_incomplete"] = {"date": iso, "failed": sorted(failed)}
    else:
        ledger["_meta"]["last_run_active"] = sorted(current_active)
        ledger["_meta"].pop("last_run_incomplete", None)
    ledger["_meta"]["last_run_date"] = iso
    return new_ips, ongoing_ips, cleared_ips, recurred_ips


def staleness_note(banner_ts, iso):
    """Flag when Shodan's flagged banner is old — the tag persists on a cached
    scan, so a recurring hit isn't necessarily a fresh observation."""
    if not banner_ts:
        return ""
    try:
        bt = datetime.strptime(banner_ts[:10], "%Y-%m-%d")
        rt = datetime.strptime(iso, "%Y-%m-%d")
        days = (rt - bt).days
    except ValueError:
        return ""
    if days >= 2:
        return f"  (Shodan last scanned {banner_ts[:10]}, {days}d ago — cached view)"
    return ""


def main():
    load_dotenv(os.path.join(SCRIPT_DIR, ".env"))

    ap = argparse.ArgumentParser(description="Daily compromise tripwire for a state.")
    ap.add_argument("--date", help="label date YYYY-MM-DD (default: today). The "
                                    "compromise tags are current-state, not a date "
                                    "window — this only names the output file.")
    ap.add_argument("--dry-run", action="store_true",
                    help="counts only: spend zero query credits, write no archive")
    args = ap.parse_args()

    state_code = os.environ.get("SHODAN_STATE_CODE", "LA")
    state_name = os.environ.get("SHODAN_STATE_NAME", "louisiana")
    iso = args.date or datetime.now().strftime("%Y-%m-%d")
    scope = f"state:{state_code} country:US"

    tags, cats, extra = build_selectors()
    selectors = ([("tag:" + t, f"{scope} tag:{t}") for t in tags]
                 + [("category:" + c, f"{scope} category:{c}") for c in cats]
                 + [(q, f"{scope} {q}") for q in extra])

    try:
        api = shodan.Shodan(get_api_key())
        info = api.info()
    except Exception as exc:
        log(f"ERROR: Shodan API auth/info failed: {exc}")
        return 1

    log(f"Compromise watch for state={state_code} ({state_name}) date={iso}"
        f"{' [DRY-RUN]' if args.dry_run else ''}")
    log(f"API: query credits {info.get('query_credits')}")

    # Optional independent geo gate (same union logic as the collector) — never
    # trust the state: filter alone. If MaxMind is unavailable, keep everything
    # (compromise hits are too valuable to drop on a missing DB).
    gate = None
    try:
        import geo
        gate = geo.GeoGate(country="US", region=state_code)
    except Exception as exc:
        log(f"Geo gate: MaxMind unavailable ({exc}); keeping all hits (state filter only)")

    def in_state(banner):
        if gate is None:
            return True
        loc = banner.get("location") or {}
        return gate.keep(banner.get("ip_str"), loc.get("country_code"), loc.get("region_code"))

    hosts = {}                 # ip -> aggregated host record
    total_matches = 0
    off_target = 0
    failed = []                # selectors whose count or search FAILED (not "zero")
    for label, query in selectors:
        n = count(api, query)
        log(f"  {label:22} count={n if n >= 0 else 'ERR'}")
        if n < 0:
            failed.append(label)
            continue
        if n == 0:
            continue
        if args.dry_run:
            continue
        banners, complete = search_all(api, query)
        if not complete:
            failed.append(label)
            log(f"    {label}: search INCOMPLETE — {len(banners)} banner(s) kept, selector marked FAILED")
        got = 0
        for banner in banners:
            got += 1
            total_matches += 1
            if not in_state(banner):
                off_target += 1
                continue
            ip = banner.get("ip_str")
            if not ip:
                continue
            h = hosts.setdefault(ip, {
                "ip": ip, "org": banner.get("org"), "isp": banner.get("isp"),
                "city": (banner.get("location") or {}).get("city"),
                "ports": set(), "tags": set(), "hostnames": [], "vulns": set(),
                "selectors": set(), "banners": []})
            h["org"] = h["org"] or banner.get("org")
            h["city"] = h["city"] or (banner.get("location") or {}).get("city")
            if banner.get("port") is not None:
                h["ports"].add(banner["port"])
            h["tags"].update(banner.get("tags") or [])
            for hn in (banner.get("hostnames") or []):
                if hn not in h["hostnames"]:
                    h["hostnames"].append(hn)
            h["vulns"].update(banner.get("vulns") or {})
            h["selectors"].add(label)
            banner["_compromise_selector"] = label
            h["banners"].append(banner)
        if got == 0 and complete:
            # count said > 0 but the paid search returned nothing: a provider
            # failure, not an empty result. Must not be read as "cleared".
            failed.append(label)
            log(f"    {label}: count={n} but search returned no banners — treating as FAILED")

    n_hits = len(hosts)

    if args.dry_run:
        log("Dry-run complete — counts above only (no credits spent, nothing archived).")
        return 0

    # --- Reconcile against the ledger: NEW / RECURRED / ONGOING / CLEARED. ---
    ledger = load_ledger()
    prior_hosts = ledger["hosts"]
    new_ips, ongoing_ips, cleared_ips, recurred_ips = reconcile(hosts, ledger, iso, failed)

    if failed:
        log(f"WARNING: {len(failed)} selector(s) FAILED ({', '.join(failed)}) — this run is "
            f"INCOMPLETE: nothing is marked cleared, the active set is carried forward.")
    if cleared_ips:
        log(f"NOTE: {len(cleared_ips)} previously-flagged host(s) no longer flagged: "
            f"{', '.join(cleared_ips)}")
    if recurred_ips:
        log(f"NOTE: {len(recurred_ips)} host(s) flagged AGAIN after having cleared: "
            f"{', '.join(recurred_ips)} — treated as new.")
    new_ips = sorted(set(new_ips) | set(recurred_ips))

    if n_hits == 0:
        save_ledger(ledger)
        if failed:
            log(f"Tripwire INCOMPLETE for {iso}: no hits seen, but {len(failed)} selector(s) failed.")
            return 5
        log(f"No compromise-flagged hosts in {state_code} for {iso}. Tripwire quiet."
            f"{f' ({off_target} off-target match(es) dropped by geo gate)' if off_target else ''}")
        return 0

    # --- HITS present: archive full banners + write a human alert. Archiving is
    # unconditional (a daily record that the host was still flagged), but the LOUD
    # block + exit 10 fire only when something is genuinely NEW. ---
    hits_dir = os.path.join(SCRIPT_DIR, "compromise_hits")
    os.makedirs(hits_dir, exist_ok=True)
    gz_path = os.path.join(hits_dir, f"{state_name}-compromise-{iso}.json.gz")
    txt_path = os.path.join(hits_dir, f"{state_name}-compromise-{iso}.txt")

    tmp = gz_path + ".tmp"
    with gzip.open(tmp, "wt", encoding="utf-8") as out:
        for h in hosts.values():
            for banner in h["banners"]:
                out.write(json.dumps(banner) + "\n")
    os.replace(tmp, gz_path)

    def line(ip):
        h = hosts[ip]
        note = staleness_note(prior_hosts[ip].get("last_banner_ts"), iso)
        if ip in recurred_ips:
            status = f"[RECURRED, first {prior_hosts[ip].get('first_seen', '?')}]"
        elif ip in new_ips:
            status = "[NEW]"
        else:
            status = f"[ongoing since {prior_hosts[ip].get('first_seen', '?')}]"
        return f"{status:28} {summarize_host(h)}{note}"

    with open(txt_path, "w") as fh:
        fh.write(f"COMPROMISE ALERT — {state_code} — {iso}\n")
        fh.write(f"{len(new_ips)} NEW (incl. {len(recurred_ips)} recurred), {len(ongoing_ips)} ongoing, "
                 f"{len(cleared_ips)} cleared. Shodan compromise flags (tag/category).\n")
        if failed:
            fh.write(f"RUN INCOMPLETE: selector(s) failed: {', '.join(failed)} — nothing marked cleared; "
                     f"previously active hosts carried forward.\n")
        fh.write("\n")
        for ip in new_ips + ongoing_ips:
            fh.write(line(ip) + "\n")
        for ip in cleared_ips:
            fh.write(f"[CLEARED]                    {ip} — no longer flagged\n")

    save_ledger(ledger)

    if new_ips:
        # Precedence: a NEW/RECURRED hit outranks an incomplete run — exit 10 so
        # the alert fires; incompleteness is recorded in the alert file, the log
        # and the ledger (_meta.last_run_incomplete) so it is not lost.
        bar = "=" * 72
        log(bar)
        log(f"⚠  COMPROMISE ALERT: {len(new_ips)} NEW flagged host(s) in {state_code} "
            f"on {iso}  ({len(ongoing_ips)} ongoing){' — RUN INCOMPLETE, see above' if failed else ''}")
        for ip in new_ips:
            log("   " + line(ip))
        if ongoing_ips:
            log(f"   ongoing (already known): {', '.join(ongoing_ips)}")
        log(f"   archived: {os.path.relpath(gz_path, SCRIPT_DIR)}  |  alert: {os.path.relpath(txt_path, SCRIPT_DIR)}")
        log(bar)
        return 10

    # Only known hosts, nothing new — stay quiet (one line, exit 0) to avoid fatigue.
    log(f"Tripwire: {len(ongoing_ips)} ongoing flagged host(s), 0 new "
        f"({', '.join(ongoing_ips)}). No new alert. Archived {os.path.relpath(gz_path, SCRIPT_DIR)}.")
    return 5 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
