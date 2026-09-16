#!/usr/bin/env python3
"""
discover_domains.py — domain-driven host discovery from certificate transparency.

For every seed domain query crt.sh for every certificate name under the seed,
collect the distinct DNS names (wildcards stripped), RESOLVE them to A/AAAA
addresses, and write:

    reference/discovery/discovered_hosts.csv    name, seed, ip, resolved_at, source,
                                                first_seen, last_seen
    reference/discovery/discovered_domains.csv  registered_domain, seed, first_seen, last_seen

Seeds, in priority order (a capped run does the important ones first):
    1. la.gov, k12.la.us
    2. triage_report.LA_EDU_DOMAINS
    3. registry domains: reference/registry/domains.csv and the `domains`
       column of reference/registry/orgs.csv
    4. domains in reference/rosters/*.csv

PASSIVE. The only network activity is (1) HTTPS to crt.sh and (2) DNS
resolution via socket.getaddrinfo. No host discovered here is ever contacted.

Bounded and resumable:
  - --max-minutes (default 45) is a whole-job deadline; --max-seeds caps the
    number of seeds per run; --max-names caps names resolved per seed.
  - crt.sh: one attempt per mode (wildcard 60 s, then unexpired-only 30 s, then
    exact-name 20 s), never multiplied by retries; responses cached 7 days under
    reference/discovery/cache/<seed>.json.
  - DNS: daemon worker threads with a hard per-seed deadline; blocked lookups
    are abandoned, never joined.
  - reference/discovery/state.json records when each seed was last completed;
    seeds never completed run first, then the stalest, so successive capped
    runs sweep the whole list. A seed completed within 7 days is skipped
    unless --no-resume.
  - Previously discovered rows are never dropped because of a cap, a deadline,
    a crt.sh failure or a DNS failure. A host row is removed only when its name
    was re-resolved in this run and no longer resolves (or no longer resolves
    to that ip). Outputs are written to a temp file and renamed atomically.

Usage:
    discover_domains.py                                  # all seeds, 45-minute cap
    discover_domains.py --seed la.gov --max-names 300
    discover_domains.py --max-seeds 20 --max-minutes 30  # the weekly runner's shape
    discover_domains.py --no-resolve --dry-run
"""
import argparse
import csv
import datetime as dt
import glob
import json
import os
import queue
import re
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
try:
    from triage_report import LA_EDU_DOMAINS  # noqa: E402
except Exception:
    LA_EDU_DOMAINS = set()

REF = os.path.join(SCRIPT_DIR, "reference")
DISC_DIR = os.path.join(REF, "discovery")
CACHE_DIR = os.path.join(DISC_DIR, "cache")
HOSTS_CSV = os.path.join(DISC_DIR, "discovered_hosts.csv")
DOMAINS_CSV = os.path.join(DISC_DIR, "discovered_domains.csv")
STATE_JSON = os.path.join(DISC_DIR, "state.json")
REGISTRY_DOMAINS = os.path.join(REF, "registry", "domains.csv")
REGISTRY_ORGS = os.path.join(REF, "registry", "orgs.csv")
ROSTER_GLOB = os.path.join(REF, "rosters", "*.csv")

CRTSH_URL = "https://crt.sh/?q={q}&output=json"
SOURCE = "crt.sh"
USER_AGENT = "shodan_query-discovery/1.0 (Louisiana public-sector exposure triage)"
CACHE_MAX_AGE_DAYS = 7
DEFAULT_MAX_MINUTES = 45
DEFAULT_MAX_NAMES = 1000
DNS_TIMEOUT_S = 8.0            # per batch of --workers names
# (mode, url suffix, timeout) — exactly one attempt each, in this order.
CRTSH_MODES = [("wildcard", "", 60), ("wildcard_unexpired", "&exclude=expired", 30), ("exact", "", 20)]
BASE_SEEDS = ["la.gov", "k12.la.us"]
HOST_COLUMNS = ["name", "seed", "ip", "resolved_at", "source", "first_seen", "last_seen"]
DOMAIN_COLUMNS = ["registered_domain", "seed", "first_seen", "last_seen"]

# Namespaces under which the NEXT label is the organization (a "public suffix"
# for our purposes). Longest match wins. Anything else: the seed itself is the
# registered domain (lsu.edu -> lsu.edu).
NAMESPACE_SUFFIXES = {"k12.la.us", "lib.la.us", "cc.la.us", "tec.la.us", "state.la.us", "la.us",
                      "la.gov", "co.us", "ci.us", "us"}

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")


def log(msg):
    print(msg, flush=True)


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


# --- Deadlines -------------------------------------------------------------------------
class Deadline:
    """Monotonic wall-clock budget. child(seconds) never outlives its parent."""

    def __init__(self, seconds=None, parent=None):
        self.at = None if seconds is None else time.monotonic() + seconds
        if parent is not None and parent.at is not None:
            self.at = parent.at if self.at is None else min(self.at, parent.at)

    def remaining(self):
        return float("inf") if self.at is None else self.at - time.monotonic()

    def expired(self):
        return self.remaining() <= 0

    def clip(self, timeout):
        return timeout if self.at is None else max(1.0, min(timeout, self.remaining()))


# --- crt.sh ----------------------------------------------------------------------------
def crtsh_fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def crtsh_query(seed, sleep=2.0, fetch_fn=crtsh_fetch, deadline=None):
    """Query crt.sh for a seed with graceful degradation: ONE attempt per mode
    with a short timeout, no retries. Returns (entries, mode), mode in
    'wildcard' | 'wildcard_unexpired' | 'exact' | 'failed'."""
    deadline = deadline or Deadline()
    for i, (mode, suffix, timeout) in enumerate(CRTSH_MODES):
        q = f"%.{seed}" if mode.startswith("wildcard") else seed
        url = CRTSH_URL.format(q=urllib.parse.quote(q)) + suffix
        if deadline.remaining() < 5:
            log(f"  {seed}: deadline reached before crt.sh {mode} query")
            break
        if i:
            time.sleep(sleep)
        try:
            entries = fetch_fn(url, timeout=deadline.clip(timeout))
            if isinstance(entries, list):
                if mode != "wildcard":
                    log(f"  {seed}: crt.sh degraded to {mode} query ({len(entries)} certs)")
                return entries, mode
            log(f"  {seed}: unexpected crt.sh payload for {mode}")
        except Exception as e:
            log(f"  {seed}: crt.sh {mode} query failed ({e}); trying a smaller query")
    return [], "failed"


def cache_path(seed):
    return os.path.join(CACHE_DIR, re.sub(r"[^a-z0-9.-]", "_", seed.lower()) + ".json")


def load_cache(seed, max_age_days=CACHE_MAX_AGE_DAYS, now=None):
    path = cache_path(seed)
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            obj = json.load(f)
        fetched = dt.datetime.fromisoformat(obj["fetched_at"])
    except Exception:
        return None
    now = now or utcnow()
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=dt.timezone.utc)
    if (now - fetched).days >= max_age_days:
        return None
    return obj


def save_cache(seed, entries, mode):
    os.makedirs(CACHE_DIR, exist_ok=True)
    obj = {"seed": seed, "fetched_at": utcnow().isoformat(),
           "mode": mode, "count": len(entries), "entries": entries}
    tmp = cache_path(seed) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, cache_path(seed))


# --- parsing ----------------------------------------------------------------------------
def normalize_name(raw):
    """One certificate name -> lowercase hostname or None. Wildcards are
    stripped ('*.x.la.gov' -> 'x.la.gov'); anything still not a hostname
    (emails, IPs, embedded '*') is dropped."""
    n = (raw or "").strip().lower().rstrip(".")
    while n.startswith("*."):
        n = n[2:]
    if not n or "*" in n or "@" in n or " " in n or "/" in n:
        return None
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", n) or n.startswith("[") or n.count(":") >= 2:
        return None
    if not HOSTNAME_RE.match(n):
        return None
    return n


def _under(name, seed):
    return name == seed or name.endswith("." + seed)


def parse_crtsh(entries, seed):
    """crt.sh JSON list -> sorted distinct hostnames under the seed."""
    names = set()
    for e in entries or []:
        blob = "\n".join([e.get("name_value") or "", e.get("common_name") or ""])
        for raw in blob.split("\n"):
            n = normalize_name(raw)
            if n and _under(n, seed):
                names.add(n)
    return sorted(names)


def registered_domain(name, seed, namespaces=NAMESPACE_SUFFIXES):
    """The organization-level domain for a discovered name.
    beau.k12.la.us <- ces.beau.k12.la.us (namespace suffix k12.la.us);
    ldh.la.gov <- www.ldh.la.gov; lsu.edu <- mail.lsu.edu (seed is the org)."""
    name = name.lower().rstrip(".")
    best = ""
    for suf in namespaces:
        if name.endswith("." + suf) and len(suf) > len(best):
            best = suf
    if best:
        rest = name[: -len(best) - 1]
        return rest.split(".")[-1] + "." + best
    if _under(name, seed):
        return seed
    return name


# --- resolution ---------------------------------------------------------------------------
def resolve_one(name, getaddrinfo=socket.getaddrinfo):
    """A/AAAA addresses for one name via the system resolver (DNS only)."""
    try:
        infos = getaddrinfo(name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, socket.herror, socket.timeout, UnicodeError, OSError):
        return []
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def resolve_names(names, workers=10, timeout=DNS_TIMEOUT_S, getaddrinfo=socket.getaddrinfo, deadline=None):
    """Resolve many names on daemon threads (cap `workers`) under a hard
    deadline: timeout per batch of `workers` names, clipped by `deadline`.
    Returns (resolved {name: [ips]}, unresolved set (answered: no address),
    pending set (not answered before the deadline; treated as unknown, never
    as gone)). Workers blocked in getaddrinfo are abandoned, not joined."""
    resolved, unresolved = {}, set()
    names = list(dict.fromkeys(names))
    if not names:
        return resolved, unresolved, set()
    todo, done = queue.Queue(), queue.Queue()
    for n in names:
        todo.put(n)

    def worker():
        while True:
            try:
                n = todo.get_nowait()
            except queue.Empty:
                return
            done.put((n, resolve_one(n, getaddrinfo)))

    for _ in range(max(1, min(workers, len(names)))):
        threading.Thread(target=worker, daemon=True).start()
    budget = timeout * (len(names) / max(1, workers) + 1)
    if deadline is not None:
        budget = min(budget, max(0.0, deadline.remaining()))
    end = time.monotonic() + budget
    answered = 0
    while answered < len(names):
        left = end - time.monotonic()
        if left <= 0:
            break
        try:
            n, ips = done.get(timeout=min(left, 1.0))
        except queue.Empty:
            continue
        answered += 1
        if ips:
            resolved[n] = ips
        else:
            unresolved.add(n)
    pending = set(names) - set(resolved) - unresolved
    if pending:
        # drain so idle workers exit; blocked ones die with the process
        while True:
            try:
                todo.get_nowait()
            except queue.Empty:
                break
        log(f"  resolver deadline ({budget:.0f}s) reached; {len(pending)} names left unresolved (kept as unknown)")
    return resolved, unresolved, pending


# --- seeds -------------------------------------------------------------------------------------
def csv_domains(path, column="domain", split=None):
    out = []
    try:
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                raw = (r.get(column) or "").strip().lower()
                for d in (raw.split(split) if split else [raw]):
                    d = d.strip()
                    if d and HOSTNAME_RE.match(d):
                        out.append(d)
    except (OSError, csv.Error):
        pass
    return out


def collect_seeds():
    """Seeds in priority order, de-duplicated; a seed under an earlier seed
    (ldh.la.gov under la.gov) is dropped."""
    groups = [list(BASE_SEEDS), sorted(LA_EDU_DOMAINS),
              csv_domains(REGISTRY_DOMAINS) + csv_domains(REGISTRY_ORGS, "domains", ";"), []]
    for path in sorted(glob.glob(ROSTER_GLOB)):
        groups[3] += csv_domains(path)
    kept = []
    for group in groups:
        for s in group:
            if s not in kept and not any(_under(s, k) for k in kept):
                kept.append(s)
    return kept


def load_state(path=None):
    path = path or STATE_JSON
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state, path=None):
    path = path or STATE_JSON
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def order_seeds(seeds, state, now=None, fresh_days=CACHE_MAX_AGE_DAYS):
    """Resumable order: seeds never completed first (priority order), then the
    stalest completed ones. Seeds completed within fresh_days are skipped.
    Returns (todo, skipped_fresh)."""
    now = now or utcnow()
    never, stale, fresh = [], [], []
    for i, s in enumerate(seeds):
        done = (state.get(s) or {}).get("completed_at")
        if not done:
            never.append(s)
            continue
        try:
            when = dt.datetime.fromisoformat(done)
            if when.tzinfo is None:
                when = when.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            never.append(s)
            continue
        if (now - when).total_seconds() < fresh_days * 86400:
            fresh.append(s)
        else:
            stale.append((when, i, s))
    stale.sort()
    return never + [s for _, _, s in stale], fresh


# --- IO ------------------------------------------------------------------------------------------
def read_csv(path):
    try:
        with open(path, newline="") as f:
            return list(csv.DictReader(f))
    except OSError:
        return []


def write_csv(path, columns, rows, dry_run=False):
    if dry_run:
        log(f"  [dry-run] would write {len(rows)} rows -> {path}")
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in columns})
    os.replace(tmp, path)
    log(f"  wrote {len(rows)} rows -> {path}")


def merge_hosts(existing, results, today, resolved_at):
    """results: {seed: {"resolved": {name: [ips]}, "unresolved": set(names)}}
    for names actually answered this run. Rules:
      - a name re-resolved with addresses: rows for those ips get last_seen=today
        (first_seen preserved); its rows for other ips are dropped;
      - a name answered with no address: its rows are dropped;
      - anything not answered (cap, deadline, crt.sh failure, seed not run):
        previous rows are kept exactly as they were."""
    out, by_name = {}, {}
    for r in existing:
        r = dict(r)
        r.setdefault("first_seen", (r.get("resolved_at") or today)[:10])
        r["first_seen"] = r["first_seen"] or (r.get("resolved_at") or today)[:10]
        r["last_seen"] = r.get("last_seen") or r["first_seen"]
        k = (r["seed"], r["name"], r["ip"])
        out[k] = r
        by_name.setdefault((r["seed"], r["name"]), []).append(k)
    for seed, res in results.items():
        for name in res.get("unresolved", ()):
            for k in by_name.pop((seed, name), []):
                out.pop(k, None)
        for name, ips in res.get("resolved", {}).items():
            for k in by_name.pop((seed, name), []):
                if k[2] not in ips:
                    out.pop(k, None)
            for ip in ips:
                k = (seed, name, ip)
                prev = out.get(k)
                out[k] = {"name": name, "seed": seed, "ip": ip, "resolved_at": resolved_at, "source": SOURCE,
                          "first_seen": prev["first_seen"] if prev else today, "last_seen": today}
    return sorted(out.values(), key=lambda r: (r["seed"], r["name"], r["ip"]))


def merge_domains(existing, found, today):
    """found: {(registered_domain, seed)}; first_seen preserved, nothing dropped."""
    rows = {}
    for r in existing:
        k = (r["registered_domain"], r["seed"])
        rows[k] = {"registered_domain": k[0], "seed": k[1], "first_seen": r.get("first_seen") or today,
                   "last_seen": r.get("last_seen") or r.get("first_seen") or today}
    for k in found:
        prev = rows.get(k)
        rows[k] = {"registered_domain": k[0], "seed": k[1],
                   "first_seen": prev["first_seen"] if prev else today, "last_seen": today}
    return [rows[k] for k in sorted(rows)]


# --- main ----------------------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", action="append", help="seed domain(s); default: all known seeds in priority order")
    ap.add_argument("--max-seeds", type=int, default=None, help="process at most N seeds this run")
    ap.add_argument("--max-names", type=int, default=DEFAULT_MAX_NAMES,
                    help=f"cap on names per seed to resolve (default {DEFAULT_MAX_NAMES})")
    ap.add_argument("--max-minutes", type=float, default=DEFAULT_MAX_MINUTES,
                    help=f"whole-job deadline in minutes (default {DEFAULT_MAX_MINUTES})")
    ap.add_argument("--no-resolve", action="store_true", help="collect names only; skip DNS")
    ap.add_argument("--dry-run", action="store_true", help="fetch and parse but write nothing")
    ap.add_argument("--sleep", type=float, default=2.0, help="seconds between crt.sh calls (default 2)")
    ap.add_argument("--workers", type=int, default=10, help="DNS concurrency cap (default 10)")
    ap.add_argument("--refresh", action="store_true", help="ignore the 7-day crt.sh cache")
    ap.add_argument("--no-resume", action="store_true",
                    help="ignore state.json: run seeds in plain priority order, including fresh ones")
    args = ap.parse_args(argv)

    job = Deadline(args.max_minutes * 60)
    state = load_state()
    if args.seed:
        seeds = [s.strip().lower() for s in args.seed]
        todo, fresh = seeds, []
    else:
        seeds = collect_seeds()
        todo, fresh = (seeds, []) if args.no_resume else order_seeds(seeds, state)
    queued = len(todo)
    if args.max_seeds is not None:
        todo = todo[: max(0, args.max_seeds)]
    log(f"seeds: {len(seeds)} known, {len(fresh)} fresh (skipped), {queued} due, {len(todo)} to run; "
        f"deadline {args.max_minutes:g} min")
    now = utcnow()
    today = now.date().isoformat()
    resolved_at = now.replace(microsecond=0).isoformat()

    results, found_domains, summary, live_calls = {}, set(), [], 0
    done_seeds = 0
    for seed in todo:
        if job.expired():
            log(f"job deadline reached after {done_seeds} seeds; remaining resume next run")
            break
        cached = None if args.refresh else load_cache(seed)
        if cached:
            entries, mode = cached["entries"], cached.get("mode", "cache")
            log(f"[{seed}] cache ({cached['fetched_at'][:10]}, {len(entries)} certs)")
        else:
            if live_calls:
                time.sleep(args.sleep)
            live_calls += 1
            log(f"[{seed}] querying crt.sh")
            entries, mode = crtsh_query(seed, sleep=args.sleep, deadline=job)
            if mode != "failed" and not args.dry_run:
                save_cache(seed, entries, mode)
        if mode == "failed":
            summary.append((seed, mode, 0, 0, 0, 0))
            log("  crt.sh failed; previous rows for this seed are kept")
            continue
        names = parse_crtsh(entries, seed)
        for n in names:
            found_domains.add((registered_domain(n, seed), seed))
        capped = names[: args.max_names]
        if len(names) > args.max_names:
            log(f"  {len(names)} names; resolving the first {args.max_names} (--max-names); the rest keep previous rows")
        resolved, unresolved, pending = {}, set(), set()
        if capped and not args.no_resolve:
            resolved, unresolved, pending = resolve_names(capped, workers=args.workers, deadline=job)
            results[seed] = {"resolved": resolved, "unresolved": unresolved}
        partial = bool(pending) or len(names) > args.max_names or mode != "wildcard"
        state[seed] = {"completed_at": utcnow().isoformat(), "mode": mode, "names": len(names),
                       "resolved": len(resolved), "partial": partial}
        if not args.dry_run:
            save_state(state)
        done_seeds += 1
        n_dom = len({d for d, s in found_domains if s == seed})
        n_ips = sum(len(v) for v in resolved.values())
        summary.append((seed, mode, len(names), n_dom, len(resolved), n_ips))
        log(f"  {len(names)} names, {n_dom} registered domains, {len(resolved)} resolved -> {n_ips} ips"
            f"{' (partial)' if partial else ''}")

    hosts = merge_hosts(read_csv(HOSTS_CSV), results, today, resolved_at)
    domains = merge_domains(read_csv(DOMAINS_CSV), found_domains, today)
    if not args.no_resolve:
        write_csv(HOSTS_CSV, HOST_COLUMNS, hosts, args.dry_run)
    write_csv(DOMAINS_CSV, DOMAIN_COLUMNS, domains, args.dry_run)

    log("\nSummary (seed, mode, names, registered_domains, resolved_names, ips):")
    for s in summary:
        log("  {:<28} {:<20} {:>6} {:>6} {:>6} {:>6}".format(*s))
    failed = [s for s in summary if s[1] == "failed"]
    if failed:
        log(f"  crt.sh failed for: {', '.join(s[0] for s in failed)}")
    left = queued - done_seeds - len(failed)
    if left > 0:
        log(f"  {left} seeds not reached this run (--max-seeds / deadline); resume continues with them")
    return 0


if __name__ == "__main__":
    sys.exit(main())
