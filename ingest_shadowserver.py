#!/usr/bin/env python3
"""
ingest_shadowserver.py — Shadowserver reports -> store/shadowserver/ (authoritative)
and the `shadowserver_events` table in the store (a rebuilt copy).

Shadowserver (shadowserver.org) is a non-profit that runs sinkholes, honeypots and
internet-wide scans and gives network owners FREE daily reports about their own
address space. For a state cyber unit it is the second, independent source of
COMPROMISE evidence (the first is the Shodan tripwire) — and, unlike Shodan, it
sees behaviour (a host contacting a sinkhole), not just banners.

NOT every report is a compromise. Report types are classed (classify_report):
  compromise  sinkhole*, *drone*, microsoft_sinkhole, spam, compromised_website,
              malware_url, botnet, cc/c2, phish, ddos_participant, malicious …
              -> the `port` column is the infected host's SOURCE port, never an
                 exposed service; leads are host-level; wording = possible infection
  exposure    scan_*, vulnerable_*, exposed_*, open_*, accessible_*, ics*, blocklist …
              -> the `port` column is the exposed service; wording = exposure to verify

Two ways in:
(a) FILES named like 2026-09-14-sinkhole_http_drone-louisiana.csv (date, type,
    scope) dropped under reference/shadowserver/incoming/; `ingest` parses every
    file there.
(b) API https://transform.shadowserver.org/api2/ — `fetch --date` lists and
    downloads a day's reports into incoming/. Auth: apikey in the JSON body,
    `HMAC2` header = hex HMAC-SHA256 of the exact body bytes keyed with the secret;
    keys from .env SHADOWSERVER_API_KEY / SHADOWSERVER_SECRET. Missing keys or a
    dead feed -> explained, exit 0.

Durability (a store rebuild wipes exposure.duckdb): the AUTHORITATIVE record is
store/shadowserver/events.parquet (append + dedupe on (report_type, timestamp, ip,
port, protocol, tag)) plus store/shadowserver/manifest.json keyed by
"<sha256>:<report_type>" (original filename, report_type, rows loaded / duplicate /
quarantined, ingested_on). leads.py reads the parquet, never the store table. A
whole `ingest` run holds store/shadowserver/.ingest.lock (fcntl.flock) across
manifest read -> dedupe -> parquet publish -> manifest write -> input move; a second
ingester exits cleanly (or waits with --wait) and never proceeds without the lock.
Each file is all-or-nothing: parquet to a pid-unique temp file + rename, then the
manifest, then the store table is re-published from the parquet (every run, and on
`restore`); if that publication fails the input stays in incoming/ so it retries.
Rows with surplus fields, a missing/invalid ip, an out-of-range port, a garbage
protocol, a missing/unparseable/FUTURE timestamp go to
reference/shadowserver/quarantine/<file>.quarantine.csv with a reason — never raise.

Subscribing: reports go to the NETBLOCK OWNER (or a CSIRT with authority over the
space). For Louisiana the natural subscriber is OTS (owner of the state netblocks)
with the cyber unit as recipient: (1) assemble the ASNs/CIDRs (OTS's ots_cidrs.csv
drop-in + parish/municipal space under written arrangement); (2) apply at
https://www.shadowserver.org/what-we-do/network-reporting/get-reports/ with a
contact at the owning organisation; (3) Shadowserver verifies ownership (RIR / LOA)
and starts daily e-mail reports; (4) request API access, put key/secret in .env;
(5) cron `fetch --date <yesterday>` + `ingest` + `leads.py refresh` after the census.

Exit codes: 0 ok, 3 another ingest holds the lock, 4 DEGRADED (a file errored /
could not be published, or the final store republish failed — the parquet and
manifest are authoritative and intact; run_nightly should mark the night degraded).
IPs are canonicalised (ipaddress ... .compressed) so IPv6 spellings match the store.

Usage:
    ingest_shadowserver.py ingest [--dry-run] [--incoming DIR] [--db PATH]
    ingest_shadowserver.py restore [--db PATH]            # after a store rebuild
    ingest_shadowserver.py fetch --date 2026-09-14 [--types a,b] [--dry-run]
    ingest_shadowserver.py sign 'body'
"""
import argparse
import csv
import fcntl
import glob
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone

import duckdb

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "store", "exposure.duckdb")
SS_DIR = os.path.join(SCRIPT_DIR, "reference", "shadowserver")
INCOMING = os.path.join(SS_DIR, "incoming")
PROCESSED = os.path.join(SS_DIR, "processed")
QUARANTINE = os.path.join(SS_DIR, "quarantine")
STORE_DIR = os.path.join(SCRIPT_DIR, "store", "shadowserver")
EVENTS_PARQUET = os.path.join(STORE_DIR, "events.parquet")
MANIFEST = os.path.join(STORE_DIR, "manifest.json")
API_BASE = "https://transform.shadowserver.org/api2/"
ENV_PATH = os.path.join(SCRIPT_DIR, ".env")

EVENT_COLUMNS = ["report_type", "timestamp", "ip", "port", "protocol", "asn", "geo", "tag", "severity",
                 "detail", "ingested_on"]
EVENT_TYPES = {"timestamp": "TIMESTAMP", "port": "INTEGER", "ingested_on": "DATE"}
EVENTS_DDL = "CREATE TABLE IF NOT EXISTS shadowserver_events (" + ", ".join(
    f"{c} {EVENT_TYPES.get(c, 'VARCHAR')}" for c in EVENT_COLUMNS) + ")"
DEDUPE_KEY = ("report_type", "timestamp", "ip", "port", "protocol", "tag")
PROTOCOLS = {"tcp", "udp", "icmp", "other"}
LOCK_NAME = ".ingest.lock"
CORE = ("timestamp", "ip", "protocol", "port", "asn", "geo", "tag")
_FILENAME_RE = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2})-(?P<type>[a-z0-9_]+)(?:-(?P<scope>.+))?\.csv$", re.I)
COMPROMISE_MARKERS = ("sinkhole", "drone", "spam", "compromised", "malware", "botnet", "cc_", "_cc",
                      "c2", "phish", "ddos_participant", "malicious", "infected", "honeypot_")
EXPOSURE_MARKERS = ("scan_", "vulnerable", "exposed", "open_", "accessible", "ics", "blocklist",
                    "darknet", "device_id", "ssl", "amplification")


def log(msg):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} - {msg}", flush=True)


def load_env(path=ENV_PATH):
    try:
        with open(path) as fh:
            for raw in fh:
                line = raw.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass


# --- report semantics ------------------------------------------------------------

def classify_report(report_type):
    """'compromise' (a host is infected / abused) or 'exposure' (a service is
    reachable / vulnerable). Unknown types are treated as exposure — the weaker
    claim — so nobody gets accused of an infection by a naming accident."""
    t = (report_type or "").lower()
    if any(m in t for m in EXPOSURE_MARKERS) and not any(m in t for m in ("sinkhole", "drone")):
        return "exposure"
    if any(m in t for m in COMPROMISE_MARKERS):
        return "compromise"
    return "exposure"


def parse_filename(name):
    m = _FILENAME_RE.match(os.path.basename(name))
    if not m:
        return None, re.sub(r"\.csv$", "", os.path.basename(name), flags=re.I), None
    return m.group("date"), m.group("type").lower(), m.group("scope")


def severity_for(report_type, row):
    s = (row.get("severity") or "").strip().lower()
    if s:
        return s
    return "high" if classify_report(report_type) == "compromise" else (
        "medium" if any(m in (report_type or "") for m in ("vulnerable", "exposed", "ics", "blocklist", "brute"))
        else "low")


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_ts(s):
    """Shadowserver timestamps: 'YYYY-MM-DD HH:MM:SS' (UTC), ISO with 'T', 'Z' or a
    numeric offset. Returns a naive UTC datetime, or None."""
    s = (s or "").strip()
    if not s:
        return None
    s2 = s.replace("Z", "+00:00")
    if " " in s2 and "T" not in s2:
        s2 = s2.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(s2)
    except ValueError:
        try:
            dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def parse_report(path, today=None):
    """-> (sha, events, quarantined). events carry the contract columns; quarantined
    is a list of (reason, raw_row_dict)."""
    today = today or date.today()
    _, report_type, scope = parse_filename(path)
    sha = file_sha(path)
    horizon = datetime.combine(today + timedelta(days=1), datetime.min.time())
    events, bad = [], []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for raw in csv.DictReader(fh):
            if None in raw or any(isinstance(v, list) for v in raw.values()):
                bad.append(("surplus fields", {str(k): v for k, v in raw.items()}))
                continue
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items()}
            ip = row.get("ip")
            ts = parse_ts(row.get("timestamp"))
            if not ip:
                bad.append(("missing ip", row)); continue
            try:
                ip = ipaddress.ip_address(ip).compressed          # canonical spelling (IPv6 too)
            except ValueError:
                bad.append(("invalid ip", row)); continue
            if not row.get("timestamp"):
                bad.append(("missing timestamp", row)); continue
            if ts is None:
                bad.append(("unparseable timestamp", row)); continue
            if ts >= horizon:
                bad.append(("future-dated", row)); continue
            port = row.get("port")
            if port not in (None, ""):
                try:
                    port = int(port)
                except ValueError:
                    bad.append(("invalid port", row)); continue
                if not 0 <= port <= 65535:
                    bad.append(("port out of range", row)); continue
            else:
                port = None
            proto = (row.get("protocol") or "").lower()
            if proto and proto not in PROTOCOLS:
                if re.fullmatch(r"[a-z0-9_-]{1,16}", proto):
                    row["protocol_raw"], proto = proto, "other"
                else:
                    bad.append(("invalid protocol", row)); continue
            detail = {k: v for k, v in row.items() if k not in CORE and v != ""}
            detail["_file_sha"] = sha
            detail["_source_file"] = os.path.basename(path)
            detail["_class"] = classify_report(report_type)
            if scope:
                detail["_scope"] = scope
            events.append({"report_type": report_type, "timestamp": ts, "ip": ip, "port": port,
                           "protocol": proto or None,
                           "asn": row.get("asn") or None, "geo": row.get("geo") or None,
                           "tag": row.get("tag") or row.get("infection") or row.get("family") or None,
                           "severity": severity_for(report_type, row),
                           "detail": json.dumps(detail, sort_keys=True)})
    return sha, events, bad


# --- authoritative parquet + manifest ---------------------------------------------

def load_manifest(path=MANIFEST):
    try:
        with open(path) as fh:
            m = json.load(fh)
        m.setdefault("files", {})
        return m
    except (OSError, ValueError):
        return {"files": {}}


def save_manifest(m, path=MANIFEST):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w") as fh:
        json.dump(m, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _key(e):
    return tuple(str(e.get(k)) if e.get(k) is not None else "" for k in DEDUPE_KEY)


def existing_keys(parquet=EVENTS_PARQUET):
    if not parquet or not os.path.exists(parquet):
        return set()
    con = duckdb.connect()
    try:
        cols = ", ".join(DEDUPE_KEY)
        return {tuple(str(v) if v is not None else "" for v in r)
                for r in con.execute(f"SELECT {cols} FROM read_parquet('{parquet}')").fetchall()}
    finally:
        con.close()


def append_parquet(events, parquet=EVENTS_PARQUET):
    """Rewrite parquet = old ∪ new via a temp file + rename (all-or-nothing)."""
    os.makedirs(os.path.dirname(parquet), exist_ok=True)
    con = duckdb.connect()
    try:
        con.execute(EVENTS_DDL)
        if os.path.exists(parquet):
            con.execute(f"INSERT INTO shadowserver_events SELECT * FROM read_parquet('{parquet}')")
        con.executemany(f"INSERT INTO shadowserver_events VALUES ({', '.join('?' * len(EVENT_COLUMNS))})",
                        [[e[c] for c in EVENT_COLUMNS] for e in events])
        tmp = f"{parquet}.tmp-{os.getpid()}"
        con.execute(f"COPY (SELECT * FROM shadowserver_events ORDER BY timestamp, ip, port) TO '{tmp}' (FORMAT PARQUET)")
        os.replace(tmp, parquet)
    finally:
        con.close()


def restore_table(con, parquet=EVENTS_PARQUET):
    """(Re)publish the disposable store table from the authoritative parquet."""
    if con is None:
        return False
    try:
        if parquet and os.path.exists(parquet):
            con.execute(f"CREATE OR REPLACE TABLE shadowserver_events AS SELECT * FROM read_parquet('{parquet}')")
        else:
            con.execute(EVENTS_DDL)
        return True
    except duckdb.Error as exc:
        log(f"could not publish shadowserver_events into the store ({exc}); parquet is authoritative")
        return False


def write_quarantine(path, bad, quarantine_dir):
    os.makedirs(quarantine_dir, exist_ok=True)
    out = os.path.join(quarantine_dir, os.path.basename(path) + ".quarantine.csv")
    fields = sorted({k for _, r in bad for k in r})
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["_reason"] + fields)
        for reason, r in bad:
            w.writerow([reason] + [r.get(k, "") for k in fields])
    return out


def ingest_file(con, path, today, dry_run=False, processed_dir=PROCESSED, quarantine_dir=QUARANTINE,
                parquet=EVENTS_PARQUET, manifest_path=MANIFEST):
    """One CSV, all-or-nothing. Returns (status, n_loaded) with status
    loaded | duplicate | empty | error."""
    name = os.path.basename(path)
    try:
        sha = file_sha(path)
    except OSError as exc:
        log(f"  {name}: unreadable ({exc}) — left in place")
        return "error", 0
    manifest = load_manifest(manifest_path)
    _, rtype, _ = parse_filename(path)
    ident = f"{sha}:{rtype}"
    if ident in manifest["files"]:
        status, events, bad, new = "duplicate", [], [], []
    else:
        try:
            sha, events, bad = parse_report(path, today)
        except (OSError, csv.Error, UnicodeDecodeError) as exc:
            log(f"  {name}: unparseable ({exc}) — left in place")
            return "error", 0
        seen = existing_keys(parquet)
        new = []
        for e in events:
            k = _key(e)
            if k in seen:
                continue
            seen.add(k)
            new.append(dict(e, ingested_on=today))
        status = "loaded" if new else "empty"
    if dry_run:
        log(f"  {name}: {status}, {len(new)} new event(s), {len(events) - len(new)} duplicate row(s), "
            f"{len(bad)} quarantined [dry-run]")
        return status, len(new)
    if bad:
        q = write_quarantine(path, bad, quarantine_dir)
        log(f"  {name}: {len(bad)} row(s) quarantined -> {q}")
    if status == "loaded":
        append_parquet(new, parquet)
    if status != "duplicate":
        manifest["files"][ident] = {"sha256": sha, "filename": name, "report_type": rtype, "rows_loaded": len(new),
                                    "rows_duplicate": len(events) - len(new), "rows_quarantined": len(bad),
                                    "ingested_on": today.isoformat()}
        save_manifest(manifest, manifest_path)
    if not restore_table(con, parquet):
        log(f"  {name}: events saved to parquet but the store table could NOT be published — "
            f"input left in incoming/ to retry")
        return "unpublished", len(new)
    os.makedirs(processed_dir, exist_ok=True)
    os.replace(path, os.path.join(processed_dir, f"{sha[:8]}-{name}"))
    log(f"  {name}: {status}, {len(new)} new event(s)")
    return status, len(new)


def acquire_lock(parquet, wait=False):
    """Exclusive flock on <parquet dir>/.ingest.lock. Returns the open file (keep it
    open for the whole run) or None when another ingester holds it."""
    lock_path = os.path.join(os.path.dirname(parquet), LOCK_NAME)
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    fh = open(lock_path, "a+")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
    except OSError:
        fh.close()
        return None
    return fh


def ingest_dir(con, incoming=INCOMING, today=None, dry_run=False, processed_dir=PROCESSED,
               quarantine_dir=QUARANTINE, parquet=EVENTS_PARQUET, manifest_path=MANIFEST, wait=False):
    """Every file under incoming/, under ONE lock held from manifest read to input
    move. Returns {status: n}, or None when the lock could not be taken."""
    today = today or date.today()
    lock = acquire_lock(parquet, wait)
    if lock is None:
        log(f"another ingest holds {os.path.join(os.path.dirname(parquet), LOCK_NAME)} — exiting without changes")
        return None
    try:
        files = sorted(glob.glob(os.path.join(incoming, "*.csv")) + glob.glob(os.path.join(incoming, "*.CSV")))
        totals = {}
        for f in files:
            status, n = ingest_file(con, f, today, dry_run, processed_dir, quarantine_dir, parquet, manifest_path)
            totals[status] = totals.get(status, 0) + (n if status == "loaded" else 1)
        if not files:
            log(f"no CSV files under {incoming}")
        if not dry_run and con is not None and os.path.exists(parquet):
            if not restore_table(con, parquet):   # the store copy is republished every run
                totals["_republish_failed"] = 1
        return totals
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


# --- API client ------------------------------------------------------------------

def hmac2(secret, body):
    if isinstance(body, str):
        body = body.encode("utf-8")
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def api_call(method, params, key, secret, timeout=45, base=API_BASE):
    body = json.dumps(dict(params, apikey=key)).encode("utf-8")
    req = urllib.request.Request(base + method, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "HMAC2": hmac2(secret, body),
                                          "User-Agent": "shodan_query-shadowserver-ingest/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{method}: HTTP {exc.code} {exc.reason}: {exc.read()[:200]!r}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"{method}: {exc}") from None


def list_reports(day, key, secret, types=None, base=API_BASE):
    params = {"date": day if isinstance(day, str) else day.isoformat()}
    if types:
        params["reports"] = list(types)
    return json.loads(api_call("reports/list", params, key, secret, base=base).decode("utf-8"))


def download_report(report_id, key, secret, base=API_BASE):
    return api_call("reports/download", {"id": report_id}, key, secret, base=base)


def fetch(day, types=None, incoming=INCOMING, dry_run=False, base=API_BASE):
    load_env()
    key, secret = os.environ.get("SHADOWSERVER_API_KEY"), os.environ.get("SHADOWSERVER_SECRET")
    if not key or not secret:
        log("Shadowserver API keys not configured (SHADOWSERVER_API_KEY / SHADOWSERVER_SECRET in .env). "
            "Nothing fetched. See docs/LEADS.md for how the state subscribes; CSV reports can still be "
            "dropped into reference/shadowserver/incoming/ and loaded with `ingest`.")
        return 0
    try:
        reports = list_reports(day, key, secret, types, base=base)
    except (RuntimeError, ValueError) as exc:
        log(f"Shadowserver reports/list failed: {exc} — nothing fetched (a feed outage is not fatal)")
        return 0
    if not isinstance(reports, list):
        log(f"Shadowserver reports/list returned an unexpected payload: {str(reports)[:200]}")
        return 0
    log(f"{len(reports)} report(s) available for {day}")
    n = 0
    os.makedirs(incoming, exist_ok=True)
    for r in reports:
        fname = os.path.basename(r.get("file") or f"{day}-{r.get('type', 'report')}.csv")
        dest = os.path.join(incoming, fname)
        if dry_run:
            log(f"  would download {fname} (id {r.get('id')})")
            continue
        if os.path.exists(dest) or glob.glob(os.path.join(PROCESSED, f"*-{fname}")):
            log(f"  {fname}: already present, skipped")
            continue
        try:
            data = download_report(r.get("id"), key, secret, base=base)
        except RuntimeError as exc:
            log(f"  {fname}: download failed: {exc}")
            continue
        tmp = dest + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, dest)
        n += 1
        log(f"  downloaded {fname} ({len(data)} bytes)")
    return n


# --- CLI ---------------------------------------------------------------------

def _open_store(db):
    try:
        return duckdb.connect(db)
    except duckdb.Error as exc:
        log(f"store {db} not writable right now ({exc}); events are saved to parquet, table publish skipped")
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="Shadowserver report ingest (files + API).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ig = sub.add_parser("ingest")
    ig.add_argument("--incoming", default=INCOMING)
    ig.add_argument("--processed", default=PROCESSED)
    ig.add_argument("--quarantine", default=QUARANTINE)
    ig.add_argument("--db", default=DB_PATH)
    ig.add_argument("--parquet", default=EVENTS_PARQUET)
    ig.add_argument("--manifest", default=MANIFEST)
    ig.add_argument("--dry-run", action="store_true")
    ig.add_argument("--wait", action="store_true", help="wait for a running ingest instead of exiting")
    rs = sub.add_parser("restore", help="re-create the store table from the parquet (after a rebuild)")
    rs.add_argument("--db", default=DB_PATH)
    rs.add_argument("--parquet", default=EVENTS_PARQUET)
    ft = sub.add_parser("fetch")
    ft.add_argument("--date", default=date.today().isoformat())
    ft.add_argument("--types")
    ft.add_argument("--incoming", default=INCOMING)
    ft.add_argument("--dry-run", action="store_true")
    sg = sub.add_parser("sign")
    sg.add_argument("body")
    args = ap.parse_args(argv)

    if args.cmd == "ingest":
        con = None if args.dry_run else _open_store(args.db)
        try:
            totals = ingest_dir(con, args.incoming, dry_run=args.dry_run, processed_dir=args.processed,
                                quarantine_dir=args.quarantine, parquet=args.parquet, manifest_path=args.manifest,
                                wait=args.wait)
        finally:
            if con:
                con.close()
        if totals is None:
            return 3
        log("ingest summary: " + (", ".join(f"{k}={v}" for k, v in totals.items()) or "nothing to do"))
        if totals.get("error") or totals.get("unpublished") or totals.get("_republish_failed"):
            log("ingest DEGRADED: authoritative parquet/manifest are fine but a file errored or the store copy was "
                "not published (exit 4)")
            return 4
        return 0
    if args.cmd == "restore":
        con = _open_store(args.db)
        ok = restore_table(con, args.parquet)
        if con:
            con.close()
        log("shadowserver_events " + ("restored from parquet" if ok else "NOT restored"))
        return 0 if ok else 5
    if args.cmd == "fetch":
        types = [t.strip() for t in args.types.split(",")] if args.types else None
        fetch(args.date, types, args.incoming, args.dry_run)
        return 0
    if args.cmd == "sign":
        load_env()
        secret = os.environ.get("SHADOWSERVER_SECRET")
        if not secret:
            log("SHADOWSERVER_SECRET not set")
            return 1
        print(hmac2(secret, args.body))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
