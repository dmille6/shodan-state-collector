#!/usr/bin/env python3
"""
build_store.py — parse daily Shodan .gz archives into a queryable DuckDB/Parquet
analytical store.

The raw daily_downloads/*.json.gz files remain the immutable system of record.
This projects them into a columnar store you can query with SQL:

  store/observations/date=<ISO>/data.parquet   one row per banner per day
  store/vulns/date=<ISO>/data.parquet           one row per (ip,port,cve) per day
  store/exposure.duckdb                          DuckDB with views over the parquet

Because the parquet is derived, it is always safe to delete and rebuild from the
.gz archive (e.g. after a schema change): `build_store.py --all --rebuild`.

Enrichment (tier, KEV, EPSS) reuses the reference caches and classifier from
triage_report.py. PASSIVE data; findings are leads to verify.

Usage:
    build_store.py --date 2026-06-30      # (re)build one day's partition + views
    build_store.py --all                  # build every day found in daily_downloads/
    build_store.py path/to/file.json.gz   # build a specific file
"""
import argparse
import glob
import gzip
import json
import os
import sys
import tempfile

import duckdb
import triage_report as tr   # reuse classify() + signal maps + load_json()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STORE = os.path.join(SCRIPT_DIR, "store")
OBS_DIR = os.path.join(STORE, "observations")
VULN_DIR = os.path.join(STORE, "vulns")
DB_PATH = os.path.join(STORE, "exposure.duckdb")
DAILY_DIR = os.path.join(SCRIPT_DIR, "daily_downloads")


def load_enrichment():
    kev = set(tr.load_json(os.path.join(SCRIPT_DIR, "reference/kev.json"), {}).get("cves", []))
    epss = tr.load_json(os.path.join(SCRIPT_DIR, "reference/epss.json"), {})
    return kev, epss


def date_from_name(path):
    base = os.path.basename(path)
    return base.replace(".json.gz", "").split("events-")[-1]


def iter_banners(path):
    """Stream one banner (parsed JSON) at a time from a daily .gz — bounded memory
    even when a day decompresses to many GB (full HTTP bodies can be 10-15 MB each)."""
    with gzip.open(path, "rt") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("ip_str"):
                yield r


def build_day(path, kev, epss, obs_fh, vuln_fh):
    """Two streaming passes over a daily .gz, writing flattened rows to the open
    temp files obs_fh / vuln_fh. Never holds the full day in memory. Returns
    (date, n_obs, n_vuln)."""
    date = date_from_name(path)

    # Pass 1: per-IP aggregate (small) to classify sector tier.
    hosts = {}
    for r in iter_banners(path):
        h = hosts.setdefault(r["ip_str"], {"org": None, "ports": set(),
                                           "hostnames": set(), "domains": set()})
        h["org"] = h["org"] or r.get("org")
        h["ports"].add(r.get("port"))
        h["hostnames"].update(r.get("hostnames") or [])
        h["domains"].update(r.get("domains") or [])
    tier_of = {}
    for ip, h in hosts.items():
        h["hostnames"] = sorted(h["hostnames"])
        h["domains"] = sorted(h["domains"])
        tier_of[ip], _ = tr.classify(h)

    # Pass 2: stream banners → write obs + vuln rows straight to temp files.
    # We keep ONLY the exposure-relevant fields (never the giant http body), so
    # the store stays tiny regardless of how large the raw banners are.
    n_obs = n_vuln = 0
    for r in iter_banners(path):
        ip = r["ip_str"]
        port = r.get("port")
        loc = r.get("location") or {}
        obs_fh.write(json.dumps({
            "date": date, "ip": ip, "port": port,
            "transport": r.get("transport"), "asn": r.get("asn"),
            "org": r.get("org"), "isp": r.get("isp"),
            "product": r.get("product"), "version": r.get("version"),
            "city": loc.get("city"), "region_code": loc.get("region_code"),
            "hostnames": ",".join(r.get("hostnames") or []),
            "domains": ",".join(r.get("domains") or []),
            "hash": str(r.get("hash")), "tier": tier_of.get(ip),
        }) + "\n")
        n_obs += 1
        for cve, meta in (r.get("vulns") or {}).items():
            cvss = meta.get("cvss") if isinstance(meta, dict) else None
            try:
                cvss = float(cvss) if cvss is not None else None
            except (TypeError, ValueError):
                cvss = None
            vuln_fh.write(json.dumps({
                "date": date, "ip": ip, "port": port, "cve": cve,
                "cvss": cvss, "in_kev": cve in kev, "epss": epss.get(cve),
            }) + "\n")
            n_vuln += 1
    return date, n_obs, n_vuln


def copy_to_partition(con, tmp_path, n_rows, out_dir, date, select_sql):
    """COPY an already-written temp NDJSON into that date's parquet partition."""
    part_dir = os.path.join(out_dir, f"date={date}")
    os.makedirs(part_dir, exist_ok=True)
    out_parquet = os.path.join(part_dir, "data.parquet")
    if n_rows == 0:
        # No rows for this table today — drop any stale partition so the glob
        # doesn't try to read an empty file.
        if os.path.exists(out_parquet):
            os.remove(out_parquet)
        return None
    con.execute(f"COPY ({select_sql.format(src=repr(tmp_path))}) "
                f"TO '{out_parquet}' (FORMAT PARQUET)")
    return out_parquet


OBS_SELECT = """
SELECT CAST(date AS DATE) AS date, ip, CAST(port AS INTEGER) AS port, transport,
       CAST(asn AS VARCHAR) AS asn, org, isp, product, CAST(version AS VARCHAR) AS version,
       city, region_code, hostnames, domains, hash, tier
FROM read_json_auto({src}, format='newline_delimited', maximum_object_size=100000000)
"""
VULN_SELECT = """
SELECT CAST(date AS DATE) AS date, ip, CAST(port AS INTEGER) AS port, cve,
       CAST(cvss AS DOUBLE) AS cvss, CAST(in_kev AS BOOLEAN) AS in_kev,
       CAST(epss AS DOUBLE) AS epss
FROM read_json_auto({src}, format='newline_delimited')
"""


def refresh_views(con):
    """(Re)define views over all parquet partitions + derived analytics."""
    obs_glob = os.path.join(OBS_DIR, "date=*", "*.parquet")
    vuln_glob = os.path.join(VULN_DIR, "date=*", "*.parquet")
    con.execute(f"CREATE OR REPLACE VIEW observations AS "
                f"SELECT * FROM read_parquet('{obs_glob}', union_by_name=true)")
    con.execute(f"CREATE OR REPLACE VIEW vulns AS "
                f"SELECT * FROM read_parquet('{vuln_glob}', union_by_name=true)")
    # Latest banner per ip:port (the current picture).
    con.execute("""
        CREATE OR REPLACE VIEW current_state AS
        SELECT * EXCLUDE (rn) FROM (
          SELECT *, row_number() OVER (PARTITION BY ip, port ORDER BY date DESC) AS rn
          FROM observations
        ) WHERE rn = 1
    """)
    # Exposure lifecycle: first/last seen + dwell for each ip:port.
    con.execute("""
        CREATE OR REPLACE VIEW lifecycle AS
        SELECT ip, port,
               min(date) AS first_seen, max(date) AS last_seen,
               count(DISTINCT date) AS days_observed,
               date_diff('day', min(date), max(date)) + 1 AS span_days
        FROM observations GROUP BY ip, port
    """)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?", help="a specific .gz to load")
    ap.add_argument("--date", help="load daily_downloads/<state>-events-<date>.json.gz")
    ap.add_argument("--all", action="store_true", help="load every daily file")
    ap.add_argument("--rebuild", action="store_true", help="wipe the store first")
    args = ap.parse_args()

    if args.rebuild:
        import shutil
        for d in (OBS_DIR, VULN_DIR):
            shutil.rmtree(d, ignore_errors=True)
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)

    files = []
    if args.file:
        files = [args.file]
    elif args.all:
        files = sorted(glob.glob(os.path.join(DAILY_DIR, "*-events-*.json.gz")))
    elif args.date:
        files = glob.glob(os.path.join(DAILY_DIR, f"*-events-{args.date}.json.gz"))
    else:
        ap.error("give a file, --date, or --all")
    files = [f for f in files if ".backup" not in f]
    if not files:
        print("No matching files.")
        return 1

    os.makedirs(STORE, exist_ok=True)
    kev, epss = load_enrichment()
    con = duckdb.connect(DB_PATH)
    for path in files:
        of = tempfile.NamedTemporaryFile("w", suffix=".obs.ndjson", delete=False)
        vf = tempfile.NamedTemporaryFile("w", suffix=".vuln.ndjson", delete=False)
        try:
            date, n_obs, n_vuln = build_day(path, kev, epss, of, vf)
            of.close(); vf.close()
            copy_to_partition(con, of.name, n_obs, OBS_DIR, date, OBS_SELECT)
            copy_to_partition(con, vf.name, n_vuln, VULN_DIR, date, VULN_SELECT)
            print(f"{date}: {n_obs:,} observations, {n_vuln:,} vuln rows")
        finally:
            of.close(); vf.close()
            os.unlink(of.name); os.unlink(vf.name)
    refresh_views(con)
    n_obs = con.execute("SELECT count(*) FROM observations").fetchone()[0]
    n_days = con.execute("SELECT count(DISTINCT date) FROM observations").fetchone()[0]
    con.close()
    print(f"Store ready: {n_obs:,} observations across {n_days} day(s) -> {DB_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
