#!/usr/bin/env python3
"""
backfill_missed.py — morning repair job for the nightly collection.

The nightly run can miss a day (box off, process killed) or come back PARTIAL
(exit 3: a page was lost or the fetch was below MIN_COMPLETENESS_PCT). Both were
correctly logged but nothing ever ACTED on them, so gaps and partial days silently
accumulated in an archive whose whole value is "no missing days". This job runs
at 06:00 and repairs any recent day that needs it.

A day needs a RE-PULL when ANY of:
  * its daily_downloads/<name>-events-<date>.json.gz is missing (even if a
    .backup.* copy exists — the collector moves the file aside before a re-pull,
    so a re-pull that died leaves the day "stranded" in a backup);
  * status/<date>.rc is not 0 — including the in-progress marker (-1) that both
    run_nightly.sh and this job write before touching a day, which is what a run
    killed mid-way leaves behind.
A day needs a MERGE ONLY (no re-pull) when it is otherwise clean but .backup.*
copies still sit beside it: that is unfinished merge work from an interrupted
repair. A day with a file, no backups and no status record predates the
bookkeeping and is left alone.

Why a lookback of a few days, not just yesterday: after downtime the first morning
back should repair every day it can. But Shodan's after:/before: match a host's
LATEST banner timestamp, so every day a backfill waits, more of that day's hosts
have been re-scanned out of the window — backfill value decays fast. Hence a
short default lookback (BACKFILL_LOOKBACK_DAYS=3); weeks-old days are gone.

Never makes a day worse. After a re-pull, the fresh file and EVERY existing copy
of the day are merged into one file, de-duplicated only on byte-identical
records, so anything that differs at all is kept. The merged file
(a superset of everything readable) is published if it is non-empty. A source
that could not be fully read is never deleted — it stays as a backup and the day
is left marked unclean so the next morning merges again; a source with lines
the merge could not carry is parked under a .rejected.* name (bytes preserved,
not re-merged). Only backups whose every line is in the merged file are
removed. If a merge cannot run, the best readable backup is put back by rename.
The merged day is then re-projected into the DuckDB/Parquet store.

Stale temp files (*.tmp older than a day) are removed — we hold the pipeline
lock, so nothing is writing them.

Usage:
    backfill_missed.py                 # repair the last BACKFILL_LOOKBACK_DAYS days
    backfill_missed.py --date 2026-08-29   # force a re-pull of one specific day
    backfill_missed.py --dry-run       # report only: touches no archive/status
                                       # (still appends to the log, takes the lock)

Exit codes: 0 nothing needed, or every repaired day ended clean (collector exit
0 and a complete merge); 3 at least one inspected day is still not clean
(partial / suspect / missing / skipped by the disk guard / merge incomplete /
repair crashed) — per-day detail is in status/<date>.rc and the log; 1 could not
get the pipeline lock.
"""
import argparse
import fcntl
import glob
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
import urllib.request
from datetime import datetime, timedelta

from shodan_collect import load_dotenv, log as _log

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(SCRIPT_DIR, "venv", "bin", "python")
STATUS_DIR = os.path.join(SCRIPT_DIR, "status")
LOCK_PATH = os.path.join(SCRIPT_DIR, ".pipeline.lock")
RC_RUNNING = -1                 # in-progress marker (also written by run_nightly.sh)
RC_CORRUPT = -2                 # status file present but unparseable
MIN_FREE_GB = 3                 # same abort threshold as run_nightly.sh
GB = 1024 ** 3


def log(msg):
    _log(f"backfill: {msg}")


# --- status bookkeeping -------------------------------------------------------

def read_rc(iso):
    """Recorded collector rc for the day: None if there is no record at all,
    RC_CORRUPT if a record exists but cannot be parsed (broken bookkeeping is
    NOT the same as a day that predates bookkeeping)."""
    p = os.path.join(STATUS_DIR, f"{iso}.rc")
    if not os.path.exists(p):
        return None
    try:
        with open(p) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return RC_CORRUPT


def prior_rc(iso):
    """The day's recorded rc, or 3 (partial) when there is no usable one."""
    rc = read_rc(iso)
    return 3 if rc in (None, RC_RUNNING, RC_CORRUPT) else rc


def write_rc(iso, rc):
    """Atomic: write to a temp file then rename, so a kill never leaves an empty rc."""
    os.makedirs(STATUS_DIR, exist_ok=True)
    final = os.path.join(STATUS_DIR, f"{iso}.rc")
    tmp = final + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(f"{rc}\n")
    os.replace(tmp, final)


# --- archive helpers ----------------------------------------------------------

def record_key(line):
    """Merge identity = the EXACT record text (digested to save memory). Two lines
    are duplicates only if they are byte-for-byte the same JSON; anything that
    differs at all — a second observation of the same banner with a different
    timestamp, different metadata, two hosts serving an identical banner — is
    kept. That is what makes the merged file a true superset of its inputs. The
    collector's own hash-only dedup is deliberately NOT reused here: it would
    silently drop one of two distinct observations."""
    return hashlib.sha1(line.encode("utf-8")).digest()


class GzSource:
    """Streams (raw_line, key) from a daily .gz and REMEMBERS how the read went:
      complete  — the stream reached a clean end-of-file. Any read/decode error
                  ends the stream early with complete=False; callers must never
                  treat such a source as fully consumed. With `truncated_ok`
                  (the file is KNOWN to be a cut-off download) the one expected
                  error — EOFError, "compressed file ended before the end-of-
                  stream marker" — also counts as complete: the deflate stream
                  simply stops there and nothing past it can be recovered by
                  anyone. Any OTHER error (zlib corruption, BadGzipFile, OSError,
                  bad UTF-8) still means incomplete, even for a cut-off download.
      rejected  — lines that were not a JSON object and were skipped. A source
                  with rejected lines has content the merge did not carry; it
                  must be preserved, not deleted. (A cut-off download's ragged
                  last line counts too — cheap insurance; such sources are never
                  deleted anyway, see backfill_day.)"""

    def __init__(self, path, truncated_ok=False):
        self.path = path
        self.truncated_ok = truncated_ok
        self.count = 0
        self.rejected = 0
        self.complete = False
        self.error = None

    def __iter__(self):
        try:
            with gzip.open(self.path, "rt", encoding="utf-8") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        obj = None
                    if not isinstance(obj, dict):
                        self.rejected += 1          # skipped, but remembered
                        continue
                    self.count += 1
                    yield line, record_key(line)
            self.complete = True
        except Exception as exc:                   # corrupt gzip, zlib.error, OSError, UTF-8 ...
            self.error = exc
            # Only the one error a cut-off stream MUST end with (EOFError) counts
            # as "read everything it has". zlib corruption, BadGzipFile, a
            # permission/I/O error or bad UTF-8 could all hide unread content.
            if self.truncated_ok and isinstance(exc, EOFError):
                self.complete = True
                log(f"  recovered {self.count} records from cut-off download "
                    f"{os.path.basename(self.path)}")
            else:
                log(f"  WARNING: {os.path.basename(self.path)} could not be read to the end "
                    f"after {self.count} records ({exc})")


def count_records(path):
    """Parseable records in a daily .gz (None if absent). Tolerates corrupt files."""
    if not os.path.isfile(path):
        return None
    src = GzSource(path)
    for _ in src:
        pass
    return src.count


def merge_copies(sources, tmp_dest):
    """Union all `sources` (first = preferred on key collision) into a NEW gzip
    at `tmp_dest`. Nothing is published or deleted here — the caller inspects the
    returned GzSource objects (count / complete) and decides.
    Returns (n_merged, [GzSource, ...])."""
    seen = set()
    readers = []
    with gzip.open(tmp_dest, "wt", encoding="utf-8") as out:
        for path in sources:
            src = GzSource(path, truncated_ok=path.endswith(PARTIAL_PULL_SUFFIX))
            for line, key in src:
                if key in seen:
                    continue
                seen.add(key)
                out.write(line + "\n")
            readers.append(src)
    return len(seen), readers


def free_bytes(path):
    return shutil.disk_usage(path).free


def unique_name(path, tag, suffix=""):
    """<path>.<tag>.<epoch>[.n]<suffix>, guaranteed not to exist yet."""
    base = f"{path}.{tag}.{int(time.time())}"
    cand = base + suffix
    n = 0
    while os.path.exists(cand):
        n += 1
        cand = f"{base}.{n}{suffix}"
    return cand


PARTIAL_PULL_SUFFIX = ".partialpull"      # a quarantined, cut-off collector .tmp


def quarantine_partial_pull(path):
    """If the collector left a cut-off download (<path>.tmp) behind, move it to a
    .backup.*.partialpull name so (a) the next collector run cannot open and
    truncate it, (b) the merge picks it up as a backup copy and salvages every
    record it holds. Returns the new name or None."""
    tmp = path + ".tmp"
    if not os.path.isfile(tmp):
        return None
    dest = unique_name(path, "backup", PARTIAL_PULL_SUFFIX)
    os.replace(tmp, dest)
    log(f"  quarantined cut-off download {os.path.basename(tmp)} -> {os.path.basename(dest)}")
    return dest


class Copy:
    def __init__(self, path, complete, count):
        self.path, self.complete, self.count = path, complete, count


def best_backup(path):
    """The .backup.* copy of a day best suited to stand in as the canonical file:
    only FULLY READABLE ones with every line a JSON object qualify (anything
    else could break build_store), most records wins. Cut-off downloads (.partialpull) are never
    promoted — they must stay quarantined so the merge keeps treating their
    ragged end as expected. Returns a Copy or None."""
    cands = [b for b in glob.glob(path + ".backup.*") if not b.endswith(PARTIAL_PULL_SUFFIX)]
    scored = []
    for b in cands:
        src = GzSource(b)
        for _ in src:
            pass
        if src.complete and not src.rejected:   # a file build_store could choke on
            scored.append((src.count, b))       # must never become the canonical
    if not scored:
        return None
    count, b = max(scored)
    return Copy(b, True, count)


def hc_ping(url, suffix, msg):
    """Non-fatal healthcheck ping (used with /log so it never changes status)."""
    if not url:
        return
    try:
        req = urllib.request.Request(url + suffix, data=msg.encode()[:10000], method="POST")
        urllib.request.urlopen(req, timeout=10)
    except Exception as exc:
        log(f"healthcheck ping failed (non-fatal): {exc}")


# --- the repair ---------------------------------------------------------------

def day_status(daily_dir, state_name, iso):
    """Return (path, action, reason) with action in {None, 'repull', 'merge'}."""
    path = os.path.join(daily_dir, f"{state_name}-events-{iso}.json.gz")
    rc = read_rc(iso)
    backups = glob.glob(path + ".backup.*")
    if not os.path.isfile(path):
        return path, "repull", ("file missing (stranded backup present)" if backups
                                else "file missing")
    if rc == RC_RUNNING:
        return path, "repull", "previous run was interrupted (in-progress marker left behind)"
    if rc == RC_CORRUPT:
        return path, "repull", "status record unreadable (broken bookkeeping)"
    if rc not in (None, 0):
        return path, "repull", f"nightly exit {rc}"
    if backups or os.path.isfile(path + ".tmp"):
        return path, "merge", "unmerged backup / cut-off download beside a clean day"
    return path, None, "ok" if rc == 0 else "ok (pre-status day)"


def _fallback_restore(iso, path, why, lock_fd=None):
    """A merge could not run (no space / crash). Emergency, rename-only repair:
      * canonical missing  -> put the best fully-readable backup back in place;
      * canonical present  -> if a fully-readable backup has MORE records, swap
        it in (the smaller file is kept as a backup).
    The swap maximises what the store can see right now; it is not a superset
    guarantee (the smaller file may hold records the bigger one lacks) — that is
    what the next morning's merge is for, and every byte stays on disk under a
    merge-discoverable name. Always records 3 so that merge happens."""
    bb = best_backup(path)
    if not os.path.isfile(path):
        if bb:
            os.replace(bb.path, path)
            log(f"{iso}: {why} — restored {os.path.basename(bb.path)} "
                f"({bb.count} records) as the day's file (rename)")
    elif bb and bb.complete:
        # A fuller, fully readable backup beats a smaller canonical (e.g. a thin
        # re-pull that displaced a big original): swap them by rename.
        have = count_records(path)
        if bb.count > have:
            aside = unique_name(path, "backup")
            os.replace(path, aside)
            os.replace(bb.path, path)
            log(f"{iso}: {why} — swapped in {os.path.basename(bb.path)} ({bb.count} records) "
                f"over the {have}-record file, which is kept as {os.path.basename(aside)}")
    log(f"{iso}: day left UNCLEAN ({why})")
    write_rc(iso, 3)
    if os.path.isfile(path):            # keep the store in step with whatever stands
        project(iso, lock_fd)
    return 3


def project(iso, lock_fd=None):
    """Re-project one day into the DuckDB/Parquet store; warn on failure."""
    kw = {"pass_fds": [lock_fd]} if lock_fd is not None else {}
    proj = subprocess.run([PY, os.path.join(SCRIPT_DIR, "build_store.py"), "--date", iso], **kw)
    if proj.returncode != 0:
        log(f"{iso}: WARNING build_store exited {proj.returncode} — store partition may be stale")


def backfill_day(iso, path, action, lock_fd, dry_run):
    """Repair one day. action 'repull' re-collects then merges; 'merge' only merges.
    Returns the day's resulting rc: 0 only when the collector (if run) returned 0
    AND every copy was merged to completion; otherwise 3 (or the collector's own
    non-zero code)."""
    daily_dir = os.path.dirname(path)

    def copies_now():
        return ([path] if os.path.isfile(path) else []) + sorted(glob.glob(path + ".backup.*"))

    copies = copies_now()
    tmp_pull = path + ".tmp"
    log(f"{iso}: {action}; existing copies: "
        + (", ".join(f"{os.path.basename(p)}={count_records(p)}" for p in copies) or "none")
        + (f"; cut-off download {os.path.basename(tmp_pull)} present" if os.path.isfile(tmp_pull) else ""))
    if dry_run:
        return 0
    os.makedirs(daily_dir, exist_ok=True)

    prior = prior_rc(iso)               # read BEFORE we overwrite it with the marker
    write_rc(iso, RC_RUNNING)           # from here on, a death means "repair me again"
    rc = prior

    quarantine_partial_pull(path)       # never let the collector truncate a cut-off pull
    copies = copies_now()

    # Space budget for the WHOLE repair. A re-pull adds a fresh copy of unknown
    # size B (assume: as big as the biggest copy we have, at least 256MB), and
    # the merged union can be as large as the sum of everything (E + B). So a
    # re-pull needs headroom + E + 2B before it starts; a merge-only needs
    # headroom + E. Sizes are gzip'd-input estimates, not hard bounds, which is
    # why the merge re-checks right before it writes.
    existing_bytes = sum(os.path.getsize(p) for p in copies)
    pull_est = max(max((os.path.getsize(p) for p in copies), default=0), 256 * 1024 * 1024)
    need = MIN_FREE_GB * GB + existing_bytes + (2 * pull_est if action == "repull" else 0)
    if free_bytes(daily_dir) < need:
        return _fallback_restore(iso, path, f"not enough free space (need ~{need // (1024**2)}MB "
                                            f"incl. {MIN_FREE_GB}GB headroom)", lock_fd)

    if action == "repull":
        rc = subprocess.run([PY, os.path.join(SCRIPT_DIR, "shodan_collect.py"), "--date", iso],
                            pass_fds=[lock_fd]).returncode   # child inherits the lock
        new_exists = os.path.isfile(path)
        log(f"{iso}: collector rc={rc}, new records="
            f"{count_records(path) if new_exists else 'no file'}")
        if not new_exists:
            rc = prior                  # re-pull added nothing; the day stands as before
            quarantine_partial_pull(path)   # a pull killed mid-way still has records

    # Every copy that now exists: fresh pull first (preferred), then backups.
    copies = copies_now()
    if not copies:
        log(f"{iso}: nothing to merge — day still missing")
        write_rc(iso, 3)
        return 3

    # Re-check the budget for the merge output itself now that the pull is in.
    if free_bytes(daily_dir) < MIN_FREE_GB * GB + sum(os.path.getsize(p) for p in copies):
        return _fallback_restore(iso, path, "not enough free space for the merged file", lock_fd)

    tmp = path + ".merge.tmp"
    try:
        merged_n, readers = merge_copies(copies, tmp)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    detail = ", ".join(f"{os.path.basename(r.path)}={r.count}"
                       f"{'' if r.complete else '(INCOMPLETE)'}"
                       f"{f'(+{r.rejected} rejected lines)' if r.rejected else ''}"
                       for r in readers)
    all_complete = all(r.complete for r in readers)
    log(f"{iso}: merged {len(copies)} cop{'y' if len(copies) == 1 else 'ies'} (exact-line dedup) -> "
        f"{merged_n} records ({detail})")

    if merged_n == 0:
        os.remove(tmp)
        return _fallback_restore(iso, path, "merge produced no records; nothing published", lock_fd)

    # If the canonical file itself could not be fully read, or held lines the
    # merge could not carry, keep its bytes: park it before the merged file
    # takes its place.
    canon = next((r for r in readers if r.path == path), None)
    parked = None
    if canon is not None and (not canon.complete or canon.rejected):
        parked = unique_name(path, "backup")    # discoverable name until publication
        os.replace(path, parked)
        log(f"{iso}: canonical file {'not fully readable' if not canon.complete else 'had rejected lines'}"
            f" — preserved as {os.path.basename(parked)}")
    os.replace(tmp, path)               # publish the merged day
    if parked and canon.complete and canon.rejected:
        # Only now (merged file safely in place) retire it from the merge set.
        retired = unique_name(path, "rejected")
        os.replace(parked, retired)
        log(f"{iso}: {os.path.basename(parked)} retired as {os.path.basename(retired)}")

    # Backups after the merge:
    #   * ordinary backup, read to completion, nothing rejected -> every byte of
    #     content is in the merged file: delete it;
    #   * cut-off download (.partialpull) -> NEVER deleted. Once merged it is
    #     parked as .salvaged.<ts> (a name the merge does not glob), so its raw
    #     bytes survive for a manual look no matter how its read ended;
    #   * anything with rejected lines -> parked as .rejected.<ts>, same idea;
    #   * anything incomplete -> stays a .backup.* for another pass.
    for r in readers:
        if r.path == path or not os.path.exists(r.path):
            continue
        if r.path.endswith(PARTIAL_PULL_SUFFIX):
            if r.complete:
                parked = unique_name(path, "salvaged")
                os.replace(r.path, parked)
                log(f"{iso}: cut-off download merged ({r.count} records) — bytes kept as "
                    f"{os.path.basename(parked)}")
            # else: stays quarantined as a backup; day goes unclean below
        elif r.complete and not r.rejected:
            os.remove(r.path)
            log(f"{iso}: removed merged-in backup {os.path.basename(r.path)}")
        elif r.complete and r.rejected:
            parked = unique_name(path, "rejected")
            os.replace(r.path, parked)
            log(f"{iso}: {os.path.basename(r.path)} had {r.rejected} rejected lines — "
                f"preserved as {os.path.basename(parked)}")

    if not all_complete:
        log(f"{iso}: one or more copies were incomplete — day stays unclean for another pass")
        rc = 3
    elif rc in (RC_RUNNING, RC_CORRUPT):
        rc = 3
    write_rc(iso, rc)

    project(iso, lock_fd)
    return rc


def sweep_tmp(daily_dir, dry_run):
    """Housekeeping for leftovers older than a day. Merge temps are disposable.
    A collector .tmp is a cut-off download that may hold records nobody can get
    again — it is quarantined (renamed), never deleted, so a later --date repair
    can still salvage it."""
    cutoff = time.time() - 86400
    for tmp in glob.glob(os.path.join(daily_dir, "*.tmp")):
        if os.path.getmtime(tmp) >= cutoff:
            continue
        if tmp.endswith(".merge.tmp"):
            log(f"removing stale merge temp {os.path.basename(tmp)}{' (dry-run)' if dry_run else ''}")
            if not dry_run:
                os.remove(tmp)
        elif tmp.endswith(".json.gz.tmp"):
            log(f"stale cut-off download {os.path.basename(tmp)}: quarantining"
                f"{' (dry-run)' if dry_run else ''}")
            if not dry_run:
                quarantine_partial_pull(tmp[:-len(".tmp")])


def main():
    load_dotenv(os.path.join(SCRIPT_DIR, ".env"))
    ap = argparse.ArgumentParser(description="Re-pull / merge missing, partial or interrupted recent days.")
    ap.add_argument("--date", help="force a re-pull of this one day (YYYY-MM-DD)")
    ap.add_argument("--lookback", type=int,
                    default=int(os.environ.get("BACKFILL_LOOKBACK_DAYS", "3")),
                    help="how many days back (from yesterday) to inspect")
    ap.add_argument("--dry-run", action="store_true", help="report only, change nothing")
    args = ap.parse_args()

    state_name = os.environ.get("SHODAN_STATE_NAME", "louisiana")
    daily_dir = os.path.join(SCRIPT_DIR, os.environ.get("OUTPUT_DIR", "daily_downloads"))
    hc_url = os.environ.get("HEALTHCHECK_URL", "").strip()

    lock = open(LOCK_PATH, "a")         # "a": never truncate another holder's file
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log("pipeline lock held (nightly still running?) — exiting without action")
        return 1

    if args.date:
        # Normalize to the exact YYYY-MM-DD the collector uses in filenames, so
        # "2026-9-5" cannot bookkeep one name while the collector writes another.
        try:
            days = [datetime.strptime(args.date, "%Y-%m-%d").strftime("%Y-%m-%d")]
        except ValueError:
            log(f"ERROR: --date must be YYYY-MM-DD (got {args.date!r})")
            return 1
    else:
        today = datetime.now().date()
        days = [(today - timedelta(days=i)).isoformat() for i in range(1, args.lookback + 1)]

    if not args.dry_run:
        os.makedirs(daily_dir, exist_ok=True)
    log(f"checking {', '.join(days)}{' [DRY-RUN]' if args.dry_run else ''}")
    unclean = 0
    repaired = []
    for iso in days:
        path = os.path.join(daily_dir, f"{state_name}-events-{iso}.json.gz")
        try:
            path, action, reason = day_status(daily_dir, state_name, iso)
            if args.date:
                action = "repull"
            if action is None:
                log(f"{iso}: {reason}")
                continue
            log(f"{iso}: needs {action} — {reason}")
            rc = backfill_day(iso, path, action, lock.fileno(), args.dry_run)
        except Exception:
            log(f"{iso}: repair CRASHED — will be looked at again tomorrow\n"
                + traceback.format_exc())
            if not args.dry_run:
                try:
                    # A crash after the collector moved the day aside must not
                    # leave it stranded: put the best readable copy back, record 3.
                    _fallback_restore(iso, path, "repair crashed", lock.fileno())
                except Exception as exc:
                    log(f"{iso}: could not run fallback restore either ({exc})")
            rc = 3
        repaired.append(f"{iso} rc={rc}")
        if rc != 0:
            unclean += 1

    try:
        sweep_tmp(daily_dir, args.dry_run)
    except Exception as exc:
        log(f"housekeeping sweep failed (non-fatal): {exc}")

    if repaired and not args.dry_run:
        hc_ping(hc_url, "/log", "backfill: " + "; ".join(repaired))
    log("done" + (f" — repaired: {', '.join(repaired)}" if repaired else " — nothing to do"))
    return 3 if unclean else 0


if __name__ == "__main__":
    sys.exit(main())
