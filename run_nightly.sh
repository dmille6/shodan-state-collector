#!/usr/bin/env bash
#
# run_nightly.sh — the nightly pipeline: collect, then project into the store.
#
# 1. Collect the day's delta (shodan_collect.py).
# 2. Project that day's .gz into the DuckDB/Parquet store (build_store.py).
# 3. Compromise tripwire (compromise_watch.py).
#
# The store step runs even if collection came back PARTIAL (exit 3) so partial
# days are still queryable; the script exits with the COLLECTOR's status so
# cron/monitoring still sees a partial/failed collection.
#
# Bookkeeping added so a missed or bad night is NOTICED and REPAIRED:
#   * status/<date>.rc records the collector's exit code for that day (-1 while
#     a run is in progress); the 06:00 backfill_missed.py job re-pulls any recent
#     day whose file is missing or whose rc != 0.
#   * HEALTHCHECK_URL (.env) — a dead-man's-switch ping (healthchecks.io or
#     compatible). cron can report a run that FAILED; nothing reports a run that
#     never happened (box off, cron dead). The check alerts on SILENCE.
#     rc 0 and 3 ping success (3 = partial, auto-backfilled next morning);
#     anything else pings /fail.
#   * A lock shared with backfill_missed.py so the two never run concurrently.
#
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$DIR/venv/bin/python"
TODAY="$(date +%Y-%m-%d)"
ts() { date '+%Y-%m-%d %H:%M:%S'; }

# Single-instance lock (shared with backfill_missed.py).
exec 9>"$DIR/.pipeline.lock"
if ! flock -n 9; then
    echo "$(ts) - run_nightly: another pipeline run holds the lock — exiting" >&2
    exit 1
fi

# Dead-man's-switch ping. HEALTHCHECK_URL is resolved with the SAME .env loader
# the python scripts use (env var overrides .env; quotes stripped), so shell and
# python can never disagree about it. Silent no-op when unset.
HC="$(cd "$DIR" && "$PY" -c 'import os, shodan_collect as s; s.load_dotenv(".env"); print(os.environ.get("HEALTHCHECK_URL", "").strip())' 2>/dev/null)" \
    || echo "$(ts) - run_nightly: WARNING could not resolve HEALTHCHECK_URL (python/.env problem) — pings disabled this run" >&2
# Archive directory, resolved the same way the collector resolves OUTPUT_DIR.
OUT_SUBDIR="$(cd "$DIR" && "$PY" -c 'import os, shodan_collect as s; s.load_dotenv(".env"); print(os.environ.get("OUTPUT_DIR", "daily_downloads").strip())' 2>/dev/null)"
[ -n "$OUT_SUBDIR" ] || OUT_SUBDIR=daily_downloads
hc() {  # hc <suffix> [message]
    [ -n "$HC" ] || return 0
    curl -fsS -m 10 --retry 3 -o /dev/null --data-raw "${2:-}" "$HC$1" >/dev/null 2>&1 \
        || echo "$(ts) - run_nightly: healthcheck ping $1 failed (non-fatal)" >&2
}
record_rc() {  # record_rc <date> <rc>  — atomic (tmp + rename), never an empty file
    mkdir -p "$DIR/status" && echo "$2" > "$DIR/status/$1.rc.tmp" && mv -f "$DIR/status/$1.rc.tmp" "$DIR/status/$1.rc"
}

hc /start "collection for $TODAY starting"
# In-progress marker (-1). If this run is killed before it records a real rc,
# the marker is what the 06:00 backfill sees — and it treats it as "repair me".
# If the marker can't be written the bookkeeping is broken: say so loudly (and
# ping /fail so it's noticed), but still collect — the data matters more.
bookkeeping_broken=0
if ! record_rc "$TODAY" -1; then
    echo "$(ts) - run_nightly: CRITICAL cannot write $DIR/status/ — morning repair will be blind to this run" >&2
    bookkeeping_broken=1
fi

# Disk-space guard. Full-fidelity days can be ~2GB and unpredictable; a full ROOT
# filesystem would break cron/logging/the system. Warn when low; abort before
# critically low (losing one day is recoverable-ish; a wedged box is worse).
avail_gb=$(( $(df -P "$DIR" | awk 'NR==2{print $4}') / 1024 / 1024 ))
echo "$(ts) - run_nightly: ${avail_gb}GB free on $(df -P "$DIR" | awk 'NR==2{print $6}')"
if [ "$avail_gb" -lt 3 ]; then
    echo "$(ts) - CRITICAL: <3GB free — SKIPPING collection to protect the system. Offload archives or expand the disk." >&2
    record_rc "$TODAY" 1 || true
    hc /fail "CRITICAL: <3GB free, collection skipped for $TODAY"
    exit 1
elif [ "$avail_gb" -lt 10 ]; then
    echo "$(ts) - WARNING: only ${avail_gb}GB free — offload old archives / expand disk soon." >&2
fi

# --date pins the collector to the date this wrapper recorded, so a start that
# straddles midnight can't collect one day while we bookkeep another.
"$PY" "$DIR/shodan_collect.py" --date "$TODAY"
collect_rc=$?
if ! record_rc "$TODAY" "$collect_rc"; then
    echo "$(ts) - run_nightly: CRITICAL could not record rc=$collect_rc for $TODAY" >&2
    bookkeeping_broken=1
fi

# Project into the store if a file for today exists (partial counts too).
store_rc=0
if ls "$DIR/$OUT_SUBDIR"/*-events-"$TODAY".json.gz >/dev/null 2>&1; then
    "$PY" "$DIR/build_store.py" --date "$TODAY"
    store_rc=$?
    [ "$store_rc" -eq 0 ] || echo "$(ts) - run_nightly: WARNING build_store exited $store_rc — store may be stale" >&2
fi

# Compromise tripwire: ask Shodan for hosts it has FLAGGED as compromised/malicious
# in this state (its own threat tags/categories), separate from the exposure census
# above. It keeps a ledger of already-seen hosts, so exit 10 (the loud ALERT block)
# fires only on a genuinely NEW flagged host; hosts Shodan has been flagging for days
# are archived and noted quietly (exit 0) to avoid nightly alert fatigue. It does not
# change this script's exit status (which stays the COLLECTOR's, so census monitoring
# is unaffected) — a new hit is surfaced via the ALERT block in this log and
# compromise_hits/.
"$PY" "$DIR/compromise_watch.py"
watch_rc=$?

# Phase 2 evidence: Shadowserver reports (no-op until the state subscribes and
# keys are in .env), then the leads table — AFTER the store, the tripwire and
# Shadowserver, so new compromise evidence becomes a lead the same night. Runs
# even when no census file arrived (external evidence still needs reconciling).
if [ -f "$DIR/ingest_shadowserver.py" ]; then
    "$PY" "$DIR/ingest_shadowserver.py" fetch --date "$TODAY" >/dev/null 2>&1 || true
    "$PY" "$DIR/ingest_shadowserver.py" ingest || echo "$(ts) - run_nightly: WARNING shadowserver ingest exited $?" >&2
fi
if [ -f "$DIR/leads.py" ] && [ "$store_rc" -eq 0 ]; then
    "$PY" "$DIR/leads.py" refresh || echo "$(ts) - run_nightly: WARNING leads refresh exited $?" >&2
elif [ -f "$DIR/leads.py" ]; then
    echo "$(ts) - run_nightly: leads refresh skipped (store build failed)" >&2
fi
# Sensitive derived data (named orgs, attribution, packets): owner + group only.
chmod -R o-rwx "$DIR/store" "$DIR/reports" "$DIR/reference/registry" "$DIR/reference/discovery" \
      "$DIR/reference/shadowserver" "$DIR/compromise_hits" 2>/dev/null || true
if [ "$watch_rc" -eq 10 ]; then
    echo "$(ts) - run_nightly: COMPROMISE TRIPWIRE FIRED — see the ALERT block above and $DIR/compromise_hits/" >&2
elif [ "$watch_rc" -eq 5 ]; then
    echo "$(ts) - run_nightly: WARNING compromise tripwire INCOMPLETE (a Shodan count/search failed) — nothing marked cleared" >&2
fi

summary="$(grep -h "Wrote .* unique records .*$TODAY" "$DIR/shodan_collection.log" 2>/dev/null | tail -1)"
if [ "$bookkeeping_broken" -eq 1 ]; then
    # Collection may have been fine, but the morning repair is blind to it — that
    # is a failure someone must look at, so it must not end green.
    hc /fail "rc=$collect_rc but status/ bookkeeping FAILED for $TODAY. ${summary}"
else
    case "$collect_rc" in
        0) hc "" "rc=0 ok. ${summary}" ;;
        3) hc "" "rc=3 PARTIAL (backfill will retry at 06:00). ${summary}" ;;
        *) hc /fail "rc=$collect_rc collection FAILED for $TODAY. ${summary}" ;;
    esac
fi

exit "$collect_rc"
