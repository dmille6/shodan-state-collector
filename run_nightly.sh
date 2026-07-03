#!/usr/bin/env bash
#
# run_nightly.sh — the nightly pipeline: collect, then project into the store.
#
# 1. Collect the day's delta (shodan_collect.py).
# 2. Project that day's .gz into the DuckDB/Parquet store (build_store.py).
#
# The store step runs even if collection came back PARTIAL (exit 3) so partial
# days are still queryable; the script exits with the COLLECTOR's status so
# cron/monitoring still sees a partial/failed collection.
#
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$DIR/venv/bin/python"
TODAY="$(date +%Y-%m-%d)"
ts() { date '+%Y-%m-%d %H:%M:%S'; }

# Disk-space guard. Full-fidelity days can be ~2GB and unpredictable; a full ROOT
# filesystem would break cron/logging/the system. Warn when low; abort before
# critically low (losing one day is recoverable-ish; a wedged box is worse).
avail_gb=$(( $(df -P "$DIR" | awk 'NR==2{print $4}') / 1024 / 1024 ))
echo "$(ts) - run_nightly: ${avail_gb}GB free on $(df -P "$DIR" | awk 'NR==2{print $6}')"
if [ "$avail_gb" -lt 3 ]; then
    echo "$(ts) - CRITICAL: <3GB free — SKIPPING collection to protect the system. Offload archives or expand the disk." >&2
    exit 1
elif [ "$avail_gb" -lt 10 ]; then
    echo "$(ts) - WARNING: only ${avail_gb}GB free — offload old archives / expand disk soon." >&2
fi

"$PY" "$DIR/shodan_collect.py"
collect_rc=$?

# Project into the store if a file for today exists (partial counts too).
if ls "$DIR"/daily_downloads/*-events-"$TODAY".json.gz >/dev/null 2>&1; then
    "$PY" "$DIR/build_store.py" --date "$TODAY"
fi

exit "$collect_rc"
