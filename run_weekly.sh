#!/usr/bin/env bash
# run_weekly.sh — Sunday maintenance, before the nightly:
#   1. refresh_reference.py   KEV, EPSS, MaxMind GeoIP, exploit index, IOC feeds
#   2. refresh_rosters.py     public sector rosters (water, healthcare, education, ...)
#   3. discover_domains.py    certificate-transparency discovery + DNS resolution
#   4. build_registry.py      owner registry -> store/registry/*.parquet
# Each step is optional (skipped if the script is absent) and fail-soft.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$DIR/venv/bin/python"
ts() { date '+%Y-%m-%d %H:%M:%S'; }
for step in refresh_reference.py refresh_rosters.py discover_domains.py build_registry.py; do
    if [ -f "$DIR/$step" ]; then
        echo "$(ts) - run_weekly: $step"
        "$PY" "$DIR/$step" || echo "$(ts) - run_weekly: WARNING $step exited $?" >&2
    fi
done
echo "$(ts) - run_weekly: done"
