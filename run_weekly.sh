#!/usr/bin/env bash
# run_weekly.sh — Sunday maintenance, before the nightly:
#   1. refresh_reference.py   KEV, EPSS, MaxMind GeoIP, exploit index, IOC feeds
#   2. refresh_rosters.py     public sector rosters (water, healthcare, education, ...)
#   3. discover_domains.py    certificate-transparency discovery + DNS resolution (capped)
#   4. build_registry.py      owner registry -> store/registry/*.parquet
# Each step is optional (skipped if the script is absent), fail-soft, and runs
# under a hard `timeout` so a stuck feed can never run into the 23:30 nightly.
# The whole run must finish inside WEEKLY_BUDGET_MIN (default 100 min).
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$DIR/venv/bin/python"
ts() { date '+%Y-%m-%d %H:%M:%S'; }
WEEKLY_BUDGET_MIN="${WEEKLY_BUDGET_MIN:-100}"
start=$(date +%s)
rc_all=0
run_step() {  # run_step <minutes> <script> [args...]
    local mins="$1"; shift
    local script="$1"; shift
    [ -f "$DIR/$script" ] || return 0
    local used=$(( ($(date +%s) - start) / 60 ))
    if [ "$used" -ge "$WEEKLY_BUDGET_MIN" ]; then
        echo "$(ts) - run_weekly: budget exhausted (${used}m) — skipping $script" >&2; rc_all=1; return 0
    fi
    echo "$(ts) - run_weekly: $script (limit ${mins}m)"
    timeout --kill-after=60 "${mins}m" "$PY" "$DIR/$script" "$@"
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "$(ts) - run_weekly: WARNING $script exited $rc$([ "$rc" -eq 124 ] && echo ' (timed out)')" >&2
        rc_all=1
    fi
}
run_step 15 refresh_reference.py
run_step 30 refresh_rosters.py --max-minutes 25
run_step 45 discover_domains.py --max-minutes 40 --max-seeds 40 --max-names 500
run_step 20 build_registry.py
chmod -R o-rwx "$DIR/store" "$DIR/reference/registry" "$DIR/reference/discovery" "$DIR/reference/rosters" 2>/dev/null || true
echo "$(ts) - run_weekly: done in $(( ($(date +%s) - start) / 60 ))m (rc $rc_all)"
exit "$rc_all"
