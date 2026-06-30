#!/usr/bin/env bash
#
# shodan_query.sh — daily collector for a US state's internet-exposed hosts.
#
# Pulls the day's DELTA of Shodan host records for the configured state (hosts
# that Shodan (re)scanned in the last ~24h) and archives them, one gzipped
# NDJSON file per day, under daily_downloads/.
#
# Why a delta and not a full census: Shodan's index keeps only each host's
# LATEST banner. Once a host is re-scanned its previous state is gone forever,
# so the only way to build history is to capture the forward daily delta. This
# archive is therefore an immutable, irreplaceable system of record.
#
# All configuration lives in .env (see .env.example). This script hard-codes no
# paths — it runs from wherever it lives.
#
set -euo pipefail

# --- Resolve this script's own directory (portable; no hard-coded paths) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Load .env if present (export everything it defines) ---
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/.env"
    set +a
fi

# --- Configuration (with safe defaults; .env overrides) ---
SHODAN_STATE_CODE="${SHODAN_STATE_CODE:-LA}"            # 2-letter region code for the Shodan query
SHODAN_STATE_NAME="${SHODAN_STATE_NAME:-louisiana}"    # human name, used in output filenames
SHODAN_ORG_RESCUE="${SHODAN_ORG_RESCUE:-true}"         # also pull org:<name> hosted outside the state
SHODAN_ORG_NAME="${SHODAN_ORG_NAME:-$SHODAN_STATE_NAME}"  # org search term for the rescue query
OUTPUT_SUBDIR="${OUTPUT_DIR:-daily_downloads}"         # subfolder (under this dir) for the archive
RETENTION_DAYS="${RETENTION_DAYS:-0}"                  # delete archives older than N days; 0 = keep forever
VENV_DIR="${VENV_DIR:-$SCRIPT_DIR/venv}"               # virtualenv holding the shodan CLI

DAILY_DIR="$SCRIPT_DIR/$OUTPUT_SUBDIR"
LOG_FILE="$SCRIPT_DIR/shodan_collection.log"
SHODAN_CMD="$VENV_DIR/bin/shodan"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }

# --- Preflight checks ---
if [ ! -x "$SHODAN_CMD" ]; then
    log "ERROR: shodan CLI not found at $SHODAN_CMD. Create the venv and 'pip install shodan'."
    exit 1
fi
if ! "$SHODAN_CMD" info >/dev/null 2>&1; then
    log "ERROR: Shodan API auth failed. Run: $SHODAN_CMD init <YOUR_API_KEY>"
    exit 1
fi

mkdir -p "$DAILY_DIR"
log "Starting Shodan collection for state=$SHODAN_STATE_CODE ($SHODAN_STATE_NAME)"
log "API: $("$SHODAN_CMD" info 2>/dev/null | tr '\n' ' ')"

# --- Date window ---
# IMPORTANT: filenames use ISO (YYYY-MM-DD), but Shodan's after:/before: filters
# REQUIRE DD/MM/YYYY. Passing ISO to after:/before: silently returns ~0 results.
current_date="$(date +%Y-%m-%d)"
yesterday_q="$(date -d 'yesterday' +%d/%m/%Y)"
tomorrow_q="$(date -d 'tomorrow'  +%d/%m/%Y)"
WINDOW="after:$yesterday_q before:$tomorrow_q"

output_filename="${SHODAN_STATE_NAME}-events-${current_date}.json.gz"
output_path="$DAILY_DIR/$output_filename"

# Don't clobber a same-day run — back the existing file up instead.
if [ -f "$output_path" ]; then
    log "WARNING: $output_filename already exists — backing up."
    mv "$output_path" "${output_path}.backup.$(date +%s)"
fi

# --- Build the query list ---
# QUERIES[0] is the primary geo query and MUST succeed. Supplemental queries are
# additive (merged + deduped) and are allowed to fail without aborting the run.
QUERIES=("state:${SHODAN_STATE_CODE} country:US $WINDOW")
if [ "$SHODAN_ORG_RESCUE" = "true" ]; then
    # Recover state-named orgs that geolocate OUTSIDE the state (e.g. cloud-hosted).
    QUERIES+=("org:${SHODAN_ORG_NAME} -state:${SHODAN_STATE_CODE} $WINDOW")
fi

log "Output file: $output_path"

# --- Download each query to a temp file ---
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
part_files=()
i=0
for q in "${QUERIES[@]}"; do
    part="$work_dir/part_${i}.json.gz"
    log "Running query[$i]: $q"
    if "$SHODAN_CMD" download "$part" --limit -1 "$q"; then
        if [ -s "$part" ]; then
            part_files+=("$part")
        else
            log "WARNING: query[$i] returned no results"
        fi
    else
        log "ERROR: shodan download failed for query[$i]: $q"
        if [ "$i" -eq 0 ]; then
            log "ERROR: primary geo query failed — aborting."
            exit 1
        fi
    fi
    i=$((i + 1))
done

# --- Merge all parts into one gzipped NDJSON, deduping by banner 'hash' ---
# (fallback dedup key: ip_str:port:timestamp). One record = one Shodan banner.
record_count=0
if [ "${#part_files[@]}" -gt 0 ]; then
    record_count=$(zcat "${part_files[@]}" 2>/dev/null | python3 -c '
import sys, json, gzip
seen = set(); n = 0
with gzip.open(sys.argv[1], "wt", encoding="utf-8") as out:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = rec.get("hash")
        if key is None:
            key = "%s:%s:%s" % (rec.get("ip_str"), rec.get("port"), rec.get("timestamp"))
        if key in seen:
            continue
        seen.add(key); out.write(line + "\n"); n += 1
print(n)
' "$output_path")
fi
record_count="${record_count:-0}"

# --- Report result ---
if [ "$record_count" -gt 0 ]; then
    file_size=$(stat -c%s "$output_path" 2>/dev/null || echo "?")
    log "Wrote $record_count unique records to $output_filename (${file_size} bytes)"
else
    # A zero-record delta day is suspicious — it was the symptom of the ISO-date bug.
    rm -f "$output_path"
    log "WARNING: 0 records collected for $current_date (all queries empty). Check the query window and API."
    exit 2
fi

# --- Optional retention cleanup ---
if [ "$RETENTION_DAYS" -gt 0 ] 2>/dev/null; then
    deleted=$(find "$DAILY_DIR" -name "${SHODAN_STATE_NAME}-events-*.json.gz" -mtime "+${RETENTION_DAYS}" -print -delete | wc -l)
    [ "$deleted" -gt 0 ] && log "Retention: deleted $deleted archive(s) older than ${RETENTION_DAYS} days"
fi

log "Done."
