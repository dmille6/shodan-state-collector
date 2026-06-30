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

# Silence the (harmless) pkg_resources deprecation warning shodan 1.31 emits,
# so it doesn't clutter the log on every run.
export PYTHONWARNINGS="ignore::UserWarning"

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
MAX_DOWNLOAD_ATTEMPTS="${MAX_DOWNLOAD_ATTEMPTS:-3}"    # retries when a download comes back truncated
MIN_COMPLETENESS_PCT="${MIN_COMPLETENESS_PCT:-90}"     # a download is "complete" if saved >= this % of count
RETRY_SLEEP="${RETRY_SLEEP:-30}"                       # seconds to wait between download retries

DAILY_DIR="$SCRIPT_DIR/$OUTPUT_SUBDIR"
LOG_FILE="$SCRIPT_DIR/shodan_collection.log"
SHODAN_CMD="$VENV_DIR/bin/shodan"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"; }

# download_query <query> <dest.json.gz>
# Downloads a query to <dest>, guarding against Shodan's silent partial downloads.
# Shodan occasionally drops the connection mid-download and saves only part of the
# result set while still exiting 0 (it just prints a soft "fewer results were saved"
# notice — which it ALSO prints on a 99.9%-complete download, so that notice alone
# is not a reliable failure signal). We instead compare the saved record count
# against a free `shodan count`, and retry if it's well short. The best (largest)
# attempt is kept. Sets global DL_SAVED to the saved count; returns 0 if complete,
# 1 if still short after all attempts.
download_query() {
    local query="$1" dest="$2"
    local expected saved best_saved=-1 attempt tmp
    DL_SAVED=0

    # `shodan count` is free (no query-credit cost) — our reference for "how many
    # results should we have gotten". Strip to digits; default 0 if it fails.
    expected="$("$SHODAN_CMD" count "$query" 2>/dev/null | tr -dc '0-9')"
    expected="${expected:-0}"

    for attempt in $(seq 1 "$MAX_DOWNLOAD_ATTEMPTS"); do
        # NOTE: the Shodan CLI appends ".json.gz" unless the name already ends in
        # it, so the temp name MUST end in .json.gz or the file lands elsewhere.
        tmp="${dest%.json.gz}.attempt${attempt}.json.gz"
        if "$SHODAN_CMD" download "$tmp" --limit -1 "$query" >>"$LOG_FILE" 2>&1; then
            saved="$(zcat "$tmp" 2>/dev/null | wc -l)"
        else
            saved=0
            log "  attempt ${attempt}/${MAX_DOWNLOAD_ATTEMPTS}: shodan download returned an error"
        fi

        # Keep whichever attempt yielded the most records.
        if [ "$saved" -gt "$best_saved" ]; then
            best_saved="$saved"; mv -f "$tmp" "$dest"
        else
            rm -f "$tmp"
        fi
        DL_SAVED="$best_saved"

        # Complete if we can't get a reference count, or saved >= MIN_COMPLETENESS_PCT% of it.
        if [ "$expected" -le 0 ] || [ $(( saved * 100 )) -ge $(( expected * MIN_COMPLETENESS_PCT )) ]; then
            log "  attempt ${attempt}/${MAX_DOWNLOAD_ATTEMPTS}: saved ${saved} of ~${expected} (complete)"
            return 0
        fi

        log "  attempt ${attempt}/${MAX_DOWNLOAD_ATTEMPTS}: saved ${saved} of ~${expected} — partial (<${MIN_COMPLETENESS_PCT}%)"
        if [ "$attempt" -lt "$MAX_DOWNLOAD_ATTEMPTS" ]; then
            log "  retrying in ${RETRY_SLEEP}s..."
            sleep "$RETRY_SLEEP"
        fi
    done

    log "  WARNING: query still incomplete after ${MAX_DOWNLOAD_ATTEMPTS} attempts: best ${best_saved} of ~${expected}"
    return 1
}

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

# --- Download each query (with retry on partial) to a temp file ---
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
part_files=()
incomplete=false   # set true if any query stays short after all retries
i=0
for q in "${QUERIES[@]}"; do
    part="$work_dir/part_${i}.json.gz"
    log "Running query[$i]: $q"
    if ! download_query "$q" "$part"; then
        incomplete=true   # we keep the best partial, but flag the day as incomplete
    fi
    if [ -s "$part" ]; then
        part_files+=("$part")
    else
        log "WARNING: query[$i] returned no results"
        if [ "$i" -eq 0 ]; then
            log "ERROR: primary geo query produced no data — aborting."
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
if [ "$record_count" -le 0 ]; then
    # A zero-record delta day is suspicious — it was the symptom of the ISO-date bug.
    rm -f "$output_path"
    log "WARNING: 0 records collected for $current_date (all queries empty). Check the query window and API."
    exit 2
fi

file_size=$(stat -c%s "$output_path" 2>/dev/null || echo "?")
log "Wrote $record_count unique records to $output_filename (${file_size} bytes)"

# --- Optional retention cleanup ---
if [ "$RETENTION_DAYS" -gt 0 ] 2>/dev/null; then
    deleted=$(find "$DAILY_DIR" -name "${SHODAN_STATE_NAME}-events-*.json.gz" -mtime "+${RETENTION_DAYS}" -print -delete | wc -l)
    [ "$deleted" -gt 0 ] && log "Retention: deleted $deleted archive(s) older than ${RETENTION_DAYS} days"
fi

# A file was written, but if any query stayed short after all retries the day is
# only partially complete — keep the data, but exit non-zero so cron/monitoring
# flags it instead of treating a truncated day as a clean success.
if [ "$incomplete" = true ]; then
    log "WARNING: collection for $current_date is PARTIAL (a query stayed below ${MIN_COMPLETENESS_PCT}% after ${MAX_DOWNLOAD_ATTEMPTS} attempts). Data kept; flagging for review."
    exit 3
fi

log "Done."
