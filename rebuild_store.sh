#!/usr/bin/env bash
# rebuild_store.sh — re-project EVERY daily archive into the DuckDB/Parquet
# store (needed after any classifier or schema change). Holds the pipeline
# lock so the nightly and the morning repair cannot run concurrently. Output is
# unbuffered so /tmp/rebuild.log (or wherever you redirect) shows progress.
#
#   nohup ./rebuild_store.sh > /tmp/rebuild.log 2>&1 &
#   grep -c "vuln rows" /tmp/rebuild.log      # days completed so far
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec flock -n "$DIR/.pipeline.lock" "$DIR/venv/bin/python" -u "$DIR/build_store.py" --all --rebuild
