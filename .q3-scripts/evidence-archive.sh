#!/usr/bin/env bash
# dev2. Archive ~/release-evidence to Dropbox before dev2 retires (main ruling 11-09). Throttled; a check follows the copy.
# Excludes the three secret-shaped files only if they were ever placed here (they live in biz/release-waves, not here).
set -u
SRC=$HOME/release-evidence
DST=dropbox:Backups/dev2-release-evidence-20261109
L=$HOME/.agent-harness/logs/release-evidence-archive
mkdir -p "$L"
echo "START $(date -u +%FT%TZ)" > "$L/status"
rclone copy "$SRC" "$DST" --tpslimit 2 --transfers 2 --checkers 4 --retries 10 --retries-sleep 30s --low-level-retries 20 \
  --dropbox-chunk-size 64M --log-file "$L/copy.log" --log-level NOTICE --stats 5m --stats-one-line --stats-log-level NOTICE
echo "COPY_RC=$? $(date -u +%FT%TZ)" >> "$L/status"
rclone check "$SRC" "$DST" --size-only --tpslimit 2 --checkers 4 --one-way --log-file "$L/check.log" --log-level NOTICE \
  --differ "$L/differ.txt" --missing-on-dst "$L/missing.txt" --error "$L/error.txt"
echo "CHECK_RC=$? $(date -u +%FT%TZ)" >> "$L/status"
echo "COUNTS differ=$(wc -l < "$L/differ.txt") missing=$(wc -l < "$L/missing.txt") error=$(wc -l < "$L/error.txt")" >> "$L/status"
echo ARCHIVE_END >> "$L/status"
