#!/usr/bin/env bash
# dev2. Main ruling 11-09: one tar|zstd archive per top-level evidence directory through rclone rcat (--tpslimit 2),
# newest and small first, big ones last; manifest (file list + sha256) beside each; read-back verification after all
# uploads, newest first. Status lines in $L/status: SENT, SEND_FAILED, VERIFIED, MISMATCH, UNREADABLE.
set -u
SRC=$HOME/release-evidence
DST=dropbox:Backups/dev2-release-evidence-20261109
L=$HOME/.agent-harness/logs/release-evidence-archive
M=$L/manifests
mkdir -p "$M"
RC=(--tpslimit 2 --retries 10 --low-level-retries 20 --dropbox-chunk-size 64M)
EXC=(--exclude=node_modules --exclude='biz/release-waves/deploys/20261105T155628Z/migrate-dry.txt'
     --exclude='biz/release-waves/deploys/20261105T155628Z/migrate-apply.txt' --exclude='biz/release-waves/deploys/20261105T155628Z/ship.log')
say(){ echo "$* $(date -u +%FT%TZ)" >> "$L/status"; }
say "STREAM_START"
cd "$SRC" || exit 2
# Order: under 5G first, newest first within each group.
python3 -I - > "$M/order.txt" <<'PY'
import os
rows = []
for d in os.listdir('.'):
    if not os.path.isdir(d) or os.path.islink(d): continue
    size = 0
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x != 'node_modules']
        for f in files:
            try: size += os.lstat(os.path.join(root, f)).st_size
            except OSError: pass
    rows.append((size > 5 << 30, -os.path.getmtime(d), d))
for big, neg, d in sorted(rows): print(d)
PY
say "ORDER $(wc -l < "$M/order.txt") directories"
loose=$(find . -maxdepth 1 -type f | wc -l)
[ "$loose" -gt 0 ] && echo "__loose_files__" >> "$M/order.txt"
while read -r d; do
  if [ "$d" = "__loose_files__" ]; then set -- $(find . -maxdepth 1 -type f -printf '%P\n'); else set -- "$d"; fi
  find "$@" -name node_modules -prune -o -type f -print 2>/dev/null | sort > "$M/$d.files.txt"
  find "$@" ! -readable 2>/dev/null | wc -l > "$M/$d.unreadable.txt"
  rm -f "$M/$d.sha256"
  tar --ignore-failed-read --warning=no-file-changed "${EXC[@]}" -cf - "$@" 2>> "$L/tar.log" | zstd -q -T4 -3 \
    | tee >(sha256sum | cut -d' ' -f1 > "$M/$d.sha256") \
    | rclone rcat "$DST/$d.tar.zst" "${RC[@]}" --log-file "$L/rcat.log" --log-level NOTICE
  rc=$?
  for i in $(seq 1 60); do [ -s "$M/$d.sha256" ] && break; sleep 1; done
  { echo "archive $d.tar.zst"; echo "sha256 $(cat "$M/$d.sha256" 2>/dev/null)"; echo "files $(wc -l < "$M/$d.files.txt")";
    echo "unreadable_entries $(cat "$M/$d.unreadable.txt")"; echo "excluded node_modules and 3 files of run 20261105T155628Z by path"; echo "--- files";
    cat "$M/$d.files.txt"; } > "$M/$d.manifest.txt"
  rclone copyto "$M/$d.manifest.txt" "$DST/$d.manifest.txt" "${RC[@]}" --log-file "$L/rcat.log" --log-level NOTICE || rc=$((rc+100))
  if [ $rc = 0 ]; then say "SENT $d $(cat "$M/$d.sha256")"; else say "SEND_FAILED $d rc=$rc"; fi
done < "$M/order.txt"
say "UPLOADS_DONE"
# Read-back, newest first (same order).
while read -r d; do
  grep -q "^SENT $d " "$L/status" || continue
  want=$(cat "$M/$d.sha256")
  got=$(rclone cat "$DST/$d.tar.zst" "${RC[@]}" 2>> "$L/verify.log" | sha256sum | cut -d' ' -f1)
  if [ "$got" = "$want" ]; then say "VERIFIED $d"; else say "MISMATCH $d want=$want got=$got"; fi
done < "$M/order.txt"
say "ARCHIVE_END"
