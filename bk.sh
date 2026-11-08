#!/bin/bash
# usage: bk.sh <repo> ; run ON t2-dev in ~/gq-branch-clean/r4. fresh mirror -> bundle -> verify -> dropbox -> rclone check
set -euo pipefail
r="$1"; ts=$(date -u +%Y%m%dT%H%M%SZ); cd ~/gq-branch-clean/r4
if [ ! -d "$r.git" ]; then git clone --mirror -q "git@github.com:ericmacdougall/$r.git" "$r.git"; fi
git -C "$r.git" remote update --prune >/dev/null 2>&1
git -C "$r.git" for-each-ref > "refs-$r-$ts.txt"
git -C "$r.git" bundle create "$PWD/$r-$ts.bundle" --all 2>&1 | tail -1
git -C "$r.git" bundle verify "$PWD/$r-$ts.bundle" 2>&1 | tail -2
sha256sum "$r-$ts.bundle" > "$r-$ts.bundle.sha256"
dest="dropbox:Backups/repo-archives-private/$r-branchclean4-$ts"
rclone copy "refs-$r-$ts.txt" "$dest/"; rclone copy "$r-$ts.bundle.sha256" "$dest/"; rclone copy "$r-$ts.bundle" "$dest/" --transfers 1
mkdir -p "chk-$r-$ts"; cp "$r-$ts.bundle" "$r-$ts.bundle.sha256" "refs-$r-$ts.txt" "chk-$r-$ts/"
rclone check "chk-$r-$ts" "$dest" 2>&1 | tail -3
echo BACKUP_OK "$r" "$dest" "$(cut -d' ' -f1 "$r-$ts.bundle.sha256")" refs="$(wc -l < "refs-$r-$ts.txt")" ts="$ts"
