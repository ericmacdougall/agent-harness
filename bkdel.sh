#!/bin/bash
# on t2-dev: for each dir: tar (excluding derivable dirs) -> size cap -> sha256 -> rclone to Dropbox -> rclone check -> only then rm -rf. Logs free space after each.
D=dropbox:Backups/repo-archives-private/t2dev-disk-20261109
W=/home/eric/gq-branch-clean/bkdel; mkdir -p $W; log=$W/bkdel.log
for d in "$@"; do
  n=$(basename "$d")
  [ -d "$d" ] || { echo "MISSING $d" | tee -a $log; continue; }
  case "$d" in */repos/harness|*lessons-authoring*|*yates*|*android-sdk*|*sites-seo*|*compl-fix*) echo "PROTECTED $d" | tee -a $log; continue;; esac
  busy=$(for p in /proc/[0-9]*; do echo "$(readlink $p/cwd 2>/dev/null) $(tr '\0' ' ' < $p/cmdline 2>/dev/null)"; done 2>/dev/null | grep -v -e "grep -cF" -e "bkdel.sh" -e "ssh " | grep -cF "$d")
  [ "$busy" -gt 0 ] && { echo "SKIP busy $d" | tee -a $log; continue; }
  t=$W/$n.tar.zst
  tar --exclude=node_modules --exclude=.next --exclude=dist --exclude=build --exclude=target --exclude=.venv --exclude=.cache -C "$(dirname $d)" -cf - "$n" 2>/dev/null | zstd -q -T2 -o $t
  mb=$(du -m $t | cut -f1)
  if [ "$mb" -gt 600 ]; then echo "SKIP backup too big ${mb}MB $d" | tee -a $log; rm -f $t; continue; fi
  zstd -tq $t || { echo "SKIP bad archive $d" | tee -a $log; continue; }
  (cd $W && sha256sum $n.tar.zst > $n.tar.zst.sha256)
  rclone copy $t $D/ --tpslimit 2 --transfers 1 && rclone copy $W/$n.tar.zst.sha256 $D/ --tpslimit 2
  if rclone check $W $D --include "$n.tar.zst*" --tpslimit 2 2>&1 | grep -q " 0 differences found"; then
    rm -rf -- "$d" && echo "DEL $d backup=${mb}MB free=$(df -BG --output=avail / | tail -1)" | tee -a $log
    rm -f $t
  else
    echo "SKIP check failed $d" | tee -a $log
  fi
done
