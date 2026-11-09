#!/bin/bash
# on t2-dev: standalone clones only. git bundle --all + tar of dirty/untracked-not-ignored files -> Dropbox -> rclone check -> rm -rf. Reads dirs from clonedel.txt.
D=dropbox:Backups/repo-archives-private/t2dev-disk-20261109
W=/home/eric/gq-branch-clean/bkdel; mkdir -p $W; log=$W/clonedel.log
while read -r d; do
  [ -d "$d/.git" ] || { echo "NOTCLONE $d" | tee -a $log; continue; }
  [ -f "$d/.git" ] && { echo "LINKED $d" | tee -a $log; continue; }
  n=$(echo "$d" | sed 's#/home/eric/##; s#/#_#g')
  busy=$(for p in /proc/[0-9]*; do echo "$(readlink $p/cwd 2>/dev/null) $(tr '\0' ' ' < $p/cmdline 2>/dev/null)"; done 2>/dev/null | grep -v -e "grep -cF" -e clonedel -e "ssh " | grep -cF "$d")
  [ "$busy" -gt 0 ] && { echo "SKIP busy $d" | tee -a $log; continue; }
  b=$W/$n.bundle; x=$W/$n.dirty.tar.zst
  git -C "$d" bundle create $b --all >/dev/null 2>&1 || { echo "SKIP bundle failed $d" | tee -a $log; continue; }
  git -C "$d" bundle verify $b >/dev/null 2>&1 || { echo "SKIP bundle unverified $d" | tee -a $log; continue; }
  git -C "$d" ls-files -m -o --exclude-standard -z | tar -C "$d" --null -T - -cf - 2>/dev/null | zstd -q -o $x
  mb=$(( $(du -m $b | cut -f1) + $(du -m $x | cut -f1) ))
  [ "$mb" -gt 1500 ] && { echo "SKIP backup too big ${mb}MB $d" | tee -a $log; rm -f $b $x; continue; }
  (cd $W && sha256sum $n.bundle $n.dirty.tar.zst > $n.sha256)
  rclone copy $b $D/ --tpslimit 2 --transfers 1 && rclone copy $x $D/ --tpslimit 2 && rclone copy $W/$n.sha256 $D/ --tpslimit 2
  if rclone check $W $D --include "$n.*" --tpslimit 2 2>&1 | grep -q " 0 differences found"; then
    rm -rf -- "$d" && echo "DEL $d backup=${mb}MB free=$(df -BG --output=avail / | tail -1)" | tee -a $log
    rm -f $b $x
  else echo "SKIP check failed $d" | tee -a $log; fi
done < /home/eric/gq-branch-clean/clonedel.txt
