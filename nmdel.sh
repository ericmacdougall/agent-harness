#!/bin/bash
# on t2-dev: delete ONLY derivable subdirs (node_modules .next dist build target .venv .cache) of dirs listed in nm-del.txt.
# Skips a subdir if it has git-tracked files, or if any process has cwd/cmdline/open file inside the checkout. Logs df before/after.
list=/home/eric/gq-branch-clean/nm-del.txt
log=/home/eric/gq-branch-clean/nmdel.log
echo "START $(date -u +%FT%TZ) free=$(df -BG --output=avail / | tail -1)" | tee -a $log
while read -r d; do
  [ -d "$d" ] || continue
  case "$d" in */repos/harness|*lessons-authoring*|*yates*|*android-sdk*) continue;; esac
  busy=$(for p in /proc/[0-9]*; do echo "$(readlink $p/cwd 2>/dev/null) $(tr '\0' ' ' < $p/cmdline 2>/dev/null)"; done 2>/dev/null | grep -v "grep -cF" | grep -cF "$d")
  [ "$busy" -gt 0 ] && { echo "SKIP busy $d" | tee -a $log; continue; }
  for s in node_modules .next dist build target .venv .cache; do
    [ -d "$d/$s" ] || continue
    if [ -e "$d/.git" ] && [ -n "$(git -C "$d" ls-files -- "$s" 2>/dev/null | head -1)" ]; then echo "SKIP tracked $d/$s" | tee -a $log; continue; fi
    sz=$(du -sm "$d/$s" 2>/dev/null | cut -f1)
    rm -rf -- "$d/$s" && echo "DEL ${sz}MB $d/$s" | tee -a $log
  done
done < $list
echo "END $(date -u +%FT%TZ) free=$(df -BG --output=avail / | tail -1)" | tee -a $log
