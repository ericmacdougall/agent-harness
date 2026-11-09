#!/bin/bash
# on t2-dev: derivable only. (1) ~/.gradle/caches if no gradle/java process; (2) node_modules/.next/dist/build of old bt-release-smoke trees (not b33ada8231d9) with no process inside.
log=/home/eric/gq-branch-clean/urgfree.log
echo "START $(date -u +%FT%TZ) free=$(df -BG --output=avail / | tail -1)" | tee -a $log
procs() { for p in /proc/[0-9]*; do echo "$(readlink $p/cwd 2>/dev/null) $(tr '\0' ' ' < $p/cmdline 2>/dev/null)"; done 2>/dev/null | grep -v -e "urgfree" -e "ssh " -e "grep "; }
P=$(procs)
if echo "$P" | grep -qiE "gradle|GradleDaemon|gradlew"; then
  echo "SKIP gradle: a gradle process is running" | tee -a $log
else
  sz=$(du -sm /home/eric/.gradle/caches 2>/dev/null | cut -f1)
  rm -rf /home/eric/.gradle/caches && echo "DEL ${sz}MB ~/.gradle/caches" | tee -a $log
fi
for d in /home/eric/repos/bt-release-smoke-*; do
  case "$d" in *b33ada8231d9*) echo "HELD $d (ship not live)" | tee -a $log; continue;; esac
  if echo "$P" | grep -qF "$d"; then echo "SKIP busy $d" | tee -a $log; continue; fi
  for s in node_modules .next dist build; do
    [ -d "$d/$s" ] || continue
    if [ -e "$d/.git" ] && [ -n "$(git -C "$d" ls-files -- "$s" 2>/dev/null | head -1)" ]; then echo "SKIP tracked $d/$s" | tee -a $log; continue; fi
    sz=$(du -sm "$d/$s" 2>/dev/null | cut -f1)
    rm -rf -- "$d/$s" && echo "DEL ${sz}MB $d/$s" | tee -a $log
  done
done
echo "END $(date -u +%FT%TZ) free=$(df -BG --output=avail / | tail -1)" | tee -a $log
