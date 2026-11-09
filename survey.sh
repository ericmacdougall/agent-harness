#!/bin/bash
# on t2-dev, READ-ONLY survey of the biggest dirs: size, last write, running processes (cwd or cmdline inside), git state (dirty, unpushed, stash), derivable subdirs sizes.
out=/home/eric/gq-branch-clean/survey.tsv; : > $out
procs=$(for p in /proc/[0-9]*; do echo "$(readlink $p/cwd 2>/dev/null) $(tr '\0' ' ' < $p/cmdline 2>/dev/null)"; done)
for d in /home/eric/wt/* /home/eric/repos/* /home/eric/rt-15477 /home/eric/rt-15477d /home/eric/rt-15477e /home/eric/rt-15477f /home/eric/pp-josh-batch /home/eric/lessons2-t2c /home/eric/pp-hwq-prep-s654 /home/eric/rt561 /home/eric/probe-a9b6 /home/eric/pp-hwq-stgapp /home/eric/branch-cleanup-20261108 /home/eric/sites-seo; do
  [ -d "$d" ] || continue
  case "$d" in */repos/harness|*lessons-authoring*|*yates*|*android-sdk*) continue;; esac
  sz=$(du -sm "$d" 2>/dev/null | cut -f1)
  [ "${sz:-0}" -lt 800 ] && continue
  age=$(( ( $(date +%s) - $(find "$d" -maxdepth 3 -type f -not -path '*/node_modules/*' -not -path '*/.git/*' -printf '%T@\n' 2>/dev/null | sort -n | tail -1 | cut -d. -f1) ) / 3600 ))
  np=$(echo "$procs" | grep -cF "$d")
  g="-"; dirty=-; unp=-; st=-
  if [ -e "$d/.git" ]; then
    g=git; dirty=$(git -C "$d" status --porcelain 2>/dev/null | grep -vE '(node_modules|\.next|dist/|build/|\.cache)' | wc -l)
    unp=$(git -C "$d" log --branches --not --remotes --oneline 2>/dev/null | wc -l)
    st=$(git -C "$d" stash list 2>/dev/null | wc -l)
  fi
  der=$(du -sm "$d"/node_modules "$d"/.next "$d"/dist "$d"/build "$d"/target "$d"/.venv "$d"/.cache 2>/dev/null | awk '{s+=$1} END{print s+0}')
  echo -e "$sz\t$d\tage_h=$age\tprocs=$np\t$g\tdirty=$dirty\tunpushed=$unp\tstash=$st\tderivable_mb=$der" >> $out
done
sort -rn $out | head -60
echo SURVEY_DONE
df -h / | tail -1
