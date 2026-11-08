#!/bin/bash
# usage: cls.sh <repo>  (on t2-dev, in ~/gq-branch-clean/r4) -> c-<repo>.tsv: branch sha age_days merged cherry_unique behind conflicts
r="$1"; cd ~/gq-branch-clean/r4
[ -d "$r.git" ] || git clone --mirror -q "git@github.com:ericmacdougall/$r.git" "$r.git"
g="$r.git"; D=$(git -C $g symbolic-ref --short HEAD); now=$(date +%s)
git -C $g for-each-ref --format='%(refname:short) %(objectname) %(committerdate:unix)' refs/heads | while read b sha t; do
  [ "$b" = "$D" ] && continue
  age=$(( (now-t)/86400 ))
  if git -C $g merge-base --is-ancestor $sha $D; then merged=1; else merged=0; fi
  uniq=$(git -C $g cherry $D $sha 2>/dev/null | grep -c '^+')
  behind=$(git -C $g rev-list --count $sha..$D)
  if [ "$merged" = 1 ] || [ "$uniq" = 0 ]; then conf=0; else
  out=$(timeout 60 git -C $g merge-tree --write-tree --name-only --no-messages $D $sha 2>/dev/null); rc=$?
  if [ $rc -eq 0 ]; then conf=0; elif [ $rc -eq 1 ]; then conf=$(echo "$out" | tail -n +2 | grep -v '^$' | wc -l); else conf=ERR; fi; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$b" "$sha" "$age" "$merged" "$uniq" "$behind" "$conf"
done > "c-$r.tsv"
echo "$r $(wc -l < c-$r.tsv) default=$D"
