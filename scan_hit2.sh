#!/bin/bash
# on t2-dev: for the flagged lines print only variable NAMES and the value length class (never values)
cd /home/eric/gq-branch-clean/tcr/mirror.git || exit 1
git show cede65472a2aafa0e8bdd242732d90052baf0652:narration/beginner-and-audio-workflow.md | sed -n '45,46p' | python3 -I -c '
import sys,re
for l in sys.stdin:
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)=(\S+)", l):
        v=m.group(2)
        kind="path/word" if re.fullmatch(r"[A-Za-z0-9_./-]*", v) and ("/" in v or "." in v or v.isalpha()) else "other"
        print(m.group(1), "len", len(v), kind)
    print("--- command word after assignments:", re.findall(r"python3\s+(\S+)", l)[:1])
'
