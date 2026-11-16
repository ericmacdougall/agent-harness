#!/usr/bin/env bash
# F1 mutants: each edits the committed selfhost-ctl.py, runs the F1 tests, and restores the file from git.
# Usage: bash mutants.sh <repo>   (run on t2-dev)
cd "$1/infra/release-harness" || exit 9
P=$HOME/repos/fx-16136/venv/bin/python
git diff --quiet -- selfhost-ctl.py || { echo "selfhost-ctl.py is dirty; stop"; exit 9; }
mut(){ # name, python-literal old, python-literal new
  python3 - "$2" "$3" <<'PY' || { echo "$1: anchor missing"; return; }
import sys
p = 'selfhost-ctl.py'; t = open(p).read(); o, n = sys.argv[1], sys.argv[2]
assert t.count(o) == 1, t.count(o)
open(p, 'w').write(t.replace(o, n))
PY
  r=$(timeout 600 "$P" -B -m pytest -q -p no:cacheprovider test_rw_ship_selfhost.py -k "f1_ or unresolved_containerd or measures_dockers" 2>&1 | tail -1)
  echo "$1: $r"
  git checkout -q -- selfhost-ctl.py
}
mut M1-holder-count  "    if len(holders) != 1:" "    if len(holders) < 1:"
mut M2-default-agree "        if len(set(live.values())) > 1:" "        if len(set(live.values())) > 99:"
mut M3-dockerd-count "        if len(ds) != 1: raise" "        if len(ds) < 1: raise"
mut M4-section-stop  "        if re.match(r'^\s*\[', line): break" "        if re.match(r'^\s*\[', line): pass"
mut M5-two-sockets   "    if len(inodes) > 1: raise" "    if len(inodes) > 99: raise"
mut M6-imports       "            raise Refused('the containerd config %s uses imports, which can override its root' % cfg)" "            pass"
mut M7-root-exists   "    if not os.path.isdir(real): raise" "    if False: raise"
mut M8-euid-root     "        if os.geteuid() == 0: raise" "        if False: raise"
git diff --quiet -- selfhost-ctl.py && echo "restored clean"
