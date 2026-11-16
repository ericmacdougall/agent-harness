#!/bin/bash
# goodqa#16136: restage the release-harness runtime (rw-ship.sh, selfhost-ctl.py) from bugtracker c6b303ae into the harness
# config/goodqa-release/bin and rebind RELEASE_BINDING. Runs on t2-dev in ~/repos/fx-16136/harness.
set -euo pipefail
BT=~/repos/fx-16136/bugtracker; H=~/repos/fx-16136/harness; C=c6b303aee61cdeba2ff8e3784764d6d5c3bb1e74
D=$H/config/goodqa-release/bin
cd "$H"
echo "before:"; for f in rw-ship.sh selfhost-ctl.py RELEASE_BINDING; do sha256sum "$D/$f"; done
for f in rw-ship.sh selfhost-ctl.py; do git -C "$BT" show "$C:infra/release-harness/$f" > "$D/$f"; done
chmod +x "$D/rw-ship.sh"
python3 - "$D/RELEASE_BINDING" "$C" "$(sha256sum "$D/rw-ship.sh" | cut -c1-64)" "$(sha256sum "$D/selfhost-ctl.py" | cut -c1-64)" <<'PY'
import re, sys
p, commit, ship, ctl = sys.argv[1:5]; t = open(p).read()
t, n1 = re.subn(r'(?m)^commit [0-9a-f]{40}$', 'commit ' + commit, t)
t, n2 = re.subn(r'(?m)^[0-9a-f]{64}(  bin/rw-ship\.sh)$', ship + r'\1', t)
t, n3 = re.subn(r'(?m)^[0-9a-f]{64}(  bin/selfhost-ctl\.py)$', ctl + r'\1', t)
assert (n1, n2, n3) == (1, 1, 1), (n1, n2, n3)
open(p, 'w').write(t)
PY
echo "after:"; for f in rw-ship.sh selfhost-ctl.py RELEASE_BINDING; do sha256sum "$D/$f"; done
cat "$D/RELEASE_BINDING"
git diff --stat
