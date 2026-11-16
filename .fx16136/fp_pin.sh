#!/bin/bash
# goodqa#16136: repoint test_fp_unchanged_by_job_pin_reporting at b3604eae (on origin; same tree as 5a78109), then prove
# it in a fresh blobless clone of origin and against a broken variant. Run on t2-dev.
set -u
W=${1:?worktree}; H=${2:?head commit}; C=${3:?clone dir}; T=infra/release-harness/test_rw_ship_selfhost.py; PY=~/repos/fx-16136/venv/bin/python
cd "$W" || exit 2
python3 - "$T" <<'EOF'
import sys
p = sys.argv[1]; t = open(p).read()
for old, new in [("the 5a78109 ctl and this ctl agree", "the b3604eae ctl (same tree as the installed 5a78109) and this ctl agree"),
                 ("'selfhost-ctl.5a78109.py'", "'selfhost-ctl.b3604eae.py'"),
                 ("'5a78109ac2d3:infra/release-harness/selfhost-ctl.py'", "'b3604eaec1c6eac8a0f2558ca7f8ebd24cdc7254:infra/release-harness/selfhost-ctl.py'")]:
    assert t.count(old) == 1, old; t = t.replace(old, new)
open(p, 'w').write(t); print('repointed')
EOF
echo "tree check: $(git rev-parse b3604eaec1c6:infra/release-harness 5a78109ac2d3:infra/release-harness | tr '\n' ' ')"
rm -rf "$C"
URL=$(git remote get-url origin)
timeout 900 git clone -q --filter=blob:none --no-checkout "$URL" "$C" || { echo "clone failed"; exit 3; }
cd "$C" && git sparse-checkout set --no-cone '/infra/' '/tools/lane-harness/' '/.gitignore' '/apps/*/Dockerfile' '/apps/*/Dockerfile.*' \
  && git checkout -q "$H" || { echo "checkout failed"; exit 3; }
echo "fresh clone at $(git rev-parse --short HEAD); has 5a78109: $(git cat-file -e 5a78109ac2d3^{commit} 2>/dev/null && echo yes || echo no)"
cp "$W/$T" "$T"
export SCRATCH="$C/.scratch/rc" TMPDIR="$C/.scratch/rc/tmp"; mkdir -p "$TMPDIR"
timeout 600 $PY -m pytest -q -p no:cacheprovider --basetemp="$SCRATCH/fx" "$T" -k test_fp_unchanged_by_job_pin_reporting > "$C".fp-fresh.txt 2>&1; echo "fresh clone, repointed test: exit $? $(tail -1 "$C".fp-fresh.txt)"
git show "$H":"$T" > "$T"
timeout 600 $PY -m pytest -q -p no:cacheprovider --basetemp="$SCRATCH/fx" "$T" -k test_fp_unchanged_by_job_pin_reporting > "$C".fp-fresh-old.txt 2>&1; echo "fresh clone, old 5a78109 test: exit $? $(tail -1 "$C".fp-fresh-old.txt)"
cp "$W/$T" "$T"
python3 - infra/release-harness/selfhost-ctl.py <<'EOF'
import sys, re
p = sys.argv[1]; t = open(p).read()
old = "        return dict(core, fp=fp, running=run,"
assert t.count(old) == 1
t = t.replace(old, "        fp = hashlib.sha256((fp + json.dumps(jobs, sort_keys=True)).encode()).hexdigest()   # MUTANT job pins in fp\n" + old)
open(p, 'w').write(t); print('mutant: job pins folded into fp')
EOF
timeout 600 $PY -m pytest -q -p no:cacheprovider --basetemp="$SCRATCH/fx" "$T" -k test_fp_unchanged_by_job_pin_reporting > "$C".fp-fresh-mut.txt 2>&1; echo "fresh clone, broken variant: exit $? $(tail -1 "$C".fp-fresh-mut.txt)"
git checkout -q -- infra/release-harness/selfhost-ctl.py && git status --short | head -3
