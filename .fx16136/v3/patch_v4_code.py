#!/usr/bin/env python3
"""1377 v4 code fixes: receipt bugtracker-pr1377-gate-v3 F7 (sampler) and F8 (push-env.sh). Run from the bugtracker repo root."""
import sys


def edit(path, old, new, count=1):
    t = open(path).read()
    n = t.count(old)
    if n != count:
        sys.exit('anchor %r in %s found %d times, want %d' % (old[:70], path, n, count))
    open(path, 'w').write(t.replace(old, new))


S = 'infra/selfhost/app/cmdline-sampler.py'
edit(S, '''-e, -e(attached), -e(cluster), --env or --env(attached). NO_SAMPLE (also a failure): fewer than `--expect-runs` runs seen, so a
silent sampler can never pass. Exit 0 only on PASS.''', '''-e, -e(attached), -e(cluster), --env or --env(attached). NO_SAMPLE (also a failure): fewer than `--expect-runs` runs seen, so a
silent sampler can never pass. Exit 0 only on PASS. Arguments are checked first (receipt bugtracker-pr1377-gate-v3 F7):
--expect-runs >= 1, --seconds and --interval finite and > 0, --interval <= --seconds; anything else is FAIL, exit 2, no
sampling. PASS also needs at least one poll and every expected run seen.''')
edit(S, '''import argparse
import json
import os''', '''import argparse
import json
import math
import os''')
edit(S, '''    if not ID_RE.match(a.container):
        return {'verdict': 'FAIL', 'label': 'sampled', 'error': 'container id must be 12-64 lowercase hex'}, 1
''', '''    if not ID_RE.match(a.container):
        return {'verdict': 'FAIL', 'label': 'sampled', 'error': 'container id must be 12-64 lowercase hex'}, 1
    bad_arg = ('--expect-runs must be at least 1' if a.expect_runs < 1 else
               '--seconds must be a finite number above 0' if not (math.isfinite(a.seconds) and a.seconds > 0) else
               '--interval must be a finite number above 0' if not (math.isfinite(a.interval) and a.interval > 0) else
               '--interval must not exceed --seconds' if a.interval > a.seconds else None)
    if bad_arg:
        return {'verdict': 'FAIL', 'label': 'sampled', 'error': bad_arg}, 2
''')
edit(S, '''    while time.monotonic() < end and len(runs) < max(a.expect_runs, 1) * 10:
        scan(a.proc, a.container, seen, runs)
        polls += 1
        time.sleep(a.interval)
    bad = [r for r in runs if BAD.intersection(r['flags'])]
    if len(runs) < a.expect_runs:''', '''    while (polls == 0 or time.monotonic() < end) and len(runs) < a.expect_runs * 10:
        scan(a.proc, a.container, seen, runs)
        polls += 1
        time.sleep(a.interval)
    bad = [r for r in runs if BAD.intersection(r['flags'])]
    if polls < 1 or len(runs) < a.expect_runs:''')

P = 'infra/selfhost/app/push-env.sh'
edit(P, '''sm() { gcloud secrets versions access latest --secret "$1" --project "$SM_PROJECT"; }''',
     '''HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# goodqa#16148 (receipt bugtracker-pr1377-gate-v3 F8): the canonical JOB_ENVFILE line rw-ship gate (b) requires. One
# source: ENV_LINE in apply-job-secrets-host.py (selfhost-ctl.py's JOBSECRET_KEY_LINE is tested equal to it). The file
# below is installed whole, so a regeneration without this line would remove the wiring.
JOBSECRET_LINE=$(python3 -I - "$HERE/apply-job-secrets-host.py" <<'PY'
import ast, sys
c = {}
for n in ast.parse(open(sys.argv[1]).read()).body:
    if isinstance(n, ast.Assign) and len(n.targets) == 1 and getattr(n.targets[0], 'id', None) in ('ENV_KEY', 'ENV_LINE'):
        v = n.value
        c[n.targets[0].id] = v.value if isinstance(v, ast.Constant) else c['ENV_KEY'] + v.right.value
print(c['ENV_LINE'])
PY
)
[[ $JOBSECRET_LINE =~ ^JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/[a-z0-9-]+$ ]] || { echo "push-env.sh: no canonical JOB_ENVFILE line" >&2; exit 1; }

sm() { gcloud secrets versions access latest --secret "$1" --project "$SM_PROJECT"; }''')
edit(P, '''  line JOB_DISPATCH_TOKEN "$DISPATCH_TOKEN"
  worker_base
}''', '''  line JOB_DISPATCH_TOKEN "$DISPATCH_TOKEN"
  printf '%s\\n' "$JOBSECRET_LINE"   # a path, not a secret: the key itself is a root-only file (derive-job-secrets.py)
  worker_base
}''')
print('v4 code applied')
