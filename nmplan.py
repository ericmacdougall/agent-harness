"""Batch 1: derivable dirs (node_modules, .next, dist/build output) of idle checkouts. Candidate = no process (cwd/cmdline), last write >= 24h ago, not named in a WAL touched in the last 24h (other than mine), not a protected path.
Prints the plan and writes nm-del.txt (one literal directory per line) for the remote delete script."""
import subprocess, glob, os, time, re
W = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/'
tsv = subprocess.run(['ssh', 't2-dev', 'cat gq-branch-clean/survey.tsv'], capture_output=True, text=True).stdout.splitlines()
wal = []
for f in glob.glob('/Users/eric/.claude/wals/*/*.jsonl'):
    if time.time() - os.path.getmtime(f) < 24 * 3600 and 'agent-ab8a7d1bf54ed3c9a' not in f:
        wal.append(open(f, errors='ignore').read())
wal = '\n'.join(wal)
rows = []
for l in tsv:
    p = l.split('\t')
    sz, path = int(p[0]), p[1]
    kv = dict(x.split('=') for x in p[2:] if '=' in x)
    rows.append((sz, path, int(kv['age_h']), int(kv['procs']), int(kv.get('derivable_mb', 0))))
plan = []
skip = []
for sz, path, age, procs, der in rows:
    base = os.path.basename(path)
    if der < 100:
        continue
    why = None
    if procs > 0:
        why = 'running process'
    elif age < 24:
        why = 'written in the last 24h'
    elif len(base) > 5 and base in wal:
        why = 'named in a WAL within 24h'
    elif any(x in path for x in ('lessons-authoring', 'repos/harness', 'yates', 'android-sdk')):
        why = 'protected path'
    if why:
        skip.append((path, der, why))
    else:
        plan.append((path, der))
print('PLAN: %d dirs, derivable %.1f GB' % (len(plan), sum(d for _, d in plan) / 1024))
for p, d in plan:
    print('  ', d, 'MB', p)
print('SKIPPED:')
for p, d, w in skip:
    print('  ', d, 'MB', p, '|', w)
open(W + 'nm-del.txt', 'w').write(''.join(p + '\n' for p, d in plan))
