#!/usr/bin/env python3
"""cmdline-sampler.py -- goodqa#16148 spec v4 AC-6 (3), NEG-18 (build conditions P2, R6).

A read-only, unprivileged, post-deploy check that no docker CLI started by the job-dispatcher carries a job env value
on its command line (/proc/PID/cmdline is world-readable in the host PID namespace). It looks only at processes
whose /proc/PID/cgroup names the job-dispatcher container (`--container ID`, resolved by the caller at sample time),
polls about every 50 ms for `--seconds`, and keeps only flag NAMES and the argv length of each `docker run`:
  * a long flag is cut at its first `=`, and kept only if it is on the allow-list, else recorded as `--(other)`;
  * a short flag with an attached value (`-eK=V`) is recorded as `-e(attached)`; others as `-x` if allow-listed;
  * a non-flag token is only counted. Raw argv is never stored, printed or written.
Result (one JSON line): verdict PASS | FAIL | NO_SAMPLE, label "sampled" (not exhaustive). FAIL: any observed run has
-e, -e(attached), --env or --env(attached). NO_SAMPLE (also a failure): fewer than `--expect-runs` runs seen, so a
silent sampler can never pass. Exit 0 only on PASS.
  python3 -I cmdline-sampler.py --container <64-hex id> --seconds 120 --expect-runs 3
"""
import argparse
import json
import os
import re
import sys
import time

ALLOWED_LONG = {'--rm', '--env-file', '--env', '--cap-drop', '--security-opt', '--read-only', '--tmpfs', '--memory',
                '--memory-swap', '--cpus', '--pids-limit', '--detach', '--name', '--label', '--network', '--user'}
ALLOWED_SHORT = {'-d', '-e', '-i', '-t', '-u'}
BAD = {'-e', '-e(attached)', '--env', '--env(attached)'}
ID_RE = re.compile(r'^[0-9a-f]{12,64}$')


def sanitize(argv):
    """Flag names only. argv[0] is the docker binary; argv[1] must be `run`."""
    flags = []
    for tok in argv[2:]:
        if tok.startswith('--'):
            name, eq, _ = tok.partition('=')
            if name not in ALLOWED_LONG:
                name = '--(other)'
            flags.append(name + ('(attached)' if eq and name in ('--env',) else ''))
        elif tok.startswith('-') and len(tok) >= 2:
            short = tok[:2]
            if len(tok) > 2:
                flags.append((short if short in ALLOWED_SHORT else '-(other)') + '(attached)')
            else:
                flags.append(short if short in ALLOWED_SHORT else '-(other)')
    return {'argc': len(argv), 'flags': flags}


def in_container(cgroup_text, container):
    return any(('docker-%s.scope' % container) in l or ('/docker/%s' % container) in l for l in cgroup_text.splitlines())


def scan(proc, container, seen, runs):
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return
    for pid in pids:
        base = os.path.join(proc, pid)
        try:
            with open(os.path.join(base, 'cgroup')) as f:
                if not in_container(f.read(), container):
                    continue
            with open(os.path.join(base, 'cmdline'), 'rb') as f:
                raw = f.read()
            try:
                with open(os.path.join(base, 'stat')) as f:
                    start = f.read().rsplit(')', 1)[-1].split()[19]
            except (OSError, IndexError):
                start = ''
        except OSError:
            continue
        key = (pid, start)
        if key in seen:
            continue
        argv = [a.decode('utf-8', 'replace') for a in raw.split(b'\0') if a]
        if len(argv) >= 2 and os.path.basename(argv[0]) == 'docker' and argv[1] == 'run':
            seen.add(key)
            runs.append(sanitize(argv))
        del argv, raw


def run(argv):
    p = argparse.ArgumentParser(prog='cmdline-sampler.py')
    p.add_argument('--container', required=True)
    p.add_argument('--seconds', type=float, default=60.0)
    p.add_argument('--expect-runs', type=int, default=1)
    p.add_argument('--interval', type=float, default=0.05)
    p.add_argument('--proc', default='/proc')
    a = p.parse_args(argv)
    if not ID_RE.match(a.container):
        return {'verdict': 'FAIL', 'label': 'sampled', 'error': 'container id must be 12-64 lowercase hex'}, 1
    seen, runs = set(), []
    end = time.monotonic() + a.seconds
    polls = 0
    while time.monotonic() < end and len(runs) < max(a.expect_runs, 1) * 10:
        scan(a.proc, a.container, seen, runs)
        polls += 1
        time.sleep(a.interval)
    bad = [r for r in runs if BAD.intersection(r['flags'])]
    if len(runs) < a.expect_runs:
        verdict = 'NO_SAMPLE'
    elif bad:
        verdict = 'FAIL'
    else:
        verdict = 'PASS'
    out = {'verdict': verdict, 'label': 'sampled', 'runs_seen': len(runs), 'expect_runs': a.expect_runs, 'polls': polls,
           'runs_with_env_file': sum(1 for r in runs if '--env-file' in r['flags']), 'runs_with_env_flag': len(bad),
           'runs': runs}
    return out, 0 if verdict == 'PASS' else 1


def main():
    out, code = run(sys.argv[1:])
    sys.stdout.write(json.dumps(out, sort_keys=True) + '\n')
    return code


if __name__ == '__main__':
    sys.exit(main())
