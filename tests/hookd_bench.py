#!/usr/bin/env python3
"""CPU and wall per Bash tool call: the 7 PreToolUse hooks, cold versus hookc + hookd (GoodQA goodqa#14859).

  python3 tests/hookd_bench.py --hookc BIN [--runs 15]

Runs under a scratch HOME with its own hookd. CPU is client CPU (RUSAGE_CHILDREN) plus, for the server path, the
server's request-children CPU taken from status.json before and after (status is rewritten every 5 s).
"""

import argparse
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hookd_parity as hp  # noqa: E402

CASES = {'bash_ls': 'ls -la /tmp | head', 'bash_git': 'git -C /tmp status --short && git log --oneline -3',
         'bash_kill': 'pkill -f node'}


def cpu():
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime


def status(run_dir):
    time.sleep(5.5)
    return json.loads((run_dir / 'status.json').read_text())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--hookc', required=True)
    ap.add_argument('--runs', type=int, default=15)
    args = ap.parse_args()
    base = Path(tempfile.mkdtemp(prefix='hkb-', dir='/tmp'))
    os.chmod(base, 0o700)
    home = hp.scratch_home(base, 'h')
    run_dir = base / 'r'
    server = hp.start_server(home, run_dir, base / 'hookd.log')
    out = {}
    try:
        for name, cmd in CASES.items():
            payload = {'session_id': hp.SESSION, 'cwd': str(home), 'hook_event_name': 'PreToolUse',
                       'tool_name': 'Bash', 'tool_input': {'command': cmd}, 'tool_use_id': 'toolu_bench'}
            data = json.dumps(payload).encode()
            for mode in ('cold', 'server'):
                env = hp.child_env(home, {'HOOKD_RUN_DIR': str(run_dir)} if mode == 'server' else None)
                before = status(run_dir) if mode == 'server' else None
                c0, t0 = cpu(), time.perf_counter()
                for _ in range(args.runs):
                    for script, hargs in hp.BASH_HOOKS:
                        argv = (['python3'] if mode == 'cold' else [args.hookc]) + [str(hp.HOOKS / script)] + hargs
                        subprocess.run(argv, input=data, capture_output=True, env=env, cwd=str(home))
                wall = (time.perf_counter() - t0) / args.runs
                used = (cpu() - c0) / args.runs
                server_cpu = 0.0
                if mode == 'server':
                    after = status(run_dir)
                    server_cpu = (after['children_cpu_s'] - before['children_cpu_s']
                                  + after['cpu_s'] - before['cpu_s']) / args.runs
                    out.setdefault('server_rss_kb', after.get('maxrss_kb'))
                out['%s/%s' % (name, mode)] = {'wall_ms': round(wall * 1000, 1),
                                               'client_cpu_ms': round(used * 1000, 1),
                                               'server_cpu_ms': round(server_cpu * 1000, 1),
                                               'total_cpu_ms': round((used + server_cpu) * 1000, 1)}
    finally:
        os.killpg(server.pid, signal.SIGTERM)
        server.wait(timeout=10)
        shutil.rmtree(base, ignore_errors=True)
    out['runs'] = args.runs
    out['host'] = os.uname().nodename
    out['load'] = os.getloadavg()
    print(json.dumps(out, indent=1))


if __name__ == '__main__':
    main()
