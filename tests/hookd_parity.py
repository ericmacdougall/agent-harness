#!/usr/bin/env python3
"""Server-versus-cold parity for hookd (GoodQA goodqa#14859).

The corpus is built locally from the repository's own guard corpora (tests/command_guard_corpus.py and
tests/kill_guard_corpus.json) plus synthetic payloads for every other hook event. No transcripts are read.
The same ordered case list runs twice in two scratch HOMEs:
  A: cold, `python3 <hook> <arg>` exactly as settings.json registered it before hookd;
  B: through `hookc` against a hookd started with HOME=B.
Each case compares exit code, stdout and stderr after replacing the scratch HOME with @HOME@. The run prints a
JSON summary and exits 1 on any difference. `--seed-flip` makes hookc's server lie on one case (a failing control:
the comparison must catch it).

  python3 tests/hookd_parity.py --hookc BIN [--limit N] [--seed 7] [--only bash] [--jobs 1]

Commands in the corpus are DATA: they are handed to the hooks as JSON text and never executed (rule S1).
"""

import argparse
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'harness' / 'hooks'
# A failing control: the hooks dir copy whose hookd.py answers every call with exit 0 and no output.
BROKEN = ('        exec(pre.main_code[script], module.__dict__)  # noqa: S102 - the script\'s own __main__ block\n',
          '        pass  # CONTROL: broken server allows everything\n')
SESSION = '0f0e0d0c-0b0a-4000-8000-00000000a11d'

BASH_HOOKS = [('command_guard_hook.py', ['hook']), ('kill_guard.py', ['hook']), ('wal.py', ['pretool']),
              ('tier_gate.py', ['hook']), ('commit_policy.py', ['hook']), ('bg_lint.py', []),
              ('heavy_job_guard.py', [])]
EVENT_HOOKS = {
    'UserPromptSubmit': [('wal.py', ['prompt']), ('provenance_hooks.py', ['prompt']), ('ledger_reminder.py', [])],
    'SubagentStart': [('wal.py', ['subagent']), ('tier_gate.py', ['start'])],
    'SubagentStop': [('wal.py', ['subagent_stop']), ('tier_gate.py', ['stop']), ('dropped_gate.py', ['subagent-stop'])],
    'Stop': [('provenance_hooks.py', ['stop-lint']), ('dropped_gate.py', [])],
    'Agent': [('wal.py', ['pretool']), ('tier_gate.py', ['hook']), ('agent_gate.py', [])],
    'Edit': [('wal.py', ['pretool'])],
    'AskUserQuestion': [('provenance_hooks.py', ['ask-gate'])],
    'GoodQA': [('spec_flow.py', ['hook'])],
}


def bash_commands(rng, limit):
    sys.path.insert(0, str(ROOT / 'tests'))
    import command_guard_corpus as cgc  # noqa: E402
    cmds = []
    for name in dir(cgc):
        value = getattr(cgc, name)
        if name.isupper() and isinstance(value, list):
            for row in value:
                if isinstance(row, str):
                    cmds.append(row)
                elif isinstance(row, dict) and isinstance(row.get('cmd'), str):
                    cmds.append(row['cmd'])
    kg = json.loads((ROOT / 'tests' / 'kill_guard_corpus.json').read_text())
    cmds += [r['cmd'] for r in kg['rows'] if isinstance(r.get('cmd'), str)]
    cmds += ['ls -la', 'git status --short', 'git commit -m "feat(x): y"', 'pkill -f node', 'kill -9 1',
             'rm -rf ~/.claude/wals', 'python3 -m pytest -x', 'sleep 1 &', 'go test ./...', 'npm run build']
    seen, unique = set(), []
    for c in cmds:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    rng.shuffle(unique)
    return unique[:limit] if limit else unique


def cases(rng, limit, only):
    home = '@HOME@'
    out = []
    if only in (None, 'bash'):
        for i, cmd in enumerate(bash_commands(rng, limit)):
            cmd = cmd.replace('@WT@', home + '/.agent-harness/work/S/T/wt').replace('@TASK@', home + '/.agent-harness/work/S/T')
            payload = {'session_id': SESSION, 'transcript_path': home + '/t.jsonl', 'cwd': home,
                       'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                       'tool_input': {'command': cmd, 'description': 'parity'}, 'tool_use_id': 'toolu_p%d' % i}
            out.append(('bash-%d' % i, BASH_HOOKS, payload))
    if only in (None, 'events'):
        agent = {'session_id': SESSION, 'cwd': home, 'hook_event_name': 'PreToolUse', 'tool_name': 'Agent',
                 'tool_input': {'description': 'x', 'prompt': 'do it', 'subagent_type': 'task-owner', 'model': 'sonnet'},
                 'tool_use_id': 'toolu_agent'}
        out += [
            ('prompt', EVENT_HOOKS['UserPromptSubmit'], {'session_id': SESSION, 'cwd': home,
             'hook_event_name': 'UserPromptSubmit', 'prompt': 'please fix the build'}),
            ('agent', EVENT_HOOKS['Agent'], agent),
            ('agent-opus', EVENT_HOOKS['Agent'], dict(agent, tool_input=dict(agent['tool_input'], model='opus'))),
            ('edit', EVENT_HOOKS['Edit'], {'session_id': SESSION, 'cwd': home, 'hook_event_name': 'PreToolUse',
             'tool_name': 'Edit', 'tool_input': {'file_path': home + '/x.py', 'old_string': 'a', 'new_string': 'b'}}),
            ('sub-start', EVENT_HOOKS['SubagentStart'], {'session_id': SESSION, 'cwd': home,
             'hook_event_name': 'SubagentStart', 'agent_id': 'a0000000000000001', 'agent_type': 'task-owner'}),
            ('sub-stop', EVENT_HOOKS['SubagentStop'], {'session_id': SESSION, 'cwd': home,
             'hook_event_name': 'SubagentStop', 'agent_id': 'a0000000000000001', 'agent_type': 'task-owner',
             'stop_hook_active': False}),
            ('stop', EVENT_HOOKS['Stop'], {'session_id': SESSION, 'cwd': home, 'hook_event_name': 'Stop',
             'stop_hook_active': False}),
            ('ask', EVENT_HOOKS['AskUserQuestion'], {'session_id': SESSION, 'cwd': home, 'hook_event_name': 'PreToolUse',
             'tool_name': 'AskUserQuestion', 'tool_input': {'questions': [{'question': 'A or B?', 'options': []}]}}),
            ('goodqa', EVENT_HOOKS['GoodQA'], {'session_id': SESSION, 'cwd': home, 'hook_event_name': 'PreToolUse',
             'tool_name': 'mcp__goodqa__close_issue_done', 'tool_input': {'issueId': 'x'}}),
            ('garbage', [('command_guard_hook.py', ['hook']), ('kill_guard.py', ['hook']), ('wal.py', ['pretool'])],
             '{not json'),
            ('empty', [('command_guard_hook.py', ['hook']), ('kill_guard.py', ['hook'])], ''),
        ]
    return out


def scratch_home(base, name):
    home = Path(base) / name
    (home / '.claude').mkdir(parents=True)
    (home / '.agent-harness').mkdir()
    # hooks find their policies next to the scripts; ~/.claude/hooks points at the code under test
    (home / '.claude' / 'hooks').symlink_to(HOOKS)
    return home


def child_env(home, extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('HOOKD_', 'HOOKC_', 'CLAUDE_', 'AH_'))}
    env.update(HOME=str(home), PYTHONDONTWRITEBYTECODE='1')
    env.update(extra or {})
    return env


def normalize(text, home):
    text = text.replace(str(home), '@HOME@')
    text = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+00:00|Z)?', '@TS@', text)
    return text


def run_hook(argv, payload, env, home, cwd):
    data = payload.replace('@HOME@', str(home)) if isinstance(payload, str) else json.dumps(payload).replace('@HOME@', str(home))
    t0 = time.perf_counter()
    p = subprocess.run(argv, input=data.encode(), capture_output=True, env=env, cwd=str(cwd), timeout=120)
    return (p.returncode, normalize(p.stdout.decode('utf-8', 'replace'), home),
            normalize(p.stderr.decode('utf-8', 'replace'), home)), time.perf_counter() - t0


def start_server(home, run_dir, log):
    env = child_env(home, {'HOOKD_RUN_DIR': str(run_dir), 'HOOKD_LOG': str(log)})
    python = os.path.realpath(shutil.which('python3', path=env.get('PATH')) or sys.executable)  # the cold path's python3
    proc = subprocess.Popen([python, str(HOOKS / 'hookd.py'), 'serve', '--python', python], env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    sock = Path(run_dir) / 'hookd.sock'
    for _ in range(300):
        if sock.exists():
            return proc
        time.sleep(0.05)
    proc.kill()
    raise SystemExit('hookd did not start')


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--hookc', required=True)
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--seed', type=int, default=7)
    ap.add_argument('--only', choices=['bash', 'events'])
    ap.add_argument('--keep', action='store_true')
    ap.add_argument('--report')
    ap.add_argument('--control', action='store_true', help='run against a deliberately broken hookd copy')
    args = ap.parse_args(argv)
    global HOOKS
    control_dir = None
    if args.control:
        control_dir = Path(tempfile.mkdtemp(prefix='hkc-'))
        shutil.copytree(HOOKS, control_dir / 'hooks', ignore=shutil.ignore_patterns('__pycache__'))
        hookd = control_dir / 'hooks' / 'hookd.py'
        text = hookd.read_text()
        if BROKEN[0] not in text:
            raise SystemExit('control patch did not apply')
        hookd.write_text(text.replace(BROKEN[0], BROKEN[1]))
        HOOKS = control_dir / 'hooks'
    rng = random.Random(args.seed)
    base = Path(tempfile.mkdtemp(prefix='hkp-', dir='/tmp' if os.path.isdir('/tmp') else None))
    os.chmod(base, 0o700)
    # the same basename under different parents: guards print a directory's basename ("(a)" vs "(b)" made 68
    # false diffs on t2-dev 2026-11-06), and normalize() only replaces the full HOME path
    home_a, home_b = scratch_home(base / 'a', 'home'), scratch_home(base / 'b', 'home')
    run_dir = base / 'r'
    server = start_server(home_b, run_dir, base / 'hookd.log')
    diffs, n, served_fallbacks = [], 0, 0
    outcomes = {}
    t_cold = t_warm = 0.0
    try:
        for name, hooks, payload in cases(rng, args.limit, args.only):
            for script, hargs in hooks:
                path = str(HOOKS / script)
                cold, dt_a = run_hook(['python3', path] + hargs, payload, child_env(home_a), home_a, home_a)
                warm, dt_b = run_hook([args.hookc, path] + hargs, payload,
                                      child_env(home_b, {'HOOKD_RUN_DIR': str(run_dir), 'HOOKC_DEBUG': '1'}),
                                      home_b, home_b)
                n += 1
                key = 'rc%d%s' % (cold[0], '+out' if cold[1].strip() else '')
                outcomes[key] = outcomes.get(key, 0) + 1
                t_cold += dt_a
                t_warm += dt_b
                if 'hookc: cold path' in warm[2]:
                    served_fallbacks += 1
                    warm = (warm[0], warm[1], re.sub(r'hookc: cold path \([^)]*\)\n', '', warm[2]))
                if cold != warm:
                    diffs.append({'case': name, 'hook': script, 'args': hargs, 'seed': args.seed,
                                  'cold': cold, 'server': warm})
    finally:
        os.killpg(server.pid, signal.SIGTERM)
        server.wait(timeout=10)
        if not args.keep:
            shutil.rmtree(base, ignore_errors=True)
        if control_dir:
            shutil.rmtree(control_dir, ignore_errors=True)
    verdict_diffs = sum(1 for d in diffs if d['cold'][0] != d['server'][0] or d['cold'][1] != d['server'][1])
    summary = {'seed': args.seed, 'calls': n, 'diffs': len(diffs), 'verdict_diffs': verdict_diffs, 'server_fallbacks': served_fallbacks,
               'cold_outcomes': outcomes, 'control': args.control,
               'cold_wall_s': round(t_cold, 2), 'server_wall_s': round(t_warm, 2), 'first_diffs': diffs[:5]}
    if args.report:
        Path(args.report).write_text(json.dumps(dict(summary, diffs_all=diffs), indent=1))
    print(json.dumps(summary, indent=1)[:20000])
    if n == 0:
        print('no cases ran', file=sys.stderr)
        return 1
    if args.control:
        # The control passes only when the comparison caught the broken server.
        return 0 if diffs else 1
    return 1 if diffs or served_fallbacks else 0


if __name__ == '__main__':
    sys.exit(main())
