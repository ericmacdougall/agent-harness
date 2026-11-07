"""Live canary run for the kill guard (GoodQA #14506, AC-7). dev2 ONLY, scratch HOME ONLY (rule S2).

    env -i HOME=$(mktemp -d) PATH=/usr/bin:/bin KILL_GUARD_LIVE=1 python3 tests/live_kill_canary.py

What it does: installs the guard files into the scratch HOME, starts its OWN sleepers (three owned ones that prove
ownership by cwd, by interpreter plus script, and by the spawn ledger; one canary in a sibling worktree that is not
owned), then drives the real hook launcher with JSON built here. Candidate text is only ever delivered on stdin to
the hook, which analyses it; nothing in this file executes a candidate (no shell, no eval). Owned sleepers that the
guard allows are then stopped by this harness itself through safe_signal, the only function that signals, and which
refuses any PID this harness did not start. The canary and a canary file must survive every case.

The failing control runs the same positives against a copy of the guard with policy mode off: every one must be
allowed, which shows the canary would have been exposed. No candidate kill is ever executed in either run.
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = json.loads((ROOT / 'tests' / 'kill_guard_corpus.json').read_text(encoding='utf-8'))
LITERAL = 'netwatch orphans --kill --pid'
STARTED = set()
FILES = ('kill_guard.py', 'kill_guard_policy.json', 'command_guard.py', 'command_guard_policy.json', 'redact.py',
         'safe_input.py')


def refuse(why):
    sys.stderr.write('live_kill_canary refused: %s\n' % why)
    sys.exit(3)


def preflight():
    if socket.gethostname().split('.')[0] != 'dev2':
        refuse('this host is not dev2')
    if os.environ.get('KILL_GUARD_LIVE') != '1':
        refuse('KILL_GUARD_LIVE=1 is not set')
    home = os.path.realpath(os.environ.get('HOME', ''))
    if not home.startswith('/tmp/') or os.listdir(home):
        refuse('HOME must be a fresh empty mktemp directory under /tmp')
    return Path(home)


def safe_signal(pid, sig):
    """The only place in the live harness that signals. Refuses any PID this harness did not start."""
    if pid not in STARTED:
        raise RuntimeError('refusing to signal pid %d: this harness did not start it' % pid)
    os.kill(pid, sig)


def alive(pid):
    try:
        safe_signal(pid, 0)
    except ProcessLookupError:
        return False
    # a zombie still answers signal 0; read its state
    try:
        return Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()[0] != 'Z'
    except OSError:
        return False


def start(argv, cwd):
    proc = subprocess.Popen(argv, cwd=str(cwd), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    STARTED.add(proc.pid)
    return proc


def run_hook(hook, command, cwd, env):
    payload = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command}, 'cwd': str(cwd)})
    done = subprocess.run([sys.executable, '-I', str(hook), 'hook'], input=payload.encode(), env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    return done.returncode, done.stderr.decode('utf-8', 'replace')


def install_guard(dest, mode='enforce'):
    dest.mkdir(parents=True)
    for name in FILES:
        src = ROOT / 'harness' / 'hooks' / name
        if src.exists():
            shutil.copy2(str(src), str(dest / name))
    policy = json.loads((dest / 'kill_guard_policy.json').read_text())
    policy['mode'] = mode
    (dest / 'kill_guard_policy.json').write_text(json.dumps(policy))
    return dest / 'kill_guard.py'


def main():
    home = preflight()
    real_home = Path(os.path.expanduser('~' + os.environ.get('USER', 'eric')))
    real_state = real_home / '.agent-harness' / 'state' / 'kill-guard'
    real_before = real_state.stat().st_mtime if real_state.exists() else None
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin'}
    hook = install_guard(home / '.claude' / 'hooks')
    off_hook = install_guard(home / 'off-hooks', mode='off')
    wt, other = home / 'wt', home / 'other-wt'
    for repo in (wt, other):
        (repo / 'sub').mkdir(parents=True)
        subprocess.run(['git', 'init', '-q', str(repo)], check=True, env=env)
    (wt / 'sleeper.py').write_text('import time\ntime.sleep(600)\n')
    canary_file = home / 'canary.txt'
    canary_file.write_text('alive\n')
    sentinel = home / 'sentinel-ran'
    results = {'cases': 0, 'host': socket.gethostname()}

    owned_cwd = start(['/usr/bin/sleep', '601'], wt / 'sub')
    owned_script = start([sys.executable, str(wt / 'sleeper.py')], home)
    spawn = subprocess.run([sys.executable, '-I', str(hook), 'spawn', '--', '/usr/bin/sh', '-c',
                            'cd /tmp && exec /usr/bin/sleep 603'], cwd=str(wt), env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=30, check=False)
    assert spawn.returncode == 0, spawn.stderr
    spawned_pid = json.loads(spawn.stdout)['pid']
    STARTED.add(spawned_pid)
    canary = start(['/usr/bin/sleep', '604'], other / 'sub')
    time.sleep(0.5)
    owned = [owned_cwd.pid, owned_script.pid, spawned_pid]

    def check_canary(label):
        assert alive(canary.pid), 'CANARY GONE after ' + label
        assert canary_file.read_text() == 'alive\n', 'CANARY FILE CHANGED after ' + label
        assert not sentinel.exists(), 'a candidate command ran after ' + label

    def expect(command, want_block, label, which=hook, cwd=None):
        code, err = run_hook(which, command, cwd or wt / 'sub', env)
        results['cases'] += 1
        if want_block:
            assert code == 2, '%s: expected block, got %d (%s)' % (label, code, err[:200])
            assert LITERAL in err and len(err.strip().splitlines()) == 1, '%s: bad message %r' % (label, err[:200])
        else:
            assert code == 0, '%s: expected allow, got %d (%s)' % (label, code, err[:200])
        check_canary(label)

    # 1. ownership proofs, real processes, real probes
    for pid, label in zip(owned, ('cwd proof', 'argv proof', 'ledger proof')):
        expect('kill %d' % pid, False, label)
    expect('kill -9 %d %d %d' % tuple(owned), False, 'all owned')
    expect('kill -0 %d' % canary.pid, False, 'signal 0 on the canary')
    expect('kill %d' % canary.pid, True, 'canary pid')
    expect('kill %d %d' % (owned[0], canary.pid), True, 'owned plus canary')
    expect('kill -9 %d' % os.getpid(), True, 'the hook ancestor (this harness)')
    expect('kill 1', True, 'init')
    expect('kill -9 -1', True, 'every process')
    expect('ssh host kill %d' % owned[0], True, 'owned pid over ssh')
    expect('pkill -f 604; touch %s' % sentinel, True, 'pkill then sentinel')
    expect('pgrep -f sleep | xargs kill -9', True, 'pgrep into xargs kill')
    expect('kill $(pgrep -f sleep)', True, 'kill of a substitution')
    expect('echo hello', False, 'harmless command')
    # a worktree process seen from the other worktree is not owned
    expect('kill %d' % owned[0], True, 'owned pid seen from the sibling worktree', cwd=other / 'sub')

    # 2. the corpus sweep through the real launcher (rows that need the fake world are excluded)
    sweep = [r for r in CORPUS['rows'] if not set(r['tags']) & {'ownership', 'job', 'spawn'} and not r.get('ps')]
    for row in sweep:
        expect(row['cmd'], row['expect'] == 'block', row['id'])
    results['sweep_rows'] = len(sweep)
    results['sweep_positives'] = sum(1 for r in sweep if r['expect'] == 'block')

    # 3. failing control: the same positives against the guard with mode off must ALL be allowed
    exposed = 0
    for row in sweep:
        if row['expect'] != 'block':
            continue
        code, _err = run_hook(off_hook, row['cmd'], wt / 'sub', env)
        assert code == 0, 'control: guard off still blocked %s' % row['id']
        exposed += 1
    results['control_exposed_positives'] = exposed
    check_canary('control')

    # 4. the harness itself stops the owned sleepers the guard allowed; the canary is untouched
    for proc_pid in owned:
        safe_signal(proc_pid, signal.SIGTERM)
    deadline = time.time() + 10
    while time.time() < deadline and any(alive(p) for p in owned):
        time.sleep(0.2)
    assert not any(alive(p) for p in owned), 'owned sleepers did not stop'
    check_canary('stopping owned sleepers')
    for proc in (owned_cwd, owned_script):
        proc.wait(timeout=5)

    # 5. safe_signal refuses a PID it did not start; real HOME state is untouched
    try:
        safe_signal(os.getppid(), 0)
    except RuntimeError:
        results['safe_signal_refuses_foreign_pid'] = True
    else:
        raise AssertionError('safe_signal accepted a pid this harness did not start')
    real_after = real_state.stat().st_mtime if real_state.exists() else None
    assert real_before == real_after, 'the real HOME kill-guard state changed'
    results['canary_alive_at_end'] = alive(canary.pid)
    safe_signal(canary.pid, signal.SIGTERM)  # our own canary, now finished with
    canary.wait(timeout=5)
    results['verdict'] = 'PASS'
    print(json.dumps(results, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    finally:
        for pid in list(STARTED):
            try:
                safe_signal(pid, signal.SIGTERM)
            except (ProcessLookupError, RuntimeError):
                pass
