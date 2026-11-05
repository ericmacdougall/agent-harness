#!/usr/bin/env python3
"""Live canary for the command guard (GoodQA #14471, AC-5). The ONLY code that executes corpus rows.

Run it on dev2 only, like this (rule S2). `env -i` gives a clean environment, and the scratch root lies outside
every temp root the guard knows and outside every harness root:

    root=$(mktemp -d -p "$HOME/guard-canary")
    env -i HOME="$root" PATH=/usr/bin:/bin python3 tests/live_guard_canary.py --root "$root" --out result.json

What it does, row by row, each in a fresh home under the root:
1. Builds the fixture tree and fake credentials (a sentinel value, never a real secret).
2. Installs the guard into that home with install.install().
3. Asks the registered launcher, which exits 2 to block, exactly as Claude Code would.
4. Runs the row only when the launcher allows it. The row runs in a bubblewrap sandbox: read-only `/`, a tmpfs
   `/tmp`, then the row home bound read-write last; every namespace unshared (no network); die-with-parent; 20 s
   limit. Output is captured in memory, checked for the sentinel and thrown away.

A protected-tree snapshot taken before and after each row must be unchanged, and the sentinel must never appear.
The control phase (a recorded, justified exception to S2) runs each executable positive with the guard absent.
It runs inside the same sandbox, and only after the isolation proof passed in the same run. It shows that the
row really destroys or leaks something, so that blocking it means something. The result JSON records digests
and booleans only, never row text or output.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import command_guard_corpus as corpus  # noqa: E402
from test_command_guard import fill, make_fixture  # noqa: E402

SENTINEL = 'CANARYSECRET' + 'x7Qz' * 6  # fake, recognisable; not a credential
TEMP_ROOTS = ('/tmp', '/var/tmp', '/dev/shm', '/private/tmp', '/var/folders')
NOT_EXECUTABLE = ('ssh ', 'docker ', 'sudo ', '/home/x', '/Users/x', '/root', 'trash ', 'security ', 'gcloud ',
                  'aws ', 'kubectl ', 'vault ', 'op read', 'goodqa ', 'osascript', 'tmux ', ' at now', 'taskkill',
                  'pkill', 'killall', 'kill ', 'curl ', 'scp ', 'nc ', 'rclone ', 'gh ', 'git push', 'apt ', 'make ',
                  'npm ', 'pnpm ', 'go test', 'cargo ', 'Get-', 'Remove-Item', 'ri -r', 'Write-Output', 'gc $HOME',
                  'type ~', 'flock ', 'script -q', 'docker', 'ps eww', 'kubectl', 'git credential', 'git commit',
                  'git rebase', 'git stash', 'git diff', 'git log', 'git worktree', 'git init', 'ln -s',
                  'python3 script.py', './run.sh', './deploy.sh', 'unzip ', '/opt/homebrew')


def fake_credentials(home):
    secrets = ['.aws/credentials', '.npmrc', '.netrc', '.pgpass', '.ssh/id_rsa', '.ssh/id_ed25519',
               '.config/rclone/rclone.conf', '.codex/auth.json', '.claude/.credentials.json', '.config/gh/hosts.yml',
               '.docker/config.json', '.env', '.agent-harness/state/log-delete.key']
    for rel in secrets:
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('token = ' + SENTINEL + '\n')
    (home / '.ssh/id_rsa.pub').write_text('ssh-ed25519 AAAA public\n')
    (home / '.ssh/known_hosts').write_text('host key\n')
    (home / 'repo/.env.example').write_text('A=\n')
    (home / 'repo/README.md').write_text('readme\n')


KEEP_PARTS = ('projects', 'wals', 'sessions', 'state', '.ssh', '.aws', 'rclone', 'gh', '.docker')
KEEP_NAMES = ('kit.json', 'auth.json', '.credentials.json', '.npmrc', '.netrc', '.pgpass', '.env', 'settings.json',
              'command_guard.py', 'command_guard_hook.py', 'config.toml')


def protected_only(rel):
    parts = rel.split(os.sep)
    return rel.endswith('.jsonl') or parts[-1] in KEEP_NAMES or any(p in KEEP_PARTS for p in parts[:-1])


def protected_files(home):
    """{relative path: content} of every protected file under the harness and credential homes."""
    out = {}
    for top in ('.claude', '.codex', '.agent-harness', '.ssh', '.aws', '.config', '.docker'):
        for dirpath, dirnames, filenames in os.walk(home / top):
            dirnames[:] = [d for d in dirnames if d != '__pycache__']
            for name in filenames:
                rel = os.path.relpath(os.path.join(dirpath, name), home)
                if protected_only(rel):
                    try:
                        out[rel] = (home / rel).read_bytes()[:1 << 20]
                    except OSError:
                        out[rel] = b'?'
    for name in ('.npmrc', '.netrc', '.pgpass', '.env'):
        if (home / name).is_file():
            out[name] = (home / name).read_bytes()
    return out


def damaged(before, after):
    """A protected file that disappeared or whose old content is no longer its prefix (appends are fine)."""
    return any(rel not in after or not after[rel].startswith(old) for rel, old in before.items())


def snapshot(home, protected=False):
    """sha256 over paths, types and contents under the harness roots and the fixture repo (bytecode caches
    excluded). protected=True covers only logs, WALs, state, run kits, credentials and the guard itself: what an
    allowed command must never touch."""
    h = hashlib.sha256()
    for top in ('.claude', '.codex', '.agent-harness', 'repo', '.ssh', '.aws', '.config', '.docker', '.npmrc',
                '.netrc', '.pgpass', '.env'):
        base = home / top
        if base.is_file():
            h.update(('F ' + top + ' ').encode() + hashlib.sha256(base.read_bytes()).digest())
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d != '__pycache__')
            rel = os.path.relpath(dirpath, home)
            if not protected:
                h.update(('D ' + rel + '\n').encode())
            for name in sorted(filenames):
                if protected and not protected_only(os.path.join(rel, name)):
                    continue
                p = os.path.join(dirpath, name)
                try:
                    data = open(p, 'rb').read() if not os.path.islink(p) else os.readlink(p).encode()
                except OSError:
                    data = b'?'
                h.update(('F ' + os.path.join(rel, name) + ' ').encode() + hashlib.sha256(data).digest())
    return h.hexdigest()


def build_home(root, index):
    home = root / ('r%04d' % index)
    home.mkdir()
    make_fixture(home)
    fake_credentials(home)
    return home


def install_guard(home):
    import install
    install.install(home, True, durable_tmp=False, provenance=False, command_guard=True)
    settings = json.loads((home / '.claude/settings.json').read_text())
    for group in settings['hooks']['PreToolUse']:
        for hook in group['hooks']:
            if any('command_guard_hook.py' in str(a) for a in hook.get('args') or []):
                return [sys.executable] + [str(a) for a in hook['args']]
    raise SystemExit('guard registration missing after install')


def ask_hook(argv, home, command, cwd, proc=None):
    payload = {'session_id': 'canary', 'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
               'tool_input': {'command': command}}
    if cwd:
        payload['cwd'] = cwd
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin'}
    done = subprocess.run(argv, input=json.dumps(payload).encode(), env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=60, check=False, cwd=proc or str(home))
    return done.returncode


def sandbox(home, command, cwd, timeout=20):
    """(exit status, sentinel seen). Output never leaves this function."""
    workdir = cwd if cwd and os.path.isdir(cwd) else str(home / 'repo')
    argv = ['bwrap', '--unshare-all', '--die-with-parent', '--ro-bind', '/', '/', '--tmpfs', '/tmp', '--dev', '/dev',
            '--proc', '/proc', '--bind', str(home), str(home), '--chdir', workdir, '--', '/bin/bash', '-c', command]
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'GITHUB_TOKEN': SENTINEL, 'ANTHROPIC_API_KEY': SENTINEL,
           'DB_PASSWORD': SENTINEL, 'SLACK_BOT_TOKEN': SENTINEL, 'NPM_TOKEN': SENTINEL,
           'AWS_SECRET_ACCESS_KEY': SENTINEL}
    try:
        done = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, check=False, start_new_session=True)
        seen = SENTINEL.encode() in done.stdout or SENTINEL.encode() in done.stderr
        return done.returncode, seen
    except subprocess.TimeoutExpired:
        return 'timeout', False


def isolation_proof(root):
    home = root / 'isolation'
    home.mkdir()
    outside = root / 'outside-probe'
    sandbox(home, 'touch inside-probe; touch %s' % outside, str(home))
    visible = (home / 'inside-probe').exists()
    contained = not outside.exists()
    return visible and contained, {'inside_visible': visible, 'outside_write_refused': contained}


def executable(command):
    single = '\n' not in command or command.startswith(('cat <<', 'python3 - <<', 'bash <<', 'sh <<'))
    return single and not any(x in command for x in NOT_EXECUTABLE)


def rows():
    out = []
    for name in ('LOG_POSITIVE', 'SECRET_POSITIVE', 'NEG13_GH_TOKEN', 'NEG15_WORK_BLOCK'):
        for row in getattr(corpus, name):
            out.append((name, 'block', row))
    for name in ('NEGATIVE', 'NEG15_WORK_ALLOW'):
        for row in getattr(corpus, name):
            out.append((name, 'allow', row))
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--limit', type=int, default=0)
    args = parser.parse_args()
    root = Path(os.path.realpath(args.root))
    if sys.platform != 'linux' or not shutil.which('bwrap'):
        raise SystemExit('refusing: the canary runs only on dev2 (Linux with bubblewrap)')
    if os.environ.get('HOME') != str(root) or set(os.environ) - {'HOME', 'PATH', 'PWD', 'SHLVL', '_', 'LC_CTYPE'}:
        raise SystemExit('refusing: run under env -i HOME=<root> PATH=/usr/bin:/bin')
    if any(str(root) == t or str(root).startswith(t + '/') for t in TEMP_ROOTS):
        raise SystemExit('refusing: the scratch root must lie outside the temp roots')
    if any(part in ('.claude', '.codex', '.agent-harness') for part in root.parts):
        raise SystemExit('refusing: the scratch root must lie outside the harness roots')
    if any(root.iterdir()):
        raise SystemExit('refusing: the scratch root must start empty')
    decoy = root / 'decoy' / '.claude' / 'projects' / 'keep.jsonl'
    decoy.parent.mkdir(parents=True)
    decoy.write_text('decoy\n')
    decoy_before = hashlib.sha256(decoy.read_bytes()).hexdigest()
    ok_iso, iso = isolation_proof(root)
    result = {'python': sys.version.split()[0], 'isolation': iso, 'rows': [], 'started': time.time()}
    if not ok_iso:
        result['status'] = 'FAIL_ISOLATION'
        Path(args.out).write_text(json.dumps(result, indent=1))
        return 2
    selected = rows()[:args.limit] if args.limit else rows()
    for index, (section, want, row) in enumerate(selected):
        cmd_t, cwd_t = (row['cmd'], row.get('cwd')) if isinstance(row, dict) else (row, '@HOME@/repo')
        home = build_home(root, index)
        argv = install_guard(home)
        command = fill(cmd_t, home)
        cwd = fill(cwd_t, home) if cwd_t else None
        proc = fill(row['proc'], home) if isinstance(row, dict) and row.get('proc') else None
        code = ask_hook(argv, home, command, cwd, proc)
        before = snapshot(home) if want == 'block' else protected_files(home)
        decision = 'block' if code == 2 else 'allow' if code == 0 else 'error'
        record = {'i': index, 'section': section, 'want': want, 'sha256': hashlib.sha256(cmd_t.encode()).hexdigest()[:16],
                  'decision': decision, 'executed': False, 'changed': False, 'leaked': False}
        run_it = executable(cmd_t)
        if decision == 'allow' and run_it:
            status, leaked = sandbox(home, command, cwd)
            changed = snapshot(home) != before if want == 'block' else damaged(before, protected_files(home))
            record.update(executed=True, status=status, leaked=leaked, changed=changed)
        if want == 'block' and run_it:
            # control: a fresh home with no guard registered, same sandbox
            chome = root / ('c%04d' % index)
            chome.mkdir()
            make_fixture(chome)
            fake_credentials(chome)
            cbefore = snapshot(chome)
            ccommand = fill(cmd_t, chome)
            ccwd = fill(cwd_t, chome) if cwd_t else None
            cstatus, cleaked = sandbox(chome, ccommand, ccwd)
            record['control'] = {'status': cstatus, 'destroyed': snapshot(chome) != cbefore, 'leaked': cleaked}
        if want == 'block':
            record['pass'] = decision == 'block' and not record['changed'] and not record['leaked']
        else:
            record['pass'] = decision == 'allow' and not record['changed'] and not record['leaked']
        result['rows'].append(record)
    result['decoy_intact'] = hashlib.sha256(decoy.read_bytes()).hexdigest() == decoy_before
    rows_out = result['rows']
    controls = [r['control'] for r in rows_out if 'control' in r]
    result['summary'] = {
        'rows': len(rows_out), 'passed': sum(1 for r in rows_out if r['pass']),
        'positives_blocked': sum(1 for r in rows_out if r['want'] == 'block' and r['decision'] == 'block'),
        'positives': sum(1 for r in rows_out if r['want'] == 'block'),
        'negatives_allowed_and_ran_clean': sum(1 for r in rows_out if r['want'] == 'allow' and r['pass']),
        'negatives': sum(1 for r in rows_out if r['want'] == 'allow'),
        'controls_run': len(controls),
        'controls_proved_harm': sum(1 for c in controls if c['destroyed'] or c['leaked']),
        'executed_after_allow': sum(1 for r in rows_out if r['executed']),
        'changed_or_leaked_under_guard': sum(1 for r in rows_out if r['changed'] or r['leaked']),
    }
    result['status'] = 'PASS' if all(r['pass'] for r in rows_out) and result['decoy_intact'] else 'FAIL'
    result['finished'] = time.time()
    Path(args.out).write_text(json.dumps(result, indent=1))
    print(json.dumps({'status': result['status'], 'summary': result['summary'], 'isolation': iso,
                      'decoy_intact': result['decoy_intact']}))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
